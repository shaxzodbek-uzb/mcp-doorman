"""The Doorman orchestrator: deny-by-default + fail-closed guard pipeline + mount.

:meth:`Doorman.guard_call` is the heart of the library. Every one of the five guarantees
(deny-by-default, scope fail-closed, rate limit, redaction, audit) is enforced here and is
exercisable entirely offline by injecting the ``call`` function — which is exactly how the
test suite reaches >90% coverage without a network or the MCP SDK.
"""

from __future__ import annotations

import inspect
import sys
import time
from collections.abc import Callable, Sequence
from typing import Any

from .audit import AuditRecord, AuditSink, make_sink, shape
from .auth import AuthConfig, oauth
from .config import Settings
from .errors import ConfigError, DoormanError, Forbidden, NotExposed, RateLimited, Unauthorized
from .exposure import Registry, ToolSpec
from .principal import Principal, Transport
from .ratelimit import RateLimiter
from .redaction import Redactor
from .scopes import authorize

_DEFAULT = object()  # sentinel: "fall back to the settings value"


class Doorman:
    """Wraps a FastAPI app with secure-by-default MCP exposure."""

    oauth = staticmethod(oauth)

    def __init__(
        self,
        app: Any = None,
        *,
        auth: AuthConfig | None = None,
        rate_limit: str | None = _DEFAULT,  # type: ignore[assignment]
        redact: Sequence[str] = (),
        audit: str | AuditSink = "stderr",
        tenant_claim: str = "tenant_id",
        settings: Settings | None = None,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.app = app
        self._settings = settings or Settings()
        self._auth = auth
        self._registry = Registry()
        self._redactor = Redactor().with_extra_keys(redact)
        spec = self._settings.rate_limit if rate_limit is _DEFAULT else rate_limit
        self._rate = RateLimiter(spec, clock=clock)
        self._sink = make_sink(audit)
        self._tenant_claim = tenant_claim
        if app is not None:
            self.scan_app(app)

    # -- registration -----------------------------------------------------------------

    @property
    def registry(self) -> Registry:
        return self._registry

    @property
    def auth(self) -> AuthConfig | None:
        return self._auth

    @property
    def settings(self) -> Settings:
        return self._settings

    def register(self, spec: ToolSpec) -> None:
        """Register a pre-built :class:`ToolSpec` (offline/testing path)."""
        self._registry.add(spec)

    def scan_app(self, app: Any) -> list[ToolSpec]:
        """Discover ``@expose``'d routes on ``app``. Duck-typed; never imports FastAPI."""
        found: list[ToolSpec] = []
        for route in getattr(app, "routes", []):
            handler = getattr(route, "endpoint", None)
            if handler is None:
                continue
            # Pass methods through as-is (possibly empty); add_route fails closed on an
            # exposed route whose methods cannot be determined rather than assuming GET.
            methods = getattr(route, "methods", None) or []
            spec = self._registry.add_route(handler=handler, methods=methods)
            if spec is not None:
                found.append(spec)
        return found

    # -- identity ---------------------------------------------------------------------

    def principal_from_token(self, token: str | None, *, transport: Transport) -> Principal:
        """Resolve a verified :class:`Principal` from a bearer token, or anonymous.

        A missing/empty token yields an unverified principal (``verified=False``) — which
        the scope check denies for any scoped tool. A present token is validated by the
        configured verifier and audience-bound before it is trusted.
        """
        if not token:
            return Principal(subject="", transport=transport, verified=False)
        if self._auth is None or self._auth.verifier is None:
            raise Unauthorized("a token was presented but no verifier is configured")
        access = self._auth.verifier.verify(token)
        self._auth.check_audience(access)
        return Principal(
            subject=access.subject,
            scopes=access.scopes,
            tenant=access.tenant,
            transport=transport,
            verified=True,
        )

    # -- the pipeline -----------------------------------------------------------------

    def _emit(
        self,
        *,
        name: str,
        args: dict,
        principal: Principal,
        status: str,
        reason: str,
        scopes: tuple[str, ...],
        started: float,
    ) -> None:
        self._sink.emit(
            AuditRecord(
                tool=name,
                caller=principal.subject or "anonymous",
                tenant=principal.tenant,
                transport=principal.transport.value,
                status=status,
                reason=reason,
                arg_shape=shape(args),
                duration_ms=(time.perf_counter() - started) * 1000.0,
                scopes_required=scopes,
            )
        )

    def _rate_caller(self, principal: Principal, caller_hint: str | None) -> str:
        """The key for per-caller rate limiting.

        A verified subject keys on itself. Unverified callers must NOT all collapse into
        one shared 'anonymous' bucket (that lets one client starve every other), so we key
        on a per-connection hint (e.g. peer address) when the transport supplies one.
        """
        if principal.verified and principal.subject:
            return principal.subject
        return caller_hint or "anonymous"

    def _guard_prelude(
        self, name: str, args: dict, principal: Principal, started: float,
        caller_hint: str | None,
    ) -> ToolSpec:
        """Run the deny -> authorize -> rate steps, auditing every failure exit."""
        try:
            spec = self._registry.get(name)
        except NotExposed:
            self._emit(name=name, args=args, principal=principal, status="error",
                       reason="not_exposed", scopes=(), started=started)
            raise
        try:
            authorize(spec, principal)
        except Unauthorized:
            self._emit(name=name, args=args, principal=principal, status="denied",
                       reason="unauthorized", scopes=spec.scopes, started=started)
            raise
        except Forbidden:
            self._emit(name=name, args=args, principal=principal, status="denied",
                       reason="forbidden:scope", scopes=spec.scopes, started=started)
            raise
        try:
            self._rate.check(tool=name, caller=self._rate_caller(principal, caller_hint))
        except RateLimited:
            self._emit(name=name, args=args, principal=principal, status="rate_limited",
                       reason="rate_limited", scopes=spec.scopes, started=started)
            raise
        return spec

    def guard_call(
        self,
        name: str,
        args: dict,
        principal: Principal,
        call: Callable[[dict], Any],
        *,
        caller_hint: str | None = None,
    ) -> Any:
        """Guard one synchronous tool invocation. Emits exactly one audit record.

        ``caller_hint`` keys per-caller rate limiting for unverified callers (e.g. the peer
        address) so anonymous traffic is not collapsed into a single shared bucket.
        """
        started = time.perf_counter()
        spec = self._guard_prelude(name, args, principal, started, caller_hint)
        try:
            result = call(args)
        except Exception:
            self._emit(name=name, args=args, principal=principal, status="error",
                       reason="handler_error", scopes=spec.scopes, started=started)
            raise
        redacted = self._redactor.with_extra_keys(spec.redact).redact(result)
        self._emit(name=name, args=args, principal=principal, status="ok",
                   reason="ok", scopes=spec.scopes, started=started)
        return redacted

    async def aguard_call(
        self,
        name: str,
        args: dict,
        principal: Principal,
        call: Callable[[dict], Any],
        *,
        caller_hint: str | None = None,
    ) -> Any:
        """Async variant. ``call`` may be sync or a coroutine function."""
        started = time.perf_counter()
        spec = self._guard_prelude(name, args, principal, started, caller_hint)
        try:
            result = call(args)
            if inspect.isawaitable(result):
                result = await result
        except Exception:
            self._emit(name=name, args=args, principal=principal, status="error",
                       reason="handler_error", scopes=spec.scopes, started=started)
            raise
        redacted = self._redactor.with_extra_keys(spec.redact).redact(result)
        self._emit(name=name, args=args, principal=principal, status="ok",
                   reason="ok", scopes=spec.scopes, started=started)
        return redacted

    # -- transport --------------------------------------------------------------------

    def mount(self, endpoint: str | None = None) -> Any:
        """Mount the MCP server onto ``self.app``. Fail-closed on missing auth.

        Lazy-imports the MCP integration; a missing ``mcp`` extra raises a
        :class:`DoormanError` with an install hint. Refuses to mount a remote bridge with
        no auth when ``require_auth_for_remote`` is set — you cannot accidentally ship an
        unauthenticated bridge.
        """
        endpoint = endpoint or self._settings.endpoint
        if self._auth is None and self._settings.require_auth_for_remote:
            raise ConfigError(
                "refusing to mount a remote MCP bridge with no auth: pass "
                "auth=Doorman.oauth(...), or use Doorman.dev() for localhost-only prototyping"
            )
        from .integrations.fastmcp import _mount

        return _mount(self, endpoint)

    def build_server(self, *, name: str | None = None) -> Any:
        """Build (but do not mount) the underlying MCP server. Lazy-imports ``mcp``."""
        from .integrations.fastmcp import build_server

        return build_server(self, name=name or self._settings.server_name)

    @staticmethod
    def dev(app: Any = None, **kw: Any) -> Doorman:
        """Localhost prototyping preset: auth disabled, relaxed rate limit. Never in prod."""
        kw.setdefault("audit", "stderr")
        kw.setdefault("rate_limit", "1000/min per_caller")
        settings = Settings(require_auth_for_remote=False)
        doorman = Doorman(app, auth=None, settings=settings, **kw)
        sys.stderr.write(
            "⚠️  mcp-doorman: dev() preset active — auth disabled and security defaults "
            "loosened. Localhost prototyping only; do NOT use in production.\n"
        )
        return doorman


__all__ = ["Doorman", "DoormanError"]
