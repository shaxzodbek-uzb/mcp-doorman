"""MCP transport wiring — the only module allowed to import ``mcp``/FastAPI.

This is a thin, best-effort adapter that maps the deny-by-default :class:`ToolSpec`
registry onto the official ``mcp`` low-level :class:`Server` and routes every
``tools/call`` through :meth:`Doorman.aguard_call`, so the five core guarantees apply on
the wire exactly as they do offline. It is deliberately small: the SDK owns the protocol.

The MCP spec gets its largest revision on 2026-07-28 (sessions removed, ``Mcp-Method``
headers, JSON Schema 2020-12). Building on the official SDK transfers most of that churn;
this module is expected to track the SDK rather than reimplement it.
"""

from __future__ import annotations

import inspect
from typing import TYPE_CHECKING, Any

from ..errors import DoormanError, Forbidden, RateLimited, Unauthorized
from ..principal import Transport

if TYPE_CHECKING:
    from ..doorman import Doorman

_INSTALL_HINT = (
    "the MCP integration needs the optional extra: pip install 'mcp-doorman[mcp]' "
    "(installs the official 'mcp' SDK)"
)


def _require_mcp() -> tuple[Any, Any]:
    try:
        import mcp.types as types  # type: ignore
        from mcp.server.lowlevel import Server  # type: ignore
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise DoormanError(_INSTALL_HINT) from exc
    return Server, types


_PY_TO_JSON = {int: "integer", float: "number", bool: "boolean", str: "string"}


def _json_type(annotation: Any) -> dict:
    """Best-effort JSON Schema fragment for a single parameter annotation."""
    origin = getattr(annotation, "__args__", None)
    if origin:  # Optional[X] / Union[...] -> use the first non-None arg
        for arg in origin:
            if arg is not type(None):
                return _json_type(arg)
    return {"type": _PY_TO_JSON.get(annotation, "string")}


def _input_schema(handler: Any) -> dict:
    """Derive a tool ``inputSchema`` from the handler signature (path/query/body params)."""
    try:
        sig = inspect.signature(handler)
    except (TypeError, ValueError):  # pragma: no cover - exotic callables
        return {"type": "object", "properties": {}}
    props: dict[str, Any] = {}
    required: list[str] = []
    for pname, param in sig.parameters.items():
        if pname in ("self", "cls", "request", "response", "background_tasks"):
            continue
        if param.kind in (param.VAR_POSITIONAL, param.VAR_KEYWORD):
            continue
        ann = param.annotation if param.annotation is not inspect.Parameter.empty else str
        props[pname] = _json_type(ann)
        if param.default is inspect.Parameter.empty:
            required.append(pname)
    schema: dict[str, Any] = {"type": "object", "properties": props}
    if required:
        schema["required"] = required
    return schema


def build_server(doorman: Doorman, *, name: str | None = None) -> Any:
    """Construct an ``mcp`` low-level :class:`Server` backed by the guarded registry.

    ``tools/list`` returns one tool per :class:`ToolSpec` (schema + annotations);
    ``tools/call`` runs through :meth:`Doorman.aguard_call`, extracting the verified
    principal from the request token (HTTP) or marking the call STDIO (fail-closed for
    scoped tools). Raises :class:`DoormanError` if the ``mcp`` extra is not installed.
    """
    Server, types = _require_mcp()
    server = Server(name or "mcp-doorman")

    @server.list_tools()
    async def _list_tools() -> list[Any]:
        return [
            types.Tool(
                name=spec.name,
                description=spec.description or spec.name,
                inputSchema=_input_schema(spec.handler),
                annotations=types.ToolAnnotations(**spec.annotations()),
            )
            for spec in doorman.registry.specs()
        ]

    @server.call_tool()
    async def _call_tool(name: str, arguments: dict | None) -> list[Any]:
        args = arguments or {}
        token, transport, peer = _request_auth(server)
        try:
            principal = doorman.principal_from_token(token, transport=transport)

            async def _invoke(call_args: dict) -> Any:
                spec = doorman.registry.get(name)
                result = spec.handler(**call_args)
                if inspect.isawaitable(result):
                    result = await result
                return result

            result = await doorman.aguard_call(name, args, principal, _invoke, caller_hint=peer)
        except (Unauthorized, Forbidden) as exc:
            return [types.TextContent(type="text", text=f"denied: {exc}")]
        except RateLimited as exc:
            msg = f"rate limited; retry in {exc.retry_after:.1f}s"
            return [types.TextContent(type="text", text=msg)]
        except DoormanError as exc:
            return [types.TextContent(type="text", text=f"error: {exc}")]
        return [types.TextContent(type="text", text=_stringify(result))]

    return server


def _request_auth(server: Any) -> tuple[str | None, Transport, str | None]:
    """Extract ``(bearer token, transport, peer)`` from the SDK request context.

    Returns ``(None, STDIO, None)`` when no HTTP request context is present — so scoped
    tools fail closed rather than silently bypass auth (the headline fix vs other bridges).
    ``transport`` is derived from the ASGI scope type (not from whether access raises), and
    ``peer`` is the client host used to key per-connection rate limiting for anon callers.
    """
    try:
        ctx = server.request_context  # type: ignore[attr-defined]
        request = getattr(ctx, "request", None)
        if request is None:
            return None, Transport.STDIO, None
        scope = getattr(request, "scope", {}) or {}
        is_web = scope.get("type") in ("http", "websocket")
        transport = Transport.HTTP if is_web else Transport.STDIO
        client = getattr(request, "client", None)
        peer = getattr(client, "host", None)
        headers = getattr(request, "headers", {}) or {}
        auth = headers.get("authorization") or headers.get("Authorization")
        if auth and auth.lower().startswith("bearer "):
            return auth[7:].strip(), transport, peer
        return None, transport, peer
    except Exception:
        return None, Transport.STDIO, None


def _stringify(result: Any) -> str:
    import json

    if isinstance(result, str):
        return result
    try:
        return json.dumps(result, ensure_ascii=False, default=str)
    except TypeError:  # pragma: no cover
        return str(result)


def _mount(doorman: Doorman, endpoint: str) -> Any:
    """Mount the streamable-HTTP MCP app onto ``doorman.app`` and add security routes.

    Adds the RFC 9728 Protected Resource Metadata endpoint and an Origin-check middleware
    (DNS-rebinding protection). Best-effort across SDK versions; raises
    :class:`DoormanError` with an install hint when the ``mcp`` extra is missing.
    """
    _require_mcp()
    app = doorman.app
    if app is None:
        raise DoormanError("Doorman has no app to mount onto; construct Doorman(app=...)")

    server = build_server(doorman, name=doorman.settings.server_name)

    try:
        from mcp.server.streamable_http_manager import StreamableHTTPSessionManager  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise DoormanError(_INSTALL_HINT) from exc

    manager = StreamableHTTPSessionManager(app=server, json_response=True, stateless=True)
    allowed_origins = frozenset(doorman.settings.allowed_origins)

    async def _handle(scope: Any, receive: Any, send: Any) -> None:
        # DNS-rebinding protection: reject disallowed cross-origin requests (403).
        if scope.get("type") == "http" and not _origin_allowed(scope, allowed_origins):
            await _send_403(send, b"origin not allowed")
            return
        await manager.handle_request(scope, receive, send)

    # RFC 9728 Protected Resource Metadata (discovery pointer to the external AS).
    if doorman.auth is not None:
        metadata = doorman.auth.metadata()

        async def _prm(scope: Any, receive: Any, send: Any) -> None:
            import json

            body = json.dumps(metadata).encode()
            await send({"type": "http.response.start", "status": 200,
                        "headers": [(b"content-type", b"application/json")]})
            await send({"type": "http.response.body", "body": body})

        _add_route(app, "/.well-known/oauth-protected-resource", _prm)

    _add_route(app, endpoint, _handle, methods=("GET", "POST"))
    return app


_LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})


def _origin_allowed(scope: Any, allowed: frozenset[str]) -> bool:
    """Validate the ASGI request Origin (DNS-rebinding protection).

    No ``Origin`` header (typical non-browser MCP client) -> allowed. Otherwise, allowed
    when ``allowed`` is configured and contains the origin, or — when not configured — only
    for localhost origins (matching the same-origin/localhost default).
    """
    headers = dict(scope.get("headers") or [])
    raw = headers.get(b"origin")
    if not raw:
        return True
    origin = raw.decode("latin-1")
    if allowed:
        return origin in allowed
    from urllib.parse import urlparse

    host = (urlparse(origin).hostname or "").lower()
    return host in _LOCAL_HOSTS


async def _send_403(send: Any, body: bytes) -> None:
    await send(
        {
            "type": "http.response.start",
            "status": 403,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": body})


def _add_route(app: Any, path: str, handler: Any, methods: tuple[str, ...] = ("GET",)) -> None:
    """Attach a raw ASGI handler to a Starlette/FastAPI app, version-tolerantly."""
    try:
        from starlette.routing import Route  # type: ignore

        app.router.routes.append(Route(path, handler, methods=list(methods)))
    except Exception as exc:  # pragma: no cover - non-Starlette app
        raise DoormanError(f"could not mount route {path!r}: {exc}") from exc
