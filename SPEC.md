# mcp-doorman — Canonical Build Spec (single source of truth)

> Every builder reads THIS file and implements exactly the signatures, names, and
> behaviors below. Do not invent extra public API. Match names character-for-character.
> When in doubt, prefer fewer moving parts and stdlib over dependencies. The core is
> the moat: pure, offline-testable governance logic. The MCP/transport wiring is a thin,
> lazy-imported integration layer — it must NOT leak into the core's import graph.

## What it is (positioning)

A **secure-by-default FastAPI→MCP bridge**. Turning a FastAPI app into an MCP server is
already a solved, commoditized problem (`fastapi_mcp`, `FastMCP.from_fastapi`). Those
tools optimize for *5-minutes-to-a-tool* and ship security as opt-in primitives you must
assemble yourself (FastMCP) or omit entirely (`fastapi_mcp`). Everything that ships the
full governance stack — scopes, rate limits, PII redaction, audit — is a heavyweight
network **gateway** (Kong / Higress / TrueFoundry): an extra hop and extra infra.

`mcp-doorman` is the missing middle: a single `pip install` library that runs
**in-process** and makes the **secure configuration the default**. Five guarantees no
mainstream in-process bridge combines:

1. **Deny-by-default exposure.** A FastAPI route is **never** an MCP tool unless you
   explicitly `@expose(...)` it. Destructive HTTP methods (POST/PUT/PATCH/DELETE) refuse
   to be exposed unless you pass `destructive=True`, and that flag auto-emits the MCP
   `destructiveHint` annotation so client safety UIs can gate the call.
2. **Scope→tool authorization, fail-closed — including on STDIO.** A tool that declares
   `scopes=[...]` is denied unless the caller presents a verified principal whose scopes
   are a superset. The headline fix: when there is **no** verified auth context (no token,
   or STDIO transport where FastMCP silently returns `None` and bypasses every check),
   `mcp-doorman` **denies** instead of allowing. Insecure-by-omission is impossible.
3. **Built-in rate limiting + call budget.** Per-caller and per-tool token buckets, pure
   in-process, no Redis. Directly answers the documented uncontrolled-tool-loop /
   ~$400-runaway failure mode.
4. **PII redaction at the source.** Configured keys (`*_token`, `email`, ...) and value
   patterns (email / phone / SSN / card) are redacted from tool **results** before they
   reach the model, and from anything the audit layer would otherwise record.
5. **Structured audit out of the box.** One OTel-friendly record per invocation: caller
   identity, tool name, argument **SHAPE** (container types / lengths / counts — never
   values and never caller-controlled keys), status, latency. SOC2/HIPAA/GDPR evidence
   without bolting on logging by hand.

Plus an **allowlist** (only `@expose`d tools exist), an **audience-binding** token-verifier
seam (RFC 8707 / 9068 — so a token minted for one server cannot be replayed against
another), a **FastMCP / `mcp`-SDK integration** that mounts Streamable HTTP onto an
existing FastAPI app, and a **CLI**.

Tagline: *"FastMCP gives you the tools; this gives you the seatbelts — secure-by-default,
in-process, no gateway."*

### What this explicitly is NOT
- NOT a JSON-RPC / transport reimplementation. It builds **on** the official `mcp` Python
  SDK / FastMCP (`streamable_http_app()`, low-level `Server`, `TokenVerifier`).
- NOT an authorization server. It is a **resource server** seam: you bring an external AS
  (Auth0 / Keycloak / blaze-sso); `mcp-doorman` validates audience + scope and serves the
  RFC 9728 metadata pointer.
- NOT a network gateway. No extra hop, no Envoy/K8s. It lives inside your app process.

## Package layout

```
mcp_doorman/
  __init__.py          # public exports (see below) + __version__
  errors.py            # exception types
  principal.py         # Transport, Principal (verified caller identity + scopes + tenant)
  exposure.py          # ToolSpec, expose() decorator, Registry (deny-by-default), annotations
  scopes.py            # authorize() — fail-closed scope check (incl. STDIO)
  ratelimit.py         # TokenBucket, RateLimiter, parse_rate_spec()
  redaction.py         # Redactor (key globs + value regexes, recursive)
  audit.py             # AuditRecord, shape(), AuditSink protocol, StderrSink, NullSink
  auth.py              # AccessToken, TokenVerifier protocol, StaticVerifier, AuthConfig, oauth()
  config.py            # Settings (pydantic-settings, env DOORMAN_*)
  doorman.py           # Doorman — orchestrator: register + guard_call pipeline + mount()
  integrations/
    __init__.py
    fastmcp.py         # build_server(...) / _mount(...) onto mcp SDK + FastAPI (lazy import)
  cli.py               # `mcp-doorman` entry point (argparse, stdlib)
tests/                 # pytest; pure-logic tests MUST need NO network and NO mcp/fastapi
examples/              # runnable snippets
```

Distribution name `mcp-doorman`; import package `mcp_doorman`. Python >=3.10. License MIT
(holder "Shaxzodbek Sobirov / Blaze"). The only hard dependency is `pydantic-settings`;
everything MCP/FastAPI-specific is an **optional extra**, lazily imported. The `guard`
pipeline and all five guarantees are exercisable and tested with **zero** optional deps.

## Core types & exact signatures

### errors.py
```python
class DoormanError(Exception): ...
class NotExposed(DoormanError):
    """A tool name was requested that is not in the deny-by-default registry."""
class DestructiveNotAllowed(DoormanError):
    """expose() on a destructive HTTP method without destructive=True."""
class Unauthorized(DoormanError):
    """Maps to MCP/HTTP 401 — no verified principal where one is required (fail-closed)."""
class Forbidden(DoormanError):
    """Maps to 403 — verified principal lacks the required scope(s)."""
class RateLimited(DoormanError):
    """Per-caller or per-tool token bucket exhausted. Carries `retry_after: float`."""
class ConfigError(DoormanError):
    """Invalid configuration (e.g. remote bind with no auth, bad rate spec)."""
```
`RateLimited.__init__(self, message, *, retry_after: float)` stores `self.retry_after`.

### principal.py
```python
class Transport(str, Enum):
    HTTP = "http"
    STDIO = "stdio"

@dataclass(frozen=True)
class Principal:
    subject: str                       # verified caller id (token `sub`), "" if anonymous
    scopes: frozenset[str] = frozenset()
    tenant: str | None = None          # value of the configured tenant claim
    transport: Transport = Transport.HTTP
    verified: bool = False             # True ONLY if produced by a TokenVerifier
    def has_scopes(self, required: Iterable[str]) -> bool:
        """True iff every required scope is present. Empty `required` -> True."""

ANONYMOUS = Principal(subject="", verified=False)
```
A `Principal` is "trusted" only when `verified is True`. The integration constructs it
from a validated token; `ANONYMOUS` (or a stdio call with no token) is `verified=False`.

### exposure.py
```python
DESTRUCTIVE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

@dataclass(frozen=True)
class ToolSpec:
    name: str
    handler: Callable                  # the underlying FastAPI route function
    methods: frozenset[str]            # HTTP methods of the route
    description: str = ""
    scopes: tuple[str, ...] = ()       # required OAuth scopes (AND semantics)
    destructive: bool = False          # acknowledged side effects
    read_only: bool = True             # derived: True iff no destructive method
    redact: tuple[str, ...] = ()       # extra per-tool redaction keys (merged with global)
    rate: str | None = None            # optional per-tool override, e.g. "10/min"
    def annotations(self) -> dict:
        """MCP tool annotations: {'readOnlyHint': bool, 'destructiveHint': bool}.
        destructiveHint is True iff `destructive`; readOnlyHint True iff `read_only`."""

def expose(*, name: str | None = None, scopes: Sequence[str] = (),
           destructive: bool = False, description: str | None = None,
           redact: Sequence[str] = (), rate: str | None = None) -> Callable:
    """Decorator. Stamps a pending-spec onto the wrapped function via the attribute
    `_doorman_expose` (a dict of the kwargs). Returns the function UNCHANGED so it still
    works as a normal FastAPI route (decorate it BELOW the @app.get/post line, or above —
    both work because we only read the attribute later). `name` defaults to the function
    __name__. Does NOT enforce destructive here (methods are unknown until the route is
    bound); enforcement happens in Registry.add_route."""

class Registry:
    """Deny-by-default. Only routes carrying `_doorman_expose` become tools."""
    def __init__(self) -> None: ...
    def add_route(self, *, handler, methods: Iterable[str]) -> ToolSpec | None:
        """If `handler` carries `_doorman_expose`, build+validate a ToolSpec and store it.
        Raise DestructiveNotAllowed if the route has a destructive method but the spec did
        not pass destructive=True. Return the ToolSpec, or None if the handler is not
        exposed (the deny-by-default path). Duplicate tool names raise ConfigError."""
    def get(self, name: str) -> ToolSpec:        # raises NotExposed
    def __contains__(self, name: str) -> bool: ...
    def names(self) -> list[str]: ...
    def specs(self) -> list[ToolSpec]: ...
```
`add_route` is the single chokepoint where deny-by-default + destructive-gating are
enforced. `read_only` is computed as `methods.isdisjoint(DESTRUCTIVE_METHODS)`.

### scopes.py
```python
def authorize(spec: ToolSpec, principal: Principal) -> None:
    """Fail-closed scope check. Rules, in order:
    1. If spec.scopes is empty -> allow (return None). (Public tool; still rate-limited
       and audited.)
    2. principal must be verified. If not principal.verified -> raise Unauthorized
       (THIS is the STDIO/no-token fail-closed guarantee: a stdio call yields an
       unverified principal, so a scoped tool is denied, never silently bypassed).
    3. If principal.has_scopes(spec.scopes) -> allow; else raise Forbidden.
    """
```
Pure function, no I/O. This is the single most important security test target.

### ratelimit.py
```python
@dataclass
class TokenBucket:
    capacity: float
    refill_per_sec: float
    tokens: float
    updated: float                     # monotonic timestamp
    def take(self, now: float, n: float = 1.0) -> bool:
        """Refill based on elapsed (capacity-capped), then take n if available.
        Return True if taken, False otherwise. Pure given `now` (monotonic seconds)."""
    def retry_after(self, now: float, n: float = 1.0) -> float:
        """Seconds until n tokens are available (0.0 if available now)."""

def parse_rate_spec(spec: str) -> list[tuple[str, float, float]]:
    """Parse 'COUNT/UNIT [per_caller|per_tool][; ...]' into
    (scope, capacity, refill_per_sec) tuples. UNIT in {s,sec,second,m,min,minute,h,hour}.
    scope defaults to 'per_caller'. Examples:
      '60/min'                       -> [('per_caller', 60, 1.0)]
      '60/min per_caller; 10/min per_tool'
                                     -> [('per_caller',60,1.0),('per_tool',10,1/6)]
    Raise ConfigError on malformed input."""

class RateLimiter:
    def __init__(self, spec: str | None, *, clock: Callable[[], float] | None = None,
                 max_buckets: int = 100_000) -> None:
        """spec=None disables limiting (check() is a no-op). clock defaults to
        time.monotonic; injectable for tests. max_buckets bounds memory against
        high-cardinality callers: at the cap, fully-recovered buckets (reconstructable,
        lossless) are dropped first, then least-recently-used are evicted."""
    def check(self, *, tool: str, caller: str, cost: float = 1.0) -> None:
        """Enforce every configured rule. per_caller buckets key on caller; per_tool
        buckets key on tool. On exhaustion raise RateLimited(retry_after=...). A failed
        rule does NOT consume tokens from rules not yet checked (check cheapest/most-
        specific deterministically; document order = spec order)."""
```
Buckets are kept in a dict keyed by `(scope, key)`. Pure arithmetic; the only time source
is the injectable monotonic clock.

### redaction.py
```python
REDACTED = "«redacted»"
# Default value patterns (compiled regex): email, e164-ish phone, US SSN, credit-card-ish.
DEFAULT_VALUE_PATTERNS: tuple[re.Pattern, ...]
# Default sensitive key globs: password, passwd, secret, token, *_token, api_key, apikey,
# authorization, ssn, credit_card, card_number, cvv.
DEFAULT_KEYS: tuple[str, ...]

class Redactor:
    def __init__(self, keys: Sequence[str] = DEFAULT_KEYS, *,
                 value_patterns: Sequence[re.Pattern] = DEFAULT_VALUE_PATTERNS,
                 mask: str = REDACTED) -> None:
        """keys are fnmatch globs matched case-insensitively against dict KEYS.
        value_patterns are searched inside string VALUES."""
    def with_extra_keys(self, extra: Iterable[str]) -> "Redactor":
        """Return a new Redactor whose key set is the union (per-tool merge)."""
    def redact(self, obj: Any) -> Any:
        """Return a deep-copied, redacted structure. Rules:
        - structured objects (pydantic model_dump / dataclass asdict / plain __dict__) are
          normalized to a dict first, then walked — so a returned model is NOT a leak.
        - Mapping: if a key (coerced to str; bytes decoded) matches a sensitive glob ->
          value becomes mask. Else recurse into the value.
        - list/tuple/set/frozenset: recurse elementwise (preserve container kind).
        - str: substitute every value-pattern match with mask.
        - bytes: decode UTF-8 and scan; undecodable binary is passed through unscanned.
        - int (not bool): scanned as a string for card/SSN shapes (masked iff matched).
        - other scalars (bool/float/None): returned unchanged.
        Never mutates the input. Must not raise on cyclic structures (track id())."""
```
Redaction is applied to tool **results** before return, and the audit layer records only
shapes — so raw PII values never reach the model nor the logs.

### audit.py
```python
@dataclass(frozen=True)
class AuditRecord:
    tool: str
    caller: str                        # principal.subject or "anonymous"
    tenant: str | None
    transport: str
    status: str                        # "ok" | "denied" | "error" | "rate_limited"
    reason: str                        # short machine-ish reason, e.g. "forbidden:scope"
    arg_shape: dict                    # from shape(args) — keys/types/lengths, NO values
    duration_ms: float
    scopes_required: tuple[str, ...]
    def as_dict(self) -> dict: ...

def shape(obj: Any, *, _depth: int = 0) -> Any:
    """Structural fingerprint with NO values and NO keys. dict ->
    {'type':'dict','len':N,'values': shape(a representative value)} (keys are NOT emitted —
    they may be caller-controlled data); list/tuple/set -> {'type','len','items'};
    str -> {'type':'str','len':N}; int/float/bool/None -> {'type': typename};
    depth-capped (>=4 -> {'type':'…'}). GUARANTEE: the output contains no input value and
    no input dict key — only container types, lengths, and counts. The audit test asserts
    that known sentinel values AND keys are absent from json.dumps(shape(payload))."""

class AuditSink(Protocol):
    def emit(self, record: AuditRecord) -> None: ...

class StderrSink:
    """Writes one JSON line per record to stderr (OTel-collector friendly)."""
class NullSink:
    """Drops records (testing / opt-out)."""

def make_sink(spec: "str | AuditSink | None") -> AuditSink:
    """'stderr'/'otel' -> StderrSink; None/'none'/'null' -> NullSink; an AuditSink -> itself."""
```
`otel` maps to `StderrSink` for now (a real OTel exporter is an optional future sink); the
record shape is already span-attribute friendly. Document this honestly.

### auth.py
```python
@dataclass(frozen=True)
class AccessToken:
    subject: str
    scopes: frozenset[str]
    audience: tuple[str, ...] = ()
    tenant: str | None = None
    raw: str | None = None

class TokenVerifier(Protocol):
    def verify(self, token: str) -> AccessToken: ...
        # raise Unauthorized on any failure (expired/invalid/etc.)

@dataclass(frozen=True)
class AuthConfig:
    issuer: str
    resource: str                      # this server's audience (RFC 8707 binding)
    required_scopes: tuple[str, ...] = ()
    tenant_claim: str = "tenant_id"
    verifier: TokenVerifier | None = None   # None until wired to a real AS
    def metadata(self) -> dict:
        """RFC 9728 Protected Resource Metadata body:
        {'resource': resource, 'authorization_servers': [issuer], 'scopes_supported': [...]}"""
    def check_audience(self, token: AccessToken) -> None:
        """Raise Unauthorized if `resource` not in token.audience (when audience present).
        Empty token.audience is treated as a failure when a resource is configured
        (fail-closed) UNLESS verifier is a StaticVerifier marked permissive."""

class StaticVerifier:
    """In-memory verifier for tests/dev: maps opaque token strings -> AccessToken."""
    def __init__(self, tokens: dict[str, AccessToken]) -> None: ...
    def verify(self, token: str) -> AccessToken:   # raises Unauthorized if unknown

def oauth(*, issuer: str, resource: str, required_scopes: Sequence[str] = (),
          tenant_claim: str = "tenant_id", verifier: TokenVerifier | None = None) -> AuthConfig:
    """Convenience builder. Exposed as Doorman.oauth (staticmethod)."""
```
The core never performs network I/O. A real JWKS/introspection verifier is provided by the
integration extra or by the user; the core's job is audience + scope enforcement.

### config.py
```python
class Settings(BaseSettings):  # pydantic-settings, env_prefix="DOORMAN_", reads .env
    endpoint: str = "/mcp"
    rate_limit: str | None = "60/min per_caller; 10/min per_tool"
    audit: str = "stderr"
    tenant_claim: str = "tenant_id"
    require_auth_for_remote: bool = True   # remote bind w/o auth -> ConfigError
    allowed_origins: tuple[str, ...] = ()  # empty -> only same-origin/localhost allowed
    server_name: str = "mcp-doorman"
```

### doorman.py — `Doorman`
```python
class Doorman:
    def __init__(self, app=None, *, auth: AuthConfig | None = None,
                 rate_limit: str | None = "<settings default>",
                 redact: Sequence[str] = (), audit: "str | AuditSink" = "stderr",
                 tenant_claim: str = "tenant_id", settings: Settings | None = None,
                 clock: Callable[[], float] | None = None) -> None:
        """Build the registry, redactor (DEFAULT_KEYS + `redact`), rate limiter, audit
        sink, and store auth. `app` (a FastAPI/Starlette app) is OPTIONAL: when given,
        scan_app() is called immediately to discover @expose'd routes; when omitted you
        register ToolSpecs directly (the offline/testing path)."""

    oauth = staticmethod(oauth)        # Doorman.oauth(issuer=..., resource=...)

    def register(self, spec: ToolSpec) -> None: ...
    def scan_app(self, app) -> list[ToolSpec]:
        """Walk app.routes; for each, call Registry.add_route(handler, methods). Return the
        exposed specs. Lazy/duck-typed so the core does not import FastAPI."""
    def principal_from_token(self, token: str | None, *, transport: Transport) -> Principal:
        """None/'' -> ANONYMOUS with the given transport (verified=False). Else use the
        AuthConfig.verifier to verify, check audience, and build a verified Principal
        (subject/scopes/tenant). Verifier failure -> Unauthorized."""

    def guard_call(self, name: str, args: dict, principal: Principal,
                   call: Callable[[dict], Any], *, caller_hint: str | None = None) -> Any:
        """THE pipeline. `caller_hint` (e.g. peer address) keys per-caller rate limiting for
        unverified callers so anonymous traffic is not collapsed into one shared bucket.
        In order, fail-closed, always auditing the outcome:
          1. spec = registry.get(name)            # NotExposed -> audited 'error', re-raised
          2. authorize(spec, principal)           # Unauthorized/Forbidden -> audited 'denied'
          3. rate.check(tool=name, caller=principal.subject or 'anonymous')  # RateLimited
          4. result = call(args)                  # exceptions -> audited 'error', re-raised
          5. redacted = redactor.with_extra_keys(spec.redact).redact(result)
          6. emit AuditRecord(status='ok', arg_shape=shape(args), duration_ms=...)
          7. return redacted
        Every exit path (including each raise) emits exactly ONE AuditRecord with the right
        status/reason and arg_shape=shape(args). Never logs raw args or raw result."""

    async def aguard_call(self, name, args, principal, call) -> Any:
        """Async variant; `call` may be sync or a coroutine function."""

    def mount(self, endpoint: str | None = None):
        """Delegate to integrations.fastmcp._mount(self, endpoint or settings.endpoint).
        Lazy-imports mcp/fastmcp; missing -> DoormanError with an actionable pip hint.
        Validates: remote exposure with auth=None and require_auth_for_remote -> ConfigError
        (fail-closed: you cannot accidentally ship an unauthenticated remote bridge)."""

    @staticmethod
    def dev(app=None, **kw) -> "Doorman":
        """Localhost prototyping preset: auth disabled, audit='stderr', rate limit relaxed.
        Prints a one-line warning that security defaults are loosened. Never use in prod."""
```
`guard_call` is the heart. It is exercised entirely offline (inject `call`), which is how
all five guarantees get high-coverage tests.

### integrations/fastmcp.py
```python
def build_server(doorman: "Doorman", *, name: str | None = None):
    """Construct a low-level mcp.server.Server whose @list_tools returns one mcp Tool per
    ToolSpec (name, description, inputSchema derived from the handler signature, annotations
    from spec.annotations()), and whose @call_tool routes through doorman.aguard_call(...),
    extracting the Principal from the validated request token (HTTP) or marking the call
    STDIO (verified=False). Lazy-import `mcp`; missing -> DoormanError('pip install
    "mcp-doorman[mcp]"'). This is the only module allowed to import mcp/fastapi."""

def _mount(doorman, endpoint: str):
    """Mount build_server(...).streamable_http_app() onto doorman.app at `endpoint` via
    Starlette Mount + lifespan, add the RFC 9728 metadata route
    (/.well-known/oauth-protected-resource -> doorman.auth.metadata()) and an Origin-check
    wrapper (403 on disallowed Origin; uses settings.allowed_origins, empty -> localhost
    only; absent Origin header -> allowed for non-browser clients). Return the app."""
```
Integration code is best-effort and covered only by import/lazy-error tests offline (no live
MCP client). Keep it small; the SDK does the protocol.

### cli.py — entry point `mcp-doorman` (argparse, stdlib only)
Subcommands:
- `doctor` — print settings summary, the resolved redaction key set, rate spec, audit sink,
  and whether the mcp/fastapi extras import (up/down). No network.
- `lint <module:app>` — import the FastAPI app, scan it, and print each exposed tool with
  its methods, scopes, destructive flag, and annotations; warn on destructive-without-scope
  and on exposed tools with no scopes. Exit non-zero if any warning (CI-friendly).
- `version` — print __version__.
Exit non-zero with a clean message on DoormanError.

### __init__.py exports
`Doorman, expose, ToolSpec, Registry, Principal, Transport, ANONYMOUS, authorize,
RateLimiter, TokenBucket, parse_rate_spec, Redactor, REDACTED, AuditRecord, shape,
AuditSink, StderrSink, NullSink, make_sink, AccessToken, TokenVerifier, StaticVerifier,
AuthConfig, oauth, Settings, DoormanError, NotExposed, DestructiveNotAllowed, Unauthorized,
Forbidden, RateLimited, ConfigError`. Define `__version__ = "0.1.0"`.

## Tests (pytest) — MUST pass offline (no network, no mcp/fastapi required)
1. `test_exposure`: undecorated route -> add_route returns None (deny-by-default); a GET
   @expose -> ToolSpec(read_only=True); a POST @expose WITHOUT destructive -> raises
   DestructiveNotAllowed; with destructive=True -> annotations()['destructiveHint'] True;
   duplicate name -> ConfigError; registry.get(unknown) -> NotExposed.
2. `test_scopes_fail_closed` (HEADLINE): scoped tool + unverified principal -> Unauthorized;
   scoped tool + STDIO principal (verified=False) -> Unauthorized (the bypass-fix);
   scoped tool + verified principal missing a scope -> Forbidden; with all scopes -> passes;
   unscoped tool + anonymous -> passes. Parametrize to assert NO (principal) input makes a
   scoped tool callable without verified+sufficient scopes.
3. `test_ratelimit`: TokenBucket refill math (monotonic clock injected); per_caller vs
   per_tool keying; exhaustion -> RateLimited with retry_after>0; parse_rate_spec happy +
   malformed (ConfigError); spec=None disables.
4. `test_redaction`: sensitive key -> value masked regardless of type; nested dict/list
   recursion; email/phone/ssn value patterns masked; per-tool with_extra_keys union;
   input is not mutated; cyclic structure does not raise. LEAKAGE TEST: redact a payload
   containing a known secret and assert the secret substring is absent from the output.
5. `test_audit`: shape() contains NO input value (assert known sentinel values absent from
   json.dumps(shape(payload))); record.as_dict round-trips; status/reason correct.
6. `test_doorman_pipeline`: guard_call happy path returns REDACTED result and emits one
   'ok' record with arg_shape (capture via a list-backed sink); denied path emits 'denied'
   and raises; rate-limited path emits 'rate_limited'; handler error emits 'error' and
   re-raises; assert raw arg values and raw secret never appear in any emitted record.
7. `test_doorman_mount_guards`: Doorman(auth=None).mount() with require_auth_for_remote ->
   ConfigError; Doorman.dev() builds with auth disabled and warns.
8. `test_integration_lazyimport`: importing integrations.fastmcp and calling build_server
   without `mcp` installed raises DoormanError with the pip hint (skip if mcp IS installed).
9. `test_imports`: `import mcp_doorman` pulls in NO mcp/fastapi (assert those modules are
   not force-imported by the core); all names in __all__ are importable; __version__ set.
Aim >90% coverage of errors/principal/exposure/scopes/ratelimit/redaction/audit/auth/
doorman. integrations/cli covered by light import/lint tests.

## Quality bar
- Ruff-clean (line length 100), type hints throughout, docstrings on public API.
- No secrets, no hard-coded keys. The core import graph imports NO mcp/fastapi SDK.
- Security correctness is the product: the fail-closed, redaction-leakage, audit-no-values,
  and rate-limit tests are load-bearing — they must be precise, not smoke tests.
- README: positioning + the five guarantees, a comparison table vs `fastapi_mcp` /
  `FastMCP.from_fastapi` / gateways, a 60-second quickstart, the `@expose` + `Doorman`
  example, the STDIO fail-closed story, an honest "what this is NOT" + a "known risks"
  (thin-layer absorption; 2026-07-28 spec RC) section. Accurate to the actual code.
- Honesty: do not claim transport/spec conformance the integration does not yet implement.
  The core guarantees are real and tested; the MCP wiring is clearly marked "built on the
  official SDK, integration is best-effort / evolving with the 2026-07-28 RC."
```
