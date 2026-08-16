# mcp-doorman

**Secure-by-default FastAPI→MCP bridge.** FastMCP gives you the tools; this gives you the
seatbelts — deny-by-default exposure, scope→tool authorization that fails **closed** (even
on STDIO), built-in rate limiting, PII redaction at the source, and a structured audit
log. In-process. No gateway.

```bash
pip install mcp-doorman          # core (dependency-light)
pip install "mcp-doorman[mcp]"   # + the official MCP transport
```

> **Status:** beta (`0.2.0`). The five security guarantees are implemented and covered by
> an offline test suite. The MCP wire transport is built on the official `mcp` SDK and is
> evolving toward the 2026-07-28 spec revision — see [Known limits](#known-limits--honest-caveats).

---

## Why

Turning a FastAPI app into an MCP server is already a commodity. [`fastapi_mcp`][fam] and
[`FastMCP.from_fastapi`][fastmcp] do it in five minutes — and ship security as opt-in
primitives you assemble yourself, or omit entirely. The result, in the wild:

- An **open RFC-8707 token-confusion advisory** ([GHSA-5h2m-4q8j-pqpj][ghsa]) — a token
  minted for one MCP server can be replayed against another.
- A documented **~$400 runaway** from an uncontrolled tool-call loop — no rate or cost guard.
- **No per-tool RBAC**, no output sanitization, no audit trail out of the box.
- FastMCP's own docs: *"for bootstrapping and prototyping, not for mirroring your API."*

Everything that *does* ship the full governance stack — scopes, rate limits, redaction,
audit — is a heavyweight **network gateway** (Kong, Higress, TrueFoundry): an extra hop and
extra infrastructure to stand up and operate. Overkill for one service exposing eight
endpoints.

`mcp-doorman` is the missing middle: a single `pip install` that runs **in-process** and
makes the **secure configuration the default**. Insecure-by-omission is impossible.

## The five guarantees

1. **Deny-by-default exposure.** A route is never a tool unless you `@expose` it.
   Destructive methods (POST/PUT/PATCH/DELETE) refuse to publish without an explicit
   `destructive=True`, which auto-emits the MCP `destructiveHint` annotation.
2. **Scope→tool authorization, fail-closed — including STDIO.** A scoped tool is denied
   unless the caller presents a **verified** principal with sufficient scopes. When there's
   no verified context (no token, or STDIO where other bridges silently return `None` and
   *bypass* every check), doorman **denies**.
3. **Rate limiting + cost budget.** Per-caller and per-tool token buckets, in-process, no
   Redis — the direct answer to the runaway-loop failure mode. Tighten one expensive tool
   with `@expose(rate=…)`, and cap total spend with `@expose(cost=…)` plus a
   [budget](#rate-limits-and-budgets). Both fail closed.
4. **PII redaction at the source.** Sensitive keys (`*_token`, `email`, …) and value
   patterns (email/phone/SSN/card) are redacted from tool **results** before they reach the
   model, and from anything the audit layer would record.
5. **Structured audit out of the box.** One OTel-friendly record per call: caller, tool,
   argument **shape** (container types/lengths/counts — *never values, never
   caller-controlled keys*), status, latency.

## 60-second quickstart

```python
from fastapi import FastAPI
from mcp_doorman import Doorman, expose

app = FastAPI()

# Deny-by-default: nothing is a tool unless decorated.
@expose(name="get_invoice", scopes=["invoices:read"])
@app.get("/invoices/{id}")
async def get_invoice(id: str):
    return {"id": id, "email": "alice@example.com"}   # email auto-redacted in the result

@expose(name="refund", scopes=["invoices:write"], destructive=True, redact=["amount"])
@app.post("/invoices/{id}/refund")
async def refund(id: str, amount: float):
    return {"id": id, "refunded": amount}

# One secure mount: Streamable HTTP, RFC 9728 metadata, audience-bound tokens,
# rate limits, redaction, and audit — all on by default.
Doorman(
    app,
    auth=Doorman.oauth(
        issuer="https://sso.example.com",
        resource="https://api.example.com/mcp",   # RFC 8707 audience binding
    ),
    rate_limit="60/min per_caller; 10/min per_tool",
    redact=["email", "phone", "ssn", "*_token"],
    audit="stderr",
).mount("/mcp")
```

Prototyping locally? `Doorman.dev(app)` loosens auth for localhost so the secure default
never blocks first-run DX (it prints a warning and must never be used in production).

Lint what you're about to expose, in CI:

```bash
mcp-doorman lint myapp.main:app   # lists tools, scopes, destructive flags; exits non-zero on warnings
mcp-doorman doctor                # settings + whether the [mcp] extra is installed
```

## Rate limits and budgets

A rate limit answers *how often*. A budget answers *how much*. The runaway-loop failure
mode needs both: a loop can stay comfortably under 60 calls a minute and still spend a
fortune if each call hits a paid API.

**Per-tool rate override.** Tighten one tool without loosening the rest:

```python
@expose(scopes=["reports:read"], rate="5/min per_caller")
async def generate_report(...): ...
```

Enforced *in addition to* the Doorman-wide limit, never instead of it. A malformed spec
raises at decoration time, so it fails on import rather than on the first call.

**Cost budget.** Declare what a tool is worth and cap the total:

```python
@expose(scopes=["ai:write"], cost=25)      # this one hits a paid API
async def summarize(...): ...

@expose(scopes=["invoices:read"])          # cost defaults to 1
async def get_invoice(...): ...

doorman = Doorman(app, auth=..., budget="500/day per_caller")
```

`summarize` now costs 25 units of that 500; twenty calls exhaust the day. The unit is
whatever you decide — cents, credits, API calls, seconds. There is **no default budget**:
a cost unit means nothing until a deployment defines one, and a guessed default would be
security theatre.

Exceeding it raises `BudgetExceeded` and audits `status="budget_exceeded"`, distinct from
`rate_limited` so you can tell *calling too fast* from *calling too expensively* — the
first is fixed by backing off, the second usually isn't. It subclasses `RateLimited`, so
existing handlers keep working.

Ordering matters and is tested: the budget is checked **after** the rate limit, so a call
refused for being too frequent keeps its allowance. And rules are probed before any are
committed, so a rejected call never burns tokens from the limits that would have passed.

```python
doorman.remaining_budget(tool="summarize", caller="user-1")   # 475.0
```

Every audit record carries the call's declared `cost`, so spend is reconstructable from
the log without a second system.

> **In-process, like everything else here.** Buckets live in one process's memory; two
> replicas each enforce the budget independently. That is the same trade-off the rate
> limiter already makes — no Redis, no gateway — and the reason this is a guard rail
> against a runaway loop, not a billing system.

## How it compares

| | `fastapi_mcp` | `FastMCP.from_fastapi` | **mcp-doorman** |
|---|---|---|---|
| Exposure default | expose-all (opt-out) | expose-all (RouteMap) | **deny-by-default**, destructive gated |
| Per-tool scopes | by hand in each handler | `require_scopes()` primitive, **bypassed on STDIO** | **enforced at the library layer, fail-closed on STDIO** |
| Multi-tenant token safety (RFC 8707) | open advisory, replayable | DIY audience checks | **audience binding by default** |
| Rate / loop & cost guard | none (documented $400) | none ("build it yourself") | **built-in token bucket + cost budget, no Redis** |
| PII redaction (results) | none | not provided | **redaction-at-source, on by default** |
| Audit / observability | none built-in | custom middleware | **structured per-call audit (shape, not values)** |
| Deployment shape | in-process, security DIY | in-process, primitives DIY | **in-process with gateway-grade secure defaults** |

For *full* enterprise governance at the edge, a gateway (Kong/Higress/TrueFoundry) is still
the right tool. `mcp-doorman` is for the single service that wants those controls **without**
standing one up.

## What this is NOT

- **Not** a JSON-RPC / transport reimplementation. It builds **on** the official `mcp`
  Python SDK / FastMCP.
- **Not** an authorization server. It's a *resource server* seam: bring your own AS
  (Auth0 / Keycloak / your SSO); doorman validates audience + scope and serves the RFC 9728
  metadata pointer.
- **Not** a network gateway. No extra hop, no Envoy/K8s — it lives in your app process.

## Known limits & honest caveats

- **Thin-layer risk.** This is a curated, opinionated layer on top of the SDK; FastMCP could
  ship "secure defaults" presets in future. The moat is the opinionated config + redaction
  engine + audit schema + fail-closed-on-STDIO, not novel protocol work.
- **Spec churn.** The MCP spec's largest revision lands **2026-07-28** (sessions removed,
  `Mcp-Method` headers, JSON Schema 2020-12, error-code changes). The core guarantees are
  transport-independent; the wire integration tracks the official SDK as it absorbs the RC.
- **Scoped vs unscoped tools.** `mount()` refuses a bridge with no `AuthConfig`, and any
  tool that declares `scopes` requires a verified caller. An exposed tool with **no**
  scopes stays *anonymously callable by design* (a public tool) — `mcp-doorman lint` warns
  on every scopeless exposed tool so this is a deliberate choice, not an accident.
- **Redaction is heuristic.** Sensitive **keys** (any depth, any container — dicts, lists,
  sets, bytes, dataclasses, pydantic models) are masked, and common PII **value** shapes
  (email/phone/SSN/card) are stripped. But a novel secret hidden in free text, or a phone
  shorter than ~9 digits, can slip through — add your own `value_patterns` for stricter
  coverage. Undecodable binary is passed through unscanned.
- **Limits are per process.** Rate buckets and budgets live in one process's memory, so N
  replicas each enforce the limit independently and the effective ceiling is N× what you
  configured. That is the price of "no Redis, no gateway". Size accordingly, or put a
  shared limiter in front when the exact number matters.
- **Security bar.** A security-positioned library that ships a redaction bypass hurts more
  than a convenience library would. The fail-closed, redaction-leakage, audit-no-values, and
  rate-limit tests are load-bearing and run on every change (a 6-agent red-team pass shaped
  the 0.1.0 hardening). Found a hole?
  [Open an issue.](https://github.com/shaxzodbek-uzb/mcp-doorman/issues)

## License

MIT © 2026 Shaxzodbek Qambaraliyev / Blaze. See [LICENSE](LICENSE).

[fam]: https://github.com/tadata-org/fastapi_mcp
[fastmcp]: https://github.com/jlowin/fastmcp
[ghsa]: https://github.com/advisories
