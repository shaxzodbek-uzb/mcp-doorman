# Changelog

All notable changes to `mcp-doorman` are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/) and the project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-08-16

### Added
- **Per-caller cost budget.** `Doorman(budget="1000/day per_caller")` counts the
  cost of calls rather than their number, so a tool that hits a paid API can be
  weighted above a cheap lookup. `expose(cost=...)` declares what one call is
  worth; unannotated tools cost `1.0`.
- `BudgetExceeded`, raised when the allowance is spent. It subclasses
  `RateLimited`, so existing `except RateLimited` handlers and the integration
  layer's status mapping keep working — but a client that wants to can now tell
  *calling too fast* (fixed by backing off) from *calling too expensively*
  (usually not).
- `Doorman.remaining_budget(tool=, caller=)`.
- Budgets are **off by default**. A cost unit means nothing until a deployment
  defines one, and a guessed default would be security theatre.

### Fixed
- **`expose(rate=...)` was accepted and then never enforced.** A per-tool rate
  override was parsed into the tool spec and silently dropped, so a tool marked
  `rate="5/min per_caller"` was limited only by the Doorman-wide rate. Per-tool
  overrides now apply *in addition to* the global limit — tightening one tool
  cannot loosen the rest.
- A malformed `rate=` spec now fails at decoration time rather than on the first
  call in production.

## [0.1.0] — 2026-06-20

Initial beta. The five secure-by-default guarantees, implemented as a dependency-light,
offline-testable core with a lazy-imported MCP transport.

### Added
- **Deny-by-default exposure** — `@expose(...)` opt-in; destructive HTTP methods require
  `destructive=True` and auto-emit the `destructiveHint` annotation (`exposure.py`).
- **Fail-closed scope authorization**, including STDIO — an unverified principal can never
  satisfy a scoped tool (`scopes.py`).
- **Token-bucket rate limiting**, per-caller and per-tool, no Redis (`ratelimit.py`).
- **PII redaction at the source** — sensitive key globs + PII value patterns, recursive,
  non-mutating, cycle-safe (`redaction.py`).
- **Structured audit** — one record per call carrying argument *shape* (keys/types/lengths),
  never values; `StderrSink` / `NullSink` / custom sinks (`audit.py`).
- **Resource-server auth seam** — `AccessToken`, `TokenVerifier`, audience binding
  (RFC 8707/9068), RFC 9728 metadata body, `StaticVerifier` for tests (`auth.py`).
- **`Doorman`** orchestrator with the `guard_call` / `aguard_call` pipeline, `Doorman.dev()`
  localhost preset, and a fail-closed `mount()` (refuses a remote bridge with no auth).
- **MCP integration** (`integrations/fastmcp.py`) building on the official `mcp` SDK —
  lazy-imported behind the `[mcp]` extra.
- **CLI** — `mcp-doorman doctor | lint | version`.
- Offline test suite + live-wire integration tests, and a CI matrix.

### Security (0.1.0 hardening, from a 6-agent red-team pass)
- Redaction now covers `bytes`, `set`/`frozenset`, dataclasses, pydantic models, int
  card/SSN values, and non-str sensitive keys — closing five silent value-leak gaps.
- Audit `shape()` no longer emits dict **keys** (which can be caller-controlled data); it
  records container types, lengths, and counts only.
- Rate limiting bounds its bucket map (LRU + lossless eviction) against high-cardinality
  callers, and keys anonymous callers by a per-connection hint instead of one shared bucket;
  `parse_rate_spec` rejects a `0/UNIT` limit.
- The Origin / DNS-rebinding check promised by the integration is now actually implemented
  and wired to `allowed_origins`; `scan_app` fails closed on routes with unknown methods.

[Unreleased]: https://github.com/shaxzodbek-uzb/mcp-doorman/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/shaxzodbek-uzb/mcp-doorman/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/shaxzodbek-uzb/mcp-doorman/releases/tag/v0.1.0
