# Contributing to mcp-doorman

Thanks for helping make MCP servers secure by default. This is a small, focused library —
contributions that keep it small and sharp are the most welcome.

## Project shape

- The **core** (`mcp_doorman/` minus `integrations/`) is dependency-light and must import
  **no** `mcp`/FastAPI SDK. The five guarantees live here and are tested fully offline.
- The **integration** (`mcp_doorman/integrations/`) is the only place allowed to import the
  MCP SDK, and it does so lazily.
- [`SPEC.md`](SPEC.md) is the canonical description of every public signature and behavior.
  Change the spec in the same PR as the code.

## Dev setup

```bash
uv venv && uv pip install -e '.[dev]'    # core + test tooling
uv run pytest -q                          # 57 offline tests
uv run ruff check .                        # lint (line length 100)
```

To exercise the wire integration: `uv pip install -e '.[dev,mcp,fastapi]'`.

## The bar for changes

This is a **security-positioned** project, so:

1. **Fail closed.** Any new decision path must default to denying when context is missing.
2. **No values in logs.** The audit layer records argument *shapes*, never values. Keep it
   that way; add a leakage assertion for anything new.
3. **Tests are load-bearing, not smoke.** The fail-closed (`test_scopes.py`), redaction
   leakage (`test_redaction.py`), audit-no-values (`test_audit.py`), and rate-limit
   (`test_ratelimit.py`) tests are the product's contract. Extend them precisely.
4. **Ruff-clean, typed, docstringed** on every public symbol.

## Reporting a security issue

If you find a redaction bypass, an auth fail-open, or a token-confusion path, please open a
GitHub issue marked **security** (or email shaxzodbek@blaze.uz). A reproducer beats a
description.

## Pull requests

- Keep PRs scoped to one concern; update `SPEC.md`, `CHANGELOG.md`, and tests together.
- New public API needs a spec entry, a docstring, and a test. New behavior that loosens a
  default needs an explicit, documented reason.
