"""60-second quickstart: a FastAPI app exposed as a secure MCP server.

Run the offline guard demo (no extras needed):

    python examples/quickstart.py

To actually serve it over MCP, install the extra and mount onto your ASGI server:

    pip install "mcp-doorman[mcp,fastapi]"
    uvicorn examples.quickstart:app
"""

from __future__ import annotations

from mcp_doorman import (
    AccessToken,
    Doorman,
    Principal,
    StaticVerifier,
    ToolSpec,
    Transport,
    expose,
)

# --- A normal FastAPI app (import guarded so the file runs without fastapi installed) ---
try:
    from fastapi import FastAPI

    app = FastAPI()

    @expose(name="get_invoice", scopes=["invoices:read"])
    @app.get("/invoices/{invoice_id}")
    async def get_invoice(invoice_id: str):
        return {"id": invoice_id, "email": "alice@example.com", "amount": 42.0}

    @expose(name="refund", scopes=["invoices:write"], destructive=True, redact=["amount"])
    @app.post("/invoices/{invoice_id}/refund")
    async def refund(invoice_id: str, amount: float):
        return {"id": invoice_id, "refunded": amount}

    # One secure mount. Uncomment when the [mcp] extra is installed:
    # Doorman(
    #     app,
    #     auth=Doorman.oauth(
    #         issuer="https://sso.example.com",
    #         resource="https://api.example.com/mcp",
    #     ),
    #     rate_limit="60/min per_caller; 10/min per_tool",
    #     redact=["email", "phone", "ssn", "*_token"],
    # ).mount("/mcp")
except ImportError:  # fastapi not installed — the offline demo below still works
    app = None


def offline_demo() -> None:
    """Show the guard pipeline end-to-end without a server or the MCP SDK."""
    verifier = StaticVerifier(
        {
            "reader-token": AccessToken(
                subject="alice",
                scopes=frozenset({"invoices:read"}),
                audience=("https://api.example.com/mcp",),
                tenant="acme",
            )
        }
    )
    doorman = Doorman(
        auth=Doorman.oauth(
            issuer="https://sso.example.com",
            resource="https://api.example.com/mcp",
            verifier=verifier,
        ),
        rate_limit="5/min per_caller",
        redact=["amount"],
        audit="stderr",  # one JSON audit line per call goes to stderr
    )
    doorman.register(
        ToolSpec(
            name="get_invoice",
            handler=lambda invoice_id: {"id": invoice_id, "email": "alice@example.com"},
            methods=frozenset({"GET"}),
            scopes=("invoices:read",),
        )
    )

    # 1) A verified caller with the right scope gets a redacted result.
    principal = doorman.principal_from_token("reader-token", transport=Transport.HTTP)
    result = doorman.guard_call(
        "get_invoice", {"invoice_id": "INV-1"}, principal,
        lambda a: {"id": a["invoice_id"], "email": "alice@example.com"},
    )
    print("authorized call ->", result)  # email redacted

    # 2) A STDIO / anonymous caller is denied fail-closed on a scoped tool.
    anon = Principal(subject="", transport=Transport.STDIO, verified=False)
    try:
        doorman.guard_call("get_invoice", {"invoice_id": "INV-1"}, anon, lambda a: {})
    except Exception as exc:  # noqa: BLE001 - demo
        print("stdio call    ->", type(exc).__name__, "(fail-closed)")


if __name__ == "__main__":
    offline_demo()
