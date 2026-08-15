"""Environment-driven settings (``DOORMAN_*``)."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration. Reads ``DOORMAN_*`` env vars and ``.env``."""

    model_config = SettingsConfigDict(env_prefix="DOORMAN_", env_file=".env", extra="ignore")

    endpoint: str = "/mcp"
    rate_limit: str | None = "60/min per_caller; 10/min per_tool"
    #: Cost ceiling, same grammar as rate_limit but counted in the cost units declared
    #: by expose(cost=...). Off by default: a cost unit means nothing until a
    #: deployment defines one, and a guessed default would be security theatre.
    budget: str | None = None
    audit: str = "stderr"
    tenant_claim: str = "tenant_id"
    require_auth_for_remote: bool = True
    allowed_origins: tuple[str, ...] = ()
    server_name: str = "mcp-doorman"
