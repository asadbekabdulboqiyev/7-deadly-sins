from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """All settings are read from .env with the SINS_ prefix."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SINS_", extra="ignore")

    database_url: str = "postgresql+asyncpg://asadbek@localhost:5432/sins"
    redis_url: str = "redis://localhost:6379/0"

    # Authorization gate
    verify_token_ttl_hours: int = 72
    verify_recheck_days: int = 30

    # Security guardrails — enforced at code level, cannot be disabled.
    max_rps: int = 50
    tool_timeout_seconds: int = 900

    # Only these adapters run. Comma-separated string:
    # "nuclei,osv,pride,envy,lust,gluttony,wrath".
    # Access via get_settings().allowed_engines_list().
    allowed_engines: str = "nuclei,osv,pride,envy,lust,gluttony,wrath"

    # Retry count when an engine fails transiently (timeout, network error).
    adapter_max_attempts: int = 2
    adapter_retry_backoff_seconds: float = 2.0

    # HTTP protection
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 600

    # Data retention policy (in days). Used by `sins prune` and the ARQ cron.
    retention_days: int = 180

    # Threat-intel enrichment (CISA KEV + FIRST EPSS) for PDF reports.
    # Disable in air-gapped environments: SINS_THREAT_INTEL_ENABLED=0.
    threat_intel_enabled: bool = True
    threat_intel_timeout_seconds: float = 8.0

    # Browser access (marketing site + local Vite dev server), comma-separated.
    # `*` is accepted, but then credentials are disabled: per the CORS spec a
    # wildcard origin cannot be combined with `allow_credentials=True`.
    cors_origins: str = (
        "http://localhost:5173,http://127.0.0.1:5173,http://localhost:4173,http://127.0.0.1:4173"
    )
    # How often the SSE progress stream polls the scan row.
    sse_poll_seconds: float = 0.4

    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def allowed_engines_list(self) -> list[str]:
        return [e.strip() for e in self.allowed_engines.split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
