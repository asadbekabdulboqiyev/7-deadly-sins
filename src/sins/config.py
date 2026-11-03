from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Barcha sozlamalar SINS_ prefiksi bilan .env dan o'qiladi."""

    model_config = SettingsConfigDict(env_file=".env", env_prefix="SINS_", extra="ignore")

    database_url: str = "postgresql+asyncpg://asadbek@localhost:5432/sins"
    redis_url: str = "redis://localhost:6379/0"

    # Authorization gate
    verify_token_ttl_hours: int = 72
    verify_recheck_days: int = 30

    # Xavfsizlik to'siqlari — kod darajasida majburlanadi, o'chirib bo'lmaydi.
    max_rps: int = 50
    tool_timeout_seconds: int = 900

    # Faqat shu adapterlar ishga tushadi. Vergul bilan ajratilgan satr:
    # "nuclei,osv". Foydalanishda get_settings().allowed_engines_list().
    allowed_engines: str = "nuclei,osv"

    # Engine vaqtincha yiqilsa (timeout, tarmoq xatosi) qayta urinishlar soni.
    adapter_max_attempts: int = 2
    adapter_retry_backoff_seconds: float = 2.0

    # HTTP himoyasi
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 600

    # Ma'lumot saqlash siyosati (kunlarda). `sins prune` va ARQ cron ishlatadi.
    retention_days: int = 180

    def allowed_engines_list(self) -> list[str]:
        return [e.strip() for e in self.allowed_engines.split(",") if e.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
