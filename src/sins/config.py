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

    # Faqat shu adapterlar ishga tushadi. Yangi tool qo'shilsa — shu yerga yoziladi.
    allowed_engines: tuple[str, ...] = ("nuclei", "osv")


@lru_cache
def get_settings() -> Settings:
    return Settings()
