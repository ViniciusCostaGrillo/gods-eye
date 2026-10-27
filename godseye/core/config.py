"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuration settings for God's Eye OSINT Platform."""

    model_config = SettingsConfigDict(
        env_prefix="GODSEYE_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    app_name: str = "God's Eye (𓂀) OSINT Platform"
    version: str = "1.0.0"
    db_path: str = Field(default=str(Path.home() / ".godseye" / "godseye.db"))
    cache_ttl_seconds: int = Field(default=3600)
    l1_cache_max_size: int = Field(default=512)
    http_timeout_seconds: float = Field(default=12.0)
    http_max_retries: int = Field(default=3)
    http_max_elapsed_seconds: float = Field(default=45.0)
    max_concurrency: int = Field(default=8)
    retention_days: int = Field(default=90)
    offline_demo_fallback: bool = Field(default=True)

    # Optional API keys for Freemium / Licensed OSINT providers
    hibp_api_key: str | None = Field(default=None)
    shodan_api_key: str | None = Field(default=None)
    virustotal_api_key: str | None = Field(default=None)
    urlscan_api_key: str | None = Field(default=None)
    abuseipdb_api_key: str | None = Field(default=None)
    otx_api_key: str | None = Field(default=None)
    github_token: str | None = Field(default=None)
    ipinfo_token: str | None = Field(default=None)
    portal_transparencia_api_key: str | None = Field(default=None)
    datajud_api_key: str | None = Field(default=None)

    # API Server security
    api_secret_key: str = Field(default="godseye-local-analyst-key")
    webhook_signing_secret: str = Field(default="godseye-webhook-hmac-secret")


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached singleton Settings instance."""
    return Settings()
