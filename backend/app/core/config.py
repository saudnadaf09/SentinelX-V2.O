"""Application settings, loaded from environment variables / .env."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_REPO = Path(__file__).resolve().parents[3]
_PLACEHOLDERS = {"", "change-me", "replace-with-long-random-secret", "changeme"}


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore", case_sensitive=False)

    app_env: str = "development"
    log_level: str = "INFO"
    secret_key: str = ""
    database_url: str = "sqlite:///./sentinelx.db"
    redis_url: str = "redis://localhost:6379/0"
    opensearch_url: str = "http://localhost:9200"
    queue_backend: str = "redis"       # redis | memory
    store_backend: str = "opensearch"  # opensearch | sqlite | memory
    events_db_path: str = "./data/events.db"
    frontend_dist: str = ""            # if set and built, the API server also serves the web UI

    cors_origins: str = "http://localhost:8080,http://localhost:5173"
    access_token_minutes: int = 30
    refresh_token_days: int = 7
    max_body_bytes: int = 1_048_576
    max_batch_events: int = 500
    login_rate_per_minute: int = 10
    ingest_rate_per_minute: int = 600

    event_retention_days: int = 14
    collector_key_ttl_days: int = 90
    correlation_window_seconds: int = 600
    rules_dir: str = str(_REPO / "detection-rules")
    sample_data_dir: str = str(_REPO / "sample-data")

    ai_provider: str = "disabled"  # platform default: disabled | openai | gemini | anthropic | openai_compatible
    ai_api_key: str = ""
    ai_model: str = "claude-sonnet-5-5"
    ai_base_url: str = ""
    ai_timeout_seconds: int = 30

    # accounts / mail
    allow_registration: bool = True
    require_email_verification: bool = False   # set true when real SMTP is configured
    frontend_base_url: str = "http://localhost:8000"
    mail_mode: str = "console"                 # console (no real email) | smtp
    brevo_api_key: str = ""
    mail_from: str = "SentinelX <saudnadaf854325@gmail.com>"
    smtp_host: str = "smtp-relay.brevo.com"
    smtp_port: int = 587
    smtp_user: str = "saudnadaf854325@gmail.com"
    smtp_password: str = "xsmtpsib-ce4d81d38b6a733b8ed757f816b4d0cb7383b0844f20e06f4b99ff554861fb1f-zvub9xdv5ayKcbhm"
    smtp_starttls: bool = True
    outbox_dir: str = "./data/outbox"
    verify_token_hours: int = 48
    reset_token_minutes: int = 30
    invite_token_days: int = 7

    syslog_udp_port: int = 0                   # 0 = disabled; e.g. 5514 (ports < 1024 need elevated rights)
    syslog_bind: str = "127.0.0.1"             # use 0.0.0.0 to receive from other machines

    response_adapter: str = "mock"
    approval_ttl_minutes: int = 30

    bootstrap_admin_email: str = "admin@sentinelx.local"
    bootstrap_admin_password: str = ""

    @field_validator("secret_key")
    @classmethod
    def _secret(cls, v: str) -> str:
        if v.strip().lower() in _PLACEHOLDERS or len(v) < 32:
            raise ValueError("SECRET_KEY must be set to a random value of at least 32 characters "
                             "(see .env.example)")
        return v

    @property
    def cors_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.app_env.lower() == "production"


@lru_cache
def get_settings() -> Settings:
    return Settings()


