"""Application configuration via Pydantic Settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """BTagent backend configuration. Loaded from environment variables."""

    model_config = SettingsConfigDict(env_prefix="BTAGENT_", env_file=".env")

    # Environment
    env: str = "dev"  # dev | staging | prod
    debug: bool = False
    log_level: str = "info"

    # Database
    database_url: str = "postgresql+asyncpg://btagent:btagent@localhost:5432/btagent"
    db_pool_size: int = 20
    db_max_overflow: int = 10
    db_echo: bool = False

    # Redis
    redis_url: str = "redis://localhost:6379"

    # MinIO / S3
    s3_endpoint: str = "http://localhost:9000"
    s3_access_key: str = "minioadmin"
    s3_secret_key: str = "minioadmin"
    s3_bucket: str = "btagent-evidence"
    s3_region: str = "us-east-1"

    # Auth
    jwt_secret: str = "CHANGE-ME-IN-PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Agent defaults
    default_model_provider: str = "anthropic"
    default_model_id: str = "claude-sonnet-4-20250514"
    mock_connectors: bool = False

    # Rate limiting
    rate_limit_enabled: bool = True

    # Observability
    otel_enabled: bool = False
    otel_endpoint: str = "http://localhost:4317"
    langfuse_enabled: bool = False
    langfuse_public_key: str = ""
    langfuse_secret_key: str = ""
    langfuse_host: str = "https://cloud.langfuse.com"

    # Slack
    slack_bot_token: str = ""
    slack_channel: str = ""

    # Data retention
    event_retention_days: int = 90
    audit_retention_years: int = 7


@lru_cache
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
