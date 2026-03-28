"""Application configuration via Pydantic Settings."""

import logging
from functools import lru_cache

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_config_logger = logging.getLogger("btagent.config")

_INSECURE_JWT_DEFAULTS = frozenset({
    "CHANGE-ME-IN-PRODUCTION",
    "change-me-in-production-use-openssl-rand-hex-32",
    "secret",
    "changeme",
})


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

    @model_validator(mode="after")
    def _validate_jwt_secret(self) -> "Settings":
        """SEC-001 FIX: Refuse to start with a known-insecure JWT secret in non-dev."""
        if self.env not in ("dev", "test") and self.jwt_secret in _INSECURE_JWT_DEFAULTS:
            raise ValueError(
                "CRITICAL: BTAGENT_JWT_SECRET is set to a known default value. "
                "Generate a secure secret with: openssl rand -hex 32"
            )
        if self.jwt_secret in _INSECURE_JWT_DEFAULTS:
            _config_logger.warning(
                "JWT secret is a known default. This is acceptable in dev/test "
                "but MUST be changed before any staging or production deployment."
            )
        if len(self.jwt_secret) < 32 and self.env not in ("dev", "test"):
            raise ValueError(
                "BTAGENT_JWT_SECRET must be at least 32 characters in non-dev environments."
            )
        return self

    @model_validator(mode="after")
    def _validate_s3_credentials(self) -> "Settings":
        """SEC-P2-002 FIX: Reject default S3 credentials in non-dev environments."""
        if self.env not in ("dev", "test") and self.s3_access_key == "minioadmin":
            raise ValueError(
                "CRITICAL: BTAGENT_S3_ACCESS_KEY is set to 'minioadmin'. "
                "Configure real S3/MinIO credentials for non-dev environments."
            )
        return self

    # CORS
    cors_origins: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Agent defaults
    default_model_provider: str = "anthropic"
    default_model_id: str = "claude-sonnet-4-20250514"
    mock_connectors: bool = False

    # Embedding / Knowledge Base
    embedding_provider: str = "openai"  # openai | ollama
    embedding_model: str = "text-embedding-3-small"
    openai_api_key: str = ""
    ollama_base_url: str = "http://localhost:11434"

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
