"""Application configuration via Pydantic Settings."""

import logging
from functools import lru_cache

from pydantic import BaseModel, Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

_config_logger = logging.getLogger("btagent.config")

_INSECURE_JWT_DEFAULTS = frozenset(
    {
        "CHANGE-ME-IN-PRODUCTION",
        "change-me-in-production-use-openssl-rand-hex-32",
        "secret",
        "changeme",
    }
)

# Dev-grade CORS origins. These are the localhost Vite/preview/ingress ports
# the SPA runs on locally. They are the default ``cors_origins`` value and are
# fine for dev/test, but in ``prod`` they signal that ``BTAGENT_CORS_ORIGINS``
# was never configured — see ``Settings._validate_cors_origins``.
_DEV_CORS_ORIGINS: tuple[str, ...] = (
    "http://localhost:5173",
    "http://localhost:3000",
    "http://localhost:3001",
    "http://localhost:8080",
)


class OIDCProviderConfig(BaseModel):
    """Generic OIDC provider config (#144 Phase 1b).

    One entry per IdP, keyed by the ``{provider}`` path segment used in the SSO
    routes (``/auth/sso/{provider}/login``). Everything the authorization-code +
    PKCE flow needs is derived from the issuer's discovery document
    (``{issuer}/.well-known/openid-configuration``) at request time, so only the
    client registration + role mapping live here.

    ``client_secret`` follows the ``${secret:...}`` / ``${env:...}`` injection
    pattern — it is resolved lazily in ``auth/oidc.py`` (never eagerly in
    config) so an unresolved reference can't break app boot.

    CI SAFETY: this model is only ever populated when an operator explicitly
    configures a provider. The default ``Settings.oidc_providers`` is an empty
    dict, and there is deliberately NO validator that fails on emptiness — a
    backend with no provider boots fine (the SSO routes 404 for unknown
    providers).
    """

    # Issuer URL — discovery is fetched from ``{issuer}/.well-known/openid-configuration``.
    issuer: str
    client_id: str
    # ``${secret:...}`` / ``${env:...}`` reference (resolved at request time).
    client_secret: str
    # Exact, fully-qualified callback URL registered with the IdP. The callback
    # route enforces that the configured value matches an allowlist (itself).
    redirect_uri: str
    scopes: list[str] = Field(default_factory=lambda: ["openid", "email", "profile"])
    # ID-token / userinfo claim carrying the user's group/role membership.
    role_claim: str = "groups"
    # Maps a value found in ``role_claim`` → a BTagent role. First match wins
    # (iterated against the claim's value(s)). Anything unmatched → ``analyst``.
    role_map: dict[str, str] = Field(default_factory=dict)
    # Role assigned when no ``role_map`` entry matches (or the claim is absent).
    default_role: str = "analyst"


class SAMLProviderConfig(BaseModel):
    """Generic SAML 2.0 IdP config (#170, Phase 2).

    One entry per IdP, keyed by the ``{provider}`` path segment used in the SAML
    routes (``/auth/saml/{provider}/login``). The SP is configured here; the IdP
    side is either auto-discovered from ``idp_metadata_url`` (preferred) or
    specified manually via ``idp_entity_id`` + ``sso_url`` + ``x509cert``.

    ``x509cert`` follows the ``${secret:...}`` / ``${env:...}`` injection pattern
    — it is resolved lazily in ``auth/saml.py`` (never eagerly in config) so an
    unresolved reference can't break app boot.

    CI SAFETY: like ``OIDCProviderConfig``, this model is only ever populated
    when an operator explicitly configures a provider. ``Settings.saml_providers``
    defaults to an empty dict, so a backend with no SAML provider boots fine and
    the SAML routes 404 for unknown providers. The per-provider validator below
    runs ONLY on populated entries, so it never fires on the empty default.

    Trust model: a SAML assertion has no ``email_verified`` analogue, so a
    validly-*signed* assertion carrying an email attribute is treated as
    verified (the signature is the IdP's non-repudiation guarantee). The
    no-silent-link-to-password-account gate in ``_jit_provision`` still applies.
    """

    # --- IdP side: metadata URL (preferred) OR manual entity_id/sso_url/cert ---
    idp_metadata_url: str | None = None
    idp_entity_id: str | None = None
    sso_url: str | None = None
    # IdP signing certificate (PEM or base64 DER). ``${secret:...}`` ref allowed;
    # resolved lazily at request time in ``auth/saml.py``.
    x509cert: str | None = None

    # --- SP side ---
    # Our SP EntityID — MUST equal the assertion's AudienceRestriction/Audience.
    sp_entity_id: str
    # Absolute Assertion Consumer Service URL: .../auth/saml/{provider}/acs
    acs_url: str
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"

    # --- attribute mapping ---
    # SAML attribute Name carrying email; if None, email is derived from NameID.
    email_attr: str | None = None
    # SAML attribute Name carrying role/group membership (may be multi-valued).
    role_attr: str = "Role"
    role_map: dict[str, str] = Field(default_factory=dict)
    default_role: str = "analyst"

    # --- validation knobs ---
    # Clock-skew tolerance (seconds) for NotBefore / NotOnOrAfter conditions.
    assertion_skew_seconds: int = 60
    # IdP metadata cache TTL (seconds).
    metadata_ttl_seconds: int = 3600

    @model_validator(mode="after")
    def _validate_idp(self) -> "SAMLProviderConfig":
        if not self.idp_metadata_url and not (
            self.idp_entity_id and self.sso_url and self.x509cert
        ):
            raise ValueError(
                "SAML provider needs idp_metadata_url OR (idp_entity_id + sso_url + x509cert)"
            )
        return self


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

    # MFA (opt-in TOTP, #144). ``mfa_issuer`` labels the authenticator entry.
    # ``mfa_secret_enc_key`` is the Fernet key used to encrypt TOTP secrets at
    # rest; it follows the ``${secret:...}`` / env injection pattern.
    #
    # CI / test-mode safety: this key is INTENTIONALLY allowed to be empty and
    # there is deliberately NO model_validator that fails when it is unset —
    # ``Settings(env="test")`` must construct fine with no key so the backend
    # boots in CI (where MFA is never exercised). The MFA code path itself
    # resolves the effective key lazily (see ``auth/mfa.py``):
    #   * if a key is configured, it is used verbatim;
    #   * else, in dev/test ONLY, a deterministic key is derived from
    #     ``jwt_secret`` so the test suite can round-trip without extra config;
    #   * else (prod, no key) the MFA endpoints raise a clear config error —
    #     MFA is opt-in, so this only affects users actively enrolling.
    mfa_issuer: str = "BTagent"
    mfa_secret_enc_key: str = ""

    # Generic OIDC SSO (#144, Phase 1b). A dict of provider-key → config; the
    # provider key is the ``{provider}`` path segment in the SSO routes.
    #
    # CI / test-mode safety: the default is an EMPTY dict and there is
    # deliberately NO validator that fails when it is empty. With no provider
    # configured, ``Settings(env="test")`` constructs and the backend boots
    # normally; the SSO routes simply return 404 for any unknown/unconfigured
    # provider, so the existing login/UAT/E2E suites are unaffected.
    #
    # Populate from env as JSON, e.g.:
    #   BTAGENT_OIDC_PROVIDERS='{"okta": {"issuer": "https://acme.okta.com",
    #     "client_id": "...", "client_secret": "${secret:vault:oidc/okta#secret}",
    #     "redirect_uri": "https://btagent.example.com/api/v1/auth/sso/okta/callback",
    #     "role_claim": "groups", "role_map": {"soc-admins": "admin"}}}'
    oidc_providers: dict[str, OIDCProviderConfig] = Field(default_factory=dict)

    # Generic SAML 2.0 SSO (#170, Phase 2). Same shape + CI-safety contract as
    # ``oidc_providers``: an EMPTY default dict, no validator that fails on
    # emptiness, so test/CI boot is unaffected and unknown providers 404.
    #
    # SAML support is an OPTIONAL ``backend[saml]`` extra (pysaml2 + the xmlsec
    # system libs); ``auth/saml.py`` lazy-imports it, so this config and app
    # boot cost nothing on the slim image. A SAML route hit on an image without
    # the extra returns 503.
    #
    # Populate from env as JSON, e.g.:
    #   BTAGENT_SAML_PROVIDERS='{"okta": {
    #     "idp_metadata_url": "https://acme.okta.com/app/abc/sso/saml/metadata",
    #     "sp_entity_id": "https://btagent.example.com",
    #     "acs_url": "https://btagent.example.com/api/v1/auth/saml/okta/acs",
    #     "role_attr": "Role", "role_map": {"soc-admins": "admin"}}}'
    saml_providers: dict[str, SAMLProviderConfig] = Field(default_factory=dict)

    # Frontend root the SSO callback 302-redirects to after establishing the
    # session. Defaults to "/" (same-origin SPA behind the API host/ingress).
    frontend_url: str = "/"

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
    cors_origins: list[str] = list(_DEV_CORS_ORIGINS)

    @model_validator(mode="after")
    def _validate_cors_origins(self) -> "Settings":
        """B7 (#141): hardened CORS is the default for prod.

        In ``prod`` the operator MUST supply an explicit ``BTAGENT_CORS_ORIGINS``
        allowlist. We fail loudly at startup if it is unset (still the dev
        localhost defaults), empty, contains a ``*`` wildcard, or lists a
        localhost origin — any of which would either disable the cookie-auth
        ``allow_credentials`` flow or expose the API to untrusted browsers.

        Dev/test stay permissive: they keep the localhost defaults untouched,
        so ``BTAGENT_ENV=test`` (CI) and ``BTAGENT_ENV=dev`` start normally.
        """
        if self.env != "prod":
            return self

        origins = self.cors_origins
        if not origins:
            raise ValueError(
                "CRITICAL: BTAGENT_CORS_ORIGINS must be set to an explicit "
                "allowlist of your frontend origin(s) in prod, e.g. "
                '["https://btagent.example.com"].'
            )
        if any(o.strip() == "*" for o in origins):
            raise ValueError(
                "CRITICAL: BTAGENT_CORS_ORIGINS may not contain '*' in prod — "
                "wildcard CORS is incompatible with cookie auth "
                "(allow_credentials=True) and exposes the API to any origin."
            )
        if any("localhost" in o or "127.0.0.1" in o for o in origins):
            raise ValueError(
                "CRITICAL: BTAGENT_CORS_ORIGINS still lists a localhost origin "
                "in prod — set it to your real frontend origin(s), e.g. "
                '["https://btagent.example.com"].'
            )
        return self

    # Agent defaults
    default_model_provider: str = "anthropic"
    default_model_id: str = "claude-sonnet-4-20250514"
    mock_connectors: bool = False

    # Proactive threat hunting scheduler (#112 integration). The arq worker
    # runs the enabled builtin hunt packs on this cadence and lands their hits
    # in the #119 triage inbox; the stale-suppression sweep (#119) runs on its
    # own cadence. All overridable via ``BTAGENT_HUNT_*`` env vars.
    #   BTAGENT_HUNT_SCHEDULER_INTERVAL_HOURS=4
    #   BTAGENT_HUNT_SCHEDULER_BACKENDS='["splunk","sentinel"]'
    hunt_scheduler_interval_hours: int = 4
    hunt_scheduler_backends: list[str] = Field(default_factory=lambda: ["splunk"])
    hunt_scheduler_lookback_hours: int = 24
    hunt_scheduler_max_hits_per_query: int = 100
    # The stale-suppression sweep cadence (minutes past each hour it fires on).
    hunt_suppression_sweep_minute: int = 0
    # Codex #202 P1: whether the scheduled hunt-pack cron is allowed to run.
    # The default backends (``hunt_scheduler_backends``) target Splunk, whose
    # LIVE execution path raises NotImplementedError (the ``_real_executor``
    # placeholder). With ``mock_connectors=False`` (the production default)
    # every scheduled tick would silently create zero findings. So this knob
    # *derives* from ``mock_connectors`` when left unset: enabled when mocks
    # are on, disabled when mocks are off. An operator who has wired live
    # connectors can force it on via ``BTAGENT_HUNT_SCHEDULE_ENABLED=true``.
    # Left as ``None`` here so the post-init validator can tell "unset"
    # (derive from mocks) apart from an explicit ``true``/``false``.
    hunt_schedule_enabled: bool | None = None

    @model_validator(mode="after")
    def _derive_hunt_schedule_enabled(self) -> "Settings":
        """Default ``hunt_schedule_enabled`` from ``mock_connectors`` when unset.

        Mocks on → schedule on (the deterministic executor produces findings);
        mocks off → schedule off (live execution is not yet wired and would
        no-op), unless the operator explicitly set the flag.
        """
        if self.hunt_schedule_enabled is None:
            self.hunt_schedule_enabled = self.mock_connectors
        return self

    # Cross-Investigation Pattern Hunter (#120). The weekly scan walks the
    # closed-investigation pgvector corpus and surfaces cross-case weak-signal
    # patterns as hunt proposals. Unlike the hunt-pack scheduler this is NOT
    # connector-blocked — it runs entirely over already-stored data — so its
    # gate mirrors ``hunt_schedule_enabled`` in shape but defaults ON.
    #   BTAGENT_PATTERN_SCAN_ENABLED=false
    #   BTAGENT_PATTERN_SCAN_WEEKDAY=6   (0=Mon .. 6=Sun)
    pattern_scan_enabled: bool = True
    pattern_scan_weekday: int = 6  # Sunday
    pattern_scan_hour: int = 3
    pattern_scan_top_n: int = 10

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
