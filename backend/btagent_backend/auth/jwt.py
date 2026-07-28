"""JWT token creation and verification."""

import uuid
from datetime import UTC, datetime, timedelta

import bcrypt
from jose import jwt
from pydantic import BaseModel

from btagent_backend.config import get_settings


class TokenPayload(BaseModel):
    sub: str  # user_id
    username: str
    role: str
    exp: datetime
    type: str  # "access" or "refresh"
    jti: str | None = None  # SEC-003 FIX: JWT ID for token revocation tracking
    # AUTH-B1: org_id embedded so per-request authz can scope without an extra
    # DB lookup. Optional + defaulted to "org_default" so legacy tokens issued
    # before Phase B1 still validate during the rollout window.
    org_id: str = "org_default"
    # P142: issued-at (unix seconds). Optional so legacy tokens (issued before
    # P142) still decode; the middleware only enforces the per-user revocation
    # epoch when ``iat`` is present.
    iat: int | None = None
    # P142: refresh-token family id. Every refresh token in a single login
    # session shares one ``fid``; rotation mints a new ``jti`` but keeps the
    # ``fid``, so reuse of a consumed (already-rotated) refresh token can be
    # detected and the whole family revoked (theft response). Only set on
    # refresh tokens.
    fid: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


# bcrypt hashes at most 72 *bytes* of input. This is a property of the
# algorithm, not a policy choice, and it is measured in bytes rather than
# characters — a 30-character passphrase of non-ASCII text can exceed it.
#
# bcrypt >= 4.1 raises ValueError rather than silently truncating (older
# versions truncated, which is the classic vulnerability: a 100-character
# password and its 72-character prefix both authenticate). Raising is the
# safer behaviour, but an unhandled ValueError out of an *unauthenticated*
# login endpoint is a 500 that any anonymous caller can trigger at will, so
# both primitives below handle the over-length case explicitly.
MAX_PASSWORD_BYTES = 72

# Length is the control that matters; composition rules are deliberately
# absent (NIST SP 800-63B deprecates them — they push users toward
# predictable substitutions without adding real entropy).
MIN_PASSWORD_LENGTH = 12


def password_length_error(password: str) -> str | None:
    """Return why ``password`` is unacceptable, or ``None`` if it is fine.

    Shared by the API schema so the rule lives in one place rather than being
    restated — and drifting — at each call site.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return (
            f"Password must be at most {MAX_PASSWORD_BYTES} bytes "
            "(bcrypt's limit; non-ASCII characters count as more than one)."
        )
    return None


def hash_password(password: str) -> str:
    """Hash a password for storage.

    Raises ``ValueError`` for input bcrypt cannot hash. Callers that accept
    untrusted input must validate first — see ``password_length_error`` — so
    the user gets a 422 rather than this surfacing as a 500.
    """
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES:
        raise ValueError(f"Password exceeds bcrypt's {MAX_PASSWORD_BYTES}-byte limit")
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    """Check a candidate password against a stored hash.

    An over-length candidate returns ``False`` rather than raising. It cannot
    be a false negative: registration refuses to *set* a password bcrypt can't
    hash, so no stored hash can correspond to one. It must not be truncated to
    72 bytes and compared either — that would let a long password authenticate
    by its prefix, which is the exact bug the byte limit causes elsewhere.

    This matters because ``verify_password`` sits on the unauthenticated login
    path: letting the ValueError escape hands any anonymous caller a 500.
    """
    if len(plain.encode("utf-8")) > MAX_PASSWORD_BYTES:
        return False
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str = "org_default",
) -> tuple[str, str]:
    """Issue a signed access token and return ``(token, jti)``.

    AUTH-A2: every access token now carries a ``jti`` (JWT ID) claim so it can
    be revoked server-side via the Redis-backed revocation list. The ``jti`` is
    also returned to the caller (login / refresh endpoints) so they can record
    or revoke it without having to decode the token they just signed.

    AUTH-B1: ``org_id`` is now embedded in the token so route-level scoping can
    reject cross-org access without an extra DB lookup.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=settings.access_token_ttl_minutes)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "type": "access",
        "jti": jti,
        "org_id": org_id,
        # P142: issued-at powers the per-user revocation epoch (admin force
        # logout). int(timestamp) keeps the claim a plain JWT NumericDate.
        "iat": int(now.timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti


def create_refresh_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str = "org_default",
    family_id: str | None = None,
) -> tuple[str, str, str]:
    """Issue a signed refresh token and return ``(token, jti, family_id)``.

    AUTH-A2: refresh tokens already carried a jti; we now also return it so the
    rotation path in ``/auth/refresh`` can revoke it the moment it is consumed.

    AUTH-B1: ``org_id`` is propagated through refresh-token rotation so the
    new access token issued during refresh stays bound to the same tenant.

    P142: every refresh token carries a family id (``fid``). On login a fresh
    family is started (``family_id=None`` → new uuid); on rotation the caller
    passes the presented token's ``fid`` so the new token stays in the same
    family. The family id lets ``/auth/refresh`` detect reuse of an already-
    rotated token and revoke the entire family (theft response).
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(days=settings.refresh_token_ttl_days)
    jti = str(uuid.uuid4())
    fid = family_id or str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "type": "refresh",
        "jti": jti,
        "org_id": org_id,
        "iat": int(now.timestamp()),
        "fid": fid,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti, fid


# MFA (#144): short-lived challenge token TTL. After a correct password, an
# MFA-enrolled user gets this instead of a session pair; they have ~5 minutes
# to complete the second factor at /auth/mfa/verify.
MFA_CHALLENGE_TTL_MINUTES = 5


def create_mfa_challenge_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str = "org_default",
) -> tuple[str, str]:
    """Issue a short-TTL ``type="mfa_challenge"`` token; returns ``(token, jti)``.

    This is NOT a session token. ``get_current_user`` / ``get_ws_user`` reject
    any token whose ``type`` is not ``"access"``, so a challenge token can never
    be used to call protected endpoints. Its only valid consumer is
    ``/auth/mfa/verify``, which checks the type, verifies the second factor,
    revokes this ``jti`` (single-use), then mints the real pair.

    It carries ``sub``/``username``/``role``/``org_id`` so the verify step can
    issue a correctly-scoped session pair without re-reading the user row, and
    its own ``jti`` so it can be revoked the instant it is consumed.
    """
    settings = get_settings()
    now = datetime.now(UTC)
    expire = now + timedelta(minutes=MFA_CHALLENGE_TTL_MINUTES)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "type": "mfa_challenge",
        "jti": jti,
        "org_id": org_id,
        "iat": int(now.timestamp()),
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti


def create_token_pair(
    user_id: str,
    username: str,
    role: str,
    org_id: str = "org_default",
) -> TokenPair:
    settings = get_settings()
    access_token, _ = create_access_token(user_id, username, role, org_id=org_id)
    refresh_token, _, _ = create_refresh_token(user_id, username, role, org_id=org_id)
    return TokenPair(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


def decode_token(token: str) -> TokenPayload:
    """Decode and validate a JWT token. Raises JWTError on failure."""
    settings = get_settings()
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])
    return TokenPayload(**payload)
