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
    # AUTH-B1: org_id is embedded so the request-scoped CurrentUser dependency
    # can scope reads/writes to the caller's tenant without an extra DB hit.
    # ``None`` is tolerated for legacy tokens issued before this rollout; the
    # middleware will treat them as members of ``"org_default"`` so they keep
    # working during the rollout window.
    org_id: str | None = None


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str | None = None,
) -> tuple[str, str]:
    """Issue a signed access token and return ``(token, jti)``.

    AUTH-A2: every access token now carries a ``jti`` (JWT ID) claim so it can
    be revoked server-side via the Redis-backed revocation list. The ``jti`` is
    also returned to the caller (login / refresh endpoints) so they can record
    or revoke it without having to decode the token they just signed.

    AUTH-B1: ``org_id`` is also embedded so route-level ownership checks can
    scope reads/writes to the caller's tenant without an extra DB lookup.
    """
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(minutes=settings.access_token_ttl_minutes)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "type": "access",
        "jti": jti,
        "org_id": org_id,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti


def create_refresh_token(
    user_id: str,
    username: str,
    role: str,
    org_id: str | None = None,
) -> tuple[str, str]:
    """Issue a signed refresh token and return ``(token, jti)``.

    AUTH-A2: refresh tokens already carried a jti; we now also return it so the
    rotation path in ``/auth/refresh`` can revoke it the moment it is consumed.

    AUTH-B1: ``org_id`` is also embedded so the rotated access token issued by
    ``/auth/refresh`` carries the same tenant context.
    """
    settings = get_settings()
    expire = datetime.now(UTC) + timedelta(days=settings.refresh_token_ttl_days)
    jti = str(uuid.uuid4())
    payload = {
        "sub": user_id,
        "username": username,
        "role": role,
        "exp": expire,
        "type": "refresh",
        "jti": jti,
        "org_id": org_id,
    }
    token = jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)
    return token, jti


def create_token_pair(
    user_id: str,
    username: str,
    role: str,
    org_id: str | None = None,
) -> TokenPair:
    settings = get_settings()
    access_token, _ = create_access_token(user_id, username, role, org_id=org_id)
    refresh_token, _ = create_refresh_token(user_id, username, role, org_id=org_id)
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
