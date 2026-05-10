"""Authentication endpoints — login, refresh, logout, register (admin only)."""

import logging
from datetime import UTC, datetime

from btagent_shared.utils.ids import generate_id
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.cookies import (
    ACCESS_COOKIE_NAME,
    REFRESH_COOKIE_NAME,
    REFRESH_COOKIE_PATH,
    clear_auth_cookies,
    set_auth_cookies,
)
from btagent_backend.auth.jwt import (
    TokenPair,
    create_access_token,
    create_refresh_token,
    create_token_pair,
    decode_token,
    hash_password,
    verify_password,
)
from btagent_backend.auth.revocation import is_revoked, revoke
from btagent_backend.config import get_settings
from btagent_backend.db.models import UserRow

logger = logging.getLogger("btagent.auth.api")

# Reused by /auth/logout to read the bearer access token without forcing the
# user-fetch path through ``get_current_user`` (we still want logout to succeed
# even if the access token's jti has already been added to the revocation list
# by another tab — defence in depth).
_logout_bearer = HTTPBearer(auto_error=False)

router = APIRouter(prefix="/auth", tags=["auth"])


def _remaining_ttl(exp: datetime) -> int:
    """Return seconds until ``exp``, clamped to 0."""
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    return max(0, int((exp - datetime.now(UTC)).total_seconds()))


class LoginRequest(BaseModel):
    username: str
    password: str


class RegisterRequest(BaseModel):
    username: str
    email: str
    password: str
    # SEC-008 FIX: Validate role against the UserRole enum to prevent arbitrary values
    role: str = "analyst"

    @field_validator("role")
    @classmethod
    def validate_role(cls, v: str) -> str:
        from btagent_shared.types.enums import UserRole

        valid_roles = {r.value for r in UserRole}
        if v not in valid_roles:
            raise ValueError(
                f"Invalid role '{v}'. Must be one of: {', '.join(sorted(valid_roles))}"
            )
        return v


class RefreshRequest(BaseModel):
    """Refresh request body.

    Phase C1: ``refresh_token`` is now *optional* in the body — when omitted,
    the endpoint reads the value from the ``btagent_refresh`` httpOnly cookie.
    """

    refresh_token: str | None = None


class LogoutRequest(BaseModel):
    """Optional refresh token so logout can revoke the whole session.

    The access token comes from the ``Authorization`` header; the refresh
    token (if the client still holds one) is supplied here so we can revoke
    both halves of the session in a single round-trip.
    """

    refresh_token: str | None = None


@router.post("/login", response_model=TokenPair)
async def login(
    body: LoginRequest,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user and return JWT token pair.

    Phase C1: tokens are *also* placed into httpOnly cookies on the response so
    the browser never exposes them to JavaScript. The JSON body still carries
    them for the rollout window — the frontend will stop reading them in
    Phase C2 and existing mobile/CLI clients keep working in the meantime.
    """
    result = await db.execute(select(UserRow).where(UserRow.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # AUTH-B1: bind the issued tokens to the user's org so per-request authz
    # has tenant context without an extra DB lookup.
    pair = create_token_pair(user.id, user.username, user.role, org_id=user.org_id)

    # AUTH-C1: set httpOnly cookies (primary path) alongside the JSON body
    # (compat path).
    set_auth_cookies(response, pair.access_token, pair.refresh_token)

    return pair


@router.post("/refresh", response_model=TokenPair)
async def refresh(
    request: Request,
    response: Response,
    body: RefreshRequest | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(_logout_bearer),
):
    """Exchange a refresh token for a new token pair.

    AUTH-A2: implements *refresh-token rotation*. The supplied refresh token's
    ``jti`` is checked against the revocation list and then immediately revoked,
    so the token can only be redeemed once. A second attempt with the same
    refresh token returns 401.

    The OLD access-token's ``jti`` is **also** revoked on every successful
    rotation — otherwise a leaked access token would stay valid until its
    short TTL elapses even though the rotation contract has minted a new
    pair. The old token is resolved from the ``Authorization`` header first,
    then the ``btagent_access`` cookie (browser path).

    Phase C1: when the JSON body has no ``refresh_token``, fall back to the
    ``btagent_refresh`` httpOnly cookie. On success, the new pair is *also*
    written back as cookies so the browser keeps an httpOnly session.
    """
    # Resolve the refresh token from body, then cookie.
    refresh_token: str | None = body.refresh_token if body is not None else None
    if not refresh_token:
        refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)
    if not refresh_token:
        raise HTTPException(status_code=401, detail="Missing refresh token")

    try:
        payload = decode_token(refresh_token)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.type != "refresh":
        raise HTTPException(status_code=401, detail="Expected refresh token")

    # If this refresh token has already been used (or admin-revoked), reject.
    if payload.jti and await is_revoked(payload.jti):
        raise HTTPException(
            status_code=401,
            detail="Refresh token has been revoked",
            headers={"WWW-Authenticate": 'Bearer error="invalid_token"'},
        )

    # Rotate: revoke the old refresh token's jti before issuing the new pair.
    if payload.jti:
        await revoke(payload.jti, _remaining_ttl(payload.exp))

    # AUTH-A2: also revoke the OLD access-token jti on rotation so the
    # outgoing token stops working immediately, not after its TTL.
    # ``decode_token`` errors fall through silently — refresh must still
    # succeed when the caller's access token is already expired/missing
    # (the refresh flow's whole purpose is recovering from that state).
    old_access_token: str | None = None
    if credentials is not None and credentials.credentials:
        old_access_token = credentials.credentials
    if not old_access_token:
        old_access_token = request.cookies.get(ACCESS_COOKIE_NAME)
    if old_access_token:
        try:
            old_access_payload = decode_token(old_access_token)
        except JWTError:
            old_access_payload = None
        if old_access_payload is not None and old_access_payload.jti:
            await revoke(
                old_access_payload.jti,
                _remaining_ttl(old_access_payload.exp),
            )

    settings = get_settings()
    # AUTH-B1: keep the same org_id on rotation so the new pair stays bound
    # to the same tenant as the original session.
    access_token, _ = create_access_token(
        payload.sub, payload.username, payload.role, org_id=payload.org_id
    )
    new_refresh_token, _ = create_refresh_token(
        payload.sub, payload.username, payload.role, org_id=payload.org_id
    )

    # AUTH-C1: rewrite both cookies on every successful refresh so the
    # browser's httpOnly session keeps pace with header-based clients.
    set_auth_cookies(response, access_token, new_refresh_token)

    return TokenPair(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=settings.access_token_ttl_minutes * 60,
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    request: Request,
    response: Response,
    body: LogoutRequest | None = None,
    credentials: HTTPAuthorizationCredentials | None = Depends(_logout_bearer),
):
    """Revoke the caller's access token and (optionally) refresh token.

    AUTH-A2: writes the tokens' ``jti`` claims to the Redis-backed revocation
    list with a TTL equal to each token's remaining lifetime, so subsequent
    requests using either token are rejected with 401 by ``get_current_user``
    / ``/auth/refresh``.

    Phase C1: also reads tokens from the ``btagent_access`` /
    ``btagent_refresh`` httpOnly cookies (cookie-only browser sessions don't
    set the Authorization header) and clears both cookies on the response so
    the browser drops them immediately.

    Logout is idempotent and never errors on a malformed/expired token —
    revocation of an already-dead token is a harmless no-op.
    """
    # Resolve the access token: Authorization header first, then cookie.
    access_token: str | None = None
    if credentials is not None and credentials.credentials:
        access_token = credentials.credentials
    if not access_token:
        access_token = request.cookies.get(ACCESS_COOKIE_NAME)

    if access_token:
        try:
            access_payload = decode_token(access_token)
        except JWTError:
            access_payload = None
        if access_payload is not None and access_payload.jti:
            await revoke(access_payload.jti, _remaining_ttl(access_payload.exp))

    # Resolve the refresh token: body first, then cookie.
    refresh_token: str | None = body.refresh_token if body is not None else None
    if not refresh_token:
        refresh_token = request.cookies.get(REFRESH_COOKIE_NAME)

    if refresh_token:
        try:
            refresh_payload = decode_token(refresh_token)
        except JWTError:
            refresh_payload = None
        if refresh_payload is not None and refresh_payload.jti:
            await revoke(refresh_payload.jti, _remaining_ttl(refresh_payload.exp))

    # AUTH-C1: drop the browser's httpOnly cookies so the next request is
    # unauthenticated even before the access-token's TTL expires.
    clear_auth_cookies(response)

    return None


@router.post("/register", response_model=dict, status_code=201)
async def register(
    body: RegisterRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Register new user (admin only)."""
    current_user.require_permission("user:create")

    # Check if username or email exists
    existing = await db.execute(
        select(UserRow).where((UserRow.username == body.username) | (UserRow.email == body.email))
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    # AUTH-B1: new users inherit the creating admin's org_id (defense against
    # mass-assignment of org_id from the request body).
    user = UserRow(
        id=generate_id("usr"),
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
        org_id=current_user.org_id,
    )
    db.add(user)
    await db.flush()

    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/me")
async def me(current_user: CurrentUser = Depends(get_current_user)):
    """Get current user info from JWT."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role,
        "org_id": current_user.org_id,
    }
