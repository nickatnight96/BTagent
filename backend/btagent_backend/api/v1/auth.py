"""Authentication endpoints — login, refresh, register (admin only)."""

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.jwt import (
    TokenPair,
    create_token_pair,
    decode_token,
    hash_password,
    verify_password,
)
from btagent_backend.db.models import UserRow
from btagent_shared.utils.ids import generate_id

router = APIRouter(prefix="/auth", tags=["auth"])


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
            raise ValueError(f"Invalid role '{v}'. Must be one of: {', '.join(sorted(valid_roles))}")
        return v


class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/login", response_model=TokenPair)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    """Authenticate user and return JWT token pair."""
    result = await db.execute(select(UserRow).where(UserRow.username == body.username))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    return create_token_pair(user.id, user.username, user.role)


@router.post("/refresh", response_model=TokenPair)
async def refresh(body: RefreshRequest):
    """Exchange refresh token for new token pair."""
    try:
        payload = decode_token(body.refresh_token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if payload.type != "refresh":
        raise HTTPException(status_code=401, detail="Expected refresh token")

    return create_token_pair(payload.sub, payload.username, payload.role)


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
        select(UserRow).where(
            (UserRow.username == body.username) | (UserRow.email == body.email)
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="Username or email already exists")

    user = UserRow(
        id=generate_id("usr"),
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    await db.flush()

    return {"id": user.id, "username": user.username, "role": user.role}


@router.get("/me")
async def me(current_user: CurrentUser = Depends(get_current_user)):
    """Get current user info from JWT."""
    return {"id": current_user.id, "username": current_user.username, "role": current_user.role}
