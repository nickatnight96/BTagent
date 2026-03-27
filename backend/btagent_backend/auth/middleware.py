"""Authentication middleware and FastAPI dependencies."""

from fastapi import Depends, HTTPException, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from btagent_backend.auth.jwt import TokenPayload, decode_token
from btagent_backend.auth.rbac import has_permission

security = HTTPBearer()


class CurrentUser:
    """Represents the authenticated user from JWT token."""

    def __init__(self, payload: TokenPayload):
        self.id = payload.sub
        self.username = payload.username
        self.role = payload.role

    def has_permission(self, permission: str) -> bool:
        return has_permission(self.role, permission)

    def require_permission(self, permission: str) -> None:
        if not self.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} requires higher role than {self.role}",
            )


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> CurrentUser:
    """FastAPI dependency: extract and validate JWT from Authorization header."""
    try:
        payload = decode_token(credentials.credentials)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {e}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected access token, got refresh token",
        )

    return CurrentUser(payload)


async def get_ws_user(websocket: WebSocket) -> CurrentUser:
    """Extract user from WebSocket query param or first message.

    WebSocket auth: connect with ?token=<jwt> query parameter.
    """
    token = websocket.query_params.get("token")
    if not token:
        await websocket.close(code=4001, reason="Missing auth token")
        raise HTTPException(status_code=401, detail="Missing WebSocket auth token")

    try:
        payload = decode_token(token)
    except JWTError:
        await websocket.close(code=4001, reason="Invalid auth token")
        raise HTTPException(status_code=401, detail="Invalid WebSocket auth token")

    if payload.type != "access":
        await websocket.close(code=4001, reason="Expected access token")
        raise HTTPException(status_code=401, detail="Expected access token")

    return CurrentUser(payload)


def require_role(min_role: str):
    """FastAPI dependency factory: require minimum role level."""

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if not has_permission(user.role, f"investigation:view"):
            raise HTTPException(status_code=403, detail="Insufficient role")
        return user

    return _check
