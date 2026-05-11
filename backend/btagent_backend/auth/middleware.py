"""Authentication middleware and FastAPI dependencies."""

import logging

from fastapi import Depends, HTTPException, Request, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError

from btagent_backend.auth.cookies import ACCESS_COOKIE_NAME
from btagent_backend.auth.jwt import TokenPayload, decode_token
from btagent_backend.auth.rbac import has_permission
from btagent_backend.auth.revocation import is_revoked

logger = logging.getLogger("btagent.auth.middleware")

# AUTH-C1: ``auto_error=False`` so missing-header isn't a hard 401 — the
# request may carry the token via httpOnly cookie instead. The dependency
# below runs the dual-read (cookie first, header second) and raises 401 only
# when neither is present.
security = HTTPBearer(auto_error=False)

# AUTH-A2: header used when rejecting a revoked or otherwise invalid token.
_INVALID_TOKEN_HEADERS = {"WWW-Authenticate": 'Bearer error="invalid_token"'}


class CurrentUser:
    """Represents the authenticated user from JWT token."""

    def __init__(self, payload: TokenPayload):
        self.id = payload.sub
        self.username = payload.username
        self.role = payload.role
        # AUTH-B1: org_id powers route-level tenant scoping. TokenPayload
        # defaults this to "org_default" for legacy tokens issued before
        # Phase B1, so the attribute is always populated.
        self.org_id = payload.org_id

    def has_permission(self, permission: str) -> bool:
        return has_permission(self.role, permission)

    def require_permission(self, permission: str) -> None:
        if not self.has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} requires higher role than {self.role}",
            )


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> CurrentUser:
    """FastAPI dependency: extract and validate JWT.

    AUTH-C1: dual-read transport. The cookie (``btagent_access``) is the new
    primary path — checked first so the browser's httpOnly session takes
    precedence. The ``Authorization: Bearer …`` header remains as a
    rollout-window compat fallback for tests, mobile/CLI clients, and the
    frontend during Phase C2.
    """
    # Cookie first, header second. Whichever wins, both feed the same JWT
    # decode + revocation check below.
    token = request.cookies.get(ACCESS_COOKIE_NAME)
    if not token and credentials is not None:
        token = credentials.credentials
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
    except JWTError:
        # SEC-018 FIX: Do not leak internal JWT error details to the client
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if payload.type != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Expected access token, got refresh token",
        )

    # AUTH-A2: enforce the Redis-backed revocation list.
    if payload.jti is None:
        # Legacy access tokens issued before AUTH-A2 have no jti and therefore
        # cannot be revoked individually. The rollout-window policy used to
        # accept them everywhere with a warning; the audit-cleanup hardening
        # closes that gap in prod (only) so a stolen legacy token can't
        # outlast the rollout. Dev/test still warn-and-accept so the suite
        # doesn't have to mint jti'd tokens for every fixture.
        from btagent_backend.config import get_settings

        if get_settings().env == "prod":
            logger.warning(
                "Rejecting legacy access token without jti in prod for user=%s",
                payload.sub,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token is missing required identifier (jti)",
                headers=_INVALID_TOKEN_HEADERS,
            )
        logger.warning(
            "Accepted legacy access token without jti for user=%s; "
            "force re-login recommended before AUTH-A2 rollout completes",
            payload.sub,
        )
    elif await is_revoked(payload.jti):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has been revoked",
            headers=_INVALID_TOKEN_HEADERS,
        )

    return CurrentUser(payload)


async def get_ws_user(websocket: WebSocket) -> CurrentUser:
    """Extract user from WebSocket cookie or ``?token=`` query param.

    AUTH-C1: cookie (``btagent_access``) is the new primary path so a browser
    that's already logged in via the httpOnly cookie can open the WS without
    putting the token on the URL. The ``?token=`` query param remains as a
    compat fallback for the existing frontend during Phase C2 and for any
    non-browser client that doesn't carry cookies.
    """
    token = websocket.cookies.get(ACCESS_COOKIE_NAME)
    if not token:
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
    """FastAPI dependency factory: require minimum role level.

    SEC-007 FIX: Compare user's role against the provided min_role using the
    RBAC role hierarchy, rather than always checking investigation:view.
    """
    from btagent_backend.auth.rbac import ROLE_HIERARCHY

    async def _check(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        try:
            from btagent_shared.types.enums import UserRole

            user_level = ROLE_HIERARCHY.get(UserRole(user.role), -1)
            required_level = ROLE_HIERARCHY.get(UserRole(min_role), 999)
        except ValueError:
            raise HTTPException(status_code=403, detail="Invalid role configuration")

        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient role: requires {min_role} or higher",
            )
        return user

    return _check
