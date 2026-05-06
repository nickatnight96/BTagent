"""HttpOnly cookie helpers for JWT access + refresh tokens (Phase C1).

The frontend persists tokens in localStorage today, which is XSS-readable.
Phase C1 introduces an httpOnly cookie transport so the browser never has
JavaScript-accessible access to the tokens. The Authorization header path
remains as a rollout-window compatibility fallback for tests, mobile/CLI
clients, and the frontend during Phase C2.

Cookie spec:

* ``btagent_access`` — HttpOnly, Secure (off in dev/test), SameSite=Lax,
  Path=/, TTL = access-token TTL.
* ``btagent_refresh`` — HttpOnly, Secure (off in dev/test), SameSite=Strict,
  Path=/api/v1/auth/refresh (tighter scope so it only reaches /refresh),
  TTL = refresh-token TTL.
"""

from __future__ import annotations

from fastapi import Response

from btagent_backend.config import get_settings

ACCESS_COOKIE_NAME = "btagent_access"
REFRESH_COOKIE_NAME = "btagent_refresh"

ACCESS_COOKIE_PATH = "/"
REFRESH_COOKIE_PATH = "/api/v1/auth/refresh"


def _is_secure() -> bool:
    """Cookies are marked Secure outside dev/test so browsers reject them on http://."""
    settings = get_settings()
    return settings.env not in ("dev", "test")


def set_auth_cookies(
    response: Response,
    access_token: str,
    refresh_token: str,
) -> None:
    """Attach both auth cookies to ``response``."""
    settings = get_settings()
    secure = _is_secure()

    access_max_age = settings.access_token_ttl_minutes * 60
    refresh_max_age = settings.refresh_token_ttl_days * 24 * 60 * 60

    response.set_cookie(
        key=ACCESS_COOKIE_NAME,
        value=access_token,
        max_age=access_max_age,
        path=ACCESS_COOKIE_PATH,
        httponly=True,
        secure=secure,
        samesite="lax",
    )
    response.set_cookie(
        key=REFRESH_COOKIE_NAME,
        value=refresh_token,
        max_age=refresh_max_age,
        path=REFRESH_COOKIE_PATH,
        httponly=True,
        secure=secure,
        samesite="strict",
    )


def clear_auth_cookies(response: Response) -> None:
    """Delete both auth cookies on ``response``.

    ``delete_cookie`` is the FastAPI/Starlette helper that emits
    ``Set-Cookie: name=; Max-Age=0; Path=...``. Path must match the path the
    cookie was originally set with, otherwise the browser will keep its copy.
    """
    response.delete_cookie(key=ACCESS_COOKIE_NAME, path=ACCESS_COOKIE_PATH)
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)
