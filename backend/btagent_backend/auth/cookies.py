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
# MFA (#144): short-lived challenge cookie set after a correct password for an
# MFA-enrolled user. Scoped tight (SameSite=Strict, path = the MFA endpoints)
# so it only travels to /auth/mfa/* and never doubles as a session cookie.
MFA_CHALLENGE_COOKIE_NAME = "btagent_mfa_challenge"

ACCESS_COOKIE_PATH = "/"
REFRESH_COOKIE_PATH = "/api/v1/auth/refresh"
MFA_CHALLENGE_COOKIE_PATH = "/api/v1/auth/mfa"


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


def set_mfa_challenge_cookie(response: Response, token: str) -> None:
    """Attach the short-lived MFA-challenge cookie (#144).

    Mirrors the access cookie's flags (HttpOnly, Secure-outside-dev) but uses
    SameSite=Strict and a tight path so it only reaches the MFA endpoints, and
    a max-age matching the challenge TTL.
    """
    from btagent_backend.auth.jwt import MFA_CHALLENGE_TTL_MINUTES

    response.set_cookie(
        key=MFA_CHALLENGE_COOKIE_NAME,
        value=token,
        max_age=MFA_CHALLENGE_TTL_MINUTES * 60,
        path=MFA_CHALLENGE_COOKIE_PATH,
        httponly=True,
        secure=_is_secure(),
        samesite="strict",
    )


def clear_mfa_challenge_cookie(response: Response) -> None:
    """Delete the MFA-challenge cookie (after a successful verify or on logout)."""
    response.delete_cookie(key=MFA_CHALLENGE_COOKIE_NAME, path=MFA_CHALLENGE_COOKIE_PATH)


def clear_auth_cookies(response: Response) -> None:
    """Delete both auth cookies on ``response``.

    ``delete_cookie`` is the FastAPI/Starlette helper that emits
    ``Set-Cookie: name=; Max-Age=0; Path=...``. Path must match the path the
    cookie was originally set with, otherwise the browser will keep its copy.
    """
    response.delete_cookie(key=ACCESS_COOKIE_NAME, path=ACCESS_COOKIE_PATH)
    response.delete_cookie(key=REFRESH_COOKIE_NAME, path=REFRESH_COOKIE_PATH)
