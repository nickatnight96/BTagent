"""TOTP MFA endpoints (#144, Phase 1a).

Opt-in second factor. Four endpoints under ``/auth/mfa``:

* ``POST /auth/mfa/enroll``   (authed) — mint a secret, return the
  ``otpauth://`` URI + one-time recovery codes, store encrypted, enabled=False.
* ``POST /auth/mfa/confirm``  (authed) — verify a code, flip enabled=True.
* ``POST /auth/mfa/disable``  (authed) — require a current code, drop the row.
* ``POST /auth/mfa/verify``   (UN-authed) — consume the login challenge token
  (set by ``/auth/login`` for enrolled users) + a TOTP/recovery code, then
  issue the real session pair via ``create_token_pair`` and set cookies.

Security notes:
  * Secrets are Fernet-encrypted at rest; recovery codes are bcrypt-hashed and
    single-use.
  * The challenge token is ``type="mfa_challenge"`` — ``get_current_user``
    rejects non-``access`` types, so it can't be replayed as a session token.
    It is revoked (its ``jti``) the instant it is consumed.
  * ``/auth/mfa/verify`` is UN-authed (the caller has no session yet) and is
    covered by the global per-IP rate limiter (anonymous bucket) for
    brute-force defense.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from jose import JWTError
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.api.deps import CurrentUser, get_current_user, get_db
from btagent_backend.auth.cookies import (
    MFA_CHALLENGE_COOKIE_NAME,
    clear_mfa_challenge_cookie,
    set_auth_cookies,
)
from btagent_backend.auth.jwt import TokenPair, create_token_pair, decode_token
from btagent_backend.auth.mfa import (
    MFAConfigError,
    decrypt_secret,
    deserialize_recovery_hashes,
    encrypt_secret,
    generate_recovery_codes,
    generate_secret,
    hash_recovery_codes,
    provisioning_uri,
    serialize_recovery_hashes,
    verify_and_consume_recovery_code,
    verify_totp,
)
from btagent_backend.auth.revocation import is_revoked, revoke
from btagent_backend.config import get_settings
from btagent_backend.db.models import UserRow
from btagent_backend.db.models_mfa import UserMFARow

logger = logging.getLogger("btagent.auth.mfa")

router = APIRouter(prefix="/auth/mfa", tags=["auth", "mfa"])


def _remaining_ttl(exp: datetime) -> int:
    if exp.tzinfo is None:
        exp = exp.replace(tzinfo=UTC)
    return max(0, int((exp - datetime.now(UTC)).total_seconds()))


# ---------------------------------------------------------------------------
# Request / response models
# ---------------------------------------------------------------------------


class EnrollResponse(BaseModel):
    # otpauth:// provisioning URI — the frontend renders the QR; the backend
    # never produces an image (no qrcode/Pillow dependency).
    provisioning_uri: str
    secret: str  # base32, shown for manual entry fallback
    recovery_codes: list[str]  # shown ONCE; only hashes are stored


class CodeRequest(BaseModel):
    code: str


class VerifyRequest(BaseModel):
    code: str


class MFAStatusResponse(BaseModel):
    enrolled: bool
    enabled: bool


# ---------------------------------------------------------------------------
# Authed enrollment management
# ---------------------------------------------------------------------------


@router.get("/status", response_model=MFAStatusResponse)
async def mfa_status(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Report whether the caller has an MFA row and whether it's enabled."""
    row = await db.get(UserMFARow, current_user.id)
    return MFAStatusResponse(
        enrolled=row is not None,
        enabled=bool(row and row.enabled),
    )


@router.post("/enroll", response_model=EnrollResponse)
async def enroll(
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Begin MFA enrollment: generate a secret + recovery codes (enabled=False).

    Re-enrolling (calling this again before confirming, or after disabling)
    overwrites any unconfirmed/old secret. We refuse to clobber an ALREADY
    enabled enrollment — the user must explicitly disable first — to avoid an
    attacker with a hijacked session silently swapping the second factor.
    """
    existing = await db.get(UserMFARow, current_user.id)
    if existing is not None and existing.enabled:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="MFA already enabled. Disable it first to re-enroll.",
        )

    secret = generate_secret()
    recovery_codes = generate_recovery_codes()

    try:
        secret_enc = encrypt_secret(secret)
        recovery_hashes = hash_recovery_codes(recovery_codes)
        uri = provisioning_uri(secret, current_user.username)
    except MFAConfigError as exc:
        # Only reachable in prod with an unset/invalid key — surface clearly.
        logger.error("MFA enroll failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    recovery_enc = serialize_recovery_hashes(recovery_hashes)

    if existing is None:
        db.add(
            UserMFARow(
                user_id=current_user.id,
                secret_enc=secret_enc,
                enabled=False,
                confirmed_at=None,
                recovery_codes_enc=recovery_enc,
            )
        )
    else:
        existing.secret_enc = secret_enc
        existing.enabled = False
        existing.confirmed_at = None
        existing.recovery_codes_enc = recovery_enc
    await db.flush()

    return EnrollResponse(
        provisioning_uri=uri,
        secret=secret,
        recovery_codes=recovery_codes,
    )


@router.post("/confirm", status_code=status.HTTP_204_NO_CONTENT)
async def confirm(
    body: CodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Confirm enrollment by proving possession of the authenticator."""
    row = await db.get(UserMFARow, current_user.id)
    if row is None:
        raise HTTPException(status_code=400, detail="No MFA enrollment in progress")

    try:
        secret = decrypt_secret(row.secret_enc)
    except MFAConfigError as exc:
        logger.error("MFA confirm failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    if not verify_totp(secret, body.code):
        raise HTTPException(status_code=400, detail="Invalid verification code")

    row.enabled = True
    row.confirmed_at = datetime.now(UTC)
    await db.flush()
    return None


@router.post("/disable", status_code=status.HTTP_204_NO_CONTENT)
async def disable(
    body: CodeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Disable MFA. Requires a current TOTP (or recovery) code as proof."""
    row = await db.get(UserMFARow, current_user.id)
    if row is None or not row.enabled:
        raise HTTPException(status_code=400, detail="MFA is not enabled")

    try:
        secret = decrypt_secret(row.secret_enc)
    except MFAConfigError as exc:
        logger.error("MFA disable failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    ok = verify_totp(secret, body.code)
    if not ok:
        # Allow a recovery code too, so a user who lost their device can still
        # turn MFA off.
        matched, _ = verify_and_consume_recovery_code(
            body.code, deserialize_recovery_hashes(row.recovery_codes_enc)
        )
        ok = matched
    if not ok:
        raise HTTPException(status_code=400, detail="Invalid verification code")

    await db.delete(row)
    await db.flush()
    return None


# ---------------------------------------------------------------------------
# UN-authed second-factor verification (consumes the login challenge)
# ---------------------------------------------------------------------------


@router.post("/verify", response_model=TokenPair)
async def verify(
    body: VerifyRequest,
    request: Request,
    response: Response,
    db: AsyncSession = Depends(get_db),
):
    """Complete login: consume the MFA challenge + a second factor.

    Flow:
      1. Read the ``mfa_challenge`` token from the scoped cookie (set by
         ``/auth/login``). Validate it decodes, is ``type="mfa_challenge"``,
         and its ``jti`` is not already revoked (replay defense).
      2. Verify a TOTP code OR a single-use recovery code against the user's
         stored (encrypted) secret. Recovery codes are consumed on use.
      3. Revoke the challenge ``jti`` so the same challenge can't be replayed.
      4. Mint the real session pair (``create_token_pair``) + set auth cookies,
         clear the challenge cookie.

    UN-authed by design (the caller has no session yet). The global per-IP
    rate limiter (anonymous bucket) throttles brute-force attempts.
    """
    challenge = request.cookies.get(MFA_CHALLENGE_COOKIE_NAME)
    if not challenge:
        raise HTTPException(status_code=401, detail="Missing MFA challenge")

    try:
        payload = decode_token(challenge)
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired MFA challenge")

    if payload.type != "mfa_challenge":
        raise HTTPException(status_code=401, detail="Invalid MFA challenge token")

    # Replay defense: a challenge is single-use. Once consumed (jti revoked),
    # a second verify with the same cookie is rejected even before code-check.
    if payload.jti and await is_revoked(payload.jti):
        raise HTTPException(status_code=401, detail="MFA challenge already used")

    row = await db.get(UserMFARow, payload.sub)
    if row is None or not row.enabled:
        # Enrollment was removed/disabled between login and verify — treat as
        # an invalid challenge rather than silently logging in.
        raise HTTPException(status_code=401, detail="MFA is not enabled for this account")

    try:
        secret = decrypt_secret(row.secret_enc)
    except MFAConfigError as exc:
        logger.error("MFA verify failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))

    matched = verify_totp(secret, body.code)
    if not matched:
        # Fall back to a single-use recovery code.
        ok, remaining = verify_and_consume_recovery_code(
            body.code, deserialize_recovery_hashes(row.recovery_codes_enc)
        )
        if ok:
            row.recovery_codes_enc = serialize_recovery_hashes(remaining)
            await db.flush()
            matched = True

    if not matched:
        raise HTTPException(status_code=401, detail="Invalid MFA code")

    # Single-use challenge: revoke its jti so it cannot be replayed.
    if payload.jti:
        await revoke(payload.jti, _remaining_ttl(payload.exp))

    # Resolve the user's current org for correctly-scoped tokens. The challenge
    # carries org_id, but re-reading guards against a stale challenge after an
    # org change; fall back to the challenge value if the row is gone.
    user = await db.get(UserRow, payload.sub)
    org_id = user.org_id if user is not None else payload.org_id

    pair = create_token_pair(payload.sub, payload.username, payload.role, org_id=org_id)
    set_auth_cookies(response, pair.access_token, pair.refresh_token)
    clear_mfa_challenge_cookie(response)

    return pair
