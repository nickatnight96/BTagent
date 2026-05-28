"""TOTP MFA primitives (#144, Phase 1a).

This module is the *crypto + protocol* layer for opt-in TOTP MFA. It has no
FastAPI / DB concerns — those live in ``api/v1/mfa.py`` and the ``user_mfa``
table. Everything here is pure functions over strings so it is trivially
unit-testable.

Contents:

* TOTP: ``generate_secret`` / ``provisioning_uri`` / ``verify_totp`` (pyotp).
* Recovery codes: generation, bcrypt hashing, single-use verification.
* Secret-at-rest: Fernet ``encrypt_secret`` / ``decrypt_secret``.

Key handling (CI safety, see ``config.py``): the Fernet key is resolved
lazily via ``_fernet()``. If ``mfa_secret_enc_key`` is set, it is used as-is.
Otherwise, in dev/test ONLY, a deterministic key is derived from
``jwt_secret`` so the suite round-trips without extra config. In prod with no
key, ``MFAConfigError`` is raised so the operator gets a clear signal — but
ONLY when a user actually enrolls/verifies, never at import or app boot.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets

import bcrypt
import pyotp
from cryptography.fernet import Fernet, InvalidToken

from btagent_backend.config import get_settings

# Number of one-time recovery codes minted at enrollment.
RECOVERY_CODE_COUNT = 10
# Length (hex chars) of each recovery code's random core. 10 hex chars ≈ 40
# bits of entropy; rendered grouped (e.g. "ab12c-de34f") for readability.
_RECOVERY_CODE_HEX_LEN = 10


class MFAConfigError(RuntimeError):
    """Raised when MFA is used but no encryption key can be resolved.

    Surfaced as a 500 by the route layer. It can ONLY occur in prod with an
    unset ``mfa_secret_enc_key`` and only on an actual enroll/verify call —
    never at import time or app boot, so it can't break CI start-up.
    """


# ---------------------------------------------------------------------------
# Fernet key resolution + secret-at-rest encryption
# ---------------------------------------------------------------------------


def _derive_test_key(jwt_secret: str) -> str:
    """Derive a deterministic Fernet key from the JWT secret (dev/test only).

    Fernet keys are 32 url-safe-base64 bytes. We SHA-256 the JWT secret to get
    exactly 32 bytes then base64-url encode. Deterministic so a secret
    encrypted in one process decrypts in another within the same test session.
    """
    digest = hashlib.sha256(f"mfa-fernet:{jwt_secret}".encode()).digest()
    return base64.urlsafe_b64encode(digest).decode()


def _resolve_key() -> str:
    """Return the effective Fernet key string, or raise ``MFAConfigError``."""
    settings = get_settings()
    key = (settings.mfa_secret_enc_key or "").strip()
    if key:
        return key
    if settings.env in ("dev", "test"):
        return _derive_test_key(settings.jwt_secret)
    raise MFAConfigError(
        "MFA is not configured: BTAGENT_MFA_SECRET_ENC_KEY is unset. "
        "Generate one with: python -c "
        "'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    )


def _fernet() -> Fernet:
    """Build a Fernet from the resolved key.

    A malformed configured key (wrong length / not base64) raises
    ``MFAConfigError`` rather than a raw ``ValueError`` so the route layer can
    return a clean 500 with an actionable message.
    """
    key = _resolve_key()
    try:
        return Fernet(key.encode() if isinstance(key, str) else key)
    except (ValueError, TypeError) as exc:
        raise MFAConfigError(
            "BTAGENT_MFA_SECRET_ENC_KEY is not a valid Fernet key (must be 32 "
            "url-safe-base64-encoded bytes)."
        ) from exc


def encrypt_secret(secret: str) -> str:
    """Fernet-encrypt a plaintext TOTP secret; returns an opaque token str."""
    return _fernet().encrypt(secret.encode()).decode()


def decrypt_secret(token: str) -> str:
    """Decrypt a Fernet token back to the plaintext TOTP secret.

    Raises ``MFAConfigError`` if the ciphertext can't be decrypted (wrong key
    / corrupt data) so callers don't leak a raw crypto exception.
    """
    try:
        return _fernet().decrypt(token.encode()).decode()
    except InvalidToken as exc:
        raise MFAConfigError(
            "Stored MFA secret could not be decrypted — the encryption key may "
            "have changed. Affected users must re-enroll."
        ) from exc


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------


def generate_secret() -> str:
    """Return a fresh random base32 TOTP secret."""
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str | None = None) -> str:
    """Build the ``otpauth://`` provisioning URI the authenticator app scans.

    The frontend renders this as a QR code (or shows ``secret`` as a manual
    fallback). ``issuer`` defaults to ``settings.mfa_issuer``.
    """
    issuer = issuer or get_settings().mfa_issuer
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str, valid_window: int = 1) -> bool:
    """Verify a 6-digit TOTP ``code`` against ``secret``.

    ``valid_window=1`` accepts the adjacent 30s steps (±1) to tolerate clock
    skew, which is the standard recommendation. Non-numeric / wrong-length
    input is rejected cheaply before hitting pyotp.
    """
    if not secret or not code:
        return False
    code = code.strip().replace(" ", "")
    if not code.isdigit():
        return False
    try:
        return pyotp.TOTP(secret).verify(code, valid_window=valid_window)
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Recovery codes
# ---------------------------------------------------------------------------


def generate_recovery_codes(count: int = RECOVERY_CODE_COUNT) -> list[str]:
    """Return ``count`` fresh, human-friendly single-use recovery codes.

    Format: two 5-char hex groups joined by a dash, e.g. ``"a1b2c-d3e4f"``.
    These are shown to the user ONCE at enrollment; only their bcrypt hashes
    are persisted.
    """
    codes: list[str] = []
    for _ in range(count):
        raw = secrets.token_hex(_RECOVERY_CODE_HEX_LEN // 2 + 1)[:_RECOVERY_CODE_HEX_LEN]
        codes.append(f"{raw[:5]}-{raw[5:]}")
    return codes


def _normalize_recovery_code(code: str) -> str:
    """Canonicalize a recovery code for comparison (case/whitespace-insensitive)."""
    return code.strip().lower().replace(" ", "")


def hash_recovery_codes(codes: list[str]) -> list[str]:
    """Bcrypt-hash each recovery code (normalized). Returns the hash list."""
    return [
        bcrypt.hashpw(_normalize_recovery_code(c).encode(), bcrypt.gensalt()).decode()
        for c in codes
    ]


def serialize_recovery_hashes(hashes: list[str]) -> str:
    """JSON-encode the recovery-code hash list for ``recovery_codes_enc``."""
    return json.dumps(hashes)


def deserialize_recovery_hashes(raw: str | None) -> list[str]:
    """Decode the stored recovery-code hash list; tolerant of empty/None."""
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return [h for h in value if isinstance(h, str)] if isinstance(value, list) else []


def verify_and_consume_recovery_code(code: str, hashes: list[str]) -> tuple[bool, list[str]]:
    """Single-use recovery-code check.

    Returns ``(matched, remaining_hashes)``. If ``code`` matches one of the
    stored bcrypt hashes, that hash is removed from the returned list (so it
    can never be used again) and ``matched`` is True. On no match the list is
    returned unchanged.
    """
    if not code:
        return False, hashes
    candidate = _normalize_recovery_code(code).encode()
    for i, h in enumerate(hashes):
        try:
            if bcrypt.checkpw(candidate, h.encode()):
                remaining = hashes[:i] + hashes[i + 1 :]
                return True, remaining
        except (ValueError, TypeError):
            # Corrupt stored hash — skip it rather than crash the verify path.
            continue
    return False, hashes
