"""SQLAlchemy ORM model for opt-in TOTP MFA (#144, Phase 1a).

MFA state lives in its own ``user_mfa`` table (one row per user, ``user_id``
as the primary key + FK → ``users.id``) rather than widening ``UserRow``.
Keeping it separate means:

* the common login lookup (``UserRow`` by username) is untouched, and the MFA
  row is fetched lazily only when needed;
* the encrypted TOTP secret + recovery-code hashes are isolated from the
  hot ``users`` row;
* a user with no MFA simply has no ``user_mfa`` row (the default), so the
  feature is genuinely opt-in.

Secret-at-rest: ``secret_enc`` is the Fernet-encrypted base32 TOTP secret.
``recovery_codes_enc`` is a JSON-encoded list of bcrypt-hashed recovery codes
(single-use; a code is removed from the list once consumed).
"""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from btagent_backend.db.models import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class UserMFARow(Base):
    __tablename__ = "user_mfa"

    # One MFA enrollment per user; PK == FK so the relationship is 1:1 and a
    # user can never have two competing secrets.
    user_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    # Fernet-encrypted base32 TOTP secret. Never stored in plaintext.
    secret_enc: Mapped[str] = mapped_column(Text, nullable=False)
    # Enrollment is two-step: enroll() writes the secret with enabled=False;
    # confirm() flips this to True once the user proves possession with a code.
    # The login flow ONLY gates on ``enabled is True``.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Set when the user first confirms a TOTP code (enabled flips true).
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # JSON list of bcrypt-hashed recovery codes (single-use). Consumed codes
    # are removed from the list.
    recovery_codes_enc: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
