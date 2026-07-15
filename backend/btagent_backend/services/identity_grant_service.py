"""First-class OAuth-grant store + ingest-side writer (#116 follow-up).

The #216 slice served ``GET /identity/grants`` read-derive from identity
findings' evidence and documented a first-class table as its deliberate
follow-up. This module is that follow-up's service layer:

* :func:`grant_fields_from_evidence` — the same pure evidence parse the
  read-derive endpoint used (grant tuple + scopes + consent + timestamps),
  shared by the writer and the legacy derive fallback.
* :func:`upsert_grant_from_finding` — the ingest-side write path, hooked into
  ``hunt_triage_service.record_finding``: whenever an identity-domain finding
  carries a complete grant tuple, the grant row is created or refreshed.
  Newest observation wins (same merge semantics as the derive endpoint's
  ``created_at`` anchor). **Fail-open**: a malformed evidence dict logs and
  returns ``None`` — grant bookkeeping must never break finding ingest.
* :func:`list_grants` — SQL-side filters + pagination for the endpoint.

Per the codebase convention nothing here commits — the caller owns that.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.identity_hunt import IdentityProvider, OAuthConsentType
from btagent_shared.utils.ids import generate_id
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_hunt import HuntFindingRow
from btagent_backend.db.models_identity import OAuthGrantRow

logger = logging.getLogger("btagent.services.identity_grants")


def _parse_dt(raw: object) -> datetime | None:
    """Accept ISO-8601 strings or datetimes from the evidence dict, ignore the rest."""
    if isinstance(raw, datetime):
        return raw
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


def _coerce_provider(raw: object) -> IdentityProvider | None:
    if isinstance(raw, IdentityProvider):
        return raw
    if isinstance(raw, str):
        try:
            return IdentityProvider(raw)
        except ValueError:
            return None
    return None


def _coerce_consent(raw: object) -> OAuthConsentType:
    if isinstance(raw, OAuthConsentType):
        return raw
    if isinstance(raw, str):
        try:
            return OAuthConsentType(raw)
        except ValueError:
            return OAuthConsentType.UNKNOWN
    return OAuthConsentType.UNKNOWN


def grant_fields_from_evidence(
    evidence: dict[str, Any] | None,
    *,
    default_provider: IdentityProvider = IdentityProvider.OKTA,
) -> dict[str, Any] | None:
    """Extract the grant tuple + attributes from a finding's evidence dict.

    Returns ``None`` when the evidence carries no complete grant tuple —
    token-replay / impossible-travel findings aren't grant-flavoured. The
    parse mirrors the #216 read-derive endpoint exactly so table-backed and
    derive-backed responses agree.
    """
    ev = evidence or {}
    principal_id = ev.get("principal_id")
    app_id = ev.get("app_id")
    if not isinstance(principal_id, str) or not isinstance(app_id, str):
        return None
    if not principal_id or not app_id:
        return None

    provider = _coerce_provider(ev.get("provider")) or default_provider
    scopes_raw = ev.get("scopes")
    scopes = [s for s in scopes_raw if isinstance(s, str)] if isinstance(scopes_raw, list) else []
    app_display_name = ev.get("app_display_name")

    return {
        "provider": provider.value,
        "principal_id": principal_id[:512],
        "app_id": app_id[:512],
        "app_display_name": (app_display_name if isinstance(app_display_name, str) else "")[:300],
        "scopes": scopes,
        "consent_type": _coerce_consent(ev.get("consent_type")).value,
        "granted_at": _parse_dt(ev.get("granted_at")),
        "last_used": _parse_dt(ev.get("last_used")),
        "revoked_at": _parse_dt(ev.get("revoked_at")),
    }


async def upsert_grant_from_finding(
    db: AsyncSession,
    *,
    finding: HuntFindingRow,
) -> OAuthGrantRow | None:
    """Create or refresh the grant row observed by an identity finding.

    Newest-wins: a finding observed after the stored ``observed_at`` refreshes
    the mutable attributes (scopes, usage, revocation, display name); an older
    or concurrent replay leaves the row untouched. Fail-open by contract —
    any unexpected error logs and returns ``None`` so ingest never breaks.
    """
    try:
        fields = grant_fields_from_evidence(finding.evidence)
        if fields is None:
            return None

        now = finding.created_at or datetime.now(UTC)
        existing = (
            await db.execute(
                select(OAuthGrantRow).where(
                    OAuthGrantRow.org_id == finding.org_id,
                    OAuthGrantRow.provider == fields["provider"],
                    OAuthGrantRow.principal_id == fields["principal_id"],
                    OAuthGrantRow.app_id == fields["app_id"],
                )
            )
        ).scalar_one_or_none()

        if existing is None:
            row = OAuthGrantRow(
                id=generate_id("oag"),
                org_id=finding.org_id,
                provider=fields["provider"],
                principal_id=fields["principal_id"],
                app_id=fields["app_id"],
                app_display_name=fields["app_display_name"],
                scopes=fields["scopes"],
                consent_type=fields["consent_type"],
                granted_at=fields["granted_at"] or now,
                last_used=fields["last_used"],
                revoked_at=fields["revoked_at"],
                source_finding_id=finding.id,
                observed_at=now,
                created_at=now,
                updated_at=now,
            )
            db.add(row)
            await db.flush()
            return row

        def _naive(dt: datetime) -> datetime:
            return dt.replace(tzinfo=None) if dt.tzinfo is not None else dt

        if _naive(now) < _naive(existing.observed_at):
            return existing  # stale replay — keep the fresher view

        existing.app_display_name = fields["app_display_name"] or existing.app_display_name
        existing.scopes = fields["scopes"] or existing.scopes
        existing.consent_type = fields["consent_type"]
        if fields["granted_at"] is not None:
            existing.granted_at = fields["granted_at"]
        if fields["last_used"] is not None:
            existing.last_used = fields["last_used"]
        # Revocation is one-way sticky unless a newer observation clears it
        # explicitly (a re-grant surfaces as a fresh non-revoked observation).
        existing.revoked_at = fields["revoked_at"]
        existing.source_finding_id = finding.id
        existing.observed_at = now
        existing.updated_at = now
        await db.flush()
        return existing
    except Exception:  # noqa: BLE001 — grant bookkeeping must never break ingest
        logger.exception(
            "oauth_grants upsert failed for finding %s (org=%s) — ingest continues",
            finding.id,
            finding.org_id,
        )
        return None


async def org_has_grants(db: AsyncSession, *, org_id: str) -> bool:
    """True when the org has at least one first-class grant row."""
    count = (
        await db.execute(
            select(func.count()).select_from(OAuthGrantRow).where(OAuthGrantRow.org_id == org_id)
        )
    ).scalar_one()
    return bool(count)


async def list_grants(
    db: AsyncSession,
    *,
    org_id: str,
    principal_id: str | None = None,
    provider: str | None = None,
    active: bool | None = None,
    page: int = 1,
    page_size: int = 50,
) -> tuple[list[OAuthGrantRow], int]:
    """Org-scoped grant listing with SQL-side filters + pagination.

    Ordered most-recently-used first (``last_used`` falling back to
    ``granted_at``), matching the read-derive endpoint's sort.
    """
    where = [OAuthGrantRow.org_id == org_id]
    if principal_id:
        where.append(OAuthGrantRow.principal_id == principal_id)
    if provider:
        where.append(OAuthGrantRow.provider == provider)
    if active is True:
        where.append(OAuthGrantRow.revoked_at.is_(None))
    elif active is False:
        where.append(OAuthGrantRow.revoked_at.is_not(None))

    total = (
        await db.execute(select(func.count()).select_from(OAuthGrantRow).where(*where))
    ).scalar_one()
    rows = (
        (
            await db.execute(
                select(OAuthGrantRow)
                .where(*where)
                .order_by(
                    func.coalesce(OAuthGrantRow.last_used, OAuthGrantRow.granted_at).desc(),
                    OAuthGrantRow.id,
                )
                .offset((page - 1) * page_size)
                .limit(page_size)
            )
        )
        .scalars()
        .all()
    )
    return list(rows), int(total)
