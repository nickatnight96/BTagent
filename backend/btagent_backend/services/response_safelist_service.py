"""Org-scoped response-safelist service (EPIC-3 #106 — collateral-outage guard).

CRUD + policy assembly for the ``response_safelist`` table. The safelist is the
operator-managed extension of the universal never-block baseline
(:data:`btagent_shared.security.safelist.BASELINE_SAFELIST`). It is consulted at
two points that must agree:

* plan time — a safelisted IOC is proposed as ``skip_allowlisted`` (defense in
  depth; wired through :func:`load_policy_tuples`), and
* execute time — a safelisted target is *refused before any block dispatch*,
  with an audited denial (the authoritative guard;
  :func:`btagent_backend.services.containment_execute_service`).

Every read/query here is scoped to a single ``org_id`` so one tenant can neither
read nor be governed by another tenant's safelist.
"""

from __future__ import annotations

import ipaddress
import logging
import re

from btagent_shared.security.safelist import BASELINE_SAFELIST, SafelistPolicy
from btagent_shared.utils.ids import generate_id
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import ResponseSafelistRow

logger = logging.getLogger("btagent.services.response_safelist")

# Entry kinds an operator may add. IPs match exactly; domains match by suffix.
VALID_ENTRY_TYPES: frozenset[str] = frozenset({"ip", "domain"})

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)


class SafelistValidationError(ValueError):
    """Raised when an operator-supplied safelist entry is malformed."""


def normalize_entry(entry_type: str, value: str) -> tuple[str, str]:
    """Validate + canonicalize a (entry_type, value) pair.

    Returns the normalized ``(entry_type, value)``. IPs are validated (and their
    canonical form stored); domains are lower-cased and trailing-dot-stripped.
    Raises :class:`SafelistValidationError` on bad input so the API can 422.
    """
    etype = (entry_type or "").strip().lower()
    raw = (value or "").strip()
    if etype not in VALID_ENTRY_TYPES:
        raise SafelistValidationError(
            f"entry_type must be one of {sorted(VALID_ENTRY_TYPES)}, got {entry_type!r}"
        )
    if not raw:
        raise SafelistValidationError("value must be non-blank")
    if etype == "ip":
        try:
            canonical = str(ipaddress.ip_address(raw))
        except ValueError as exc:
            raise SafelistValidationError(f"{raw!r} is not a valid IP address") from exc
        return "ip", canonical
    # domain
    host = raw.lower().rstrip(".")
    if not _DOMAIN_RE.match(host):
        raise SafelistValidationError(f"{raw!r} is not a valid domain")
    return "domain", host


async def add_entry(
    db: AsyncSession,
    *,
    org_id: str,
    entry_type: str,
    value: str,
    reason: str = "",
    created_by: str | None = None,
) -> ResponseSafelistRow:
    """Insert (idempotently) an org-scoped safelist entry.

    If the normalized ``(org_id, entry_type, value)`` already exists the existing
    row is returned rather than raising, so re-adding is a no-op. Not committed —
    the caller (route dependency) commits.
    """
    etype, val = normalize_entry(entry_type, value)
    existing = await db.execute(
        select(ResponseSafelistRow).where(
            ResponseSafelistRow.org_id == org_id,
            ResponseSafelistRow.entry_type == etype,
            ResponseSafelistRow.value == val,
        )
    )
    row = existing.scalar_one_or_none()
    if row is not None:
        return row

    row = ResponseSafelistRow(
        id=generate_id("safe"),
        org_id=org_id,
        entry_type=etype,
        value=val,
        reason=(reason or "").strip(),
        created_by=created_by,
    )
    db.add(row)
    await db.flush()
    logger.info("response_safelist add org=%s type=%s value=%s", org_id, etype, val)
    return row


async def list_entries(db: AsyncSession, *, org_id: str) -> list[ResponseSafelistRow]:
    """List all safelist entries for one org (newest first)."""
    result = await db.execute(
        select(ResponseSafelistRow)
        .where(ResponseSafelistRow.org_id == org_id)
        .order_by(ResponseSafelistRow.created_at.desc())
    )
    return list(result.scalars().all())


async def load_policy(db: AsyncSession, *, org_id: str) -> SafelistPolicy:
    """Build the effective never-block policy for an org: baseline + org rows."""
    rows = await list_entries(db, org_id=org_id)
    ips = [r.value for r in rows if r.entry_type == "ip"]
    suffixes = [r.value for r in rows if r.entry_type == "domain"]
    return BASELINE_SAFELIST.merge(extra_ips=ips, extra_domain_suffixes=suffixes)


async def load_policy_tuples(db: AsyncSession, *, org_id: str) -> tuple[list[str], list[str]]:
    """Return this org's raw ``(safelist_ips, safelist_domain_suffixes)``.

    Used to thread the org safelist into the bulk-mitigation planning node
    (``BulkMitigationInput.safelist_ips`` / ``safelist_domain_suffixes``) so the
    plan already skips org-safelisted targets — the baseline lives in the engine.
    """
    rows = await list_entries(db, org_id=org_id)
    ips = [r.value for r in rows if r.entry_type == "ip"]
    suffixes = [r.value for r in rows if r.entry_type == "domain"]
    return ips, suffixes


__all__ = [
    "SafelistValidationError",
    "VALID_ENTRY_TYPES",
    "add_entry",
    "list_entries",
    "load_policy",
    "load_policy_tuples",
    "normalize_entry",
]
