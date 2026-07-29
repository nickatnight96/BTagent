"""Org-scoped TAXII 2.1 feed-configuration store (#105 / UC-2.1).

CRUD over ``taxii_feeds`` — one row per subscribed TAXII collection. Three
invariants live here rather than in the route, so *every* caller gets them:

* **References only, never material.** ``auth_secret_ref`` must be a single
  complete ``${secret:vault:...}`` / ``${secret:aws:...}`` / ``${env:VAR}``
  reference (:func:`btagent_shared.utils.secrets.is_secret_reference`). A raw
  token is rejected with :class:`InvalidFeedConfig`, so a credential cannot
  land in the database via this path at all. The reference is resolved lazily,
  at poll time, by :mod:`taxii_poll_service`.
* **No credentials in the URL either.** ``server_url`` is validated by the
  engine client's :func:`normalize_server_url`, which refuses
  ``https://user:pass@host/`` — otherwise the "references only" rule would have
  an obvious back door.
* **Org scoping.** Every read/write is filtered by ``org_id``; a feed id from
  another tenant simply doesn't resolve.

Per the codebase convention nothing here commits — the route (or the arq job)
owns the single commit.
"""

from __future__ import annotations

import logging
from typing import Any

from btagent_engine.integrations.taxii import (
    AUTH_NONE,
    VALID_AUTH_STYLES,
    TaxiiConfigError,
    normalize_server_url,
)
from btagent_shared.utils.ids import generate_id
from btagent_shared.utils.secrets import is_secret_reference
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_cti import TaxiiFeedRow

logger = logging.getLogger("btagent.services.taxii_feed")

#: Bounds on the poll cadence. Below the floor a feed would hammer the server
#: (and the sweep); above the ceiling the cursor goes stale for weeks.
MIN_POLL_INTERVAL_MINUTES = 5
MAX_POLL_INTERVAL_MINUTES = 7 * 24 * 60  # one week


class InvalidFeedConfig(ValueError):
    """Operator-supplied feed configuration is malformed (route → 422)."""


class DuplicateFeedName(ValueError):
    """A feed with this name already exists for the org (route → 409)."""


# --------------------------------------------------------------------------- #
# Validation
# --------------------------------------------------------------------------- #


def _validate_name(name: str) -> str:
    cleaned = (name or "").strip()
    if not cleaned:
        raise InvalidFeedConfig("name must be non-blank")
    if len(cleaned) > 200:
        raise InvalidFeedConfig("name must be at most 200 characters")
    return cleaned


def _validate_server_url(server_url: str) -> str:
    try:
        return normalize_server_url(server_url)
    except TaxiiConfigError as exc:
        raise InvalidFeedConfig(str(exc)) from exc


def _validate_collection_id(collection_id: str) -> str:
    cleaned = (collection_id or "").strip()
    if not cleaned:
        raise InvalidFeedConfig("collection_id must be non-blank")
    if len(cleaned) > 200:
        raise InvalidFeedConfig("collection_id must be at most 200 characters")
    return cleaned


def _validate_interval(minutes: int) -> int:
    try:
        value = int(minutes)
    except (TypeError, ValueError) as exc:
        raise InvalidFeedConfig("poll_interval_minutes must be an integer") from exc
    if not (MIN_POLL_INTERVAL_MINUTES <= value <= MAX_POLL_INTERVAL_MINUTES):
        raise InvalidFeedConfig(
            "poll_interval_minutes must be between "
            f"{MIN_POLL_INTERVAL_MINUTES} and {MAX_POLL_INTERVAL_MINUTES}"
        )
    return value


def _validate_auth(auth_style: str, auth_secret_ref: str) -> tuple[str, str]:
    """Validate the auth pair. Returns the normalized ``(style, secret_ref)``.

    The security-critical half: ``auth_secret_ref`` is accepted **only** as a
    single complete secret reference. Anything else — a bare token, a string
    that merely *contains* a reference — is refused, so raw credential material
    never reaches the table. ``auth_style="none"`` forces the ref empty.
    """
    style = (auth_style or AUTH_NONE).strip().lower()
    if style not in VALID_AUTH_STYLES:
        raise InvalidFeedConfig(
            f"auth_style must be one of {sorted(VALID_AUTH_STYLES)}, got {auth_style!r}"
        )

    ref = (auth_secret_ref or "").strip()
    if style == AUTH_NONE:
        if ref:
            raise InvalidFeedConfig("auth_secret_ref must be empty when auth_style is 'none'")
        return style, ""

    if not ref:
        raise InvalidFeedConfig(f"auth_style={style!r} requires an auth_secret_ref")
    if not is_secret_reference(ref):
        raise InvalidFeedConfig(
            "auth_secret_ref must be a single ${secret:vault:...} / ${secret:aws:...} / "
            "${env:VAR} reference — raw credential material is never stored; put the "
            "token in Vault/AWS/env and reference it here."
        )
    if len(ref) > 500:
        raise InvalidFeedConfig("auth_secret_ref must be at most 500 characters")
    return style, ref


# --------------------------------------------------------------------------- #
# CRUD
# --------------------------------------------------------------------------- #


async def create_feed(
    db: AsyncSession,
    *,
    org_id: str,
    name: str,
    server_url: str,
    collection_id: str,
    auth_style: str = AUTH_NONE,
    auth_secret_ref: str = "",
    poll_interval_minutes: int = 60,
    enabled: bool = True,
    actor_id: str = "",
) -> TaxiiFeedRow:
    """Create one feed subscription for ``org_id``. Not committed."""
    clean_name = _validate_name(name)
    clean_url = _validate_server_url(server_url)
    clean_collection = _validate_collection_id(collection_id)
    style, ref = _validate_auth(auth_style, auth_secret_ref)
    interval = _validate_interval(poll_interval_minutes)

    if await get_feed_by_name(db, org_id=org_id, name=clean_name) is not None:
        raise DuplicateFeedName(f"A TAXII feed named {clean_name!r} already exists")

    row = TaxiiFeedRow(
        id=generate_id("taxii"),
        org_id=org_id,
        name=clean_name,
        server_url=clean_url,
        collection_id=clean_collection,
        auth_style=style,
        auth_secret_ref=ref,
        poll_interval_minutes=interval,
        enabled=bool(enabled),
        created_by=actor_id,
        updated_by=actor_id,
    )
    db.add(row)
    await db.flush()
    # NB: the reference string is intentionally NOT logged — it names a Vault
    # path, which is one more thing an attacker with log access shouldn't get.
    logger.info("taxii feed created: %s (org=%s, auth=%s)", row.id, org_id, style)
    return row


async def get_feed(db: AsyncSession, *, org_id: str, feed_id: str) -> TaxiiFeedRow | None:
    """Org-scoped lookup by id — a foreign org's id simply doesn't resolve."""
    return (
        await db.execute(
            select(TaxiiFeedRow).where(
                TaxiiFeedRow.org_id == org_id,
                TaxiiFeedRow.id == feed_id,
            )
        )
    ).scalar_one_or_none()


async def get_feed_by_name(db: AsyncSession, *, org_id: str, name: str) -> TaxiiFeedRow | None:
    """Org-scoped lookup by the operator-facing name."""
    return (
        await db.execute(
            select(TaxiiFeedRow).where(
                TaxiiFeedRow.org_id == org_id,
                TaxiiFeedRow.name == name,
            )
        )
    ).scalar_one_or_none()


async def list_feeds(
    db: AsyncSession, *, org_id: str, enabled_only: bool = False
) -> list[TaxiiFeedRow]:
    """All of an org's feeds, name-ordered."""
    query = select(TaxiiFeedRow).where(TaxiiFeedRow.org_id == org_id)
    if enabled_only:
        query = query.where(TaxiiFeedRow.enabled.is_(True))
    rows = (await db.execute(query.order_by(TaxiiFeedRow.name))).scalars().all()
    return list(rows)


async def list_enabled_feeds_all_orgs(db: AsyncSession) -> list[TaxiiFeedRow]:
    """Every enabled feed across every tenant — the sweep's work list.

    Multi-tenant on purpose, mirroring ``weekly_pattern_scan`` /
    ``memory_consolidation_sweep``: a sweep hard-coded to ``DEFAULT_ORG_ID``
    would permanently exclude every other tenant's feeds.
    """
    rows = (
        (
            await db.execute(
                select(TaxiiFeedRow)
                .where(TaxiiFeedRow.enabled.is_(True))
                .order_by(TaxiiFeedRow.org_id, TaxiiFeedRow.name)
            )
        )
        .scalars()
        .all()
    )
    return list(rows)


async def update_feed(
    db: AsyncSession,
    *,
    org_id: str,
    feed_id: str,
    changes: dict[str, Any],
    actor_id: str = "",
) -> TaxiiFeedRow | None:
    """Partial update of a feed's configuration. Returns ``None`` if not found.

    ``changes`` carries only the supplied fields (``exclude_unset`` semantics
    at the route). Auth is validated as a *pair*: changing only the style still
    re-checks the stored reference, so flipping ``none`` → ``bearer`` without
    supplying a reference is rejected instead of producing an unusable feed.
    """
    row = await get_feed(db, org_id=org_id, feed_id=feed_id)
    if row is None:
        return None

    if "name" in changes:
        new_name = _validate_name(changes["name"])
        if new_name != row.name:
            existing = await get_feed_by_name(db, org_id=org_id, name=new_name)
            if existing is not None and existing.id != row.id:
                raise DuplicateFeedName(f"A TAXII feed named {new_name!r} already exists")
        row.name = new_name
    if "server_url" in changes:
        row.server_url = _validate_server_url(changes["server_url"])
    if "collection_id" in changes:
        row.collection_id = _validate_collection_id(changes["collection_id"])
    if "poll_interval_minutes" in changes:
        row.poll_interval_minutes = _validate_interval(changes["poll_interval_minutes"])
    if "enabled" in changes:
        row.enabled = bool(changes["enabled"])
    if "auth_style" in changes or "auth_secret_ref" in changes:
        style = changes.get("auth_style", row.auth_style)
        ref = changes.get("auth_secret_ref", row.auth_secret_ref)
        row.auth_style, row.auth_secret_ref = _validate_auth(style, ref)

    row.updated_by = actor_id
    await db.flush()
    return row


async def delete_feed(db: AsyncSession, *, org_id: str, feed_id: str) -> bool:
    """Delete one org-scoped feed. Returns True when a row existed."""
    row = await get_feed(db, org_id=org_id, feed_id=feed_id)
    if row is None:
        return False
    await db.delete(row)
    await db.flush()
    return True


__all__ = [
    "MAX_POLL_INTERVAL_MINUTES",
    "MIN_POLL_INTERVAL_MINUTES",
    "DuplicateFeedName",
    "InvalidFeedConfig",
    "create_feed",
    "delete_feed",
    "get_feed",
    "get_feed_by_name",
    "list_enabled_feeds_all_orgs",
    "list_feeds",
    "update_feed",
]
