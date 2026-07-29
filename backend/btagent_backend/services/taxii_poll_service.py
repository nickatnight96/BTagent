"""TAXII 2.1 feed polling + ingest (#105 / UC-2.1).

The decision logic behind the ``taxii_feed_poll_sweep`` arq job. For every
enabled feed that is *due*, this service:

1. resolves the feed's ``${secret:...}`` reference — lazily, at poll time, so
   credential material never lives in the database or in memory longer than the
   call (see :func:`_resolve_credential`);
2. polls the collection **since the feed's stored cursor** via the mock-first
   :class:`~btagent_engine.integrations.taxii.TaxiiClient`;
3. hands the polled STIX objects to the **existing** ingest path — the same
   :func:`btagent_backend.services.stix_service.stix_to_iocs` +
   :func:`btagent_backend.services.ioc_service.create_iocs_bulk` pair the
   ``POST /iocs/import`` route uses. There is deliberately no second ingest
   implementation, so TLP, pattern parsing and confidence mapping cannot drift
   between the push and pull halves of UC-2.1;
4. advances the cursor and stamps the poll telemetry.

TLP
---
Handled exactly as the STIX-bundle import handles it, because it *is* that
code: ``stix_to_iocs`` derives each indicator's ``tlp_level`` from its
``object_marking_refs`` (defaulting to green) and the IOC row carries it. This
service never overrides, widens, or defaults it away — a TLP:RED indicator
polled from a feed lands as TLP:RED and is therefore blocked from STIX export
by the existing ``assert_tlp_allows_egress`` gate exactly like an imported one.

Best-effort per feed
--------------------
:func:`poll_due_feeds` isolates each feed: one unreachable server, one bad
credential reference, one malformed collection does **not** abort the sweep or
the other tenants' feeds. The failure is recorded on the feed row
(``last_status='error'`` + a scrubbed ``last_error``) so it surfaces in the API
rather than only in the logs.

Nothing here commits — the arq job owns the single commit.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from btagent_engine.integrations.taxii import (
    AUTH_NONE,
    MOCK_CREDENTIAL,
    TaxiiClient,
    TaxiiError,
    mock_mode_enabled,
    scrub_secrets,
)
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from btagent_shared.utils.secrets import resolve_secret
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow
from btagent_backend.db.models_cti import TaxiiFeedRow
from btagent_backend.services import ioc_service, stix_service, taxii_feed_service

logger = logging.getLogger("btagent.services.taxii_poll")

#: Same DoS-mitigation ceiling the bulk/import IOC routes enforce
#: (``api/v1/iocs._MAX_BULK_IOCS``): one poll can never hand more than this
#: many objects to ``create_iocs_bulk``.
MAX_OBJECTS_PER_POLL = 500

#: The resolver emits this prefix in non-prod when a vault/aws reference has no
#: client wired in and the env fallback also missed. It is a placeholder, not a
#: credential — treating it as one would ship ``<unresolved:...>`` as a bearer
#: token to a third-party server.
_UNRESOLVED_PREFIX = "<unresolved:"

#: Source label stamped on every IOC ingested from a TAXII feed, so provenance
#: is visible in the notebook/table without joining back to the feed row.
_SOURCE_PREFIX = "taxii"

#: Sentinel distinguishing "caller supplied no credential" from the meaningful
#: ``credential=None`` (auth_style="none"). Lets the sweep resolve the material
#: once — it needs it for error scrubbing — without double-resolving.
_UNSET: Any = object()


# --------------------------------------------------------------------------- #
# Result objects
# --------------------------------------------------------------------------- #


@dataclass(slots=True)
class FeedPollOutcome:
    """What one feed's poll did (or why it didn't)."""

    feed_id: str
    org_id: str
    status: str  # "ok" | "error" | "skipped"
    objects_fetched: int = 0
    iocs_created: int = 0
    cursor_advanced: bool = False
    error: str = ""


@dataclass(slots=True)
class SweepResult:
    """Aggregate of one sweep across every tenant's enabled feeds."""

    feeds_considered: int = 0
    feeds_polled: int = 0
    feeds_skipped: int = 0
    feeds_failed: int = 0
    objects_fetched: int = 0
    iocs_created: int = 0
    outcomes: list[FeedPollOutcome] = field(default_factory=list)

    def as_counts(self) -> dict[str, int]:
        return {
            "feeds_considered": self.feeds_considered,
            "feeds_polled": self.feeds_polled,
            "feeds_skipped": self.feeds_skipped,
            "feeds_failed": self.feeds_failed,
            "objects_fetched": self.objects_fetched,
            "iocs_created": self.iocs_created,
        }


# --------------------------------------------------------------------------- #
# Scheduling
# --------------------------------------------------------------------------- #


def is_due(feed: TaxiiFeedRow, *, now: datetime | None = None) -> bool:
    """True when ``feed`` has waited out its own ``poll_interval_minutes``.

    The cron fires far more often than any single feed's cadence; this is the
    per-feed gate. A never-polled feed is always due.
    """
    if not feed.enabled:
        return False
    last = feed.last_polled_at
    if last is None:
        return True
    if last.tzinfo is None:  # SQLite round-trips naive datetimes
        last = last.replace(tzinfo=UTC)
    moment = now or datetime.now(UTC)
    return moment - last >= timedelta(minutes=max(1, feed.poll_interval_minutes))


# --------------------------------------------------------------------------- #
# Credentials
# --------------------------------------------------------------------------- #


def _resolve_credential(feed: TaxiiFeedRow) -> str | None:
    """Resolve the feed's secret *reference* into material, at call time.

    Never cached, never logged, never written back to the row. Mirrors the
    declarative runner's stance: in mock mode an unresolvable reference falls
    back to a placeholder (a fixture poll must never require a live secret);
    with mocks off it is a hard error rather than sending an empty or
    ``<unresolved:...>`` Authorization header to a third party.
    """
    if feed.auth_style == AUTH_NONE or not feed.auth_secret_ref:
        return None

    resolved = resolve_secret(feed.auth_secret_ref)
    usable = bool(resolved) and not resolved.startswith(_UNRESOLVED_PREFIX)
    if usable:
        return resolved
    if mock_mode_enabled():
        return MOCK_CREDENTIAL
    raise TaxiiError(
        f"feed {feed.name!r}: credential reference did not resolve; wire it into "
        "Vault/AWS/env or run with BTAGENT_MOCK_CONNECTORS=true"
    )


# --------------------------------------------------------------------------- #
# Intake case
# --------------------------------------------------------------------------- #


async def _ensure_intake_investigation(db: AsyncSession, feed: TaxiiFeedRow) -> InvestigationRow:
    """Return (creating on first use) the case polled indicators land in.

    ``iocs.investigation_id`` is NOT NULL — every IOC belongs to a case — so a
    feed needs a destination. Rather than make operators pick one at config
    time, the first successful poll provisions a per-feed intake case and pins
    its id on the feed row; later polls reuse it.

    Org-scoped explicitly (``org_id=feed.org_id``) rather than via
    ``investigation_service.create_investigation``, which defaults to
    ``DEFAULT_ORG_ID`` and would land a tenant's feed data in the wrong org.

    Left unassigned, so it is visible to the org-wide roles
    (senior_analyst / incident_commander / admin) and not to an arbitrary
    analyst — the fail-closed side of ``assert_can_access_investigation``.
    The container is marked TLP:AMBER; each ingested IOC still carries the TLP
    derived from its own STIX markings.
    """
    if feed.intake_investigation_id:
        existing = (
            await db.execute(
                select(InvestigationRow).where(
                    InvestigationRow.id == feed.intake_investigation_id,
                    InvestigationRow.org_id == feed.org_id,
                )
            )
        ).scalar_one_or_none()
        if existing is not None:
            return existing

    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=feed.org_id,
        title=f"CTI feed intake: {feed.name}",
        description=(
            "Auto-provisioned intake case for indicators polled from the TAXII 2.1 "
            f"collection {feed.collection_id} on {feed.server_url}."
        ),
        status=InvestigationStatus.PENDING.value,
        severity=Severity.MEDIUM.value,
        tlp_level="amber",
        config={"source": "taxii_feed", "taxii_feed_id": feed.id},
    )
    db.add(inv)
    await db.flush()
    feed.intake_investigation_id = inv.id
    logger.info("taxii feed %s: provisioned intake case %s", feed.id, inv.id)
    return inv


# --------------------------------------------------------------------------- #
# Poll one feed
# --------------------------------------------------------------------------- #


async def poll_feed(
    db: AsyncSession,
    feed: TaxiiFeedRow,
    *,
    now: datetime | None = None,
    max_objects: int = MAX_OBJECTS_PER_POLL,
    client: Any = None,
    credential: Any = _UNSET,
) -> FeedPollOutcome:
    """Poll one feed since its cursor and ingest what came back.

    Raises on failure — :func:`poll_due_feeds` owns the per-feed isolation and
    the error bookkeeping. ``client`` is an injection seam for tests; when
    omitted a :class:`TaxiiClient` is built from the feed's own config (which,
    under ``BTAGENT_MOCK_CONNECTORS``, serves fixtures and makes no egress).
    ``credential`` lets the sweep pass in already-resolved material so it can
    scrub that exact value out of any error it persists; left unset, it is
    resolved here.
    """
    moment = now or datetime.now(UTC)
    if credential is _UNSET:
        credential = _resolve_credential(feed)

    taxii = client or TaxiiClient(
        server_url=feed.server_url,
        credential=credential,
        auth_style=feed.auth_style,
    )

    capped = max(1, min(int(max_objects), MAX_OBJECTS_PER_POLL))
    result = await taxii.poll(
        feed.collection_id,
        added_after=feed.last_cursor or None,
        max_objects=capped,
    )

    iocs_created = 0
    if result.objects:
        investigation = await _ensure_intake_investigation(db, feed)
        # The EXISTING ingest path — a bundle envelope around the polled
        # objects, converted by stix_service (which is what derives TLP from
        # each object's markings), then inserted via create_iocs_bulk.
        bundle: dict[str, Any] = {"type": "bundle", "objects": result.objects}
        ioc_dicts = stix_service.stix_to_iocs(
            bundle,
            investigation_id=investigation.id,
            source=f"{_SOURCE_PREFIX}:{feed.name}"[:200],
        )
        if ioc_dicts:
            rows = await ioc_service.create_iocs_bulk(
                db,
                investigation_id=investigation.id,
                iocs=ioc_dicts,
                org_id=feed.org_id,
            )
            iocs_created = len(rows)

    cursor_advanced = False
    if result.latest_added and result.latest_added != feed.last_cursor:
        feed.last_cursor = result.latest_added[:128]
        cursor_advanced = True

    feed.last_polled_at = moment
    feed.last_status = "ok"
    feed.last_error = ""
    feed.objects_ingested = int(feed.objects_ingested or 0) + iocs_created
    await db.flush()

    logger.info(
        "taxii poll ok: feed=%s org=%s objects=%d iocs=%d cursor_advanced=%s",
        feed.id,
        feed.org_id,
        result.object_count,
        iocs_created,
        cursor_advanced,
    )
    return FeedPollOutcome(
        feed_id=feed.id,
        org_id=feed.org_id,
        status="ok",
        objects_fetched=result.object_count,
        iocs_created=iocs_created,
        cursor_advanced=cursor_advanced,
    )


# --------------------------------------------------------------------------- #
# Sweep
# --------------------------------------------------------------------------- #


async def poll_due_feeds(
    db: AsyncSession,
    *,
    now: datetime | None = None,
    max_objects: int = MAX_OBJECTS_PER_POLL,
) -> SweepResult:
    """Poll every enabled, due feed across every tenant. Best-effort per feed.

    A feed that raises is recorded (``last_status='error'``, scrubbed
    ``last_error``) and the sweep moves on — one misconfigured or unreachable
    feed cannot sink the others, nor another tenant's.
    """
    moment = now or datetime.now(UTC)
    summary = SweepResult()

    for feed in await taxii_feed_service.list_enabled_feeds_all_orgs(db):
        summary.feeds_considered += 1
        if not is_due(feed, now=moment):
            summary.feeds_skipped += 1
            summary.outcomes.append(
                FeedPollOutcome(feed_id=feed.id, org_id=feed.org_id, status="skipped")
            )
            continue

        # Resolved here rather than inside ``poll_feed`` so the except branch
        # below can scrub this exact value out of the error it *persists* — a
        # third-party exception makes no redaction promise, and ``last_error``
        # is readable through the API.
        credential: Any = _UNSET
        try:
            credential = _resolve_credential(feed)
            outcome = await poll_feed(
                db, feed, now=moment, max_objects=max_objects, credential=credential
            )
        except Exception as exc:
            # Scrub twice over: the client already redacts its own messages,
            # but an exception raised elsewhere (or by a third-party library)
            # has made no such promise and this string is persisted.
            known = credential if isinstance(credential, str) else None
            detail = scrub_secrets(f"{type(exc).__name__}: {exc}", known)[:1000]
            # Stamp the attempt even though it failed: leaving ``last_polled_at``
            # unset would make the feed permanently "due" and retry on every
            # sweep tick, hammering a server that is already refusing us. The
            # feed backs off to its own configured interval instead.
            feed.last_polled_at = moment
            feed.last_status = "error"
            feed.last_error = detail
            summary.feeds_failed += 1
            summary.outcomes.append(
                FeedPollOutcome(feed_id=feed.id, org_id=feed.org_id, status="error", error=detail)
            )
            logger.warning("taxii poll failed: feed=%s org=%s — %s", feed.id, feed.org_id, detail)
            continue

        summary.feeds_polled += 1
        summary.objects_fetched += outcome.objects_fetched
        summary.iocs_created += outcome.iocs_created
        summary.outcomes.append(outcome)

    return summary


__all__ = [
    "MAX_OBJECTS_PER_POLL",
    "FeedPollOutcome",
    "SweepResult",
    "is_due",
    "poll_due_feeds",
    "poll_feed",
]
