"""Pure cross-investigation pattern-hunting logic (#120, Phase A).

Dependency-free (no DB, no embedding service, no network, no LLM) so the
extraction → clustering → proposal pipeline is trivially unit-testable and
reusable as an engine node body. It operates on plain dicts/dataclasses
(the ``ClosedInvestigationRecord`` shape below) and on the
:mod:`btagent_shared.types.pattern_hunt` models; the side-effectful
corpus-walking + persistence live in
``backend/btagent_backend/services/pattern_hunt_service.py``.

The pipeline
------------
1. :class:`WeakSignalExtractor` reads closed-investigation records and emits
   candidate :class:`WeakSignal` s — one per distinct
   ``(kind, normalised-value)`` — accumulating the set of distinct source
   investigations and the first/last-seen span.
2. :class:`WeakSignalClusterer` groups similar signals (by exact
   ``(kind, value)`` in Phase A) and ranks each cluster by

       score = frequency_factor × recency_factor × diversity_factor

   where *diversity* (how many **distinct, unrelated** investigations a
   signal spans) is the dominant term. This is the load-bearing acceptance
   criterion: a signal seen once-each in 5 unrelated investigations must
   outrank a signal seen 5 times inside a single investigation.
3. :func:`cluster_to_proposal` turns a ranked cluster into a non-empty
   :class:`~btagent_shared.types.hunt.HuntInput` plus a human-readable
   rationale.

Why diversity dominates (the explicit ranking contract)
-------------------------------------------------------
*Frequency* (total occurrences) is cheap to fake: a single noisy
investigation can rack up many hits on one observable. *Cross-investigation
diversity* is expensive to fake — it requires the same faint observable to
independently recur across cases that share no other linkage, which is
exactly the signature of a slow cross-case campaign. So diversity is scored
**super-linearly** (squared) while frequency is scored with a saturating
``log1p`` curve that deliberately caps how much a single hammering
investigation can contribute. See :func:`score_cluster` for the closed form
and :func:`btagent_shared.hunt.pattern.diversity_dominates_frequency` for
the pinned guarantee.
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from btagent_shared.types.enums import IOCType
from btagent_shared.types.hunt import HuntInput, HuntScope
from btagent_shared.types.investigation import IOC
from btagent_shared.types.pattern_hunt import (
    WeakSignal,
    WeakSignalCluster,
    WeakSignalKind,
)

# --------------------------------------------------------------------------- #
# Input shape (dep-free — callers pass these, not ORM rows)
# --------------------------------------------------------------------------- #


@dataclass
class ObservedIOC:
    """One IOC observed in a closed investigation (dep-free input)."""

    type: str
    value: str
    first_seen: datetime | None = None
    last_seen: datetime | None = None


@dataclass
class ClosedInvestigationRecord:
    """A flattened, dependency-free view of one closed investigation.

    The service builds these from ``InvestigationRow`` + its IOCs (and any
    extracted command-line / asset / ASN material) so the pure logic never
    has to touch the DB or know about SQLAlchemy. ``closed_at`` drives the
    recency term; it falls back to ``updated_at`` then ``created_at`` then
    "now" upstream so it is always populated here.
    """

    investigation_id: str
    closed_at: datetime
    iocs: list[ObservedIOC] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)
    cmdline_fragments: list[str] = field(default_factory=list)
    assets: list[str] = field(default_factory=list)
    asns: list[str] = field(default_factory=list)
    # ``adversaries`` carries any attributed threat-actor labels so a proposal
    # can seed HuntInput.adversaries when present. Empty is the common case.
    adversaries: list[str] = field(default_factory=list)


# --------------------------------------------------------------------------- #
# Normalisation helpers
# --------------------------------------------------------------------------- #

# IOC types that map to the TLD-extraction path (domains / urls / emails).
_DOMAINISH_IOC_TYPES = frozenset({"domain", "url", "email"})

# A conservative public-suffix-ish split: take the last two labels. We do NOT
# ship a full PSL here (that'd be a heavy dep) — two-label TLD+1 is the right
# granularity for "same registrable-ish suffix recurring across cases" and is
# deterministic. Multi-part suffixes (co.uk) collapse to "co.uk" which is
# still a useful clustering key.
_DOMAIN_LABEL_RE = re.compile(r"[a-z0-9.-]+", re.IGNORECASE)

_MIN_CMDLINE_FRAGMENT_LEN = 4
_MAX_VALUE_LEN = 2048


def normalize_value(kind: WeakSignalKind, value: str) -> str:
    """Canonicalise a raw observable to its clustering key.

    Lowercased + stripped throughout; ``ioc`` / ``asset`` keep their value,
    ``technique`` keeps the ATT&CK id as-is (already canonical), ``asn``
    strips a leading ``AS``. Returns ``""`` for values that normalise to
    nothing (the caller drops empties).
    """
    v = value.strip().lower()
    if not v:
        return ""
    if kind is WeakSignalKind.ASN:
        v = v.removeprefix("as").strip()
    return v[:_MAX_VALUE_LEN]


def extract_tld(domainish: str) -> str:
    """Best-effort registrable suffix (TLD+1) of a domain / url / email.

    Deterministic, PSL-free: pulls the host, drops a leading ``www.``, and
    keeps the last two dotted labels. Returns ``""`` when no host is found.
    """
    s = domainish.strip().lower()
    if not s:
        return ""
    # email -> take the domain part
    if "@" in s:
        s = s.rsplit("@", 1)[-1]
    # url -> strip scheme + path + port
    s = re.sub(r"^[a-z][a-z0-9+.-]*://", "", s)
    s = s.split("/", 1)[0]
    s = s.split("?", 1)[0]
    s = s.split(":", 1)[0]
    s = s.removeprefix("www.")
    m = _DOMAIN_LABEL_RE.match(s)
    if not m:
        return ""
    host = m.group(0).strip(".")
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        # bare host / single label — not a useful TLD key
        return ""
    return ".".join(labels[-2:])


# --------------------------------------------------------------------------- #
# Extractor
# --------------------------------------------------------------------------- #


@dataclass
class _Accum:
    """Mutable per-signal accumulator used while sweeping the corpus."""

    kind: WeakSignalKind
    value: str
    first_seen: datetime
    last_seen: datetime
    investigation_refs: set[str] = field(default_factory=set)


class WeakSignalExtractor:
    """Extract candidate weak signals from closed-investigation records.

    Produces one :class:`WeakSignal` per distinct ``(kind, normalised-value)``
    pair, accumulating: the set of distinct source investigations (which fixes
    ``distinct_investigation_count``), and the overall first/last-seen span.
    """

    def __init__(self, *, min_cmdline_fragment_len: int = _MIN_CMDLINE_FRAGMENT_LEN) -> None:
        self._min_cmdline_len = min_cmdline_fragment_len

    def extract(self, records: Iterable[ClosedInvestigationRecord]) -> list[WeakSignal]:
        """Sweep ``records`` and return the de-duplicated weak signals.

        Signals are returned sorted by ``(kind, value)`` for determinism.
        """
        acc: dict[tuple[WeakSignalKind, str], _Accum] = {}

        for rec in records:
            inv_ts = rec.closed_at
            self._ingest_iocs(acc, rec, inv_ts)
            self._ingest_simple(
                acc, WeakSignalKind.TECHNIQUE, rec.techniques, rec.investigation_id, inv_ts
            )
            self._ingest_simple(acc, WeakSignalKind.ASSET, rec.assets, rec.investigation_id, inv_ts)
            self._ingest_simple(acc, WeakSignalKind.ASN, rec.asns, rec.investigation_id, inv_ts)
            self._ingest_cmdline(acc, rec, inv_ts)

        signals: list[WeakSignal] = []
        for (kind, value), a in acc.items():
            signals.append(
                WeakSignal(
                    id=_signal_id(kind, value),
                    kind=kind,
                    value=value,
                    first_seen=a.first_seen,
                    last_seen=a.last_seen,
                    investigation_refs=sorted(a.investigation_refs),
                    distinct_investigation_count=len(a.investigation_refs),
                )
            )
        signals.sort(key=lambda s: (s.kind.value, s.value))
        return signals

    # -- per-kind ingestion --------------------------------------------------

    def _bump(
        self,
        acc: dict[tuple[WeakSignalKind, str], _Accum],
        kind: WeakSignalKind,
        value: str,
        inv_id: str,
        ts: datetime,
        *,
        first_seen: datetime | None = None,
        last_seen: datetime | None = None,
    ) -> None:
        norm = normalize_value(kind, value)
        if not norm:
            return
        key = (kind, norm)
        fs = first_seen or ts
        ls = last_seen or ts
        a = acc.get(key)
        if a is None:
            acc[key] = _Accum(
                kind=kind,
                value=norm,
                first_seen=fs,
                last_seen=ls,
                investigation_refs={inv_id},
            )
            return
        a.investigation_refs.add(inv_id)
        if fs < a.first_seen:
            a.first_seen = fs
        if ls > a.last_seen:
            a.last_seen = ls

    def _ingest_iocs(
        self,
        acc: dict[tuple[WeakSignalKind, str], _Accum],
        rec: ClosedInvestigationRecord,
        inv_ts: datetime,
    ) -> None:
        for ioc in rec.iocs:
            fs = ioc.first_seen or inv_ts
            ls = ioc.last_seen or inv_ts
            # The full IOC is always a signal.
            self._bump(
                acc,
                WeakSignalKind.IOC,
                ioc.value,
                rec.investigation_id,
                inv_ts,
                first_seen=fs,
                last_seen=ls,
            )
            # Domain-ish IOCs additionally contribute their TLD+1 key — the
            # coarser signal a campaign's rotating infra collapses onto.
            if ioc.type.strip().lower() in _DOMAINISH_IOC_TYPES:
                tld = extract_tld(ioc.value)
                if tld:
                    self._bump(
                        acc,
                        WeakSignalKind.TLD,
                        tld,
                        rec.investigation_id,
                        inv_ts,
                        first_seen=fs,
                        last_seen=ls,
                    )

    def _ingest_simple(
        self,
        acc: dict[tuple[WeakSignalKind, str], _Accum],
        kind: WeakSignalKind,
        values: Sequence[str],
        inv_id: str,
        inv_ts: datetime,
    ) -> None:
        for v in values:
            self._bump(acc, kind, v, inv_id, inv_ts)

    def _ingest_cmdline(
        self,
        acc: dict[tuple[WeakSignalKind, str], _Accum],
        rec: ClosedInvestigationRecord,
        inv_ts: datetime,
    ) -> None:
        for frag in rec.cmdline_fragments:
            norm = frag.strip().lower()
            if len(norm) < self._min_cmdline_len:
                continue
            self._bump(acc, WeakSignalKind.CMDLINE_FRAGMENT, frag, rec.investigation_id, inv_ts)


# --------------------------------------------------------------------------- #
# Clusterer + ranking
# --------------------------------------------------------------------------- #

# Ranking tunables. Chosen so cross-investigation diversity dominates raw
# occurrence frequency (see module docstring + score_cluster).
_RECENCY_HALF_LIFE_DAYS = 90.0
# Floor so an ancient-but-broadly-spread pattern still scores non-trivially.
_RECENCY_FLOOR = 0.05


def frequency_factor(total_occurrences: int) -> float:
    """Saturating contribution of raw occurrence count.

    ``log1p`` so a single investigation that hammers one observable can't
    out-shout genuine cross-case spread — the curve flattens fast. A signal
    seen 5 times scores ``ln(6) ≈ 1.79``; seen 50 times only ``ln(51) ≈
    3.93`` (≈2.2×, not 10×).
    """
    return math.log1p(max(0, total_occurrences))


def diversity_factor(distinct_investigation_count: int) -> float:
    """Super-linear contribution of cross-investigation spread.

    Squared so spreading across N unrelated investigations is worth far more
    than N occurrences in one. This is the term the acceptance test pins:
    5 distinct investigations → ``5² = 25``; 1 investigation → ``1² = 1``.
    """
    return float(max(0, distinct_investigation_count)) ** 2


def recency_factor(
    last_seen: datetime,
    *,
    now: datetime,
    half_life_days: float = _RECENCY_HALF_LIFE_DAYS,
) -> float:
    """Exponential decay on age, floored so old-but-broad patterns survive.

    Fresh (``last_seen == now``) → 1.0; one half-life old → 0.5; decays toward
    ``_RECENCY_FLOOR`` thereafter. A naive ``last_seen`` is compared as-is
    against ``now`` (callers pass matching awareness).
    """
    age = now - last_seen
    if age < timedelta(0):
        age = timedelta(0)
    age_days = age.total_seconds() / 86400.0
    decay: float = 0.5 ** (age_days / half_life_days)
    return max(_RECENCY_FLOOR, decay)


def score_cluster(cluster_members: Sequence[WeakSignal], *, now: datetime) -> float:
    """Score a cluster as ``frequency × recency × diversity``.

    * frequency — saturating ``log1p`` of total occurrences across members
      (occurrences ≈ each member's investigation_ref count summed).
    * recency — decay on the cluster's most-recent ``last_seen``.
    * diversity — squared count of **distinct** investigations across all
      members (the dominant, hard-to-fake term).

    Returns ``0.0`` for an empty cluster.
    """
    if not cluster_members:
        return 0.0

    distinct_invs: set[str] = set()
    total_occurrences = 0
    latest = cluster_members[0].last_seen
    for s in cluster_members:
        distinct_invs.update(s.investigation_refs)
        # Each distinct source investigation counts as one occurrence; a
        # member with more refs than its pinned count (shouldn't happen) is
        # bounded by the ref list itself.
        total_occurrences += max(s.distinct_investigation_count, len(s.investigation_refs))
        if s.last_seen > latest:
            latest = s.last_seen

    freq = frequency_factor(total_occurrences)
    rec = recency_factor(latest, now=now)
    div = diversity_factor(len(distinct_invs))
    return freq * rec * div


def diversity_dominates_frequency(
    *,
    spread_distinct_investigations: int,
    concentrated_occurrences: int,
    now: datetime,
) -> bool:
    """Pinned guarantee used by tests + callers reasoning about ranking.

    Returns True iff a signal seen once-each across
    ``spread_distinct_investigations`` *unrelated* investigations outranks a
    signal seen ``concentrated_occurrences`` times inside a *single*
    investigation — both evaluated fresh (same ``last_seen == now``) so only
    frequency vs. diversity decides it.
    """
    spread = WeakSignal(
        id="ws_spread",
        kind=WeakSignalKind.IOC,
        value="spread",
        first_seen=now,
        last_seen=now,
        investigation_refs=[f"inv_{i}" for i in range(spread_distinct_investigations)],
        distinct_investigation_count=spread_distinct_investigations,
    )
    concentrated = WeakSignal(
        id="ws_conc",
        kind=WeakSignalKind.IOC,
        value="conc",
        first_seen=now,
        last_seen=now,
        investigation_refs=["inv_single"],
        # one investigation, but many occurrences inside it
        distinct_investigation_count=concentrated_occurrences,
    )
    return score_cluster([spread], now=now) > score_cluster([concentrated], now=now)


class WeakSignalClusterer:
    """Group similar weak signals and rank the resulting clusters.

    Phase A clusters by exact ``(kind, value)`` — each distinct signal is its
    own cluster — which is the right granularity for the corpus walk (the
    extractor has already collapsed duplicates across investigations). The
    grouping is a seam: fuzzy / embedding-based merging plugs in here in a
    later phase without changing the ranking contract.
    """

    def cluster(
        self,
        signals: Sequence[WeakSignal],
        *,
        now: datetime,
        top_n: int | None = None,
        min_distinct_investigations: int = 2,
    ) -> list[WeakSignalCluster]:
        """Build ranked clusters from ``signals``.

        Only signals spanning at least ``min_distinct_investigations`` are
        considered — a cross-investigation pattern by definition needs to
        touch more than one case (default 2). Clusters are returned sorted by
        descending score (ties broken deterministically by signature), capped
        to ``top_n`` when given.
        """
        clusters: list[WeakSignalCluster] = []
        for sig in signals:
            if sig.distinct_investigation_count < min_distinct_investigations:
                continue
            score = score_cluster([sig], now=now)
            clusters.append(
                WeakSignalCluster(
                    id=_cluster_id(sig.kind, sig.value),
                    members=[sig],
                    score=round(score, 6),
                    rationale=_cluster_rationale(sig, now=now),
                )
            )

        clusters.sort(key=lambda c: (-c.score, c.id))
        if top_n is not None:
            clusters = clusters[:top_n]
        return clusters


# --------------------------------------------------------------------------- #
# Cluster -> HuntInput proposal
# --------------------------------------------------------------------------- #


def cluster_to_hunt_input(
    cluster: WeakSignalCluster,
    *,
    initiated_by: str,
    adversaries: Sequence[str] = (),
) -> HuntInput:
    """Transform a cluster into a non-empty :class:`HuntInput`.

    Maps each member signal to the right HuntInput field:

    * ``technique`` → ``ttps``
    * ``ioc`` → ``iocs`` (as a synthetic :class:`IOC`)
    * ``tld`` → an ``iocs`` ``domain`` entry (the registrable suffix)
    * everything else (cmdline / asset / asn) → an ``iocs`` ``other`` entry so
      the input is never empty and the observable is carried forward.

    Always yields a HuntInput valid against the "at least one of (adversaries,
    ttps, iocs) non-empty" contract — a cluster always has ≥1 member, so at
    least one of the lists is populated.

    Raises
    ------
    ValueError
        If the cluster has no members (can't form a non-empty hunt).
    """
    if not cluster.members:
        raise ValueError("cannot build a HuntInput from an empty cluster")

    ttps: list[str] = []
    iocs: list[IOC] = []
    seen_ttps: set[str] = set()

    for sig in cluster.members:
        if sig.kind is WeakSignalKind.TECHNIQUE:
            tid = sig.value.upper()
            if tid not in seen_ttps:
                seen_ttps.add(tid)
                ttps.append(tid)
        else:
            iocs.append(_signal_to_ioc(sig))

    return HuntInput(
        adversaries=list(dict.fromkeys(adversaries)),
        ttps=ttps,
        iocs=iocs,
        scope=HuntScope(),
        initiated_by=initiated_by,
    )


def _signal_to_ioc(sig: WeakSignal) -> IOC:
    """Map a non-technique signal to a synthetic :class:`IOC`."""
    ioc_type = {
        WeakSignalKind.IOC: IOCType.OTHER,
        WeakSignalKind.TLD: IOCType.DOMAIN,
        WeakSignalKind.CMDLINE_FRAGMENT: IOCType.OTHER,
        WeakSignalKind.ASSET: IOCType.OTHER,
        WeakSignalKind.ASN: IOCType.OTHER,
    }.get(sig.kind, IOCType.OTHER)
    return IOC(
        id=_ioc_id(sig),
        investigation_id="",
        type=ioc_type,
        value=sig.value[:1000],
        context=(
            f"cross-investigation weak signal ({sig.kind.value}) "
            f"seen in {sig.distinct_investigation_count} investigations"
        ),
        source="cross_investigation_pattern_hunter",
    )


def cluster_to_proposal_rationale(cluster: WeakSignalCluster) -> str:
    """Human-readable rationale for a proposal built from ``cluster``."""
    if not cluster.members:
        return "Empty cluster."
    kinds = sorted({m.kind.value for m in cluster.members})
    distinct = len({ref for m in cluster.members for ref in m.investigation_refs})
    values = ", ".join(sorted({m.value for m in cluster.members})[:5])
    return (
        f"Weak signal(s) of kind {kinds} recurring across {distinct} distinct "
        f"closed investigations (score {cluster.score:.2f}). Observables: {values}. "
        f"This cross-case recurrence is the signature of a slow campaign and "
        f"warrants a proactive hunt."
    )


# --------------------------------------------------------------------------- #
# Deterministic id + rationale helpers
# --------------------------------------------------------------------------- #


def _slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")[:48] or "x"


def _signal_id(kind: WeakSignalKind, value: str) -> str:
    return f"ws_{kind.value}_{_slug(value)}"


def _cluster_id(kind: WeakSignalKind, value: str) -> str:
    return f"wsc_{kind.value}_{_slug(value)}"


def _ioc_id(sig: WeakSignal) -> str:
    return f"ioc_{_slug(sig.value)}"


def _cluster_rationale(sig: WeakSignal, *, now: datetime) -> str:
    freq = frequency_factor(max(sig.distinct_investigation_count, len(sig.investigation_refs)))
    rec = recency_factor(sig.last_seen, now=now)
    div = diversity_factor(sig.distinct_investigation_count)
    return (
        f"{sig.kind.value} '{sig.value}' seen across "
        f"{sig.distinct_investigation_count} distinct investigations "
        f"(frequency={freq:.2f}, recency={rec:.2f}, diversity={div:.2f}); "
        f"diversity dominates so broad cross-case spread outranks "
        f"single-case repetition."
    )
