"""Hunt pack executor: transpiled Sigma queries -> engine integration nodes (#112).

``run_pack(pack, backends, ctx)`` transpiles every enabled rule for every
requested backend and executes the resulting query through the *existing*
engine integration nodes (Splunk / Sentinel / Elastic / CrowdStrike — all
honouring ``BTAGENT_MOCK_CONNECTORS``), returning raw hits as in-memory
:class:`SigmaHit` objects. Failures are isolated per rule per backend: a
broken rule (or an unreachable backend) yields an ``error`` entry in the
result and the rest of the pack still runs.

This module is deliberately persistence-free — no DB, no findings tables.

TODO(#112 integration seam): the integration PR converts each ``SigmaHit``
into a ``HuntFinding`` via ``hunt_triage_service.ingest_findings`` (the #119
store). ``SigmaHit`` carries everything that conversion needs: ``source``
(``"sigma_pack"``), ``source_run_id``, ``mitre_techniques``, ``entities``,
``observable``, and ``severity``.

Backend execution notes:

* Splunk / Sentinel / Elastic run the transpiled query verbatim through
  their search nodes.
* The engine's CrowdStrike surface has no raw event-search node yet (only
  ``list_detections``); the transpiled LogScale query is recorded on the
  result for audit while execution degrades to listing detections at or
  above the rule's severity. The real event-search call lands with the
  Phase 4 live-connector work.
"""

from __future__ import annotations

import logging
from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any

from btagent_shared.types.enums import Severity
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.hunting.pack import HuntPack, HuntPackRule
from btagent_engine.hunting.transpile import (
    SUPPORTED_BACKENDS,
    SigmaBackendName,
    SigmaTranspileError,
    transpile,
)
from btagent_engine.integrations.crowdstrike import (
    CrowdStrikeListDetectionsInput,
    CrowdStrikeListDetectionsNode,
)
from btagent_engine.integrations.elastic import ElasticSearchInput, ElasticSearchNode
from btagent_engine.integrations.sentinel import SentinelKQLQueryInput, SentinelKQLQueryNode
from btagent_engine.integrations.splunk import SplunkSearchInput, SplunkSearchNode
from btagent_engine.node import NodeContext

logger = logging.getLogger("btagent.engine.hunting.runner")


# ---------------------------------------------------------------------------
# Hit / result models
# ---------------------------------------------------------------------------


class SigmaHitEntity(BaseModel):
    """A subject of a hit — host, user, etc. Mirrors the #119 entity shape."""

    model_config = ConfigDict(extra="forbid")

    kind: str = Field(..., min_length=1, max_length=64)
    value: str = Field(..., min_length=1, max_length=512)


class SigmaHit(BaseModel):
    """One raw backend match for one Sigma rule.

    In-memory only. The #112 integration PR maps this onto a ``HuntFinding``
    via ``hunt_triage_service.ingest_findings``; the field set here is the
    superset that conversion needs.
    """

    model_config = ConfigDict(extra="forbid")

    source: str = Field(default="sigma_pack", description="HuntFinding source discriminator.")
    source_run_id: str = Field(..., description="The PackRunResult.run_id this hit came from.")
    pack_id: str
    rule_id: str
    rule_title: str
    backend: SigmaBackendName
    severity: Severity = Field(..., description="Propagated from the Sigma rule's level.")
    mitre_techniques: list[str] = Field(default_factory=list)
    entities: list[SigmaHitEntity] = Field(default_factory=list)
    observable: str | None = Field(
        default=None, description="Primary IOC-shaped value pulled from the raw event, if any."
    )
    observable_type: str | None = Field(
        default=None, description="Type of ``observable`` (ip / hash / domain)."
    )
    summary: str = ""
    raw: dict[str, Any] = Field(
        default_factory=dict, description="The raw backend event/row/detection, verbatim."
    )


class BackendRunResult(BaseModel):
    """Outcome of one rule on one backend: the query used + hits or an error."""

    model_config = ConfigDict(extra="forbid")

    backend: SigmaBackendName
    query: str | None = Field(
        default=None, description="Transpiled query; None when transpile itself failed."
    )
    hit_count: int = 0
    hits: list[SigmaHit] = Field(default_factory=list)
    error: str | None = Field(
        default=None, description="Transpile or execution failure, when one occurred."
    )


class RuleRunResult(BaseModel):
    """Per-rule outcome across all requested backends."""

    model_config = ConfigDict(extra="forbid")

    rule_id: str
    rule_title: str
    backend_results: list[BackendRunResult] = Field(default_factory=list)

    @property
    def hit_count(self) -> int:
        return sum(b.hit_count for b in self.backend_results)

    @property
    def errors(self) -> dict[str, str]:
        return {b.backend: b.error for b in self.backend_results if b.error}


class PackRunResult(BaseModel):
    """One execution of a pack across the requested backends."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    pack_id: str
    pack_name: str
    pack_version: str
    backends: list[SigmaBackendName] = Field(default_factory=list)
    started_at: datetime
    completed_at: datetime | None = None
    rule_results: list[RuleRunResult] = Field(default_factory=list)
    skipped_rule_ids: list[str] = Field(
        default_factory=list, description="Rules excluded because they are disabled in the pack."
    )

    @property
    def all_hits(self) -> list[SigmaHit]:
        return [h for r in self.rule_results for b in r.backend_results for h in b.hits]

    @property
    def error_count(self) -> int:
        return sum(len(r.errors) for r in self.rule_results)


# ---------------------------------------------------------------------------
# Entity / observable extraction from raw backend events
# ---------------------------------------------------------------------------

# Candidate flattened (lowercased, dot-joined) keys per entity kind, covering
# the field dialects of all four backends' event shapes.
_HOST_KEYS = ("host", "hostname", "host.name", "computer", "computername")
_USER_KEYS = ("user", "user.name", "account", "username", "userprincipalname", "user.id")
# Ordered by "most likely the interesting observable first".
_IP_KEYS = (
    "src_ip",
    "source.ip",
    "ipaddress",
    "host.ip",
    "dest_ip",
    "destination.ip",
    "remote_ip",
)
_HASH_KEYS = ("sha256", "hash.sha256", "process.hash.sha256", "md5", "hash.md5")
_DOMAIN_KEYS = ("domain", "dns.question.name", "query", "dest_domain")
_SUMMARY_KEYS = ("summary", "message", "commandline", "command_line", "process.command_line")


def _flatten(raw: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    """Flatten nested dicts to lowercase dot-joined keys (lists left as-is)."""
    flat: dict[str, Any] = {}
    for key, value in raw.items():
        path = f"{prefix}{str(key).lower()}"
        if isinstance(value, dict):
            flat.update(_flatten(value, prefix=f"{path}."))
        else:
            flat[path] = value
    return flat


def _first_str(flat: dict[str, Any], keys: Sequence[str]) -> str | None:
    for key in keys:
        value = flat.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, (int, float)) and key not in _SUMMARY_KEYS:
            return str(value)
    return None


def _extract_entities(flat: dict[str, Any]) -> list[SigmaHitEntity]:
    entities: list[SigmaHitEntity] = []
    host = _first_str(flat, _HOST_KEYS)
    if host:
        entities.append(SigmaHitEntity(kind="host", value=host[:512]))
    user = _first_str(flat, _USER_KEYS)
    if user:
        entities.append(SigmaHitEntity(kind="user", value=user[:512]))
    return entities


def _extract_observable(flat: dict[str, Any]) -> tuple[str | None, str | None]:
    for keys, kind in ((_IP_KEYS, "ip"), (_HASH_KEYS, "hash"), (_DOMAIN_KEYS, "domain")):
        value = _first_str(flat, keys)
        if value:
            return value[:512], kind
    return None, None


def _to_hit(
    raw: dict[str, Any],
    *,
    rule: HuntPackRule,
    pack: HuntPack,
    backend: SigmaBackendName,
    run_id: str,
) -> SigmaHit:
    flat = _flatten(raw)
    observable, observable_type = _extract_observable(flat)
    summary = _first_str(flat, _SUMMARY_KEYS) or f"{rule.title} hit on {backend}"
    return SigmaHit(
        source_run_id=run_id,
        pack_id=pack.id,
        rule_id=rule.id,
        rule_title=rule.title,
        backend=backend,
        severity=rule.severity,
        mitre_techniques=list(rule.mitre_techniques),
        entities=_extract_entities(flat),
        observable=observable,
        observable_type=observable_type,
        summary=summary[:1024],
        raw=raw,
    )


# ---------------------------------------------------------------------------
# Per-backend execution adapters (existing engine integration nodes)
# ---------------------------------------------------------------------------

# Sigma logsource -> Elastic index pattern. Mock-friendly defaults; a real
# deployment overrides per-datasource index strategy at the integration layer.
_ELASTIC_INDEX_BY_CATEGORY = {
    "network_connection": "packetbeat-*",
    "dns_query": "packetbeat-*",
    "firewall": "packetbeat-*",
}
_ELASTIC_DEFAULT_INDEX = "filebeat-*"

# Severity floor handed to CrowdStrike list_detections per rule severity.
_CS_SEVERITY_FLOOR = {
    Severity.CRITICAL: "critical",
    Severity.HIGH: "high",
    Severity.MEDIUM: "medium",
    Severity.LOW: "low",
    Severity.INFO: "all",
}


async def _run_splunk(
    query: str, rule: HuntPackRule, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    out = await SplunkSearchNode().run(
        SplunkSearchInput(query=query, earliest_time=f"-{lookback_hours}h", max_count=max_hits),
        ctx,
    )
    return out.events


async def _run_sentinel(
    query: str, rule: HuntPackRule, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    out = await SentinelKQLQueryNode().run(
        SentinelKQLQueryInput(query=query, timespan_hours=lookback_hours),
        ctx,
    )
    return out.rows[:max_hits]


async def _run_elastic(
    query: str, rule: HuntPackRule, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    index = _ELASTIC_INDEX_BY_CATEGORY.get(
        rule.logsource.get("category", ""), _ELASTIC_DEFAULT_INDEX
    )
    # Codex #198: without an @timestamp filter the query scans the whole index;
    # the size cap then fills with arbitrary documents, hiding recent matches
    # and emitting historical events as if they were fresh hunt findings.
    # Compose: query_string AND @timestamp >= now-{lookback_hours}h, then sort
    # newest-first so the size cap (max_hits) keeps the most-recent matches.
    bounded_query = {
        "bool": {
            "filter": [
                {"query_string": {"query": query}},
                {"range": {"@timestamp": {"gte": f"now-{lookback_hours}h"}}},
            ]
        }
    }
    out = await ElasticSearchNode().run(
        ElasticSearchInput(
            index=index,
            query=bounded_query,
            size=max_hits,
        ),
        ctx,
    )
    # Unwrap to the _source document; keep the envelope's metadata alongside.
    return [
        {**hit.get("_source", {}), "_index": hit.get("_index"), "_id": hit.get("_id")}
        for hit in out.hits
    ]


async def _run_crowdstrike(
    query: str, rule: HuntPackRule, ctx: NodeContext, lookback_hours: int, max_hits: int
) -> list[dict[str, Any]]:
    # No raw event-search node on the engine's CrowdStrike surface yet (see
    # module docstring) — degrade to detections at/above the rule severity.
    out = await CrowdStrikeListDetectionsNode().run(
        CrowdStrikeListDetectionsInput(
            severity=_CS_SEVERITY_FLOOR.get(rule.severity, "all"), limit=max_hits
        ),
        ctx,
    )
    return out.detections


_BACKEND_ADAPTERS = {
    "splunk": _run_splunk,
    "sentinel": _run_sentinel,
    "elastic": _run_elastic,
    "crowdstrike": _run_crowdstrike,
}


# ---------------------------------------------------------------------------
# run_pack
# ---------------------------------------------------------------------------


async def run_pack(
    pack: HuntPack,
    backends: Sequence[SigmaBackendName],
    ctx: NodeContext,
    *,
    lookback_hours: int = 24,
    max_hits_per_query: int = 100,
) -> PackRunResult:
    """Run every enabled rule of ``pack`` on every requested backend.

    Per rule per backend: transpile, execute through the integration node,
    convert raw events to :class:`SigmaHit`. A transpile or execution failure
    is captured as that ``BackendRunResult.error`` — it never aborts the rest
    of the pack run. Disabled rules are skipped (listed in
    ``skipped_rule_ids``).
    """
    unknown = [b for b in backends if b not in SUPPORTED_BACKENDS]
    if unknown:
        raise ValueError(f"unknown backends {unknown}; supported: {list(SUPPORTED_BACKENDS)}")
    if not backends:
        raise ValueError("at least one backend is required")

    run_id = generate_id("hrun")
    result = PackRunResult(
        run_id=run_id,
        pack_id=pack.id,
        pack_name=pack.name,
        pack_version=pack.version,
        backends=list(dict.fromkeys(backends)),
        started_at=datetime.now(UTC),
        skipped_rule_ids=[r.id for r in pack.rules if not r.enabled],
    )

    for rule in pack.enabled_rules:
        rule_result = RuleRunResult(rule_id=rule.id, rule_title=rule.title)
        for backend in result.backends:
            rule_result.backend_results.append(
                await _run_rule_on_backend(
                    rule,
                    backend,
                    pack=pack,
                    ctx=ctx,
                    run_id=run_id,
                    lookback_hours=lookback_hours,
                    max_hits=max_hits_per_query,
                )
            )
        result.rule_results.append(rule_result)

    result.completed_at = datetime.now(UTC)
    return result


async def _run_rule_on_backend(
    rule: HuntPackRule,
    backend: SigmaBackendName,
    *,
    pack: HuntPack,
    ctx: NodeContext,
    run_id: str,
    lookback_hours: int,
    max_hits: int,
) -> BackendRunResult:
    try:
        query = transpile(rule.sigma_yaml, backend)
    except SigmaTranspileError as exc:
        logger.warning("transpile failed: rule=%s backend=%s: %s", rule.id, backend, exc.reason)
        return BackendRunResult(backend=backend, query=None, error=str(exc))

    try:
        raw_events = await _BACKEND_ADAPTERS[backend](query, rule, ctx, lookback_hours, max_hits)
    except Exception as exc:  # one unreachable backend must not kill the run
        logger.warning("execution failed: rule=%s backend=%s: %s", rule.id, backend, exc)
        return BackendRunResult(backend=backend, query=query, error=f"execution failed: {exc}")

    hits: list[SigmaHit] = []
    for raw in raw_events:
        try:
            hits.append(_to_hit(raw, rule=rule, pack=pack, backend=backend, run_id=run_id))
        except Exception as exc:
            # A malformed event is dropped, not fatal to the rest of the hits.
            logger.warning("skipping malformed hit: rule=%s backend=%s: %s", rule.id, backend, exc)

    return BackendRunResult(backend=backend, query=query, hit_count=len(hits), hits=hits)
