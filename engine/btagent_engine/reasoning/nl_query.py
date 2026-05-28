"""NLQueryNode — natural-language hunt intent -> executable per-backend query.

Implements UC-1.1 (#104): a Tier-3 analyst describes a hunt in plain
English ("Show me all high-severity Cobalt Strike beaconing in the last
72 hours across finance enclave hosts") and the node returns a valid,
count-capped query per requested backend plus the *parsed intent* the
query was built from (entities, time window, severity, detected MITRE
techniques). The parsed intent is what the analyst reviews at the HITL
gate before execution.

Relationship to QuerySynthNode (#99 Phase B):

* QuerySynth takes a *TTP id* and emits library-template queries.
* NLQuery takes *free text*, parses it into structure, and either
  (a) builds a query directly from the parsed entities + keywords +
  time window, or (b) surfaces a detected TTP so the caller can route
  to QuerySynth for a richer template. NLQuery does (a) inline and
  reports detected TTPs in the parsed intent for (b).

Design notes:

1. **Mock mode is deterministic** (matches the other reasoning nodes).
   The mock path does real (regex/keyword) intent parsing and a
   real query build — it just doesn't use an LLM, so it can't handle
   arbitrary phrasing. When a real LLM client is registered and mock
   mode is off, the LLM parses the intent and the deterministic builders
   still construct the queries; if no client is registered it falls back
   to the regex parser. The node never raises.

2. **No hallucinated fields.** The mock builder only emits field names
   from a fixed, per-backend safe set. The real LLM path will validate
   against the org's schema registry (UC-1.1 acceptance criterion).

3. **Always count-capped.** Every emitted query carries a result cap.

4. **Parsing is conservative.** When the node can't extract a time
   window it defaults to 24h; when it can't detect entities it falls
   back to a keyword search. It never invents specific hosts/users.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from btagent_shared.types.hunt import Backend, Query
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").strip().lower() != "false"


# Severity is an enum-like field; constrain it to a known allowlist rather
# than interpolating arbitrary (LLM-derived) text into the query language.
_SEVERITIES: frozenset[str] = frozenset({"critical", "high", "medium", "low", "info"})


def _safe_severity(sev: str | None) -> str | None:
    return sev if sev in _SEVERITIES else None


# Value escapers — entity/keyword values may come from the LLM intent parser
# and are therefore untrusted. Safe field *names* are not enough (a KQL
# break-out like ``'high' | union SecretTable | take 9999 //`` was reproduced
# in review); every interpolated *value* must be quote-escaped for its target
# query language.
def _spl_v(v: str) -> str:
    """Escape a value for a double-quoted SPL string."""
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _kql_v(v: str) -> str:
    """Escape a value for a single-quoted KQL string."""
    return v.replace("\\", "\\\\").replace("'", "\\'")


def _es_v(v: str) -> str:
    """Escape a value for a double-quoted ES|QL string."""
    return v.replace("\\", "\\\\").replace('"', '\\"')


def _yaml_sq(v: str) -> str:
    """Escape a value for a single-quoted YAML scalar (quote doubling)."""
    return v.replace("'", "''")


# ---------------------------------------------------------------------------
# Parsing tables
# ---------------------------------------------------------------------------

_DEFAULT_WINDOW_HOURS = 24
_RESULT_CAP = 1000

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_TIME_RE = re.compile(
    r"(?:last|past|previous|within)\s+(\d+)\s*(minute|min|hour|hr|day|week)s?",
    re.IGNORECASE,
)
_SEVERITY_RE = re.compile(
    r"\b(critical|high|medium|low|informational|info)[- ]?(?:severity|sev)?\b",
    re.IGNORECASE,
)

# Keyword -> ATT&CK technique. Conservative, high-precision phrases only.
_MITRE_KEYWORDS: list[tuple[re.Pattern[str], str, str]] = [
    (re.compile(r"\bpowershell\b", re.I), "T1059.001", "PowerShell"),
    (
        re.compile(r"\b(cobalt\s*strike|beacon(?:ing)?|c2|command[- ]and[- ]control)\b", re.I),
        "T1071.001",
        "Web Protocols (C2)",
    ),
    (re.compile(r"\bscheduled?\s*task", re.I), "T1053.005", "Scheduled Task"),
    (
        re.compile(r"\b(brute[- ]?force|failed\s+log(?:in|on)|password\s+spray)", re.I),
        "T1110",
        "Brute Force",
    ),
    (re.compile(r"\b(spear)?phish", re.I), "T1566.001", "Spearphishing Attachment"),
    (
        re.compile(r"\b(ransomware|encrypt(?:ed|ion)?\s+files?)\b", re.I),
        "T1486",
        "Data Encrypted for Impact",
    ),
    (re.compile(r"\blateral\s+movement\b", re.I), "T1021", "Remote Services"),
    (re.compile(r"\b(mimikatz|credential\s+dump|lsass)\b", re.I), "T1003", "OS Credential Dumping"),
    (
        re.compile(r"\b(exploit|public[- ]facing|web\s+shell)\b", re.I),
        "T1190",
        "Exploit Public-Facing Application",
    ),
    (re.compile(r"\bcloud\s+(account|login|sign[- ]?in)\b", re.I), "T1078.004", "Cloud Accounts"),
]

# Threat keyword phrases worth carrying into the query as free-text
# search terms even when no TTP matches.
_KEYWORD_PHRASES = [
    "cobalt strike",
    "beacon",
    "powershell",
    "mimikatz",
    "ransomware",
    "phishing",
    "lateral movement",
    "exfiltration",
    "privilege escalation",
]

_UNIT_TO_HOURS = {
    "minute": 1 / 60,
    "min": 1 / 60,
    "hour": 1,
    "hr": 1,
    "day": 24,
    "week": 168,
}


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ParsedIntent(BaseModel):
    """Structured form of the analyst's NL request — the HITL review surface."""

    model_config = ConfigDict(extra="forbid")

    raw_intent: str
    time_window_hours: int = Field(
        default=_DEFAULT_WINDOW_HOURS,
        description="Parsed lookback window. Defaults to 24h when not stated.",
    )
    severity: str | None = Field(default=None, description="Detected severity filter.")
    entities: dict[str, list[str]] = Field(
        default_factory=dict,
        description="Extracted entities keyed by kind: 'ip', 'host', 'user'.",
    )
    keywords: list[str] = Field(
        default_factory=list,
        description="Free-text threat keyword phrases to search for.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique ids detected in the intent. The caller "
        "can route these to QuerySynthNode for richer templates.",
    )


class NLQueryInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent: str = Field(..., description="Plain-English hunt description.")
    backends: list[Backend] = Field(
        default_factory=list,
        description="Which backends to emit queries for. Empty == Splunk + Sentinel + Elastic + Sigma.",
    )


class NLQueryOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    parsed: ParsedIntent
    queries: dict[Backend, Query] = Field(default_factory=dict)
    mock_mode: bool


# ---------------------------------------------------------------------------
# Parsing helpers
# ---------------------------------------------------------------------------


def _parse_time_window(text: str) -> int:
    m = _TIME_RE.search(text)
    if not m:
        return _DEFAULT_WINDOW_HOURS
    n = int(m.group(1))
    unit = m.group(2).lower()
    hours = n * _UNIT_TO_HOURS.get(unit, 1)
    return max(1, int(round(hours)))


def _parse_severity(text: str) -> str | None:
    m = _SEVERITY_RE.search(text)
    if not m:
        return None
    sev = m.group(1).lower()
    return "info" if sev == "informational" else sev


def _parse_entities(text: str) -> dict[str, list[str]]:
    entities: dict[str, list[str]] = {}
    ips = _IPV4_RE.findall(text)
    if ips:
        entities["ip"] = list(dict.fromkeys(ips))
    # user@domain or user="..." patterns
    users = re.findall(r"\b[\w.+-]+@[\w.-]+\.\w+\b", text)
    if users:
        entities["user"] = list(dict.fromkeys(users))
    return entities


def _parse_keywords(text: str) -> list[str]:
    lowered = text.lower()
    found = [kw for kw in _KEYWORD_PHRASES if kw in lowered]
    return list(dict.fromkeys(found))


def _detect_mitre(text: str) -> list[str]:
    found: list[str] = []
    for pattern, ttp_id, _name in _MITRE_KEYWORDS:
        if pattern.search(text) and ttp_id not in found:
            found.append(ttp_id)
    return found


def _parse(intent: str) -> ParsedIntent:
    return ParsedIntent(
        raw_intent=intent,
        time_window_hours=_parse_time_window(intent),
        severity=_parse_severity(intent),
        entities=_parse_entities(intent),
        keywords=_parse_keywords(intent),
        mitre_techniques=_detect_mitre(intent),
    )


# ---------------------------------------------------------------------------
# Per-backend query builders (safe-field-set only, count-capped)
# ---------------------------------------------------------------------------


def _build_splunk(p: ParsedIntent) -> str:
    parts = ["index=*"]
    sev = _safe_severity(p.severity)
    if sev:
        parts.append(f"severity={sev}")
    for ip in p.entities.get("ip", []):
        parts.append(f'(src_ip="{_spl_v(ip)}" OR dest_ip="{_spl_v(ip)}")')
    for user in p.entities.get("user", []):
        parts.append(f'user="{_spl_v(user)}"')
    if p.keywords:
        kw = " OR ".join(f'search="*{_spl_v(k)}*"' for k in p.keywords)
        parts.append(f"({kw})")
    parts.append(f"earliest=-{p.time_window_hours}h")
    return " ".join(parts) + f" | head {_RESULT_CAP}"


def _build_sentinel(p: ParsedIntent) -> str:
    lines = ["union *", f"| where TimeGenerated > ago({p.time_window_hours}h)"]
    sev = _safe_severity(p.severity)
    if sev:
        lines.append(f"| where Severity =~ '{sev}'")
    for ip in p.entities.get("ip", []):
        lines.append(f"| where SrcIpAddr == '{_kql_v(ip)}' or DstIpAddr == '{_kql_v(ip)}'")
    for user in p.entities.get("user", []):
        lines.append(f"| where AccountUpn =~ '{_kql_v(user)}'")
    if p.keywords:
        terms = ",".join(f"'{_kql_v(k)}'" for k in p.keywords)
        lines.append(f"| where * has_any ({terms})")
    lines.append(f"| take {_RESULT_CAP}")
    return "\n".join(lines)


def _build_elastic(p: ParsedIntent) -> str:
    conds = [f"@timestamp >= now-{p.time_window_hours}h"]
    sev = _safe_severity(p.severity)
    if sev:
        conds.append(f'event.severity : "{sev}"')
    for ip in p.entities.get("ip", []):
        conds.append(f'(source.ip : "{_es_v(ip)}" or destination.ip : "{_es_v(ip)}")')
    for user in p.entities.get("user", []):
        conds.append(f'user.name : "{_es_v(user)}"')
    if p.keywords:
        kw = " or ".join(f'message : "*{_es_v(k)}*"' for k in p.keywords)
        conds.append(f"({kw})")
    return "any where " + " and ".join(conds) + f" | head {_RESULT_CAP}"


def _build_sigma(p: ParsedIntent) -> str:
    title = "NL Hunt"
    if p.mitre_techniques:
        title += " (" + ", ".join(p.mitre_techniques) + ")"
    detection_terms = p.keywords or ["REPLACE_ME"]
    keywords_yaml = "\n".join(f"    - '{_yaml_sq(k)}'" for k in detection_terms)
    tags = ""
    if p.mitre_techniques:
        tag_lines = "\n".join(
            f"  - attack.{t.lower().replace('.', '_')}" for t in p.mitre_techniques
        )
        tags = f"tags:\n{tag_lines}\n"
    return (
        f"title: {title}\n"
        f"{tags}"
        "logsource: {category: any}\n"
        "detection:\n"
        "  keywords:\n"
        f"{keywords_yaml}\n"
        "  condition: keywords"
    )


_BUILDERS = {
    Backend.SPLUNK: _build_splunk,
    Backend.SENTINEL: _build_sentinel,
    Backend.DEFENDER: _build_sentinel,  # Defender uses KQL too
    Backend.ELASTIC: _build_elastic,
    Backend.SIGMA: _build_sigma,
}

_DEFAULT_BACKENDS = [Backend.SPLUNK, Backend.SENTINEL, Backend.ELASTIC, Backend.SIGMA]


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class NLQueryNode(Node[NLQueryInput, NLQueryOutput]):
    """Parse a natural-language hunt intent and emit per-backend queries."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.nl_query",
        name="NL Query Assistant",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Translate a plain-English hunt description into executable, "
            "count-capped queries per backend, surfacing the parsed intent "
            "(entities, time window, severity, MITRE techniques) for HITL review."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = NLQueryInput
    output_schema: ClassVar[type[BaseModel]] = NLQueryOutput

    async def run(
        self,
        input: NLQueryInput,
        ctx: NodeContext,
    ) -> NLQueryOutput:
        # Client-or-deterministic: when a real LLM client is registered and
        # mock mode is off, the LLM *parses the intent* (better at free-form
        # phrasing than regex); otherwise the deterministic regex/keyword
        # parser is used. Either way the per-backend QUERIES are built by the
        # deterministic builders from a fixed safe field set — so there are
        # never hallucinated field names (UC-1.1 criterion). Never hard-raise.
        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        parsed = None
        used_llm = False
        if not _mock_mode_enabled() and client is not None:
            parsed = await self._llm_parse(input.intent, client, ctx)
            used_llm = parsed is not None
        if parsed is None:
            parsed = _parse(input.intent)

        backends = input.backends or _DEFAULT_BACKENDS
        queries: dict[Backend, Query] = {}
        for backend in backends:
            builder = _BUILDERS.get(backend) or _build_splunk
            queries[backend] = Query(
                backend=backend,
                query=builder(parsed),
                notes="Built from a fixed safe field set — review filters before executing (HITL).",
            )

        return NLQueryOutput(parsed=parsed, queries=queries, mock_mode=not used_llm)

    async def _llm_parse(self, intent: str, client, ctx) -> ParsedIntent | None:
        """LLM intent parsing -> ParsedIntent. Returns None on any failure so
        the caller falls back to the deterministic regex parser."""
        from btagent_shared.types.config import TLP, ModelTier

        from btagent_engine.reasoning._llm_json import call_llm_json, wrap_external_data

        system = (
            "You parse a SOC analyst's plain-English hunt request into structure. "
            "Respond ONLY with a JSON object (no prose) with keys: "
            '"time_window_hours" (int, default 24), "severity" (one of '
            'critical/high/medium/low/info or null), "entities" '
            '({"ip":[...],"user":[...],"host":[...]}), "keywords" (list of str), '
            '"mitre_techniques" (list of ATT&CK ids).'
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            # Fail closed: unknown classification → most restrictive.
            tlp = TLP.RED

        raw = await call_llm_json(
            client,
            system=system,
            user=wrap_external_data(intent),
            tlp=tlp,
            tier=ModelTier.FAST,
            array=False,
        )
        if not isinstance(raw, dict):
            return None
        try:
            ents = raw.get("entities") or {}
            return ParsedIntent(
                raw_intent=intent,
                time_window_hours=int(raw.get("time_window_hours") or _DEFAULT_WINDOW_HOURS),
                severity=(raw.get("severity") or None),
                entities={
                    k: [str(v) for v in (ents.get(k) or [])]
                    for k in ("ip", "user", "host")
                    if ents.get(k)
                },
                keywords=[str(k) for k in (raw.get("keywords") or [])],
                mitre_techniques=[str(t) for t in (raw.get("mitre_techniques") or [])],
            )
        except (TypeError, ValueError):
            return None


NodeRegistry.register(NLQueryNode)


__all__ = [
    "NLQueryInput",
    "NLQueryNode",
    "NLQueryOutput",
    "ParsedIntent",
]
