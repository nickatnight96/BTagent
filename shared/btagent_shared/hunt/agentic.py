"""Pure-logic Agentic-AI misuse hunt detections (Phase 6 #121).

Dependency-free (no DB, no network, no LLM) — operates solely on:
  * :mod:`btagent_shared.types.agentic_hunt` schemas
  * :mod:`btagent_shared.types.cloud_hunt` (reuses the #117 ``AgenticWorkload``
    inventory + the shadow-classification predicate so a future governance
    workflow routes cloud- and agentic-discovered shadow agents through one queue).

Every public function either:
  1. Scores an in-memory observation, or
  2. Returns :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest`
     objects with ``source=AGENTIC`` / ``domain=AGENTIC`` for the #119 triage queue.

Detections implemented (connector-independent, fixture-based):
  A1  Prompt-injection scan — pattern + heuristic match against agent inputs.
  A2  Shadow agent / shadow MCP discovery — reuses #117 ``AgenticWorkload``
      classification so the same governance routing marker is emitted.
  A3  Agent-identity abuse — observed tool / API call outside the declared
      catalogue, or executed under a higher-privilege role than the registered
      identity.
  A4  LLM exfil — secret material (cloud keys, tokens, private keys) present
      in either direction of an agent call, plus oversized outbound prompts.

Deferred (blocked on live LLM-call telemetry + agent-platform MCP connectors):
  - Real-time LLM-call telemetry ingest (Bedrock invocation logs, Vertex
    request/response capture, OpenAI / Anthropic API gateway logs).
  - Live agent-registration inventory from Bedrock AgentCore / Vertex Agent
    Engine / Cloud Run MCP.
  - Cross-call session reconstruction (multi-turn jailbreak escalation).

DEFENSIVE-FACING design note
----------------------------
The pattern lists below are *signatures of attacker behaviour to detect* and
reference public taxonomies (OWASP LLM Top-10, MITRE ATLAS). They are not, and
must not become, attack generators. New entries should be drawn from public
threat-intel sources (cited in comments) and reviewed for the same property.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from datetime import datetime

from btagent_shared.hunt.cloud import classify_workload, score_workload_risk
from btagent_shared.types.agentic_hunt import (
    AgentCallEvent,
    AgentIdentity,
    AgentIdentityKind,
    PromptInjectionCategory,
    PromptInjectionSignal,
)
from btagent_shared.types.cloud_hunt import AgenticWorkload, AgenticWorkloadKind
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import HuntEntity, HuntObservable, RecordFindingRequest

logger = logging.getLogger("btagent.hunt.agentic")

# ── Constants ────────────────────────────────────────────────────────────────

# Technique IDs referenced across detections.
# Mapped via the MITRE keyword table (agents/btagent_agents/mitre/data/mitre_keywords.yaml,
# AGENTIC block) so the triage agent can surface them in coverage analysis.
_T_CODE_EXECUTION = "T1059"  # Command and Scripting Interpreter (closest ATT&CK proxy for
# tool-mediated LLM execution; ATLAS AML.T0051 is the AI-specific reference but ATT&CK is
# the canonical taxonomy the triage queue clusters by).
_T_VALID_ACCOUNTS = "T1078"  # Valid Accounts — agent identity abused as a valid account
_T_VALID_ACCOUNTS_CLOUD = "T1078.004"  # Valid Accounts: Cloud Accounts
_T_TOKEN_FORGERY = "T1606"  # Forge Web Credentials — overlaps when an agent token is
# replayed or escalated
_T_SHADOW_WORKLOAD = "T1580"  # Cloud Infrastructure Discovery / Acquisition (shadow IT)
_T_UNSECURED_CREDS = "T1552"  # Unsecured Credentials — secret-leak prompt-injection ask

# Risk score component weights for an aggregated prompt-injection finding.
# Must stay ≤ 1.0 in sum so the result remains in [0, 1].
_PI_BASE = 0.4
_PI_PER_EXTRA_HIT = 0.15
_PI_MAX = 1.0

# Maximum length of the source-text excerpt embedded in evidence. Larger inputs
# are truncated with an elision marker to keep finding payloads bounded.
_EXCERPT_RADIUS = 60
_EXCERPT_ELISION = " […] "

# ---------------------------------------------------------------------------
# Prompt-injection signature library (DEFENSIVE-FACING)
# ---------------------------------------------------------------------------
#
# Each entry: (compiled_regex, category, label, confidence).
# Labels are short stable identifiers used in evidence; the regex itself is
# *not* surfaced verbatim in any user-facing artefact, only the label.
#
# References (where each cluster of patterns is taken from public taxonomies):
#   OWASP LLM01 (Prompt Injection)     https://owasp.org/www-project-top-10-for-large-language-model-applications/
#   MITRE ATLAS AML.T0051 (LLM Prompt Injection)
#   MITRE ATLAS AML.T0054 (LLM Jailbreak)
#   MITRE ATLAS AML.T0049 (Exploit Public-Facing Application)
#
# Patterns are deliberately conservative: high-precision, lower-recall. False
# negatives are preferable to false positives in the absence of analyst tuning.
# ---------------------------------------------------------------------------


def _ci(pattern: str) -> re.Pattern[str]:
    """Compile a case-insensitive regex (small helper for readability)."""
    return re.compile(pattern, re.IGNORECASE | re.DOTALL)


# Instruction-override patterns — OWASP LLM01 sub-category "Direct Prompt Injection".
_INSTRUCTION_OVERRIDE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        _ci(r"\bignore (?:all |any |the )?(?:previous|prior|above) instructions?\b"),
        "instruction_override.ignore_previous",
        0.92,
    ),
    (
        _ci(
            r"\bdisregard (?:all |any |the )?(?:previous|prior|above) (?:rules?|instructions?|prompts?)\b"
        ),
        "instruction_override.disregard_rules",
        0.90,
    ),
    (
        _ci(
            r"\bforget (?:everything|all|any) (?:you (?:were |have been )?told|previous instructions?)\b"
        ),
        "instruction_override.forget_everything",
        0.88,
    ),
    (
        _ci(r"\bdo not follow (?:the )?(?:system|previous|above) (?:prompt|instructions?)\b"),
        "instruction_override.refuse_system",
        0.88,
    ),
]

# Role-hijack patterns — system-prompt impersonation / "you are now" persona swaps.
# Refs: ATLAS AML.T0054 (LLM Jailbreak), OWASP LLM01.
_ROLE_HIJACK_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        _ci(
            r"\byou are (?:now )?(?:a |an )?(?:unfiltered|uncensored|developer|dev|root|admin|god)\b"
        ),
        "role_hijack.persona_swap",
        0.85,
    ),
    (
        _ci(r"^\s*system\s*[:>].{0,400}\b(?:override|new instructions?|new rules?)\b"),
        "role_hijack.fake_system_block",
        0.92,
    ),
    (_ci(r"<\s*system\s*>"), "role_hijack.system_tag_injection", 0.78),
    (
        _ci(r"\bact as (?:if you are )?(?:the )?(?:user|developer|system)\b"),
        "role_hijack.act_as",
        0.75,
    ),
]

# Jailbreak personae — well-known public jailbreak names. Detector only stores
# the LABEL, not the body of the jailbreak text. Sources: public LLM-security
# corpora (e.g. JailbreakBench, the L1B3RT4S corpus referenced in OWASP LLM-Top-10
# educational material). NO attack content is reproduced here.
_JAILBREAK_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (_ci(r"\bdan(?:\s+mode|\s+prompt|\s+v?\d+|\s+jailbreak)\b"), "jailbreak.dan_persona", 0.85),
    (_ci(r"\bdo anything now\b"), "jailbreak.dan_phrase", 0.92),
    (_ci(r"\bdeveloper mode (?:enabled|on|activated)\b"), "jailbreak.developer_mode", 0.88),
    (_ci(r"\bjailbreak\s*(?:mode|prompt|payload)?\b"), "jailbreak.literal", 0.55),
]

# Data-exfil / secret-leak requests — "print your system prompt", credential probes.
# Ref: OWASP LLM06 (Sensitive Information Disclosure), ATLAS AML.T0057.
_DATA_EXFIL_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        _ci(
            r"\b(?:print|reveal|show|output|disclose|leak) (?:me )?(?:your |the )?(?:system )?(?:prompt|instructions?)\b"
        ),
        "data_exfil.system_prompt_request",
        0.90,
    ),
    (
        _ci(r"\brepeat (?:back )?(?:everything|all) (?:above|the system message)\b"),
        "data_exfil.repeat_context",
        0.82,
    ),
    (
        _ci(
            r"\b(?:show|reveal|print) (?:your |any )?(?:api[_\- ]?keys?|secrets?|credentials?|tokens?)\b"
        ),
        "data_exfil.secret_probe",
        0.92,
    ),
]

# Tool-abuse requests — direct invocation by name with destructive verbs.
_TOOL_ABUSE_PATTERNS: list[tuple[re.Pattern[str], str, float]] = [
    (
        _ci(
            r"\b(?:call|invoke|execute|run) (?:the )?(?:tool|function|api)\s+(?:delete|drop|remove|destroy|wipe)\w*"
        ),
        "tool_abuse.destructive_invocation",
        0.88,
    ),
    (
        _ci(r"\b(?:rm\s+-rf|drop\s+table|truncate\s+table)\b"),
        "tool_abuse.shell_or_sql_destructive",
        0.85,
    ),
]

# Encoded-payload heuristic — long base64 / hex blobs embedded in otherwise-prose
# inputs are a known smuggling vector. We DON'T decode the payload; we only flag
# the *presence* and length so the analyst can inspect.
_BASE64_BLOB_RE = re.compile(r"\b[A-Za-z0-9+/]{120,}={0,2}\b")
_HEX_BLOB_RE = re.compile(r"\b(?:0x)?[0-9a-fA-F]{200,}\b")

_ALL_PATTERN_GROUPS: list[
    tuple[list[tuple[re.Pattern[str], str, float]], PromptInjectionCategory]
] = [
    (_INSTRUCTION_OVERRIDE_PATTERNS, PromptInjectionCategory.INSTRUCTION_OVERRIDE),
    (_ROLE_HIJACK_PATTERNS, PromptInjectionCategory.ROLE_HIJACK),
    (_JAILBREAK_PATTERNS, PromptInjectionCategory.JAILBREAK),
    (_DATA_EXFIL_PATTERNS, PromptInjectionCategory.DATA_EXFIL_REQUEST),
    (_TOOL_ABUSE_PATTERNS, PromptInjectionCategory.TOOL_ABUSE_REQUEST),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _redact_excerpt(text: str, match_start: int, match_end: int) -> str:
    """Return a bounded excerpt around a match with surrounding bytes elided.

    The excerpt is intentionally short and contains no leading/trailing data
    beyond ``_EXCERPT_RADIUS`` chars on each side. Newlines are normalised so
    the excerpt remains single-line-readable in the triage UI.
    """
    if not text:
        return ""
    start = max(0, match_start - _EXCERPT_RADIUS)
    end = min(len(text), match_end + _EXCERPT_RADIUS)
    prefix = _EXCERPT_ELISION if start > 0 else ""
    suffix = _EXCERPT_ELISION if end < len(text) else ""
    body = text[start:end].replace("\n", " ").replace("\r", " ")
    excerpt = f"{prefix}{body}{suffix}".strip()
    # Cap defensively — the field schema also enforces 512 max.
    return excerpt[:480]


def _scan_pattern_group(
    text: str,
    patterns: list[tuple[re.Pattern[str], str, float]],
    category: PromptInjectionCategory,
    *,
    event_id: str,
    observed_at: datetime,
    agent_identity_ref: str | None,
) -> list[PromptInjectionSignal]:
    """Return signals for every pattern that matches in ``text`` (first hit per pattern)."""
    signals: list[PromptInjectionSignal] = []
    for regex, label, confidence in patterns:
        m = regex.search(text)
        if not m:
            continue
        signals.append(
            PromptInjectionSignal(
                event_id=event_id,
                source_text=text[:16384],  # bounded; field enforces too
                redacted_excerpt=_redact_excerpt(text, m.start(), m.end()),
                category=category,
                injected_pattern=label,
                confidence=confidence,
                observed_at=observed_at,
                agent_identity_ref=agent_identity_ref,
            )
        )
    return signals


# ---------------------------------------------------------------------------
# A1 — Prompt-injection detection
# ---------------------------------------------------------------------------


def scan_for_prompt_injection(
    event: AgentCallEvent,
) -> list[PromptInjectionSignal]:
    """Scan one :class:`AgentCallEvent` for prompt-injection signals.

    Pure pattern + heuristic match — no LLM, no network. Returns one
    :class:`PromptInjectionSignal` per matched signature. The caller aggregates
    signals into a :class:`RecordFindingRequest` via :func:`build_prompt_injection_finding`.
    """
    text = event.input_text or ""
    if not text.strip():
        return []

    signals: list[PromptInjectionSignal] = []
    for patterns, category in _ALL_PATTERN_GROUPS:
        signals.extend(
            _scan_pattern_group(
                text,
                patterns,
                category,
                event_id=event.event_id,
                observed_at=event.observed_at,
                agent_identity_ref=event.agent_identity_ref,
            )
        )

    # Encoded-payload heuristic — a single blob hit is one signal.
    for blob_re, label in (
        (_BASE64_BLOB_RE, "encoded_payload.base64_blob"),
        (_HEX_BLOB_RE, "encoded_payload.hex_blob"),
    ):
        m = blob_re.search(text)
        if m:
            signals.append(
                PromptInjectionSignal(
                    event_id=event.event_id,
                    source_text=text[:16384],
                    redacted_excerpt=_redact_excerpt(text, m.start(), m.end()),
                    category=PromptInjectionCategory.ENCODED_PAYLOAD,
                    injected_pattern=label,
                    confidence=0.72,
                    observed_at=event.observed_at,
                    agent_identity_ref=event.agent_identity_ref,
                )
            )

    return signals


def build_prompt_injection_finding(
    signals: Sequence[PromptInjectionSignal],
    *,
    event: AgentCallEvent,
) -> RecordFindingRequest | None:
    """Aggregate a per-event signal list into one :class:`RecordFindingRequest`.

    Returns ``None`` when there are no signals. Severity is derived from the
    aggregated confidence and the *categories* matched: any DATA_EXFIL or
    TOOL_ABUSE category escalates severity even if the count is small.
    """
    if not signals:
        return None

    categories_hit = {s.category for s in signals}
    max_confidence = max(s.confidence for s in signals)
    # Aggregated confidence: max with a small boost per extra category up to PI_MAX.
    extra_categories = max(0, len(categories_hit) - 1)
    confidence = min(
        _PI_MAX, _PI_BASE + max_confidence * 0.4 + extra_categories * _PI_PER_EXTRA_HIT
    )

    sev_critical_cats = {
        PromptInjectionCategory.DATA_EXFIL_REQUEST,
        PromptInjectionCategory.TOOL_ABUSE_REQUEST,
    }
    if categories_hit & sev_critical_cats:
        severity = Severity.CRITICAL if confidence >= 0.85 else Severity.HIGH
    elif PromptInjectionCategory.INSTRUCTION_OVERRIDE in categories_hit:
        severity = Severity.HIGH if confidence >= 0.75 else Severity.MEDIUM
    else:
        severity = Severity.MEDIUM if confidence >= 0.65 else Severity.LOW

    techniques: list[str] = [_T_CODE_EXECUTION]
    if PromptInjectionCategory.DATA_EXFIL_REQUEST in categories_hit:
        techniques.append(_T_UNSECURED_CREDS)
    if PromptInjectionCategory.TOOL_ABUSE_REQUEST in categories_hit:
        # Tool-abuse via the agent identity escalates as valid-accounts misuse.
        techniques.append(_T_VALID_ACCOUNTS)

    matched_patterns = sorted({s.injected_pattern for s in signals})
    entities: list[HuntEntity] = [
        HuntEntity(kind="agent_call_event", value=event.event_id),
    ]
    if event.agent_identity_ref:
        entities.append(HuntEntity(kind="agent_identity", value=event.agent_identity_ref))
    observables: list[HuntObservable] = []
    if event.invoked_tool:
        observables.append(HuntObservable(type="agent_tool", value=event.invoked_tool))
    if event.invoked_api:
        observables.append(HuntObservable(type="cloud_api", value=event.invoked_api))

    title_pattern = matched_patterns[0]
    title = f"Prompt injection detected on agent call {event.event_id}: {title_pattern}" + (
        f" (+{len(matched_patterns) - 1} more)" if len(matched_patterns) > 1 else ""
    )
    description = (
        f"Agent call event {event.event_id!r} (agent={event.agent_identity_ref or 'unknown'}) "
        f"matched {len(signals)} prompt-injection signal(s) across "
        f"{len(categories_hit)} categor{'y' if len(categories_hit) == 1 else 'ies'}: "
        f"{sorted(c.value for c in categories_hit)}. "
        "Patterns matched: " + ", ".join(matched_patterns) + ". "
        "Inspect the redacted excerpts in evidence; the raw input is retained "
        "only in the upstream telemetry store, not in this finding."
    )

    return RecordFindingRequest(
        source=HuntSource.AGENTIC,
        domain=HuntDomain.AGENTIC,
        title=title[:300],
        description=description,
        severity=severity,
        confidence=confidence,
        technique_ids=techniques,
        entities=entities,
        observables=observables,
        evidence={
            "detection": "prompt_injection",
            "event_id": event.event_id,
            "agent_identity_ref": event.agent_identity_ref,
            "categories": sorted(c.value for c in categories_hit),
            "matched_patterns": matched_patterns,
            "signal_count": len(signals),
            "max_signal_confidence": max_confidence,
            "redacted_excerpts": [s.redacted_excerpt for s in signals if s.redacted_excerpt][:8],
            # Defensive: do NOT include the raw injection text in finding evidence —
            # downstream readers / log pipelines themselves may be vulnerable to
            # secondary injection on the excerpt content. Excerpts are bounded.
        },
    )


def detect_prompt_injection(
    events: Iterable[AgentCallEvent],
) -> list[RecordFindingRequest]:
    """Run the prompt-injection scan over a batch of agent-call events.

    Convenience wrapper around :func:`scan_for_prompt_injection` +
    :func:`build_prompt_injection_finding` — one finding per *event* with hits.
    """
    findings: list[RecordFindingRequest] = []
    for event in events:
        signals = scan_for_prompt_injection(event)
        finding = build_prompt_injection_finding(signals, event=event)
        if finding is not None:
            findings.append(finding)
    return findings


# ---------------------------------------------------------------------------
# A2 — Shadow agent / shadow MCP discovery
# ---------------------------------------------------------------------------


def detect_shadow_agents(
    workloads: list[AgenticWorkload],
    *,
    identities: list[AgentIdentity] | None = None,
) -> list[RecordFindingRequest]:
    """Emit findings for shadow agentic workloads + shadow agent registrations.

    Reuses #117's :func:`btagent_shared.hunt.cloud.classify_workload` so the
    *same* governance routing marker (``evidence["shadow_workload"] = True``)
    appears on both cloud-discovered and agentic-discovered shadow agents — the
    governance workflow downstream can deduplicate / merge by this flag.

    Two complementary sweeps:

    1. ``workloads`` — :class:`AgenticWorkload` records (#117). A shadow workload
       (untagged or UNMANAGED kind) is emitted as an agentic finding so the
       agentic-side triage queue sees it too. Cloud-side will also emit; the
       triage agent dedups on (kind, resource_id).
    2. ``identities`` — :class:`AgentIdentity` registrations. An UNMANAGED-kind
       identity, or any identity without ``governance_tagged=True``, is flagged
       as a *shadow agent registration* (a separate detection from the workload
       inventory — an agent can be registered without a corresponding cloud
       workload record if it runs on-prem / in a personal account).
    """
    findings: list[RecordFindingRequest] = []

    for wl in workloads:
        if not classify_workload(wl):
            continue
        risk = score_workload_risk(wl)
        severity = (
            Severity.CRITICAL if risk >= 0.8 else Severity.HIGH if risk >= 0.5 else Severity.MEDIUM
        )
        findings.append(
            RecordFindingRequest(
                source=HuntSource.AGENTIC,
                domain=HuntDomain.AGENTIC,
                title=(
                    f"Shadow agentic workload (agentic-side): "
                    f"{wl.display_name or wl.resource_id} ({wl.kind} / {wl.provider})"
                ),
                description=(
                    f"Agentic workload {wl.resource_id!r} (kind={wl.kind}, "
                    f"provider={wl.provider}) is not governance-tagged"
                    f"{' and is of unmanaged kind' if wl.kind == AgenticWorkloadKind.UNMANAGED else ''} "
                    f"(risk_score={risk:.2f}). Agentic-side shadow detection mirrors the "
                    "cloud-side finding so the governance workflow receives a single, "
                    "deduplicated routing surface. Live-MCP discovery (Bedrock AgentCore "
                    "list-agents / Vertex Agent Engine agents.list / Cloud Run MCP scan) "
                    "is deferred — see live-wiring TODO in btagent_shared.hunt.agentic."
                ),
                severity=severity,
                confidence=0.88,
                technique_ids=[_T_SHADOW_WORKLOAD, _T_VALID_ACCOUNTS_CLOUD],
                entities=[
                    HuntEntity(kind="agentic_workload", value=wl.resource_id),
                    HuntEntity(kind="cloud_identity", value=wl.identity_ref),
                ],
                observables=[
                    HuntObservable(type="cloud_resource_id", value=wl.resource_id),
                ],
                evidence={
                    "detection": "shadow_agent_workload",
                    # Same governance routing marker #117 sets — see cloud.detect_shadow_workloads.
                    "shadow_workload": True,
                    "kind": wl.kind.value,
                    "provider": wl.provider.value,
                    "governance_tagged": wl.governance_tagged,
                    "is_shadow": wl.is_shadow,
                    "has_overprivileged_identity": wl.has_overprivileged_identity,
                    "internet_reachable": wl.internet_reachable,
                    "risk_score": risk,
                    "identity_ref": wl.identity_ref,
                },
            )
        )

    for ident in identities or []:
        if ident.governance_tagged and ident.kind != AgentIdentityKind.UNMANAGED:
            continue
        severity = Severity.HIGH if ident.kind == AgentIdentityKind.UNMANAGED else Severity.MEDIUM
        findings.append(
            RecordFindingRequest(
                source=HuntSource.AGENTIC,
                domain=HuntDomain.AGENTIC,
                title=(
                    f"Shadow agent registration: "
                    f"{ident.display_name or ident.identity_ref} ({ident.kind})"
                ),
                description=(
                    f"Agent identity {ident.identity_ref!r} (kind={ident.kind}) is "
                    f"{'unmanaged' if ident.kind == AgentIdentityKind.UNMANAGED else 'not governance-tagged'}. "
                    "An unregistered or unmanaged agent identity may invoke tooling "
                    "outside its declared scope and bypasses the agent-platform's "
                    "audit / quota / safety filters. Route to governance workflow."
                ),
                severity=severity,
                confidence=0.85,
                technique_ids=[_T_SHADOW_WORKLOAD],
                entities=[
                    HuntEntity(kind="agent_identity", value=ident.identity_ref),
                ],
                observables=(
                    [HuntObservable(type="cloud_resource_id", value=ident.workload_ref)]
                    if ident.workload_ref
                    else []
                ),
                evidence={
                    "detection": "shadow_agent_identity",
                    "shadow_workload": True,
                    "kind": ident.kind.value,
                    "governance_tagged": ident.governance_tagged,
                    "identity_ref": ident.identity_ref,
                    "workload_ref": ident.workload_ref,
                    "declared_capabilities": ident.capabilities,
                    "declared_tooling": ident.tooling,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# A3 — Agent-identity abuse
# ---------------------------------------------------------------------------


def detect_agent_identity_abuse(
    events: Iterable[AgentCallEvent],
    identities: Sequence[AgentIdentity],
    *,
    privileged_role_keywords: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Flag agent calls that diverge from the registered identity's scope.

    Two divergence classes:

    1. **Out-of-toolset call** — the invoked tool / API is not in the
       :attr:`AgentIdentity.tooling` set. (When ``tooling`` is empty no
       restriction is declared and this check is skipped for that identity.)
    2. **Role escalation** — the ``observed_role`` on the call differs from
       the identity's ``declared_role`` *and* contains a privileged keyword
       (``admin`` / ``root`` / ``billing`` by default). A pure declared/observed
       mismatch without a privileged keyword is downgraded to a low-severity
       finding; outright admin escalation is HIGH.

    An event whose ``agent_identity_ref`` does not appear in the identity
    catalogue is treated as an *unregistered agent call* and itself flagged.

    Parameters
    ----------
    events:
        Per-invocation agent-call telemetry.
    identities:
        Known agent registrations.
    privileged_role_keywords:
        Lowercase keyword set; default is ``{"admin", "root", "billing"}``.
    """
    if privileged_role_keywords is None:
        privileged_role_keywords = {"admin", "root", "billing", "orgadmin", "poweruser"}

    identity_by_ref: dict[str, AgentIdentity] = {i.identity_ref: i for i in identities}
    findings: list[RecordFindingRequest] = []

    for event in events:
        ident = identity_by_ref.get(event.agent_identity_ref)

        # Unregistered agent → finding in its own right.
        if ident is None:
            findings.append(
                RecordFindingRequest(
                    source=HuntSource.AGENTIC,
                    domain=HuntDomain.AGENTIC,
                    title=(
                        f"Unregistered agent identity invoked tooling: {event.agent_identity_ref}"
                    ),
                    description=(
                        f"Agent call event {event.event_id!r} was made by identity "
                        f"{event.agent_identity_ref!r} which has no AgentIdentity "
                        f"registration. The call invoked tool "
                        f"{event.invoked_tool or '<none>'!r} "
                        f"(api={event.invoked_api or '<none>'!r}). "
                        "Unregistered identities cannot be governed and may indicate "
                        "shadow-agent activity or a compromised credential being used "
                        "to impersonate an agentic workload."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.85,
                    technique_ids=[_T_VALID_ACCOUNTS, _T_SHADOW_WORKLOAD],
                    entities=[
                        HuntEntity(kind="agent_identity", value=event.agent_identity_ref),
                        HuntEntity(kind="agent_call_event", value=event.event_id),
                    ],
                    observables=(
                        [HuntObservable(type="agent_tool", value=event.invoked_tool)]
                        if event.invoked_tool
                        else []
                    ),
                    evidence={
                        "detection": "agent_identity_abuse.unregistered",
                        "event_id": event.event_id,
                        "agent_identity_ref": event.agent_identity_ref,
                        "invoked_tool": event.invoked_tool,
                        "invoked_api": event.invoked_api,
                        "observed_role": event.observed_role,
                    },
                )
            )
            continue

        # Out-of-toolset detection — only when the identity declared a tool catalogue.
        out_of_toolset = bool(
            ident.tooling and event.invoked_tool and event.invoked_tool not in set(ident.tooling)
        )

        # Role escalation — declared vs. observed.
        declared = (ident.declared_role or "").strip()
        observed = (event.observed_role or "").strip()
        role_mismatch = bool(declared and observed and declared != observed)
        observed_lower = observed.lower()
        privileged_escalation = role_mismatch and any(
            kw in observed_lower for kw in privileged_role_keywords
        )

        if not (out_of_toolset or role_mismatch):
            continue

        # Severity: escalation to a privileged role is HIGH; out-of-toolset is HIGH
        # when combined with role mismatch, otherwise MEDIUM; pure declared/observed
        # mismatch without privileged keyword is LOW.
        if privileged_escalation:
            severity = Severity.HIGH
            confidence = 0.90
        elif out_of_toolset and role_mismatch:
            severity = Severity.HIGH
            confidence = 0.85
        elif out_of_toolset:
            severity = Severity.MEDIUM
            confidence = 0.80
        else:  # role_mismatch only, non-privileged
            severity = Severity.LOW
            confidence = 0.60

        technique_ids = [_T_VALID_ACCOUNTS]
        if privileged_escalation:
            technique_ids.append(_T_VALID_ACCOUNTS_CLOUD)
            technique_ids.append(_T_TOKEN_FORGERY)
        if out_of_toolset:
            technique_ids.append(_T_CODE_EXECUTION)

        reasons: list[str] = []
        if out_of_toolset:
            reasons.append(
                f"invoked tool {event.invoked_tool!r} is not in the declared "
                f"toolset ({sorted(ident.tooling)})"
            )
        if privileged_escalation:
            reasons.append(
                f"observed role {observed!r} differs from declared role "
                f"{declared!r} and matches a privileged keyword"
            )
        elif role_mismatch:
            reasons.append(f"observed role {observed!r} differs from declared role {declared!r}")

        findings.append(
            RecordFindingRequest(
                source=HuntSource.AGENTIC,
                domain=HuntDomain.AGENTIC,
                title=(
                    f"Agent identity abuse: "
                    f"{ident.display_name or ident.identity_ref} — "
                    f"{'privileged role escalation' if privileged_escalation else ('out-of-toolset' if out_of_toolset else 'role mismatch')}"
                ),
                description=(
                    f"Agent {ident.identity_ref!r} ({ident.kind}) made call "
                    f"{event.event_id!r}: " + "; ".join(reasons) + ". "
                    "An agent operating outside its declared scope may have been "
                    "hijacked via prompt-injection (see related A1 detections), or "
                    "the underlying credential may be replayed by another principal."
                ),
                severity=severity,
                confidence=confidence,
                technique_ids=technique_ids,
                entities=[
                    HuntEntity(kind="agent_identity", value=ident.identity_ref),
                    HuntEntity(kind="agent_call_event", value=event.event_id),
                ],
                observables=[
                    *(
                        [HuntObservable(type="agent_tool", value=event.invoked_tool)]
                        if event.invoked_tool
                        else []
                    ),
                    *(
                        [HuntObservable(type="cloud_api", value=event.invoked_api)]
                        if event.invoked_api
                        else []
                    ),
                    *(
                        [HuntObservable(type="iam_identity_ref", value=observed)]
                        if observed
                        else []
                    ),
                ],
                evidence={
                    "detection": "agent_identity_abuse",
                    "event_id": event.event_id,
                    "agent_identity_ref": ident.identity_ref,
                    "declared_role": declared or None,
                    "observed_role": observed or None,
                    "declared_tooling": list(ident.tooling),
                    "invoked_tool": event.invoked_tool,
                    "invoked_api": event.invoked_api,
                    "out_of_toolset": out_of_toolset,
                    "role_mismatch": role_mismatch,
                    "privileged_escalation": privileged_escalation,
                    "reasons": reasons,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# A4 — LLM exfil: leaked secrets + oversized outbound prompts (#121 Phase A)
# ---------------------------------------------------------------------------

_T_EXFIL_WEB = "T1567"  # Exfiltration Over Web Service — secrets leaving via inference calls

# Secret-material signatures scanned over both directions of an agent call.
# Pattern names are stable evidence keys; matches are ALWAYS masked before
# they land in finding evidence.
_SECRET_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "aws_access_key_id"),
    (
        re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}"),
        "aws_secret_access_key",
    ),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "github_token"),
    (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----"), "private_key_block"),
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
        "jwt",
    ),
    (
        re.compile(r"(?i)\b(?:api[_-]?key|client[_-]?secret|password)\s*[=:]\s*['\"]?\S{16,}"),
        "generic_credential_assignment",
    ),
]

# Outbound prompts beyond this size are anomalous for interactive agent use
# and a classic bulk-exfil channel (issue #121: "large outbound prompt").
_EXFIL_OVERSIZE_CHARS = 8000


def _mask_secret(match_text: str) -> str:
    """Keep just enough of a matched secret to identify it, never to reuse it."""
    head = match_text[:6]
    return f"{head}…[masked {len(match_text)} chars]"


def detect_llm_exfil(events: Iterable[AgentCallEvent]) -> list[RecordFindingRequest]:
    """Flag secret material and oversized payloads in agent-call bodies.

    Complements the prompt-injection scan (which flags exfil *requests* in
    inputs): this detector flags exfil *material* — actual key/token/secret
    patterns present in either direction, plus abnormally large outbound
    prompts. One finding per event with at least one signal. Matched secrets
    are masked before entering evidence; the raw text stays in the upstream
    telemetry store.
    """
    findings: list[RecordFindingRequest] = []
    for event in events:
        signals: list[dict[str, str]] = []
        for direction, text in (("input", event.input_text), ("output", event.output_text)):
            if not text:
                continue
            for pattern, name in _SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    signals.append(
                        {
                            "pattern": name,
                            "direction": direction,
                            "masked": _mask_secret(match.group(0)),
                        }
                    )
        oversized = len(event.input_text) >= _EXFIL_OVERSIZE_CHARS
        if oversized:
            signals.append(
                {
                    "pattern": "oversized_outbound_prompt",
                    "direction": "input",
                    "masked": f"{len(event.input_text)} chars",
                }
            )
        if not signals:
            continue

        secret_signals = [s for s in signals if s["pattern"] != "oversized_outbound_prompt"]
        if secret_signals:
            # Any real secret is at least HIGH; multiple secrets, a private
            # key, or a secret flowing *outward* in the response escalates.
            critical = (
                len(secret_signals) > 1
                or any(s["pattern"] == "private_key_block" for s in secret_signals)
                or any(s["direction"] == "output" for s in secret_signals)
            )
            severity = Severity.CRITICAL if critical else Severity.HIGH
            confidence = min(1.0, 0.7 + 0.1 * len(secret_signals))
        else:
            severity = Severity.MEDIUM
            confidence = 0.5

        patterns_hit = sorted({s["pattern"] for s in signals})
        entities = [HuntEntity(kind="agent_call_event", value=event.event_id)]
        if event.agent_identity_ref:
            entities.append(HuntEntity(kind="agent_identity", value=event.agent_identity_ref))
        observables: list[HuntObservable] = []
        if event.invoked_tool:
            observables.append(HuntObservable(type="agent_tool", value=event.invoked_tool))

        title = f"LLM exfil signal on agent call {event.event_id}: {patterns_hit[0]}" + (
            f" (+{len(patterns_hit) - 1} more)" if len(patterns_hit) > 1 else ""
        )
        findings.append(
            RecordFindingRequest(
                source=HuntSource.AGENTIC,
                domain=HuntDomain.AGENTIC,
                title=title[:300],
                description=(
                    f"Agent call event {event.event_id!r} "
                    f"(agent={event.agent_identity_ref or 'unknown'}) carried "
                    f"{len(secret_signals)} secret-material signal(s)"
                    + (" and an oversized outbound prompt" if oversized else "")
                    + f". Patterns: {', '.join(patterns_hit)}. Matches are masked in "
                    "evidence; the raw bodies remain only in the upstream telemetry store."
                ),
                severity=severity,
                confidence=confidence,
                technique_ids=[_T_UNSECURED_CREDS, _T_EXFIL_WEB],
                entities=entities,
                observables=observables,
                evidence={
                    "detection": "llm_exfil",
                    "event_id": event.event_id,
                    "agent_identity_ref": event.agent_identity_ref,
                    "patterns": patterns_hit,
                    "signals": signals[:12],
                    "oversized_outbound_prompt": oversized,
                    "input_chars": len(event.input_text),
                    "output_chars": len(event.output_text),
                },
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Convenience: run all detectors over a combined fixture bundle
# ---------------------------------------------------------------------------


def run_all_detectors(
    *,
    events: list[AgentCallEvent] | None = None,
    identities: list[AgentIdentity] | None = None,
    workloads: list[AgenticWorkload] | None = None,
    privileged_role_keywords: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Run every connector-independent agentic detector over a fixture bundle.

    Convenience wrapper for the golden test runner and future engine node.
    Each detection is silently skipped if its required inputs are absent.

    Returns
    -------
    list[RecordFindingRequest]
        All findings from all detectors, unsorted. Deduplication is handled by
        the downstream triage clustering logic (#119).
    """
    findings: list[RecordFindingRequest] = []

    _events = events or []
    _identities = identities or []
    _workloads = workloads or []

    if _events:
        findings.extend(detect_prompt_injection(_events))
        findings.extend(detect_llm_exfil(_events))

    if _workloads or _identities:
        findings.extend(detect_shadow_agents(_workloads, identities=_identities))

    if _events and _identities:
        findings.extend(
            detect_agent_identity_abuse(
                _events,
                _identities,
                privileged_role_keywords=privileged_role_keywords,
            )
        )

    logger.info("Agentic hunt detections complete: %d findings", len(findings))
    return findings
