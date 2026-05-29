"""AlertTriageNode — autonomous alert triage (EPIC-3 UC-3.1).

Takes a raw SIEM/EDR alert and returns a *reviewed case*: a classified
:class:`TypedIntent`, a proposed severity + disposition, a confidence
score, a plain-English explanation, an evidence trail, and 2–3
recommended next steps. The node is **read-only / advisory** — it never
executes a containment action; the analyst approves the disposition and
each next step (HITL is enforced at the run layer, not here).

Design (matches the other reasoning nodes):

1. **Mock mode is deterministic.** ``BTAGENT_MOCK_LLM`` defaults on; the
   mock path classifies via high-precision keyword rules over the alert
   text + entities, so tests/CI/local never need an LLM key.
2. **Client-or-deterministic.** When a real LLM client is registered and
   mock mode is off, the node classifies via a structured-output call
   (alert text XML-fenced as untrusted input); on any failure (or no
   client) it falls back to the deterministic classifier. It never raises.
3. **Severity redetermination.** High-risk intents (malware, exfil, C2,
   privilege escalation, lateral movement) and strong suspicious-login
   signals raise severity above the source-reported level
   (UC-3.1 acceptance criterion), flagged via ``severity_escalated``.
"""

from __future__ import annotations

import os
import re
from typing import ClassVar

from btagent_shared.types.enums import Severity
from btagent_shared.types.triage import (
    Alert,
    NextStep,
    TriageDisposition,
    TriageResult,
    TypedIntent,
)
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _mock_mode_enabled() -> bool:
    # Fail-safe: mock stays on unless explicitly disabled, so a misconfig
    # never routes a real LLM call out by accident.
    return os.getenv("BTAGENT_MOCK_LLM", "true").strip().lower() != "false"


# --------------------------------------------------------------------------- #
# Classification tables
# --------------------------------------------------------------------------- #

# Severity ordering for "raise to at least X" comparisons.
_SEV_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}
_RANK_SEV = {v: k for k, v in _SEV_RANK.items()}

# Intents that always warrant at least HIGH (confirmed-bad-shaped activity).
_HIGH_RISK: frozenset[TypedIntent] = frozenset(
    {
        TypedIntent.MALWARE_DETECTED,
        TypedIntent.DATA_EXFIL_SUSPECTED,
        TypedIntent.C2_BEACONING,
        TypedIntent.PRIVILEGE_ESCALATION,
        TypedIntent.LATERAL_MOVEMENT,
    }
)

# Ordered, high-precision intent rules. Checked most-specific/severe first;
# the first matching rule wins the classification, but *all* matched labels
# across rules are collected into the evidence trail.
_INTENT_RULES: list[tuple[TypedIntent, re.Pattern[str], str]] = [
    (
        TypedIntent.MALWARE_DETECTED,
        re.compile(
            r"\b(ransomware|malware|trojan|virus|payload|quarantin\w*|malicious\s+file|encrypt(?:ed|ing)\s+files?)\b",
            re.I,
        ),
        "malware keyword",
    ),
    (
        TypedIntent.DATA_EXFIL_SUSPECTED,
        re.compile(
            r"\b(exfiltrat\w*|data\s+(?:loss|transfer|exfil)|dlp|large\s+(?:upload|outbound)|staging\s+archive)\b",
            re.I,
        ),
        "exfil keyword",
    ),
    (
        TypedIntent.C2_BEACONING,
        re.compile(
            r"\b(beacon(?:ing)?|command[\s-]and[\s-]control|c2\b|cobalt\s*strike|periodic\s+callback)\b",
            re.I,
        ),
        "C2 keyword",
    ),
    (
        TypedIntent.PRIVILEGE_ESCALATION,
        re.compile(
            r"\b(privilege\s+escalation|privesc|uac\s+bypass|token\s+manipulation|added\s+to\s+(?:domain\s+)?admins?)\b",
            re.I,
        ),
        "privesc keyword",
    ),
    (
        TypedIntent.LATERAL_MOVEMENT,
        re.compile(
            r"\b(lateral\s+movement|psexec|wmic|pass[\s-]the[\s-]hash|remote\s+service\s+creation|smb\s+(?:exec|admin))\b",
            re.I,
        ),
        "lateral-movement keyword",
    ),
    (
        TypedIntent.PHISHING,
        re.compile(
            r"\b((?:spear)?phish\w*|malicious\s+attachment|suspicious\s+(?:email|link)|credential\s+harvest\w*)\b",
            re.I,
        ),
        "phishing keyword",
    ),
    (
        TypedIntent.RECONNAISSANCE,
        re.compile(
            r"\b(port\s+scan|network\s+scan|nmap|enumerat\w*|reconnaissance|discovery\s+activity)\b",
            re.I,
        ),
        "recon keyword",
    ),
    (
        TypedIntent.SUSPICIOUS_LOGIN,
        re.compile(
            r"\b(failed\s+log(?:in|on)|brute[\s-]?force|password\s+spray|impossible\s+travel|anomalous\s+(?:login|sign[\s-]?in)|mfa\s+(?:fail|fatigue)|unusual\s+sign[\s-]?in)\b",
            re.I,
        ),
        "suspicious-login keyword",
    ),
    (
        TypedIntent.POLICY_VIOLATION,
        re.compile(
            r"\b(policy\s+violation|unauthori[sz]ed\s+software|usb\s+(?:device|mass\s+storage)|blocked\s+by\s+policy)\b",
            re.I,
        ),
        "policy keyword",
    ),
    (
        TypedIntent.BENIGN,
        re.compile(
            r"\b(known[\s-]good|whitelist\w*|expected\s+maintenance|approved\s+change|test\s+alert)\b",
            re.I,
        ),
        "benign marker",
    ),
]

# Signals that escalate a suspicious login specifically (low -> high).
_LOGIN_ESCALATORS = re.compile(
    r"\b(impossible\s+travel|password\s+spray|brute[\s-]?force|mfa\s+fatigue)\b", re.I
)

# Per-intent recommended next steps (read-only investigation, never containment).
_NEXT_STEPS: dict[TypedIntent, list[NextStep]] = {
    TypedIntent.MALWARE_DETECTED: [
        NextStep(
            action="Pull the process tree + file hash reputation for the affected host",
            rationale="Confirm execution chain and whether the binary is known-bad.",
        ),
        NextStep(
            action="Check for the same hash/host across the fleet",
            rationale="Scope the blast radius before proposing containment.",
        ),
        NextStep(
            action="Review EDR detection timeline for the host",
            rationale="Establish first-seen and any prior related detections.",
        ),
    ],
    TypedIntent.DATA_EXFIL_SUSPECTED: [
        NextStep(
            action="Correlate outbound volume by destination and user over 24h",
            rationale="Distinguish a real transfer from normal backup/sync traffic.",
        ),
        NextStep(
            action="Identify the data classification of the source",
            rationale="Determine sensitivity / TLP of what may have left.",
        ),
        NextStep(
            action="Check the destination against TI + the egress allowlist",
            rationale="Confirm whether the endpoint is known-malicious or sanctioned.",
        ),
    ],
    TypedIntent.C2_BEACONING: [
        NextStep(
            action="Pull the periodicity + JA3/TLS fingerprint for the connection",
            rationale="Beacon jitter and fingerprint confirm C2 vs. benign polling.",
        ),
        NextStep(
            action="Enrich the destination IP/domain via TI (VirusTotal/GreyNoise)",
            rationale="Establish reputation and known-actor association.",
        ),
        NextStep(
            action="List other hosts contacting the same destination",
            rationale="Scope the campaign footprint.",
        ),
    ],
    TypedIntent.PRIVILEGE_ESCALATION: [
        NextStep(
            action="Review the account's group/role changes in the last 7 days",
            rationale="Confirm whether elevation was sanctioned.",
        ),
        NextStep(
            action="Pull the parent process / technique that triggered the alert",
            rationale="Map to the ATT&CK privilege-escalation sub-technique.",
        ),
    ],
    TypedIntent.LATERAL_MOVEMENT: [
        NextStep(
            action="Map the source→destination auth path for the user",
            rationale="Confirm an abnormal movement pattern across hosts.",
        ),
        NextStep(
            action="Check for credential-dumping precursors on the source host",
            rationale="Lateral movement often follows credential access.",
        ),
    ],
    TypedIntent.PHISHING: [
        NextStep(
            action="Retrieve the message + attachment/URL and detonate in a sandbox",
            rationale="Confirm maliciousness before recommending mailbox actions.",
        ),
        NextStep(
            action="Find other recipients of the same campaign",
            rationale="Scope exposure across the org.",
        ),
    ],
    TypedIntent.RECONNAISSANCE: [
        NextStep(
            action="Profile the scanning source (internal asset vs. external)",
            rationale="Internal scans may be sanctioned vuln management.",
        ),
        NextStep(
            action="Check whether the source is on the known-scanner allowlist",
            rationale="Suppress sanctioned scanners.",
        ),
    ],
    TypedIntent.SUSPICIOUS_LOGIN: [
        NextStep(
            action="Pull 24h auth history + geo/ASN for the user",
            rationale="Establish baseline vs. anomalous access.",
        ),
        NextStep(
            action="Check whether MFA was satisfied and from which device",
            rationale="Distinguish credential compromise from a routine new-device login.",
        ),
        NextStep(
            action="Look for follow-on privilege or data access by the account",
            rationale="Detect post-compromise activity.",
        ),
    ],
    TypedIntent.POLICY_VIOLATION: [
        NextStep(
            action="Confirm the policy and the user/asset it applies to",
            rationale="Validate the violation is in scope.",
        ),
    ],
    TypedIntent.BENIGN: [
        NextStep(
            action="Document the benign rationale and tune the detection if noisy",
            rationale="Reduce future false positives.",
        ),
    ],
    TypedIntent.UNKNOWN: [
        NextStep(
            action="Gather host/user/process context around the alert time",
            rationale="Insufficient signal to classify — pull context for manual review.",
        ),
    ],
}


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class AlertTriageInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alert: Alert


class AlertTriageOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    result: TriageResult
    mock_mode: bool = Field(
        ..., description="Whether the deterministic classifier produced this result."
    )


# --------------------------------------------------------------------------- #
# Deterministic classifier
# --------------------------------------------------------------------------- #


def _haystack(alert: Alert) -> str:
    parts = [alert.title, alert.description]
    for vals in alert.entities.values():
        parts.extend(vals)
    return " \n ".join(p for p in parts if p)


def _classify(alert: Alert) -> TriageResult:
    text = _haystack(alert)
    matched: list[tuple[TypedIntent, str]] = [
        (intent, label) for intent, pat, label in _INTENT_RULES if pat.search(text)
    ]
    evidence = [label for _, label in matched]

    intent = matched[0][0] if matched else TypedIntent.UNKNOWN

    # Severity redetermination.
    source_rank = _SEV_RANK[alert.severity]
    proposed_rank = source_rank
    escalated = False
    if intent in _HIGH_RISK:
        floor = (
            _SEV_RANK[Severity.CRITICAL]
            if intent
            in {
                TypedIntent.MALWARE_DETECTED,
                TypedIntent.DATA_EXFIL_SUSPECTED,
            }
            else _SEV_RANK[Severity.HIGH]
        )
        if proposed_rank < floor:
            proposed_rank = floor
            escalated = True
    elif intent == TypedIntent.SUSPICIOUS_LOGIN and _LOGIN_ESCALATORS.search(text):
        if proposed_rank < _SEV_RANK[Severity.HIGH]:
            proposed_rank = _SEV_RANK[Severity.HIGH]
            escalated = True
        evidence.append("login-escalator signal")
    proposed_severity = _RANK_SEV[proposed_rank]

    # Disposition.
    if intent in _HIGH_RISK:
        disposition = TriageDisposition.ESCALATE
    elif intent == TypedIntent.BENIGN:
        disposition = TriageDisposition.CLOSE_BENIGN
    elif intent == TypedIntent.POLICY_VIOLATION:
        disposition = TriageDisposition.MONITOR
    elif intent in {TypedIntent.SUSPICIOUS_LOGIN, TypedIntent.PHISHING}:
        disposition = TriageDisposition.ESCALATE if escalated else TriageDisposition.INVESTIGATE
    else:  # RECON, UNKNOWN
        disposition = TriageDisposition.INVESTIGATE

    # Confidence: more matched signals + relevant entities -> higher.
    entity_count = sum(len(v) for v in alert.entities.values())
    confidence = 0.45 + 0.15 * len(matched) + (0.1 if entity_count else 0.0)
    if intent == TypedIntent.UNKNOWN:
        confidence = 0.3
    confidence = round(min(confidence, 0.95), 2)

    explanation = _explain(intent, evidence, escalated, alert.severity, proposed_severity)
    next_steps = _NEXT_STEPS.get(intent, _NEXT_STEPS[TypedIntent.UNKNOWN])[:3]

    return TriageResult(
        typed_intent=intent,
        proposed_severity=proposed_severity,
        disposition=disposition,
        confidence=confidence,
        explanation=explanation,
        next_steps=next_steps,
        evidence=evidence,
        severity_escalated=escalated,
    )


def _explain(
    intent: TypedIntent,
    evidence: list[str],
    escalated: bool,
    source_sev: Severity,
    proposed_sev: Severity,
) -> str:
    if intent == TypedIntent.UNKNOWN:
        base = "No high-precision signal matched; classified as UNKNOWN pending analyst context-gathering."
    else:
        sig = ", ".join(evidence) or "matched signals"
        base = f"Classified as {intent.value} based on: {sig}."
    if escalated:
        base += (
            f" Severity redetermined {source_sev.value} → {proposed_sev.value}: "
            "the matched pattern is consistent with confirmed-bad activity."
        )
    return base


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #


@NodeRegistry.register
class AlertTriageNode(Node[AlertTriageInput, AlertTriageOutput]):
    """Auto-triage a raw alert into a reviewed case (read-only / advisory)."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.alert_triage",
        name="Alert Triage Agent",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Classify a raw alert into a Typed Intent with a proposed severity, "
            "disposition, confidence, explanation, evidence trail, and 2–3 "
            "recommended next steps. Read-only — the analyst approves every action."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = AlertTriageInput
    output_schema: ClassVar[type[BaseModel]] = AlertTriageOutput

    async def run(self, input: AlertTriageInput, ctx: NodeContext) -> AlertTriageOutput:
        # Client-or-deterministic: LLM classifies when registered + mock off;
        # otherwise the deterministic keyword classifier. Never hard-raise.
        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            try:
                result = await self._llm_classify(input.alert, client, ctx)
                if result is not None:
                    return AlertTriageOutput(result=result, mock_mode=False)
            except Exception:  # noqa: BLE001 - LLM failure must degrade, not crash
                import logging

                logging.getLogger("btagent.reasoning.alert_triage").warning(
                    "LLM triage failed; falling back to deterministic classifier",
                    exc_info=True,
                )
        return AlertTriageOutput(result=_classify(input.alert), mock_mode=True)

    async def _llm_classify(self, alert: Alert, client, ctx) -> TriageResult | None:
        """LLM classification -> TriageResult, or None on any failure."""
        from btagent_shared.types.config import TLP, ModelTier

        from btagent_engine.reasoning._llm_json import call_llm_json, wrap_external_data

        system = (
            "You are a SOC alert-triage analyst. Classify the alert and respond "
            "ONLY with a JSON object (no prose) with keys: "
            '"typed_intent" (one of: ' + "/".join(i.value for i in TypedIntent) + "), "
            '"proposed_severity" (critical/high/medium/low/info), '
            '"disposition" (escalate/investigate/monitor/close_benign/close_false_positive), '
            '"confidence" (0..1 float), "explanation" (one sentence), '
            '"next_steps" (list of {"action","rationale"}, 2-3 items), '
            '"evidence" (list of short strings). You investigate read-only; never '
            "recommend executing containment without analyst approval."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            tlp = TLP.RED  # fail closed
        user = wrap_external_data(
            f"source: {alert.source}\nseverity: {alert.severity.value}\n"
            f"title: {alert.title}\ndescription: {alert.description}\n"
            f"entities: {alert.entities}"
        )
        raw = await call_llm_json(
            client, system=system, user=user, tlp=tlp, tier=ModelTier.STANDARD, array=False
        )
        if not isinstance(raw, dict):
            return None
        try:
            steps = [
                NextStep(action=str(s.get("action", "")), rationale=str(s.get("rationale", "")))
                for s in (raw.get("next_steps") or [])
                if isinstance(s, dict) and s.get("action")
            ][:3]
            return TriageResult(
                typed_intent=TypedIntent(str(raw["typed_intent"]).lower()),
                proposed_severity=Severity(str(raw["proposed_severity"]).lower()),
                disposition=TriageDisposition(str(raw["disposition"]).lower()),
                confidence=max(0.0, min(1.0, float(raw.get("confidence", 0.5)))),
                explanation=str(raw.get("explanation", "")),
                next_steps=steps or _NEXT_STEPS[TypedIntent.UNKNOWN][:1],
                evidence=[str(e) for e in (raw.get("evidence") or [])][:10],
                severity_escalated=_SEV_RANK.get(Severity(str(raw["proposed_severity"]).lower()), 0)
                > _SEV_RANK[alert.severity],
            )
        except (KeyError, ValueError, TypeError):
            return None


__all__ = [
    "AlertTriageInput",
    "AlertTriageNode",
    "AlertTriageOutput",
]
