"""ResponsePlanNode — containment & response playbook generator (EPIC-3 UC-3.2).

Given a confirmed-TP triage verdict (typed intent + severity + entities),
produces a **dual-path** :class:`ResponsePlan`: a strategic NL goal plus a
tactical list of concrete connector-catalog actions.

Safety-by-design:

* **Tactical actions are deterministic, never LLM-invented.** They come
  from a vetted per-intent catalog so the agent can't hallucinate an
  arbitrary destructive action. The LLM (when available) only refines the
  *strategic narrative* (goal + rationale); the executable steps are
  fixed and auditable.
* **Nothing executes.** Every destructive step is flagged
  ``destructive=True`` + ``requires_approval=True`` (adaptive consent) and
  carries a ``rollback`` plan; investigate/document steps are read-only.
  Execution + approver capture is the run-layer's job.
"""

from __future__ import annotations

import os
from typing import ClassVar, NamedTuple

from btagent_shared.types.enums import Severity
from btagent_shared.types.response import (
    ResponseAction,
    ResponseActionType,
    ResponseCategory,
    ResponsePlan,
)
from btagent_shared.types.triage import TypedIntent
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


# --------------------------------------------------------------------------- #
# Per-intent response catalog (vetted, deterministic)
# --------------------------------------------------------------------------- #


class _Spec(NamedTuple):
    category: ResponseCategory
    action_type: ResponseActionType
    connector: str
    destructive: bool
    rollback: str | None  # may contain "{target}"
    entity_kind: str | None  # which entity supplies the target; None = no target
    description: str  # may contain "{target}"


_CONTAIN_TICKET = _Spec(
    ResponseCategory.DOCUMENT,
    ResponseActionType.OPEN_TICKET,
    "servicenow",
    False,
    None,
    None,
    "Open an incident ticket with the triage verdict + evidence",
)

_CATALOG: dict[TypedIntent, list[_Spec]] = {
    TypedIntent.MALWARE_DETECTED: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.ISOLATE_HOST,
            "crowdstrike",
            True,
            "Release {target} from network isolation",
            "host",
            "Isolate {target} to stop spread",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.FORENSIC_SNAPSHOT,
            "crowdstrike",
            False,
            None,
            "host",
            "Capture a forensic snapshot of {target}",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.DATA_EXFIL_SUSPECTED: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.BLOCK_IP,
            "panorama",
            True,
            "Remove {target} from the perimeter blocklist",
            "ip",
            "Block exfil destination {target} at the perimeter",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Pull 24h egress logs for the affected user/host",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.C2_BEACONING: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.BLOCK_IP,
            "panorama",
            True,
            "Remove {target} from the perimeter blocklist",
            "ip",
            "Block C2 destination {target} at the perimeter",
        ),
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.ISOLATE_HOST,
            "crowdstrike",
            True,
            "Release {target} from network isolation",
            "host",
            "Isolate beaconing host {target}",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.PRIVILEGE_ESCALATION: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.DISABLE_ACCOUNT,
            "okta",
            True,
            "Re-enable {target}",
            "user",
            "Disable {target} pending review",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Pull the account's recent role/group changes",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.LATERAL_MOVEMENT: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.ISOLATE_HOST,
            "crowdstrike",
            True,
            "Release {target} from network isolation",
            "host",
            "Isolate source host {target}",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Pull the auth path across the affected hosts",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.SUSPICIOUS_LOGIN: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.DISABLE_ACCOUNT,
            "okta",
            True,
            "Re-enable {target}",
            "user",
            "Disable {target} pending verification",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Pull 24h auth history for the account",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.PHISHING: [
        _Spec(
            ResponseCategory.CONTAIN,
            ResponseActionType.BLOCK_DOMAIN,
            "email_gateway",
            True,
            "Remove {target} from the block list",
            "domain",
            "Block sender/URL domain {target}",
        ),
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Find other recipients of the same campaign",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.RECONNAISSANCE: [
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Profile the scanning source (internal vs. external)",
        ),
        _CONTAIN_TICKET,
    ],
    TypedIntent.POLICY_VIOLATION: [_CONTAIN_TICKET],
    TypedIntent.BENIGN: [
        _Spec(
            ResponseCategory.DOCUMENT,
            ResponseActionType.NOTIFY,
            "slack",
            False,
            None,
            None,
            "Note the benign rationale; tune the detection if noisy",
        ),
    ],
    TypedIntent.UNKNOWN: [
        _Spec(
            ResponseCategory.INVESTIGATE,
            ResponseActionType.PULL_LOGS,
            "splunk",
            False,
            None,
            None,
            "Gather host/user/process context around the alert time",
        ),
        _CONTAIN_TICKET,
    ],
}

_CONTAINMENT_MINUTES: dict[Severity, int | None] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 15,
    Severity.MEDIUM: 30,
    Severity.LOW: 60,
    Severity.INFO: None,
}

_INTENT_PHRASE: dict[TypedIntent, str] = {
    TypedIntent.MALWARE_DETECTED: "the malware infection",
    TypedIntent.DATA_EXFIL_SUSPECTED: "the suspected data exfiltration",
    TypedIntent.C2_BEACONING: "the command-and-control channel",
    TypedIntent.PRIVILEGE_ESCALATION: "the privilege escalation",
    TypedIntent.LATERAL_MOVEMENT: "the lateral movement",
    TypedIntent.SUSPICIOUS_LOGIN: "the suspicious account access",
    TypedIntent.PHISHING: "the phishing campaign",
    TypedIntent.RECONNAISSANCE: "the reconnaissance activity",
    TypedIntent.POLICY_VIOLATION: "the policy violation",
    TypedIntent.BENIGN: "the (benign) activity",
    TypedIntent.UNKNOWN: "the unclassified alert",
}


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #


class ResponsePlanInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    typed_intent: TypedIntent
    severity: Severity = Severity.HIGH
    entities: dict[str, list[str]] = Field(default_factory=dict)


class ResponsePlanOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan: ResponsePlan
    mock_mode: bool = Field(
        ..., description="False only when the LLM refined the strategic narrative."
    )


# --------------------------------------------------------------------------- #
# Deterministic plan builder
# --------------------------------------------------------------------------- #


def _targets(entities: dict[str, list[str]], kind: str | None) -> list[str]:
    if kind is None:
        return [""]
    vals = entities.get(kind) or []
    return vals[:5] if vals else [""]


def _build_actions(intent: TypedIntent, entities: dict[str, list[str]]) -> list[ResponseAction]:
    specs = _CATALOG.get(intent, [_CONTAIN_TICKET])
    actions: list[ResponseAction] = []
    seq = 0
    for spec in specs:
        for target in _targets(entities, spec.entity_kind):
            label = target or (f"the affected {spec.entity_kind}" if spec.entity_kind else "")
            seq += 1
            actions.append(
                ResponseAction(
                    id=f"act_{seq:03d}",
                    category=spec.category,
                    action_type=spec.action_type,
                    target=target,
                    connector=spec.connector,
                    description=spec.description.replace("{target}", label).strip(),
                    destructive=spec.destructive,
                    requires_approval=spec.destructive,  # adaptive consent for destructive
                    rollback=(spec.rollback.replace("{target}", label) if spec.rollback else None),
                )
            )
    return actions


def _build_plan(
    intent: TypedIntent, severity: Severity, entities: dict[str, list[str]]
) -> ResponsePlan:
    actions = _build_actions(intent, entities)
    minutes = _CONTAINMENT_MINUTES.get(severity)
    phrase = _INTENT_PHRASE.get(intent, "the incident")
    contain_targets = sorted(
        {a.target for a in actions if a.category == ResponseCategory.CONTAIN and a.target}
    )
    where = f" on {', '.join(contain_targets)}" if contain_targets else ""
    window = f" within {minutes} minutes" if minutes else ""
    if any(a.category == ResponseCategory.CONTAIN for a in actions):
        goal = f"Contain {phrase}{where} and preserve forensic evidence{window}."
    else:
        goal = f"Investigate and document {phrase}{where}."
    n_destructive = sum(1 for a in actions if a.destructive)
    rationale = (
        f"{len(actions)} step(s) proposed for a {severity.value}-severity {intent.value}; "
        f"{n_destructive} destructive step(s) require explicit approval before execution."
    )
    return ResponsePlan(
        strategic_goal=goal,
        rationale=rationale,
        tactical_steps=actions,
        estimated_containment_minutes=minutes,
    )


# --------------------------------------------------------------------------- #
# Node
# --------------------------------------------------------------------------- #


@NodeRegistry.register
class ResponsePlanNode(Node[ResponsePlanInput, ResponsePlanOutput]):
    """Generate a dual-path containment & response plan (proposal only)."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.response_plan",
        name="Response Playbook Generator",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Generate a dual-path (strategic + tactical) response plan for a "
            "confirmed true positive. Tactical actions come from a vetted "
            "connector catalog (never LLM-invented); destructive steps are "
            "flagged for adaptive-consent approval with rollback. Executes nothing."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = ResponsePlanInput
    output_schema: ClassVar[type[BaseModel]] = ResponsePlanOutput

    async def run(self, input: ResponsePlanInput, ctx: NodeContext) -> ResponsePlanOutput:
        # Tactical steps are ALWAYS deterministic (safety). The LLM, when
        # registered + mock off, only refines the strategic goal + rationale.
        plan = _build_plan(input.typed_intent, input.severity, input.entities)

        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            try:
                narrative = await self._llm_narrative(input, plan, client, ctx)
                if narrative is not None:
                    goal, rationale = narrative
                    plan = plan.model_copy(update={"strategic_goal": goal, "rationale": rationale})
                    return ResponsePlanOutput(plan=plan, mock_mode=False)
            except Exception:  # noqa: BLE001 - LLM failure must degrade, not crash
                import logging

                logging.getLogger("btagent.reasoning.response_plan").warning(
                    "LLM narrative refinement failed; using deterministic plan", exc_info=True
                )
        return ResponsePlanOutput(plan=plan, mock_mode=True)

    async def _llm_narrative(
        self, input: ResponsePlanInput, plan: ResponsePlan, client, ctx
    ) -> tuple[str, str] | None:
        """LLM refines ONLY the strategic goal + rationale (not the actions)."""
        from btagent_shared.types.config import TLP, ModelTier

        from btagent_engine.reasoning._llm_json import call_llm_json, wrap_external_data

        system = (
            "You are an incident-response lead. Given an incident summary and a "
            "fixed list of proposed response actions, write a crisp strategic "
            "containment goal and a one-sentence rationale. Respond ONLY with a "
            'JSON object: {"strategic_goal": str, "rationale": str}. Do NOT invent '
            "new actions; the action list is fixed and authoritative."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            tlp = TLP.RED  # fail closed
        steps = "; ".join(
            f"{a.action_type.value}->{a.target or 'n/a'}" for a in plan.tactical_steps
        )
        user = wrap_external_data(
            f"intent: {input.typed_intent.value}\nseverity: {input.severity.value}\n"
            f"entities: {input.entities}\nproposed_actions: {steps}"
        )
        raw = await call_llm_json(
            client, system=system, user=user, tlp=tlp, tier=ModelTier.STANDARD, array=False
        )
        if not isinstance(raw, dict):
            return None
        goal = str(raw.get("strategic_goal") or "").strip()
        rationale = str(raw.get("rationale") or "").strip()
        if not goal:
            return None
        return goal, rationale or plan.rationale


__all__ = [
    "ResponsePlanInput",
    "ResponsePlanNode",
    "ResponsePlanOutput",
]
