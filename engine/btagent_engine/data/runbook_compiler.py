"""RunbookCompilerNode — assemble hypotheses into a HuntPlan.

Pure data-shaping step (no LLM, no vendor I/O). Takes the output of
HypothesisGenNode plus any per-TTP enrichments (queries, noise
baselines, evidence checklists) and emits a complete HuntPlan ready
for analyst execution.

Design notes:

1. **Idempotent.** Calling the node twice with the same inputs produces
   byte-equal HuntPlan output (modulo created_at / updated_at). That
   lets the runner cache the result for replay / diff views.

2. **No data invention.** If a query or noise baseline isn't supplied
   for a TTP, the corresponding fields stay empty. The Phase B
   QuerySynth and NoiseBaseline nodes are responsible for populating
   them; the compiler is just the assembler.

3. **Pivot questions + evidence checklist come from a built-in
   library.** A small ATT&CK-keyed dict covers the common techniques
   well enough for the demo. Per-org overrides can extend this in a
   future commit without breaking the schema.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import ClassVar
from uuid import uuid4

from btagent_shared.types.hunt import (
    Backend,
    CorrelationRule,
    ExecSummary,
    HuntInput,
    HuntPlan,
    HuntPlanState,
    Hypothesis,
    NoiseProfile,
    PostHuntAction,
    Query,
    TTPRunbookEntry,
    TTPState,
)
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Built-in pivot / evidence libraries
# ---------------------------------------------------------------------------

# Pivot-question templates by ATT&CK technique. If a TTP isn't here we
# fall back to a generic three-question set. Each per-TTP list is
# ordered by what an L2 analyst typically asks next.
_PIVOTS_BY_TTP: dict[str, list[str]] = {
    "T1059.001": [
        "Does the parent process include winword.exe / outlook.exe / browser process?",
        "Is the decoded -EncodedCommand on the known-bad PowerShell list?",
        "Did the host beacon outbound within 5min of the PowerShell event?",
    ],
    "T1078.004": [
        "Is the source IP on a known-bad cloud-egress list?",
        "Was there a successful login from this IP in the last 30 days?",
        "Were any privileged operations performed within the session?",
    ],
    "T1566.001": [
        "Was an attachment opened from the email?",
        "Did a child process spawn from the document?",
        "Did the user click a link in the body?",
    ],
    "T1190": [
        "Which public-facing service was the target?",
        "Is the exploit pattern in the WAF logs?",
        "Did the process tree show post-exploit behaviour?",
    ],
    "T1486": [
        "Were file-system entropy spikes detected?",
        "Are ransom notes present anywhere on the host?",
        "Were shadow copies deleted?",
    ],
}

_PIVOTS_FALLBACK = [
    "Is this activity present on more than one host in the same time window?",
    "Does the user / asset show prior history of similar events?",
    "Are there any other ATT&CK techniques co-occurring with this hit?",
]

# Evidence-collection checklists. Same fallback approach.
_EVIDENCE_BY_TTP: dict[str, list[str]] = {
    "T1059.001": [
        "Full process tree (parent -> child -> grandchild)",
        "Decoded base64 of -EncodedCommand argument",
        "Outbound net connections from the powershell PID",
        "Module load events (AMSI, .NET)",
        "User account context (interactive vs service)",
    ],
    "T1078.004": [
        "Source IP geolocation + ISP",
        "Session token / cookie id",
        "Subsequent API calls within the session",
        "MFA challenge log entries",
    ],
    "T1566.001": [
        "Email headers (full)",
        "Attachment hashes + reputation",
        "Recipient list (other users targeted)",
        "Sender SPF / DKIM / DMARC results",
    ],
    "T1190": [
        "WAF / proxy logs around the event window",
        "Vulnerable application version",
        "Post-exploit process tree",
        "Network egress from the compromised service",
    ],
    "T1486": [
        "Ransom note text + dropper location",
        "Shadow-copy deletion log",
        "Process responsible for encryption",
        "Affected file paths + counts",
    ],
}

_EVIDENCE_FALLBACK = [
    "Original alert payload",
    "Process tree at event time",
    "Network connections from involved host(s)",
    "Affected user / asset identifiers",
]


# Cross-TTP correlation rules emitted by default. Real per-org rules
# will load from config in a follow-up; these are sensible defaults.
def _default_correlation_rules() -> list[CorrelationRule]:
    return [
        CorrelationRule(
            id="corr_co_t1059_001_t1078_004",
            description="PowerShell + cloud-account use on the same host within 24h.",
            trigger=("Both T1059.001 and T1078.004 land hits on the same host within 24h."),
            action="escalate_to_ir",
        ),
        CorrelationRule(
            id="corr_multi_ttp_burst",
            description=(
                "Three or more uncorrelated TTP hits within the same scope "
                "window — likely an active intrusion."
            ),
            trigger="3+ TTPs hit within the scope's date window.",
            action="spawn_investigation",
        ),
    ]


# Post-hunt actions emitted by default. These wire the hunt back into
# the rest of the platform per the #98 closed-loop bet.
def _default_post_actions() -> list[PostHuntAction]:
    return [
        PostHuntAction(
            kind="index_case_lesson",
            description=(
                "On hunt completion, summarise outcomes into a case lesson "
                "and index into the RAG knowledge base."
            ),
        ),
        PostHuntAction(
            kind="propose_detection",
            description=(
                "For any uncovered TTP that ran a clean hunt, file a draft "
                "detection rule proposal for engineer review."
            ),
        ),
        PostHuntAction(
            kind="update_coverage_map",
            description=(
                "Mark each exercised TTP in the MITRE coverage map so the "
                "'untested for >90 days' surface stays accurate."
            ),
        ),
    ]


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class RunbookCompilerInput(BaseModel):
    """Inputs the compiler needs to assemble a HuntPlan.

    ``per_ttp_queries`` and ``per_ttp_noise`` are keyed by TTP id and
    optional — when absent the compiler emits the runbook entry with
    empty queries / no noise profile, and downstream nodes
    (QuerySynth, NoiseBaseline) fill them in later.
    """

    model_config = ConfigDict(extra="forbid")

    plan_id: str | None = Field(
        default=None,
        description="Plan id to use. If None, generated from a uuid4 prefix.",
    )
    org_id: str = Field(..., description="Tenant scope.")
    hunt_input: HuntInput
    hypotheses: list[Hypothesis] = Field(
        ...,
        description="Output of the HypothesisGen node.",
    )
    per_ttp_queries: dict[str, dict[Backend, Query]] = Field(
        default_factory=dict,
        description="TTP id -> backend -> Query.",
    )
    per_ttp_noise: dict[str, NoiseProfile] = Field(
        default_factory=dict,
        description="TTP id -> noise baseline (from NoiseBaseline node).",
    )
    coverage_delta: dict[str, bool] = Field(
        default_factory=dict,
        description=(
            "TTP id -> already_covered_by_deployed_detection. From the "
            "detection-engineering canvas (#98 Bet 1)."
        ),
    )


class RunbookCompilerOutput(BaseModel):
    """Output — the assembled HuntPlan."""

    model_config = ConfigDict(extra="forbid")

    plan: HuntPlan


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class RunbookCompilerNode(Node[RunbookCompilerInput, RunbookCompilerOutput]):
    """Assemble hypotheses + per-TTP context into a full HuntPlan."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.runbook_compiler",
        name="Runbook Compiler",
        version="0.1.0",
        category=NodeCategory.DATA,
        description=(
            "Assemble HypothesisGen output + per-TTP queries + noise "
            "baselines into a complete HuntPlan."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = RunbookCompilerInput
    output_schema: ClassVar[type[BaseModel]] = RunbookCompilerOutput

    async def run(
        self,
        input: RunbookCompilerInput,
        ctx: NodeContext,
    ) -> RunbookCompilerOutput:
        plan_id = input.plan_id or self._gen_plan_id()

        ttp_entries = [
            self._entry_from_hypothesis(
                h,
                queries=input.per_ttp_queries.get(h.ttp_id, {}),
                noise=input.per_ttp_noise.get(h.ttp_id, NoiseProfile()),
            )
            for h in input.hypotheses
        ]

        executive_summary = ExecSummary(
            adversary_profile=self._summarise_adversaries(input.hunt_input),
            scope_description=self._summarise_scope(input.hunt_input),
            success_criteria=(
                "A 'hit' is one or more findings on any TTP query. A 'clean' "
                "hunt is all TTPs queried with no findings."
            ),
            estimated_effort_hours=self._estimate_effort(ttp_entries),
            coverage_delta=input.coverage_delta,
        )

        plan = HuntPlan(
            id=plan_id,
            org_id=input.org_id,
            input=input.hunt_input,
            state=HuntPlanState.READY,
            executive_summary=executive_summary,
            hypotheses=input.hypotheses,
            ttp_entries=ttp_entries,
            correlation_rules=_default_correlation_rules(),
            post_actions=_default_post_actions(),
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        return RunbookCompilerOutput(plan=plan)

    # --- Helpers ----------------------------------------------------------- #

    @staticmethod
    def _gen_plan_id() -> str:
        # ULID-like prefix; full ULID generation belongs in shared utils,
        # so for now a uuid4 short prefix is fine — collisions are
        # vanishingly unlikely at the scale of one org's hunt history.
        return f"hunt_{uuid4().hex[:24]}"

    @staticmethod
    def _entry_from_hypothesis(
        h: Hypothesis,
        *,
        queries: dict[Backend, Query],
        noise: NoiseProfile,
    ) -> TTPRunbookEntry:
        pivots = _PIVOTS_BY_TTP.get(h.ttp_id, _PIVOTS_FALLBACK)
        evidence = _EVIDENCE_BY_TTP.get(h.ttp_id, _EVIDENCE_FALLBACK)
        return TTPRunbookEntry(
            ttp_id=h.ttp_id,
            ttp_name=h.ttp_name,
            rationale=h.rationale,
            behavioral_description=h.behavioral_description,
            queries=queries,
            expected_noise=noise,
            pivot_questions=list(pivots),
            evidence_checklist=list(evidence),
            state=TTPState.NOT_STARTED,
        )

    @staticmethod
    def _summarise_adversaries(hi: HuntInput) -> str:
        if not hi.adversaries:
            return "No named adversary; hunt is driven by explicit TTPs / IOCs."
        joined = ", ".join(hi.adversaries)
        return f"Hunting for activity consistent with: {joined}."

    @staticmethod
    def _summarise_scope(hi: HuntInput) -> str:
        scope = hi.scope
        parts: list[str] = []
        if scope.environments:
            parts.append(f"environments: {', '.join(scope.environments)}")
        if scope.hosts:
            parts.append(f"hosts: {len(scope.hosts)} explicit")
        if scope.date_from and scope.date_to:
            parts.append(f"window: {scope.date_from.isoformat()} -> {scope.date_to.isoformat()}")
        if scope.backends:
            parts.append("backends: " + ", ".join(b.value for b in scope.backends))
        if not parts:
            return "All in-scope environments, last 7 days, all configured backends."
        return "; ".join(parts) + "."

    @staticmethod
    def _estimate_effort(entries: list[TTPRunbookEntry]) -> float:
        # Coarse heuristic: 0.25h per TTP that already has a query
        # synthesised, 0.5h per TTP without one (analyst will have to
        # write it). Drop a real model in when we have execution data.
        if not entries:
            return 0.0
        synthed = sum(1 for e in entries if e.queries)
        unsynthed = len(entries) - synthed
        return round(0.25 * synthed + 0.5 * unsynthed, 2)


NodeRegistry.register(RunbookCompilerNode)


# Re-export hashlib helper symbol for tests that want deterministic
# expectations on plan ids (kept private otherwise).
__all__ = [
    "RunbookCompilerInput",
    "RunbookCompilerNode",
    "RunbookCompilerOutput",
]


def _content_hash(*parts: str) -> str:  # noqa: D401 - utility, not user-facing
    """Stable short hash over content parts. Reserved for future use."""
    h = hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()
    return h[:8]
