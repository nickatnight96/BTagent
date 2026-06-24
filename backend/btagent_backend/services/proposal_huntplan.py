"""Compile an accepted pattern-hunt proposal into a runnable HuntPlan (#120 Phase C).

Phase A/B of the Cross-Investigation Pattern Hunter mine weak signals into
:class:`~btagent_shared.types.pattern_hunt.PatternHuntProposal` objects whose
``hunt_input`` is a fully-formed :class:`~btagent_shared.types.hunt.HuntInput`.
Accepting a proposal (Phase B) only flips its state to ``accepted``. Phase C
adds the missing link: turning that ``HuntInput`` into a complete
:class:`~btagent_shared.types.hunt.HuntPlan` — hypotheses, per-TTP runbook
entries with backend queries + noise baselines — so the orchestrator can
actually run it.

This module is the **pure-logic compiler** (Phase C slice 1). It runs the
same engine node pipeline the manual `/hunt` flow uses
(:class:`HypothesisGenNode` → per-TTP :class:`QuerySynthNode` +
:class:`NoiseBaselineNode` → :class:`RunbookCompilerNode`) and returns a
``HuntPlan``. It has **no DB and no network beyond the (mock or injected) LLM
client**, so it unit-tests deterministically under ``BTAGENT_MOCK_LLM=true``.

Persistence (a ``hunt_plans`` table), the ``accept_proposal`` async hook, the
orchestrator execution wiring, and the proposal↔plan back-link are the
follow-up slices (Phase C slices 2–4) and live elsewhere; keeping the compiler
side-effect-free is what lets those slices choose sync vs. async freely.

Engine imports are kept **lazy** (inside the function) so importing this
backend module does not pull the engine's LLM / pySigma stack onto every
backend consumer's import path — the same discipline ``hunt_pack_run_service``
follows.
"""

from __future__ import annotations

import logging

from btagent_shared.types.hunt import Backend, HuntPlan
from btagent_shared.types.pattern_hunt import PatternHuntProposal
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.services.proposal_huntplan")

# Backends to synthesise queries for when a proposal's scope does not pin any.
# Mirrors the connector-tier ordering in #100; DEFENDER/SIGMA are intentionally
# excluded from the default fan-out (DEFENDER overlaps SENTINEL's KQL, SIGMA is
# the source-of-truth pseudo-backend, not an executable target).
_DEFAULT_BACKENDS: tuple[Backend, ...] = (
    Backend.SPLUNK,
    Backend.SENTINEL,
    Backend.ELASTIC,
    Backend.CROWDSTRIKE,
)


async def compile_proposal_to_huntplan(
    proposal: PatternHuntProposal,
    *,
    backends: list[Backend] | None = None,
) -> HuntPlan:
    """Compile a proposal's ``HuntInput`` into a ready-to-run ``HuntPlan``.

    Runs the deterministic-capable engine pipeline:

    1. :class:`HypothesisGenNode` — resolve the HuntInput into prioritised
       hypotheses.
    2. Per hypothesis: :class:`QuerySynthNode` (per-backend queries) +
       :class:`NoiseBaselineNode` (expected-noise profile for the first
       backend). A failure synthesising any single TTP degrades that TTP to
       empty queries / no baseline rather than failing the whole compile —
       the orchestrator's QuerySynth pass can fill the gaps at run time.
    3. :class:`RunbookCompilerNode` — assemble everything into the HuntPlan.

    Args:
        proposal: The accepted pattern-hunt proposal. ``proposal.hunt_input``
            is consumed verbatim (its ``scope.backends`` win over ``backends``
            when present); ``proposal.org_id`` becomes the plan's tenant scope.
        backends: Override for which backends to synthesise queries for when
            the proposal's ``scope.backends`` is empty. Defaults to
            :data:`_DEFAULT_BACKENDS`.

    Returns:
        A :class:`HuntPlan` in ``READY`` state (id ``hunt_<ULID>``), tenant-
        scoped to the proposal's org, carrying the proposal's ``HuntInput``
        (and thus its ``autonomy_level``) unchanged.
    """
    # Lazy engine imports — keep the pysigma/LLM stack off the backend import path.
    from btagent_engine.data import (
        NoiseBaselineInput,
        NoiseBaselineNode,
        RunbookCompilerInput,
        RunbookCompilerNode,
    )
    from btagent_engine.node import NodeContext
    from btagent_engine.reasoning import (
        HypothesisGenInput,
        HypothesisGenNode,
        QuerySynthInput,
        QuerySynthNode,
    )

    hunt_input = proposal.hunt_input
    # Scope-pinned backends win; otherwise fan out to the default set.
    target_backends: list[Backend] = list(hunt_input.scope.backends) or list(
        backends or _DEFAULT_BACKENDS
    )

    ctx = NodeContext(
        run_id=generate_id("hplan"),
        org_id=proposal.org_id,
        user_id=hunt_input.initiated_by or None,
    )

    # 1. Hypotheses.
    hyp_out = await HypothesisGenNode().run(HypothesisGenInput(hunt_input=hunt_input), ctx)
    logger.info(
        "proposal %s -> %d hypotheses (mock_mode=%s)",
        proposal.id,
        len(hyp_out.hypotheses),
        hyp_out.mock_mode,
    )

    # 2. Per-hypothesis query synthesis + noise baseline. Degrade gracefully.
    per_ttp_queries: dict[str, dict[Backend, object]] = {}
    per_ttp_noise: dict[str, object] = {}
    for h in hyp_out.hypotheses:
        try:
            qs_out = await QuerySynthNode().run(
                QuerySynthInput(
                    ttp_id=h.ttp_id,
                    behavioral_description=h.behavioral_description,
                    backends=target_backends,
                ),
                ctx,
            )
            per_ttp_queries[h.ttp_id] = qs_out.queries
        except Exception:  # noqa: BLE001 - one TTP's synth failure must not sink the compile
            logger.warning(
                "query synth failed for proposal %s ttp %s; leaving queries empty",
                proposal.id,
                h.ttp_id,
                exc_info=True,
            )
        try:
            nb_out = await NoiseBaselineNode().run(
                NoiseBaselineInput(ttp_id=h.ttp_id, backend=target_backends[0]),
                ctx,
            )
            per_ttp_noise[h.ttp_id] = nb_out.profile
        except Exception:  # noqa: BLE001 - noise baseline is best-effort enrichment
            logger.warning(
                "noise baseline failed for proposal %s ttp %s; leaving profile default",
                proposal.id,
                h.ttp_id,
                exc_info=True,
            )

    # 3. Assemble the runbook into a HuntPlan.
    rb_out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            plan_id=generate_id("hunt"),
            org_id=proposal.org_id,
            hunt_input=hunt_input,
            hypotheses=hyp_out.hypotheses,
            per_ttp_queries=per_ttp_queries,  # type: ignore[arg-type]
            per_ttp_noise=per_ttp_noise,  # type: ignore[arg-type]
        ),
        ctx,
    )
    plan = rb_out.plan
    logger.info(
        "compiled proposal %s -> plan %s (%d TTP entries, state=%s)",
        proposal.id,
        plan.id,
        len(plan.ttp_entries),
        plan.state,
    )
    return plan
