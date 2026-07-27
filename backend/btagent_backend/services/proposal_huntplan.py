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
from collections.abc import Callable

from btagent_shared.types.hunt import Backend, HuntInput, HuntPlan
from btagent_shared.types.pattern_hunt import PatternHuntProposal
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.services.proposal_huntplan")

# Adversary -> technique-set resolver, injected into the HypothesisGen node so
# named actors resolve against the seeded ``mitre_groups`` mapping (built by
# ``mitre_service.build_adversary_ttp_resolver``). ``None`` keeps the node on
# its built-in stock fallback — the DB-free unit-test path.
AdversaryResolver = Callable[[str], list[tuple[str, str]] | None]

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
    adversary_resolver: AdversaryResolver | None = None,
    deployed_technique_ids: set[str] | None = None,
) -> HuntPlan:
    """Compile a proposal's ``HuntInput`` into a ready-to-run ``HuntPlan``.

    Thin wrapper over :func:`compile_huntinput_to_huntplan` — the proposal
    contributes its ``hunt_input`` verbatim, its ``org_id`` as tenant scope,
    and its id as the log reference. ``adversary_resolver`` and
    ``deployed_technique_ids`` are forwarded unchanged (the caller builds them
    from the DB before invoking this side-effect-free compiler).
    """
    return await compile_huntinput_to_huntplan(
        proposal.hunt_input,
        org_id=proposal.org_id,
        backends=backends,
        log_ref=f"proposal {proposal.id}",
        adversary_resolver=adversary_resolver,
        deployed_technique_ids=deployed_technique_ids,
    )


async def compile_huntinput_to_huntplan(
    hunt_input: HuntInput,
    *,
    org_id: str,
    backends: list[Backend] | None = None,
    log_ref: str = "direct",
    adversary_resolver: AdversaryResolver | None = None,
    deployed_technique_ids: set[str] | None = None,
) -> HuntPlan:
    """Compile a raw ``HuntInput`` into a ready-to-run ``HuntPlan`` (#99 Phase A).

    The same pipeline serves both entry points: pattern-hunt proposals
    (via :func:`compile_proposal_to_huntplan`) and the direct
    ``POST /hunts/plan`` route where the analyst names adversaries / TTPs
    themselves.

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
        hunt_input: What to hunt for. ``scope.backends`` wins over
            ``backends`` when present.
        org_id: Tenant scope for the resulting plan.
        backends: Override for which backends to synthesise queries for when
            the input's ``scope.backends`` is empty. Defaults to
            :data:`_DEFAULT_BACKENDS`.
        log_ref: Human-readable provenance tag for log lines.
        adversary_resolver: Optional sync resolver (built by the caller from
            the seeded ``mitre_groups`` table) that maps a named actor to its
            real technique set. Injected into :class:`HypothesisGenNode`; when
            ``None`` the node uses its built-in stock fallback.
        deployed_technique_ids: Optional set of techniques the org already
            covers with a deployed detection (built by the caller from
            ``cti_detection_service.get_deployed_technique_ids``). When
            provided, the compiler cross-references each hypothesis's technique
            and populates :attr:`ExecSummary.coverage_delta` (``ttp_id ->
            already_covered``). When ``None`` the delta is left empty.

    Returns:
        A :class:`HuntPlan` in ``READY`` state (id ``hunt_<ULID>``), tenant-
        scoped to ``org_id``, carrying the ``HuntInput`` (and thus its
        ``autonomy_level``) unchanged.
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

    # Scope-pinned backends win; otherwise fan out to the default set.
    target_backends: list[Backend] = list(hunt_input.scope.backends) or list(
        backends or _DEFAULT_BACKENDS
    )

    ctx = NodeContext(
        run_id=generate_id("hplan"),
        org_id=org_id,
        user_id=hunt_input.initiated_by or None,
    )

    # 1. Hypotheses. The injected resolver (when present) pulls a named actor's
    # real technique set from the seeded mitre_groups mapping; otherwise the
    # node falls back to its built-in stock set.
    hyp_out = await HypothesisGenNode(adversary_resolver=adversary_resolver).run(
        HypothesisGenInput(hunt_input=hunt_input), ctx
    )
    logger.info(
        "%s -> %d hypotheses (mock_mode=%s)",
        log_ref,
        len(hyp_out.hypotheses),
        hyp_out.mock_mode,
    )

    # Coverage cross-reference: for every hypothesised technique, is it already
    # covered by a deployed detection? Populates ExecSummary.coverage_delta so
    # the IC sees which hunted TTPs are dark vs. already alerting. Skipped
    # (empty) when the caller didn't supply the deployed set.
    coverage_delta: dict[str, bool] = {}
    if deployed_technique_ids is not None:
        coverage_delta = {h.ttp_id: h.ttp_id in deployed_technique_ids for h in hyp_out.hypotheses}

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
                "query synth failed for %s ttp %s; leaving queries empty",
                log_ref,
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
                "noise baseline failed for %s ttp %s; leaving profile default",
                log_ref,
                h.ttp_id,
                exc_info=True,
            )

    # 3. Assemble the runbook into a HuntPlan.
    rb_out = await RunbookCompilerNode().run(
        RunbookCompilerInput(
            plan_id=generate_id("hunt"),
            org_id=org_id,
            hunt_input=hunt_input,
            hypotheses=hyp_out.hypotheses,
            per_ttp_queries=per_ttp_queries,  # type: ignore[arg-type]
            per_ttp_noise=per_ttp_noise,  # type: ignore[arg-type]
            coverage_delta=coverage_delta,
        ),
        ctx,
    )
    plan = rb_out.plan
    logger.info(
        "compiled %s -> plan %s (%d TTP entries, state=%s)",
        log_ref,
        plan.id,
        len(plan.ttp_entries),
        plan.state,
    )
    return plan
