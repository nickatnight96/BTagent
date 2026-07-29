"""QuerySynthNode — synthesise per-backend hunt queries from a TTP.

The Phase B counterpart to HypothesisGenNode (#99). Takes a hypothesis's
behavioural description + target backends and emits a concrete query for
each backend (Splunk SPL, Sentinel KQL, Elastic ES|QL, CrowdStrike Falcon
search, Sigma). RunbookCompiler then folds these into the per-TTP runbook
entry.

Design notes:

1. **Mock mode is deterministic** (matches HypothesisGen / LLMCallNode).
   When ``BTAGENT_MOCK_LLM=true`` (the default), the node emits queries
   from a built-in per-(TTP, backend) template library. The templates
   are structurally valid and plausible but not production-tuned —
   their job is to prove the pipeline and give analysts a starting
   point to edit. When a real LLM client is registered and mock mode is
   off, the LLM writes one count-capped query per backend; on any failure
   (or no client) it falls back to the deterministic template library.
   The node never raises.

2. **Count-capped by default.** Every generated query carries a
   ``| head`` / ``take`` / equivalent cap so a clumsy execution can't
   DoS the SIEM. This is a safety requirement from the NightWing
   catalog (EPIC-1 / EPIC-4).

3. **Unknown TTP -> generic template.** If a TTP isn't in the library
   the node emits a generic "search for the technique id" query per
   backend rather than failing — the analyst can refine it. A
   sub-technique with no entry of its own first tries to inherit its
   parent technique's template (``T1110.001`` -> ``T1110``); only when
   that misses too does the generic placeholder come out.

4. **Backend selection.** The node only emits queries for the backends
   the caller requests (from ``HuntScope.backends`` or an explicit
   list). Empty request -> all backends in the library.

The curated template library itself lives in
:mod:`btagent_engine.reasoning.query_templates` (kept separate so the node
stays readable as coverage grows). Its per-backend technique counts are
golden-tested in ``engine/tests/test_query_synth_coverage.py`` so breadth
can't silently regress.
"""

from __future__ import annotations

import os
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
from btagent_engine.reasoning.query_templates import (
    QUERY_LIBRARY,
    TECHNIQUE_NAMES,
    lookup_template,
)


def _mock_mode_enabled() -> bool:
    return os.getenv("BTAGENT_MOCK_LLM", "true").strip().lower() != "false"


# ---------------------------------------------------------------------------
# Per-(TTP, backend) query template library
# ---------------------------------------------------------------------------
#
# Data lives in ``query_templates`` — each template is a structurally-valid,
# count-capped query. Field names follow the common defaults for each
# platform; the real LLM path resolves them against the org's schema registry.

# Backends covered by the library at all (for the "all backends" default).
_DEFAULT_BACKENDS: list[Backend] = [
    Backend.SPLUNK,
    Backend.SENTINEL,
    Backend.ELASTIC,
    Backend.CROWDSTRIKE,
    Backend.SIGMA,
]


def _technique_label(ttp_id: str) -> str:
    """``"T1059.001"`` -> ``"T1059.001 (PowerShell...)"`` when the name is known."""
    name = TECHNIQUE_NAMES.get(ttp_id)
    return f"{ttp_id} ({name})" if name else ttp_id


def _generic_query(ttp_id: str, backend: Backend) -> str:
    """Fallback query for TTPs not in the library. Structurally valid,
    count-capped, and obviously a placeholder so the analyst refines it.
    """
    if backend == Backend.SPLUNK:
        return f'index=* tag="{ttp_id}" OR search="*{ttp_id}*" | head 500  ``` TODO: refine for {ttp_id} ```'
    if backend in (Backend.SENTINEL, Backend.DEFENDER):
        return f"// TODO: refine for {ttp_id}\nsearch '{ttp_id}' | take 500"
    if backend == Backend.ELASTIC:
        return f"any where true /* TODO: map {ttp_id} to concrete telemetry */ | head 500"
    if backend == Backend.CROWDSTRIKE:
        return f"// TODO: map {ttp_id}\nevent_platform=Win | head 500"
    return (
        f"title: TODO {ttp_id}\nlogsource: {{}}\ndetection:\n  condition: false  "
        f"# placeholder — map {ttp_id} to real telemetry"
    )


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class QuerySynthInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str = Field(..., description="ATT&CK technique id to synthesise queries for.")
    behavioral_description: str = Field(
        default="",
        description="Behavioural description from the hypothesis. Feeds the LLM "
        "path; ignored in mock mode (template library is keyed by ttp_id).",
    )
    backends: list[Backend] = Field(
        default_factory=list,
        description="Which backends to emit queries for. Empty == all library backends.",
    )


class QuerySynthOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str
    queries: dict[Backend, Query] = Field(default_factory=dict)
    mock_mode: bool


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class QuerySynthNode(Node[QuerySynthInput, QuerySynthOutput]):
    """Synthesise per-backend hunt queries for a single TTP."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.query_synth",
        name="Query Synthesizer",
        version="0.2.0",
        category=NodeCategory.REASONING,
        description=(
            "Generate per-backend hunt queries (SPL / KQL / ES|QL / Falcon / Sigma) "
            "from an ATT&CK technique and behavioural description."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = QuerySynthInput
    output_schema: ClassVar[type[BaseModel]] = QuerySynthOutput

    async def run(
        self,
        input: QuerySynthInput,
        ctx: NodeContext,
    ) -> QuerySynthOutput:
        backends = input.backends or _DEFAULT_BACKENDS

        # Client-or-deterministic: when a real LLM client is registered and
        # mock mode is off, generate queries via the model; otherwise (and on
        # any LLM failure) fall back to the deterministic template library,
        # which is genuinely functional. Never hard-raise.
        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            llm_queries = await self._llm_generate(input, backends, client, ctx)
            if llm_queries:
                return QuerySynthOutput(ttp_id=input.ttp_id, queries=llm_queries, mock_mode=False)

        queries: dict[Backend, Query] = {}
        for backend in backends:
            hit = lookup_template(input.ttp_id, backend)
            if hit is None:
                template = _generic_query(input.ttp_id, backend)
                note = f"Generic placeholder for {input.ttp_id} — refine against your schema."
            else:
                template, source_ttp = hit
                label = _technique_label(source_ttp)
                if source_ttp == input.ttp_id:
                    note = (
                        f"Count-capped curated template for {label}. "
                        "Review field names before running."
                    )
                else:
                    note = (
                        f"Count-capped curated template inherited from parent technique "
                        f"{label} (no {input.ttp_id}-specific template yet). "
                        "Review field names before running."
                    )
            queries[backend] = Query(backend=backend, query=template, notes=note)

        return QuerySynthOutput(ttp_id=input.ttp_id, queries=queries, mock_mode=True)

    async def _llm_generate(self, input, backends, client, ctx):
        """LLM path: one count-capped query per backend. Returns {} on any
        failure so the caller falls back to the template library."""
        from btagent_shared.types.config import TLP, ModelTier

        from btagent_engine.reasoning._llm_json import call_llm_json, wrap_external_data

        backend_list = ", ".join(b.value for b in backends)
        system = (
            "You are a detection engineer. Given an ATT&CK technique and a "
            "behavioural description, write ONE hunt query per requested backend. "
            "Respond ONLY with a JSON object mapping backend -> query string "
            "(no prose, no markdown). Every query MUST be result-capped "
            "(| head N, | take N, LIMIT N, or equivalent). Backends use their "
            "native language: splunk=SPL, sentinel/defender=KQL, elastic=ES|QL, "
            "crowdstrike=CQL, sigma=Sigma YAML."
        )
        user = (
            wrap_external_data(
                f"technique: {input.ttp_id}\n"
                f"behaviour: {input.behavioral_description or '(none given)'}"
            )
            + f"\nbackends: {backend_list}\nReturn the JSON object now."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            # Fail closed: unknown classification → most restrictive.
            tlp = TLP.RED

        raw = await call_llm_json(
            client, system=system, user=user, tlp=tlp, tier=ModelTier.STANDARD, array=False
        )
        if not isinstance(raw, dict):
            return {}

        out: dict[Backend, Query] = {}
        for backend in backends:
            q = raw.get(backend.value)
            if isinstance(q, str) and q.strip():
                out[backend] = Query(
                    backend=backend,
                    query=q.strip(),
                    notes=f"LLM-generated for {input.ttp_id}. Review fields before running.",
                )
        return out


NodeRegistry.register(QuerySynthNode)


__all__ = [
    "QUERY_LIBRARY",
    "TECHNIQUE_NAMES",
    "QuerySynthInput",
    "QuerySynthNode",
    "QuerySynthOutput",
]
