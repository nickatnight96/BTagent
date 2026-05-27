"""HypothesisGenNode — turn a HuntInput into a prioritised hypothesis list.

The first reasoning step of a hunt (#99 Phase A). Takes adversaries,
TTPs, and IOCs and emits an ordered list of falsifiable
:class:`Hypothesis` objects. The RunbookCompiler downstream expands
each hypothesis into a TTPRunbookEntry with per-backend queries.

Design notes:

1. **Mock mode is deterministic.** When ``BTAGENT_MOCK_LLM=true``
   (the default, matching ``LLMCallNode``), the node generates
   hypotheses synthetically from inputs — one per explicit TTP, one
   per IOC mapped via the keyword mapper (or "T1078" fallback), and
   a small adversary-stock set per named group. This lets tests and
   demos run the full pipeline without an LLM key, and gives the
   downstream nodes realistic shapes to work with.

2. **Real LLM mode lands with the LLM router in Phase B.** When
   mock mode is off, the node raises ``NotImplementedError`` -- same
   convention as ``LLMCallNode``. The router work will replace this
   stub with a structured-output call to the active provider.

3. **Priority is bounded [0, 1]**. The ordering convention is
   "higher == hunt first". Priority is *not* the same as severity
   (a low-severity but high-likelihood hypothesis still wants
   attention).

4. **The node never fabricates a TTP id**. If an input TTP isn't
   in the keyword mapper or shipped MITRE corpus, it's still emitted
   with the id as-given so the analyst can see what the input claimed
   even if our local data is stale.
"""

from __future__ import annotations

import hashlib
import os
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_shared.types.hunt import HuntInput, Hypothesis


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Hypothesis priority defaults. Adversary-derived hypotheses are most
# salient because they encode actor-specific intent; explicit TTPs are
# next; IOC-derived hypotheses are last because the IOC -> TTP mapping
# is heuristic.
_PRIORITY_ADVERSARY: float = 0.85
_PRIORITY_TTP: float = 0.75
_PRIORITY_IOC: float = 0.60

# Cap on emitted hypotheses to keep runbooks usable. Tunable per-org
# later; for now a sane default.
_MAX_HYPOTHESES: int = 25

# Adversary stock-set: a tiny built-in mapping so mock mode can produce
# plausible hypotheses for the most-named groups without depending on
# MISP being live. Real adversary -> TTP resolution lives in the MISP
# integration (Phase B follow-up).
_ADVERSARY_STOCK_TTPS: dict[str, list[tuple[str, str]]] = {
    "apt29": [
        ("T1059.001", "PowerShell"),
        ("T1078.004", "Cloud Accounts"),
        ("T1566.001", "Spearphishing Attachment"),
    ],
    "fin7": [
        ("T1566.001", "Spearphishing Attachment"),
        ("T1059.005", "Visual Basic"),
        ("T1486", "Data Encrypted for Impact"),
    ],
    "lazarus": [
        ("T1190", "Exploit Public-Facing Application"),
        ("T1486", "Data Encrypted for Impact"),
        ("T1027", "Obfuscated Files or Information"),
    ],
    "volt typhoon": [
        ("T1078.001", "Default Accounts"),
        ("T1133", "External Remote Services"),
        ("T1583.003", "Virtual Private Server"),
    ],
}

# Heuristic IOC-type -> default TTP. Real mapping is via the keyword
# mapper in agents/btagent_agents/mitre/. The fallback here is just so
# mock mode produces a non-empty hypothesis list even when the keyword
# mapper isn't loaded into the engine workspace.
_IOC_TYPE_DEFAULT_TTP: dict[str, tuple[str, str]] = {
    "ip": ("T1071.001", "Web Protocols"),
    "domain": ("T1071.004", "DNS"),
    "url": ("T1071.001", "Web Protocols"),
    "email": ("T1566.001", "Spearphishing Attachment"),
    "hash_md5": ("T1027", "Obfuscated Files or Information"),
    "hash_sha1": ("T1027", "Obfuscated Files or Information"),
    "hash_sha256": ("T1027", "Obfuscated Files or Information"),
    "cve": ("T1190", "Exploit Public-Facing Application"),
    "file_path": ("T1083", "File and Directory Discovery"),
}


def _mock_mode_enabled() -> bool:
    """Resolve the mock-mode flag at call time (so tests can flip it)."""
    return os.getenv("BTAGENT_MOCK_LLM", "true").lower() == "true"


def _stable_hypothesis_id(idx: int, seed: str) -> str:
    """Deterministic per-hypothesis id. Uses a short hash so re-runs of
    the same input produce the same ids (helps the dedup pass below).
    """
    h = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:6]
    return f"h_{idx:03d}_{h}"


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class HypothesisGenInput(BaseModel):
    """Node input — wraps a HuntInput so the canvas can hang docs off it."""

    model_config = ConfigDict(extra="forbid")

    hunt_input: HuntInput


class HypothesisGenOutput(BaseModel):
    """Node output — ordered hypotheses + bookkeeping."""

    model_config = ConfigDict(extra="forbid")

    hypotheses: list[Hypothesis] = Field(
        default_factory=list,
        description="Hypotheses sorted by priority descending. Length capped at "
        "_MAX_HYPOTHESES to keep runbooks usable.",
    )
    mock_mode: bool = Field(
        ...,
        description="Whether this output came from the deterministic mock path.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


class HypothesisGenNode(Node[HypothesisGenInput, HypothesisGenOutput]):
    """Turn a HuntInput into a prioritised list of Hypothesis objects."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.hypothesis_gen",
        name="Hypothesis Generator",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Generate a prioritised list of falsifiable threat-hunt "
            "hypotheses from an adversary / TTP / IOC input bundle."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = HypothesisGenInput
    output_schema: ClassVar[type[BaseModel]] = HypothesisGenOutput

    async def run(
        self,
        input: HypothesisGenInput,
        ctx: NodeContext,
    ) -> HypothesisGenOutput:
        # Client-or-deterministic: use the injected LLM client when one is
        # registered and mock mode is off; otherwise (mock mode, or no client)
        # fall back to the deterministic generator. Never hard-raise — that
        # would break any pipeline composing this node under MOCK_LLM=false.
        from btagent_engine.llm import get_llm_client

        client = get_llm_client()
        if not _mock_mode_enabled() and client is not None:
            try:
                hyps = await self._llm_generate(input.hunt_input, client, ctx)
                if hyps:
                    return HypothesisGenOutput(hypotheses=hyps, mock_mode=False)
            except Exception:  # noqa: BLE001 - LLM failure must degrade, not crash
                import logging

                logging.getLogger("btagent.reasoning.hypothesis_gen").warning(
                    "LLM hypothesis generation failed; falling back to deterministic",
                    exc_info=True,
                )

        hyps = self._mock_generate(input.hunt_input)
        return HypothesisGenOutput(hypotheses=hyps, mock_mode=True)

    # --- LLM generator ---------------------------------------------------- #

    async def _llm_generate(self, hunt_input, client, ctx):
        """Real LLM path: ask the model for a prioritised hypothesis list.

        Robust by construction: any parse/shape failure raises and the
        caller falls back to the deterministic generator, so a flaky model
        response can never break the hunt.
        """
        import json

        from btagent_shared.llm import LLMMessage, LLMRequest
        from btagent_shared.types.config import TLP, ModelTier

        adversaries = ", ".join(hunt_input.adversaries) or "(none)"
        ttps = ", ".join(hunt_input.ttps) or "(none)"
        iocs = ", ".join(f"{i.type}:{i.value}" for i in hunt_input.iocs) or "(none)"

        system = (
            "You are a threat-hunt planner. Given an adversary, ATT&CK TTPs, and "
            "IOCs, produce a prioritised list of falsifiable hunt hypotheses. "
            "Respond ONLY with a JSON array; each item has keys: ttp_id (ATT&CK id), "
            "ttp_name, rationale, behavioral_description, priority (0..1 float). "
            "Order by priority descending. Max 25 items."
        )
        user = (
            f"Adversaries: {adversaries}\nTTPs: {ttps}\nIOCs: {iocs}\n"
            "Return the JSON array now."
        )
        try:
            tlp = TLP(ctx.tlp_level)
        except ValueError:
            tlp = TLP.GREEN

        resp = await client.complete(
            LLMRequest(
                messages=[
                    LLMMessage(role="system", content=system),
                    LLMMessage(role="user", content=user),
                ],
                tier=ModelTier.STANDARD,
                tlp=tlp,
                temperature=0.2,
                max_tokens=2048,
                json_mode=True,
            )
        )

        text = resp.content.strip()
        # Tolerate a ```json fence or leading prose: extract the array span.
        start, end = text.find("["), text.rfind("]")
        if start == -1 or end == -1:
            raise ValueError("no JSON array in LLM response")
        raw = json.loads(text[start : end + 1])

        hyps: list[Hypothesis] = []
        for idx, item in enumerate(raw[:_MAX_HYPOTHESES], start=1):
            ttp_id = str(item["ttp_id"]).strip()
            if not ttp_id:
                continue
            priority = float(item.get("priority", _PRIORITY_TTP))
            hyps.append(
                Hypothesis(
                    id=_stable_hypothesis_id(idx, f"llm:{ttp_id}"),
                    ttp_id=ttp_id,
                    ttp_name=str(item.get("ttp_name", ttp_id)),
                    rationale=str(item.get("rationale", "")),
                    behavioral_description=str(item.get("behavioral_description", "")),
                    priority=max(0.0, min(1.0, priority)),
                    sources=["llm"],
                )
            )
        return sorted(hyps, key=lambda h: h.priority, reverse=True)

    # --- Mock generator --------------------------------------------------- #

    @staticmethod
    def _mock_generate(hunt_input: HuntInput) -> list[Hypothesis]:
        """Deterministic synthesis used in mock mode and in tests.

        Strategy:
          1. For each named adversary, emit the stock TTP set (or a
             single placeholder if we don't know the adversary).
          2. For each explicit TTP id in the input, emit one
             hypothesis. Explicit input always wins over inferred.
          3. For each IOC, infer a default TTP from its type and emit
             one hypothesis citing the IOC value.
          4. Dedupe on (ttp_id), preserving the highest-priority entry.
          5. Sort by priority desc; cap at ``_MAX_HYPOTHESES``.
        """
        candidates: list[Hypothesis] = []
        idx_counter = 0

        # 1. Adversary stock-set expansion
        for adv in hunt_input.adversaries:
            key = adv.lower().strip()
            stock = _ADVERSARY_STOCK_TTPS.get(key)
            if stock is None:
                # Unknown adversary -> single placeholder so downstream nodes
                # know there's *something* to anchor on.
                idx_counter += 1
                candidates.append(
                    Hypothesis(
                        id=_stable_hypothesis_id(idx_counter, f"adv:{key}"),
                        ttp_id="T0000",  # unknown technique placeholder
                        ttp_name=f"Unknown TTPs for {adv}",
                        rationale=(
                            f"Adversary '{adv}' is named but absent from the "
                            "local adversary -> TTP map. Resolve via MISP / "
                            "MITRE Groups before executing this hypothesis."
                        ),
                        behavioral_description=(
                            f"Look for behaviours consistent with '{adv}' "
                            "campaigns reported in your CTI feeds."
                        ),
                        priority=_PRIORITY_ADVERSARY * 0.5,
                        sources=[f"adversary:{adv}"],
                    )
                )
                continue
            for ttp_id, ttp_name in stock:
                idx_counter += 1
                candidates.append(
                    Hypothesis(
                        id=_stable_hypothesis_id(idx_counter, f"{key}:{ttp_id}"),
                        ttp_id=ttp_id,
                        ttp_name=ttp_name,
                        rationale=(
                            f"{adv} has used {ttp_id} ({ttp_name}) in prior "
                            "campaigns per the local adversary -> TTP map."
                        ),
                        behavioral_description=(
                            f"Hunt for behavioural indicators of {ttp_name} "
                            f"({ttp_id})."
                        ),
                        priority=_PRIORITY_ADVERSARY,
                        sources=[f"adversary:{adv}"],
                    )
                )

        # 2. Explicit TTPs
        for ttp in hunt_input.ttps:
            idx_counter += 1
            candidates.append(
                Hypothesis(
                    id=_stable_hypothesis_id(idx_counter, f"ttp:{ttp}"),
                    ttp_id=ttp,
                    ttp_name=ttp,  # caller didn't give a name; UI can resolve
                    rationale="Explicitly requested by the analyst.",
                    behavioral_description=(
                        f"Hunt for behavioural indicators of {ttp}."
                    ),
                    priority=_PRIORITY_TTP,
                    sources=["analyst:explicit"],
                )
            )

        # 3. IOC-derived
        for ioc in hunt_input.iocs:
            default = _IOC_TYPE_DEFAULT_TTP.get(ioc.type)
            if default is None:
                continue
            ttp_id, ttp_name = default
            idx_counter += 1
            candidates.append(
                Hypothesis(
                    id=_stable_hypothesis_id(
                        idx_counter, f"ioc:{ioc.type}:{ioc.value}"
                    ),
                    ttp_id=ttp_id,
                    ttp_name=ttp_name,
                    rationale=(
                        f"IOC '{ioc.value}' (type {ioc.type}) maps to "
                        f"{ttp_id} via the default-TTP heuristic."
                    ),
                    behavioral_description=(
                        f"Look for {ttp_name} ({ttp_id}) activity referencing "
                        f"IOC '{ioc.value}'."
                    ),
                    priority=_PRIORITY_IOC,
                    sources=[f"ioc:{ioc.type}:{ioc.value}"],
                )
            )

        # 4. Dedupe on ttp_id, keeping the highest-priority entry but
        # always merging source provenance from any duplicate so the
        # analyst can see all the reasons this TTP showed up.
        seen: dict[str, Hypothesis] = {}
        for h in candidates:
            existing = seen.get(h.ttp_id)
            if existing is None:
                seen[h.ttp_id] = h
                continue
            merged_sources = list(dict.fromkeys(existing.sources + h.sources))
            winner = h if h.priority > existing.priority else existing
            seen[h.ttp_id] = winner.model_copy(update={"sources": merged_sources})

        # 5. Sort + cap
        ordered = sorted(seen.values(), key=lambda h: h.priority, reverse=True)
        return ordered[:_MAX_HYPOTHESES]


# Make discoverable to the registry.
NodeRegistry.register(HypothesisGenNode)
