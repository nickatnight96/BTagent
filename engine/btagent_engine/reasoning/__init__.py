"""Reasoning nodes — LLM-driven steps that turn inputs into structured outputs.

Distinct from ``integrations/`` (vendor API calls) and ``data/`` (pure
transforms): these nodes do *thinking*, usually backed by an LLM call.

Live now:
  * :class:`HypothesisGenNode` — adversary/TTP/IOC -> ordered hypotheses.

Coming with Phase B of #99:
  * QuerySynth-per-backend (uses an LLM to convert a behavioural
    description into SPL/KQL/EQL/Sigma queries).
"""

from btagent_engine.reasoning.hypothesis_gen import (
    HypothesisGenInput,
    HypothesisGenNode,
    HypothesisGenOutput,
)

__all__ = [
    "HypothesisGenInput",
    "HypothesisGenNode",
    "HypothesisGenOutput",
]
