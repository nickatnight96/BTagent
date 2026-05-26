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
from btagent_engine.reasoning.nl_query import (
    NLQueryInput,
    NLQueryNode,
    NLQueryOutput,
    ParsedIntent,
)
from btagent_engine.reasoning.pivot_suggest import (
    PivotSuggestInput,
    PivotSuggestNode,
    PivotSuggestOutput,
)
from btagent_engine.reasoning.query_synth import (
    QuerySynthInput,
    QuerySynthNode,
    QuerySynthOutput,
)
from btagent_engine.reasoning.query_translate import (
    QueryTranslateInput,
    QueryTranslateNode,
    QueryTranslateOutput,
    TranslateMode,
)

__all__ = [
    "HypothesisGenInput",
    "HypothesisGenNode",
    "HypothesisGenOutput",
    "NLQueryInput",
    "NLQueryNode",
    "NLQueryOutput",
    "ParsedIntent",
    "PivotSuggestInput",
    "PivotSuggestNode",
    "PivotSuggestOutput",
    "QuerySynthInput",
    "QuerySynthNode",
    "QuerySynthOutput",
    "QueryTranslateInput",
    "QueryTranslateNode",
    "QueryTranslateOutput",
    "TranslateMode",
]
