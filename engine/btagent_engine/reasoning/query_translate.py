"""QueryTranslateNode — render a canonical QueryIR to every query language,
plus explain + optimize assistance (UC-1.3, #104).

Three modes:

* ``translate`` — render the IR to each requested backend language
  (Splunk SPL, Sentinel KQL, Elastic ES|QL, CrowdStrike CQL, Sigma).
  This is the "author once, run everywhere" core that keeps detections
  in parity across the stack.
* ``explain`` — plain-English description of what the IR matches
  (for junior-analyst training, per the acceptance criteria).
* ``optimize`` — deterministic optimization findings (missing time
  window, missing/oversized result cap, leading-wildcard predicates
  that defeat indexes, overly-broad data source).

All three are deterministic and need no LLM — the IR is fully
structured. Parsing an *existing* vendor query string back into IR
(SPL -> IR) is the LLM follow-up and is intentionally not part of this
node yet.

Field validation: when the caller supplies ``schema_fields`` (the set of
fields that exist in the target), conditions referencing an unknown
field are flagged — satisfying "flagged if a field doesn't exist in the
target".
"""

from __future__ import annotations

from enum import StrEnum
from typing import ClassVar

from btagent_shared.types.hunt import Backend
from btagent_shared.types.query_ir import LogicOp, Operator, QueryCondition, QueryIR
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

_RESULT_CAP_DEFAULT = 1000

# Languages we render. Maps onto the Backend enum members.
_TRANSLATABLE = [
    Backend.SPLUNK,
    Backend.SENTINEL,
    Backend.ELASTIC,
    Backend.CROWDSTRIKE,
    Backend.SIGMA,
]


class TranslateMode(StrEnum):
    TRANSLATE = "translate"
    EXPLAIN = "explain"
    OPTIMIZE = "optimize"


# ---------------------------------------------------------------------------
# Per-language predicate rendering
# ---------------------------------------------------------------------------


def _q(value: object) -> str:
    """Quote a scalar value for a query string."""
    if isinstance(value, (int, float)):
        return str(value)
    return f'"{value}"'


def _splunk_cond(c: QueryCondition) -> str:
    f = c.field
    v = c.value
    match c.op:
        case Operator.EQ:
            return f"{f}={_q(v)}"
        case Operator.NE:
            return f"{f}!={_q(v)}"
        case Operator.CONTAINS:
            return f'{f}="*{v}*"'
        case Operator.STARTSWITH:
            return f'{f}="{v}*"'
        case Operator.ENDSWITH:
            return f'{f}="*{v}"'
        case Operator.GT:
            return f"{f}>{v}"
        case Operator.LT:
            return f"{f}<{v}"
        case Operator.GTE:
            return f"{f}>={v}"
        case Operator.LTE:
            return f"{f}<={v}"
        case Operator.IN:
            vals = v if isinstance(v, list) else [v]
            return "(" + " OR ".join(f"{f}={_q(x)}" for x in vals) + ")"
        case Operator.REGEX:
            return f'| regex {f}="{v}"'
    return f"{f}={_q(v)}"


def _kql_cond(c: QueryCondition) -> str:
    f = c.field
    v = c.value
    match c.op:
        case Operator.EQ:
            return f"{f} == {_q(v)}"
        case Operator.NE:
            return f"{f} != {_q(v)}"
        case Operator.CONTAINS:
            return f"{f} contains {_q(v)}"
        case Operator.STARTSWITH:
            return f"{f} startswith {_q(v)}"
        case Operator.ENDSWITH:
            return f"{f} endswith {_q(v)}"
        case Operator.GT:
            return f"{f} > {v}"
        case Operator.LT:
            return f"{f} < {v}"
        case Operator.GTE:
            return f"{f} >= {v}"
        case Operator.LTE:
            return f"{f} <= {v}"
        case Operator.IN:
            vals = v if isinstance(v, list) else [v]
            return f"{f} in (" + ", ".join(_q(x) for x in vals) + ")"
        case Operator.REGEX:
            return f"{f} matches regex {_q(v)}"
    return f"{f} == {_q(v)}"


def _esql_cond(c: QueryCondition) -> str:
    f = c.field
    v = c.value
    match c.op:
        case Operator.EQ:
            return f"{f} == {_q(v)}"
        case Operator.NE:
            return f"{f} != {_q(v)}"
        case Operator.CONTAINS:
            return f'{f} LIKE "*{v}*"'
        case Operator.STARTSWITH:
            return f'{f} LIKE "{v}*"'
        case Operator.ENDSWITH:
            return f'{f} LIKE "*{v}"'
        case Operator.GT:
            return f"{f} > {v}"
        case Operator.LT:
            return f"{f} < {v}"
        case Operator.GTE:
            return f"{f} >= {v}"
        case Operator.LTE:
            return f"{f} <= {v}"
        case Operator.IN:
            vals = v if isinstance(v, list) else [v]
            return f"{f} IN (" + ", ".join(_q(x) for x in vals) + ")"
        case Operator.REGEX:
            return f"{f} RLIKE {_q(v)}"
    return f"{f} == {_q(v)}"


def _cql_cond(c: QueryCondition) -> str:
    # CrowdStrike Falcon query language — Splunk-like with /regex/ literals.
    f = c.field
    v = c.value
    match c.op:
        case Operator.EQ:
            return f"{f}={v}"
        case Operator.NE:
            return f"{f}!={v}"
        case Operator.CONTAINS:
            return f"{f}=/.*{v}.*/"
        case Operator.STARTSWITH:
            return f"{f}=/{v}.*/"
        case Operator.ENDSWITH:
            return f"{f}=/.*{v}/"
        case Operator.GT:
            return f"{f}>{v}"
        case Operator.LT:
            return f"{f}<{v}"
        case Operator.GTE:
            return f"{f}>={v}"
        case Operator.LTE:
            return f"{f}<={v}"
        case Operator.IN:
            vals = v if isinstance(v, list) else [v]
            return "(" + " OR ".join(f"{f}={x}" for x in vals) + ")"
        case Operator.REGEX:
            return f"{f}=/{v}/"
    return f"{f}={v}"


# ---------------------------------------------------------------------------
# Per-language full-query renderers
# ---------------------------------------------------------------------------


def _join(conds: list[str], logic: LogicOp, sep_and: str, sep_or: str) -> str:
    sep = sep_and if logic == LogicOp.AND else sep_or
    return sep.join(conds)


def _render_splunk(ir: QueryIR) -> str:
    parts = [f"index={ir.data_source}"]
    conds = [_splunk_cond(c) for c in ir.conditions if c.op != Operator.REGEX]
    regexes = [_splunk_cond(c) for c in ir.conditions if c.op == Operator.REGEX]
    if conds:
        parts.append(_join(conds, ir.logic, " ", " OR "))
    base = " ".join(parts)
    if ir.time_window_hours:
        base += f" earliest=-{ir.time_window_hours}h"
    for r in regexes:  # regex renders as a piped command
        base += f" {r}"
    if ir.limit:
        base += f" | head {ir.limit}"
    return base


def _render_kql(ir: QueryIR) -> str:
    lines = [ir.data_source]
    if ir.time_window_hours:
        lines.append(f"| where TimeGenerated > ago({ir.time_window_hours}h)")
    if ir.conditions:
        joined = _join([_kql_cond(c) for c in ir.conditions], ir.logic, " and ", " or ")
        lines.append(f"| where {joined}")
    if ir.limit:
        lines.append(f"| take {ir.limit}")
    return "\n".join(lines)


def _render_esql(ir: QueryIR) -> str:
    parts = [f"FROM {ir.data_source}"]
    if ir.conditions:
        joined = _join([_esql_cond(c) for c in ir.conditions], ir.logic, " AND ", " OR ")
        parts.append(f"| WHERE {joined}")
    # ES|QL has no inline time filter without a @timestamp field; emit a
    # conventional one so the query is runnable + bounded.
    if ir.time_window_hours:
        parts.insert(1, f"| WHERE @timestamp >= NOW() - {ir.time_window_hours} hours")
    if ir.limit:
        parts.append(f"| LIMIT {ir.limit}")
    return " ".join(parts)


def _render_cql(ir: QueryIR) -> str:
    parts = [f"#event_simpleName={ir.data_source}"]
    conds = [_cql_cond(c) for c in ir.conditions]
    if conds:
        parts.append(_join(conds, ir.logic, " ", " OR "))
    base = " ".join(parts)
    if ir.limit:
        base += f" | head({ir.limit})"
    return base


def _sigma_modifier(op: Operator) -> str:
    return {
        Operator.CONTAINS: "|contains",
        Operator.STARTSWITH: "|startswith",
        Operator.ENDSWITH: "|endswith",
        Operator.REGEX: "|re",
        Operator.GT: "|gt",
        Operator.LT: "|lt",
        Operator.GTE: "|gte",
        Operator.LTE: "|lte",
    }.get(op, "")


def _render_sigma(ir: QueryIR) -> str:
    lines = [f"title: {ir.title}", "logsource:", f"  category: {ir.data_source}", "detection:"]
    if ir.logic == LogicOp.AND:
        lines.append("  selection:")
        for c in ir.conditions:
            key = f"{c.field}{_sigma_modifier(c.op)}"
            lines.append(f"    {key}: {_sigma_value(c.value)}")
        lines.append("  condition: selection")
    else:  # OR -> one selection per condition, condition: 1 of selection_*
        names = []
        for i, c in enumerate(ir.conditions):
            name = f"sel_{i}"
            names.append(name)
            key = f"{c.field}{_sigma_modifier(c.op)}"
            lines.append(f"  {name}:")
            lines.append(f"    {key}: {_sigma_value(c.value)}")
        lines.append("  condition: 1 of sel_*")
    return "\n".join(lines)


def _sigma_value(v: object) -> str:
    if isinstance(v, list):
        return "[" + ", ".join(f"'{x}'" for x in v) + "]"
    if isinstance(v, (int, float)):
        return str(v)
    return f"'{v}'"


_RENDERERS = {
    Backend.SPLUNK: _render_splunk,
    Backend.SENTINEL: _render_kql,
    Backend.DEFENDER: _render_kql,
    Backend.ELASTIC: _render_esql,
    Backend.CROWDSTRIKE: _render_cql,
    Backend.SIGMA: _render_sigma,
}

_LANG_LABEL = {
    Backend.SPLUNK: "Splunk SPL",
    Backend.SENTINEL: "Sentinel KQL",
    Backend.DEFENDER: "Defender KQL",
    Backend.ELASTIC: "Elastic ES|QL",
    Backend.CROWDSTRIKE: "CrowdStrike CQL",
    Backend.SIGMA: "Sigma",
}


# ---------------------------------------------------------------------------
# Explain + optimize
# ---------------------------------------------------------------------------


def _explain(ir: QueryIR) -> str:
    if not ir.conditions:
        body = f"all events in {ir.data_source!r}"
    else:
        op_words = {
            Operator.EQ: "equals",
            Operator.NE: "does not equal",
            Operator.CONTAINS: "contains",
            Operator.STARTSWITH: "starts with",
            Operator.ENDSWITH: "ends with",
            Operator.GT: "is greater than",
            Operator.LT: "is less than",
            Operator.GTE: "is at least",
            Operator.LTE: "is at most",
            Operator.IN: "is one of",
            Operator.REGEX: "matches regex",
        }
        clauses = [f"{c.field} {op_words.get(c.op, str(c.op))} {c.value!r}" for c in ir.conditions]
        joiner = " AND " if ir.logic == LogicOp.AND else " OR "
        body = f"{ir.data_source!r} events where " + joiner.join(clauses)
    window = (
        f" over the last {ir.time_window_hours} hours"
        if ir.time_window_hours
        else " (no time bound)"
    )
    cap = f", returning up to {ir.limit} results" if ir.limit else ", uncapped"
    return f"This detection searches {body}{window}{cap}."


def _optimize(ir: QueryIR) -> list[str]:
    findings: list[str] = []
    if ir.time_window_hours is None:
        findings.append(
            "No time window — add one (earliest=/ago()/LIMIT) so the search is "
            "bounded; unbounded scans are the #1 cause of slow hunts."
        )
    if ir.limit is None:
        findings.append(
            "No result cap — add a limit to protect the backend from a runaway result set."
        )
    elif ir.limit > 10000:
        findings.append(
            f"Result cap is high ({ir.limit}); consider narrowing to <=10000 for interactive hunts."
        )
    for c in ir.conditions:
        if c.op == Operator.CONTAINS:
            findings.append(
                f"Field {c.field!r} uses a leading-wildcard contains — this "
                "defeats most field indexes. Prefer an exact match or a "
                "startswith if the prefix is known."
            )
        if c.op == Operator.REGEX:
            findings.append(
                f"Field {c.field!r} uses a regex — regexes rarely use indexes; "
                "anchor it or pre-filter with an indexed equality where possible."
            )
    if ir.data_source in ("*", "", "any"):
        findings.append(
            "Data source is unbounded (index=*) — scope it to a specific "
            "index/sourcetype/table to cut scan volume."
        )
    if not findings:
        findings.append(
            "No optimization issues detected — query is bounded, capped, and index-friendly."
        )
    return findings


# ---------------------------------------------------------------------------
# Schemas + node
# ---------------------------------------------------------------------------


class QueryTranslateInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ir: QueryIR
    mode: TranslateMode = TranslateMode.TRANSLATE
    targets: list[Backend] = Field(
        default_factory=list,
        description="Backends to render for (translate mode). Empty == all 5 languages.",
    )
    schema_fields: dict[Backend, list[str]] = Field(
        default_factory=dict,
        description="Per-backend known field names. When provided, conditions "
        "referencing an unknown field are flagged in field_warnings.",
    )


class QueryTranslateOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: TranslateMode
    translations: dict[Backend, str] = Field(default_factory=dict)
    explanation: str = ""
    optimizations: list[str] = Field(default_factory=list)
    field_warnings: list[str] = Field(
        default_factory=list,
        description="Per-target unknown-field flags (translate mode + schema_fields).",
    )


class QueryTranslateNode(Node[QueryTranslateInput, QueryTranslateOutput]):
    """Render a QueryIR across query languages, or explain/optimize it."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="reasoning.query_translate",
        name="Query Translator / Assistant",
        version="0.1.0",
        category=NodeCategory.REASONING,
        description=(
            "Author a detection once as a QueryIR and render it to SPL / KQL / "
            "ES|QL / CQL / Sigma; or explain / optimize an existing IR."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = QueryTranslateInput
    output_schema: ClassVar[type[BaseModel]] = QueryTranslateOutput

    async def run(
        self,
        input: QueryTranslateInput,
        ctx: NodeContext,
    ) -> QueryTranslateOutput:
        if input.mode == TranslateMode.EXPLAIN:
            return QueryTranslateOutput(mode=input.mode, explanation=_explain(input.ir))
        if input.mode == TranslateMode.OPTIMIZE:
            return QueryTranslateOutput(mode=input.mode, optimizations=_optimize(input.ir))

        # translate
        targets = input.targets or _TRANSLATABLE
        translations: dict[Backend, str] = {}
        warnings: list[str] = []
        for backend in targets:
            renderer = _RENDERERS.get(backend)
            if renderer is None:
                continue
            translations[backend] = renderer(input.ir)
            # field validation against the schema registry, if supplied
            known = input.schema_fields.get(backend)
            if known is not None:
                known_set = set(known)
                for c in input.ir.conditions:
                    if c.field not in known_set:
                        warnings.append(
                            f"{_LANG_LABEL.get(backend, backend.value)}: field "
                            f"{c.field!r} not found in target schema."
                        )
        return QueryTranslateOutput(
            mode=input.mode, translations=translations, field_warnings=warnings
        )


NodeRegistry.register(QueryTranslateNode)


__all__ = [
    "QueryTranslateInput",
    "QueryTranslateNode",
    "QueryTranslateOutput",
    "TranslateMode",
]
