"""Canonical query intermediate-representation (UC-1.3, #104).

The "write once, render everywhere" core. A detection engineer authors
a :class:`QueryIR` once; the QueryTranslateNode renders it to every
SIEM/EDR query language (SPL, KQL, ES|QL, CrowdStrike CQL, Sigma),
guaranteeing parity without manual porting.

shared/ tier, pydantic-only. The IR is deliberately small and
backend-agnostic: a data source, an ordered list of field conditions
combined by one top-level logical operator, an optional time window,
and a result cap. Anything a backend can't express degrades gracefully
in its renderer rather than bloating the IR.

Parsing an *existing* vendor query string back into IR (SPL -> IR) is
LLM-territory and lands with the router; the IR itself is the
deterministic, testable foundation.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field


class Operator(StrEnum):
    """Comparison operators an IR condition can express.

    Kept to the set every target language can render (exactly or via a
    documented degrade). REGEX renders natively where supported and
    falls back to a wildcard contains elsewhere.
    """

    EQ = "eq"
    NE = "ne"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    ENDSWITH = "endswith"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    IN = "in"
    REGEX = "regex"


class LogicOp(StrEnum):
    AND = "and"
    OR = "or"


class QueryCondition(BaseModel):
    """A single ``field <op> value`` predicate."""

    model_config = ConfigDict(extra="forbid")

    field: str = Field(..., description="Canonical field name (validated against schema registry).")
    op: Operator = Operator.EQ
    value: str | int | float | list[str] = Field(
        ..., description="Comparison value. A list is only valid with op=IN."
    )


class QueryIR(BaseModel):
    """Backend-agnostic detection logic — the canonical authored form."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(default="Untitled Detection", description="Human title (used in Sigma).")
    data_source: str = Field(
        ...,
        description="Logical source: a Splunk index/sourcetype, an ES|QL/Sentinel "
        "table, or a Sigma logsource category (e.g. 'process_creation').",
    )
    conditions: list[QueryCondition] = Field(default_factory=list)
    logic: LogicOp = Field(
        default=LogicOp.AND,
        description="Top-level combinator across conditions.",
    )
    time_window_hours: int | None = Field(
        default=None, ge=1, le=8760, description="Lookback window; None == backend default."
    )
    limit: int | None = Field(
        default=1000, ge=1, le=1_000_000, description="Result cap; None == uncapped (discouraged)."
    )


__all__ = ["LogicOp", "Operator", "QueryCondition", "QueryIR"]
