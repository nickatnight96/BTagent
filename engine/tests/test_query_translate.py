"""Tests for QueryTranslateNode (UC-1.3, #104)."""

from __future__ import annotations

import pytest

from btagent_engine import NodeContext
from btagent_engine.reasoning import (
    QueryTranslateInput,
    QueryTranslateNode,
    QueryTranslateOutput,
    TranslateMode,
)
from btagent_shared.types.hunt import Backend
from btagent_shared.types.query_ir import LogicOp, Operator, QueryCondition, QueryIR


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_xlate", org_id="org_test")


def _ir(**kw) -> QueryIR:
    base = dict(
        title="Encoded PowerShell",
        data_source="process_creation",
        conditions=[
            QueryCondition(field="process_name", op=Operator.EQ, value="powershell.exe"),
            QueryCondition(field="command_line", op=Operator.CONTAINS, value="-enc"),
        ],
        logic=LogicOp.AND,
        time_window_hours=24,
        limit=1000,
    )
    base.update(kw)
    return QueryIR(**base)


# --------------------------------------------------------------------------- #
# Translate: 5 languages
# --------------------------------------------------------------------------- #


async def test_translate_renders_all_five_languages():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), mode=TranslateMode.TRANSLATE), _ctx()
    )
    assert isinstance(out, QueryTranslateOutput)
    assert set(out.translations) == {
        Backend.SPLUNK,
        Backend.SENTINEL,
        Backend.ELASTIC,
        Backend.CROWDSTRIKE,
        Backend.SIGMA,
    }


async def test_splunk_render_shape():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), targets=[Backend.SPLUNK]), _ctx()
    )
    spl = out.translations[Backend.SPLUNK]
    assert spl.startswith("index=process_creation")
    assert 'process_name="powershell.exe"' in spl
    assert 'command_line="*-enc*"' in spl  # CONTAINS -> wildcard
    assert "earliest=-24h" in spl
    assert "| head 1000" in spl


async def test_kql_render_shape():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), targets=[Backend.SENTINEL]), _ctx()
    )
    kql = out.translations[Backend.SENTINEL]
    assert "process_creation" in kql
    assert "| where TimeGenerated > ago(24h)" in kql
    assert 'process_name == "powershell.exe"' in kql
    assert 'command_line contains "-enc"' in kql
    assert "| take 1000" in kql


async def test_esql_render_shape():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), targets=[Backend.ELASTIC]), _ctx()
    )
    esql = out.translations[Backend.ELASTIC]
    assert esql.startswith("FROM process_creation")
    assert "| WHERE" in esql
    assert "| LIMIT 1000" in esql


async def test_cql_render_shape():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), targets=[Backend.CROWDSTRIKE]), _ctx()
    )
    cql = out.translations[Backend.CROWDSTRIKE]
    assert "#event_simpleName=process_creation" in cql
    assert "command_line=/.*-enc.*/" in cql  # CONTAINS -> regex literal
    assert "| head(1000)" in cql


async def test_sigma_render_shape():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), targets=[Backend.SIGMA]), _ctx()
    )
    sigma = out.translations[Backend.SIGMA]
    assert "title: Encoded PowerShell" in sigma
    assert "category: process_creation" in sigma
    assert "command_line|contains: '-enc'" in sigma
    assert "condition: selection" in sigma


# --------------------------------------------------------------------------- #
# OR logic
# --------------------------------------------------------------------------- #


async def test_or_logic_splunk():
    ir = _ir(logic=LogicOp.OR)
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=ir, targets=[Backend.SPLUNK]), _ctx()
    )
    assert " OR " in out.translations[Backend.SPLUNK]


async def test_or_logic_sigma_uses_one_of():
    ir = _ir(logic=LogicOp.OR)
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=ir, targets=[Backend.SIGMA]), _ctx()
    )
    assert "condition: 1 of sel_*" in out.translations[Backend.SIGMA]


# --------------------------------------------------------------------------- #
# IN operator
# --------------------------------------------------------------------------- #


async def test_in_operator_renders_per_language():
    ir = QueryIR(
        data_source="auth",
        conditions=[QueryCondition(field="user", op=Operator.IN, value=["alice", "bob"])],
    )
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=ir, targets=[Backend.SENTINEL, Backend.ELASTIC]),
        _ctx(),
    )
    assert 'user in ("alice", "bob")' in out.translations[Backend.SENTINEL]
    assert 'user IN ("alice", "bob")' in out.translations[Backend.ELASTIC]


# --------------------------------------------------------------------------- #
# Explain mode
# --------------------------------------------------------------------------- #


async def test_explain_mode():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), mode=TranslateMode.EXPLAIN), _ctx()
    )
    assert out.mode == TranslateMode.EXPLAIN
    assert "process_creation" in out.explanation
    assert "equals" in out.explanation
    assert "contains" in out.explanation
    assert "24 hours" in out.explanation
    assert out.translations == {}


# --------------------------------------------------------------------------- #
# Optimize mode
# --------------------------------------------------------------------------- #


async def test_optimize_flags_missing_time_window():
    ir = _ir(time_window_hours=None)
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=ir, mode=TranslateMode.OPTIMIZE), _ctx()
    )
    assert any("time window" in f.lower() for f in out.optimizations)


async def test_optimize_flags_leading_wildcard():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=_ir(), mode=TranslateMode.OPTIMIZE), _ctx()
    )
    # command_line uses CONTAINS -> leading-wildcard warning
    assert any("wildcard" in f.lower() for f in out.optimizations)


async def test_optimize_clean_query_reports_no_issues():
    ir = QueryIR(
        data_source="process_creation",
        conditions=[QueryCondition(field="process_name", op=Operator.EQ, value="x.exe")],
        time_window_hours=24,
        limit=500,
    )
    out = await QueryTranslateNode().run(
        QueryTranslateInput(ir=ir, mode=TranslateMode.OPTIMIZE), _ctx()
    )
    assert any("no optimization issues" in f.lower() for f in out.optimizations)


# --------------------------------------------------------------------------- #
# Field validation against schema registry
# --------------------------------------------------------------------------- #


async def test_unknown_field_flagged_against_schema():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(
            ir=_ir(),
            targets=[Backend.SPLUNK],
            schema_fields={Backend.SPLUNK: ["process_name"]},  # command_line missing
        ),
        _ctx(),
    )
    assert any("command_line" in w for w in out.field_warnings)


async def test_all_fields_known_no_warnings():
    out = await QueryTranslateNode().run(
        QueryTranslateInput(
            ir=_ir(),
            targets=[Backend.SPLUNK],
            schema_fields={Backend.SPLUNK: ["process_name", "command_line"]},
        ),
        _ctx(),
    )
    assert out.field_warnings == []
