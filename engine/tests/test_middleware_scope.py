"""Tests for the Scope-enforcement middleware."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from btagent_engine import Node, NodeCategory, NodeContext, NodeMeta, Runner
from btagent_engine.middleware.scope import (
    InvestigationScope,
    ScopeEnforcementMiddleware,
    ScopeViolation,
)


class _In(BaseModel):
    target: str


class _Out(BaseModel):
    ok: bool


class _LookupNode(Node[_In, _Out]):
    meta = NodeMeta(
        id="integration.lookup",
        name="Lookup",
        version="0.1.0",
        category=NodeCategory.INTEGRATION,
    )
    input_schema = _In
    output_schema = _Out

    async def run(self, input, ctx):
        return _Out(ok=True)


def _ctx() -> NodeContext:
    return NodeContext(run_id="r", org_id="org_test")


# --------------------------------------------------------------------------- #
# Happy: in-scope IP passes; an unrestricted scope passes everything
# --------------------------------------------------------------------------- #


async def test_scope_allows_in_scope_ip():
    scope = InvestigationScope(allowed_cidrs=["10.0.0.0/8"])
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    out = await runner.execute(_LookupNode(), _In(target="lookup 10.1.2.3"), _ctx())
    assert out.ok is True


async def test_scope_passes_when_unrestricted():
    """Empty scope == unrestricted; no domain or IP triggers a violation."""
    scope = InvestigationScope()
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    out = await runner.execute(_LookupNode(), _In(target="evil.example.com 1.1.1.1"), _ctx())
    assert out.ok is True


# --------------------------------------------------------------------------- #
# Negative: out-of-scope IP raises ScopeViolation
# --------------------------------------------------------------------------- #


async def test_scope_blocks_out_of_scope_ip():
    scope = InvestigationScope(allowed_cidrs=["10.0.0.0/8"])
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    with pytest.raises(ScopeViolation) as exc:
        await runner.execute(_LookupNode(), _In(target="lookup 8.8.8.8"), _ctx())
    assert "8.8.8.8" in str(exc.value)
    assert exc.value.node_id == "integration.lookup"


# --------------------------------------------------------------------------- #
# Edge: explicit blocklist trumps a permissive allowlist
# --------------------------------------------------------------------------- #


async def test_scope_blocked_ip_overrides_allow_cidr():
    scope = InvestigationScope(
        allowed_cidrs=["10.0.0.0/8"],
        blocked_ips=["10.0.0.1"],  # management plane
    )
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    with pytest.raises(ScopeViolation):
        await runner.execute(_LookupNode(), _In(target="lookup 10.0.0.1"), _ctx())


# --------------------------------------------------------------------------- #
# Edge: domain enforcement honours suffix matching
# --------------------------------------------------------------------------- #


async def test_scope_subdomain_of_allowed_passes():
    scope = InvestigationScope(allowed_domains=["acme.com"])
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    out = await runner.execute(_LookupNode(), _In(target="ns1.acme.com"), _ctx())
    assert out.ok is True


async def test_scope_unrelated_domain_blocks():
    scope = InvestigationScope(allowed_domains=["acme.com"])
    runner = Runner([ScopeEnforcementMiddleware(scope)])
    with pytest.raises(ScopeViolation):
        await runner.execute(_LookupNode(), _In(target="evil.example.com"), _ctx())
