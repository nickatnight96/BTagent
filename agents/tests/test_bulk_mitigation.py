"""Tests for BulkMitigationNode (EPIC-3 UC-3.3)."""

from __future__ import annotations

from btagent_engine.node import NodeContext
from btagent_engine.reasoning import (
    BulkMitigationInput,
    BulkMitigationNode,
    BulkMitigationOutput,
    IOCRef,
)
from btagent_shared.types.enums import IOCType
from btagent_shared.types.mitigation import MitigationDecision


def _ctx() -> NodeContext:
    return NodeContext(run_id="r_mit", org_id="org_test")


async def _plan(monkeypatch, iocs, *, extra_allowlist=None) -> BulkMitigationOutput:
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
    out = await BulkMitigationNode().run(
        BulkMitigationInput(
            iocs=[IOCRef(type=t, value=v) for t, v in iocs],
            extra_allowlist=extra_allowlist or [],
        ),
        _ctx(),
    )
    assert isinstance(out, BulkMitigationOutput)
    assert out.mock_mode is True
    return out


def _by_value(out: BulkMitigationOutput, value: str):
    return next(a for a in out.plan.actions if a.ioc_value == value)


async def test_public_ip_blocked_with_rollback(monkeypatch):
    out = await _plan(monkeypatch, [(IOCType.IP, "185.220.101.42")])
    a = _by_value(out, "185.220.101.42")
    assert a.decision == MitigationDecision.BLOCK
    assert a.tool == "panorama"
    assert a.policy_object == "perimeter-blocklist"
    assert a.destructive is True
    assert a.requires_approval is True
    assert a.rollback and "185.220.101.42" in a.rollback
    assert "deny" in a.policy_preview
    assert out.plan.block_count == 1


async def test_private_ip_is_allowlisted(monkeypatch):
    out = await _plan(monkeypatch, [(IOCType.IP, "10.1.2.3")])
    a = _by_value(out, "10.1.2.3")
    assert a.decision == MitigationDecision.SKIP_ALLOWLISTED
    assert a.destructive is False
    assert a.requires_approval is False
    assert out.plan.block_count == 0


async def test_public_resolver_is_allowlisted(monkeypatch):
    out = await _plan(monkeypatch, [(IOCType.IP, "8.8.8.8")])
    assert _by_value(out, "8.8.8.8").decision == MitigationDecision.SKIP_ALLOWLISTED


async def test_critical_domain_is_allowlisted(monkeypatch):
    out = await _plan(
        monkeypatch,
        [(IOCType.DOMAIN, "login.microsoftonline.office.com"), (IOCType.DOMAIN, "evil.example")],
    )
    assert _by_value(out, "login.microsoftonline.office.com").decision == (
        MitigationDecision.SKIP_ALLOWLISTED
    )
    blocked = _by_value(out, "evil.example")
    assert blocked.decision == MitigationDecision.BLOCK
    assert blocked.tool == "umbrella"


async def test_invalid_ioc_skipped_not_blocked(monkeypatch):
    out = await _plan(
        monkeypatch,
        [(IOCType.IP, "999.999.1.1"), (IOCType.HASH_MD5, "not-a-hash")],
    )
    assert _by_value(out, "999.999.1.1").decision == MitigationDecision.SKIP_INVALID
    assert _by_value(out, "not-a-hash").decision == MitigationDecision.SKIP_INVALID
    assert out.plan.block_count == 0


async def test_unsupported_kind_skipped(monkeypatch):
    out = await _plan(monkeypatch, [(IOCType.CVE, "CVE-2024-1234")])
    a = _by_value(out, "CVE-2024-1234")
    assert a.decision == MitigationDecision.SKIP_UNSUPPORTED
    assert a.destructive is False


async def test_hashes_route_to_edr(monkeypatch):
    sha256 = "a" * 64
    out = await _plan(monkeypatch, [(IOCType.HASH_SHA256, sha256)])
    a = _by_value(out, sha256)
    assert a.decision == MitigationDecision.BLOCK
    assert a.tool == "crowdstrike"
    assert a.policy_object == "ioc-blocklist"


async def test_url_routes_and_screens_domain(monkeypatch):
    out = await _plan(
        monkeypatch,
        [
            (IOCType.URL, "https://evil.example/payload"),
            (IOCType.URL, "https://www.google.com/safe"),
        ],
    )
    blocked = _by_value(out, "https://evil.example/payload")
    assert blocked.decision == MitigationDecision.BLOCK
    assert blocked.tool == "zscaler"
    # URL whose host is allowlisted must not be blocked.
    assert _by_value(out, "https://www.google.com/safe").decision == (
        MitigationDecision.SKIP_ALLOWLISTED
    )


async def test_duplicates_collapsed(monkeypatch):
    out = await _plan(
        monkeypatch,
        [(IOCType.IP, "45.83.12.7"), (IOCType.IP, "45.83.12.7")],
    )
    decisions = [a.decision for a in out.plan.actions]
    assert decisions.count(MitigationDecision.BLOCK) == 1
    assert decisions.count(MitigationDecision.SKIP_DUPLICATE) == 1


async def test_extra_allowlist_respected(monkeypatch):
    # 45.83.12.7 is a public IP that would otherwise be blocked; the caller
    # pins it to the allowlist, so it must skip.
    out = await _plan(
        monkeypatch,
        [(IOCType.IP, "45.83.12.7")],
        extra_allowlist=["45.83.12.7"],
    )
    assert _by_value(out, "45.83.12.7").decision == MitigationDecision.SKIP_ALLOWLISTED


async def test_tools_and_counts_aggregate(monkeypatch):
    out = await _plan(
        monkeypatch,
        [
            (IOCType.IP, "45.83.12.7"),
            (IOCType.DOMAIN, "bad.example"),
            (IOCType.IP, "10.0.0.1"),  # allowlisted
        ],
    )
    assert out.plan.block_count == 2
    assert out.plan.skip_count == 1
    assert set(out.plan.tools) == {"panorama", "umbrella"}


# --------------------------------------------------------------------------- #
# LLM refines the summary ONLY — decisions stay deterministic
# --------------------------------------------------------------------------- #


async def test_llm_refines_summary_only(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _FakeClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(
                content='{"summary":"LLM summary"}',
                provider="anthropic",
                model="claude-sonnet-4-6",
            )

    clear_llm_client()
    set_llm_client(_FakeClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    iocs = [IOCRef(type=IOCType.IP, value="45.83.12.7")]
    try:
        det = await BulkMitigationNode().run(BulkMitigationInput(iocs=iocs), _ctx())
        monkeypatch.setenv("BTAGENT_MOCK_LLM", "true")
        baseline = await BulkMitigationNode().run(BulkMitigationInput(iocs=iocs), _ctx())
        assert det.mock_mode is False
        assert det.plan.summary == "LLM summary"
        # Safety: decisions/targets unchanged by the LLM.
        assert [a.decision for a in det.plan.actions] == [a.decision for a in baseline.plan.actions]
        assert [a.destructive for a in det.plan.actions] == [
            a.destructive for a in baseline.plan.actions
        ]
    finally:
        clear_llm_client()


async def test_llm_bad_response_falls_back(monkeypatch):
    from btagent_engine.llm import clear_llm_client, set_llm_client
    from btagent_shared.llm import LLMRequest, LLMResponse

    class _BadClient:
        async def complete(self, request: LLMRequest) -> LLMResponse:
            return LLMResponse(content="no json", provider="x", model="y")

    clear_llm_client()
    set_llm_client(_BadClient())
    monkeypatch.setenv("BTAGENT_MOCK_LLM", "false")
    try:
        out = await BulkMitigationNode().run(
            BulkMitigationInput(iocs=[IOCRef(type=IOCType.IP, value="45.83.12.7")]),
            _ctx(),
        )
        assert out.mock_mode is True  # deterministic summary
        assert out.plan.block_count == 1
    finally:
        clear_llm_client()
