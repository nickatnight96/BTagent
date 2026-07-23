"""Golden tests for Agentic-AI Misuse Hunter — connector-independent slice (#121).

All tests are:
- Deterministic (no network, no LLM, no DB).
- Pure-logic: they exercise btagent_shared.hunt.agentic over synthetic fixtures.
- Fast: no async, no Docker.

Test matrix:
  A1   Prompt injection — instruction-override + data-exfil input is flagged
       with the expected categories + technique.
  A2   Prompt injection — encoded-payload (base64 blob) input is flagged.
  A3   Prompt injection — benign input produces NO finding.
  A4   Prompt injection — finding evidence carries only redacted excerpts
       (raw injection text is bounded, no secrets re-emitted unbounded).
  A5   Shadow agent — fixture inventory yields shadow MCP + shadow Lambda
       findings; managed Bedrock agent NOT flagged.
  A6   Shadow agent — UNMANAGED-kind registration is itself flagged.
  A7   Shadow agent — findings carry evidence["shadow_workload"]=True
       (same routing marker #117 sets).
  A8   Agent identity abuse — out-of-toolset invocation flagged.
  A9   Agent identity abuse — privileged role escalation produces HIGH.
  A10  Agent identity abuse — unregistered identity is flagged distinctly.
  A11  Agent identity abuse — pure declared/observed mismatch without
       privileged keyword is LOW severity.
  A12  Convergence with #117 — classify_workload reused identically; same
       evidence marker.
  A13  run_all_detectors — integration sweep over the fixture bundle returns
       findings from all detectors.
  A14  RecordFindingRequest shape — every output is a valid Pydantic model
       with source=AGENTIC + domain=AGENTIC.
  A15  Pack loader — load_builtin_pack("agentic_misuse") returns the pack
       with the expected rule count (Sigma + code descriptors).
  A16  MITRE mapper — AGENTIC keywords resolve to correct technique IDs.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.hunt.agentic import (
    build_prompt_injection_finding,
    detect_agent_identity_abuse,
    detect_prompt_injection,
    detect_shadow_agents,
    run_all_detectors,
    scan_for_prompt_injection,
)
from btagent_shared.hunt.cloud import classify_workload
from btagent_shared.types.agentic_hunt import (
    AgentCallEvent,
    AgentIdentity,
    AgentIdentityKind,
    PromptInjectionCategory,
)
from btagent_shared.types.cloud_hunt import (
    AgenticWorkload,
    AgenticWorkloadKind,
    CloudProvider,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import RecordFindingRequest

from tests.fixtures.agentic.agent_fixtures import (
    AGENT_CALL_EVENTS,
    AGENT_IDENTITY_REGISTRY,
    AGENTIC_WORKLOAD_INVENTORY,
    EVT_CLEAN,
    EVT_ENCODED_PAYLOAD,
    EVT_OUT_OF_TOOLSET,
    EVT_PROMPT_INJECTION,
    EVT_ROLE_ESCALATION,
    EVT_UNREGISTERED,
    MCP_AGENT_IDENTITY_REF,
    ORG_ID,
    TRIAGE_AGENT_IDENTITY_REF,
    TRUSTED_ACCOUNT,
)

_FIXED_NOW = datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# A1–A4: Prompt-injection detection
# ---------------------------------------------------------------------------


def test_A1_prompt_injection_seeded_input_is_flagged():
    """A seeded instruction-override + data-exfil input is flagged correctly."""
    signals = scan_for_prompt_injection(EVT_PROMPT_INJECTION)
    assert len(signals) >= 2
    categories = {s.category for s in signals}
    assert PromptInjectionCategory.INSTRUCTION_OVERRIDE in categories
    assert PromptInjectionCategory.DATA_EXFIL_REQUEST in categories

    finding = build_prompt_injection_finding(signals, event=EVT_PROMPT_INJECTION)
    assert finding is not None
    assert finding.source == HuntSource.AGENTIC
    assert finding.domain == HuntDomain.AGENTIC
    # T1059 (code-execution proxy) is always present; data-exfil adds T1552.
    assert "T1059" in finding.technique_ids
    assert "T1552" in finding.technique_ids
    # Data-exfil category + high signal → severity ≥ HIGH.
    assert finding.severity in (Severity.HIGH, Severity.CRITICAL)
    assert finding.evidence["detection"] == "prompt_injection"
    assert finding.evidence["event_id"] == EVT_PROMPT_INJECTION.event_id


def test_A2_encoded_payload_input_is_flagged():
    """A long base64 blob smuggled into agent input is flagged."""
    signals = scan_for_prompt_injection(EVT_ENCODED_PAYLOAD)
    assert any(s.category == PromptInjectionCategory.ENCODED_PAYLOAD for s in signals)
    finding = build_prompt_injection_finding(signals, event=EVT_ENCODED_PAYLOAD)
    assert finding is not None
    assert "encoded_payload" in {c for c in finding.evidence["categories"]}


def test_A3_benign_input_produces_no_finding():
    """A clean, benign prompt produces NO prompt-injection finding."""
    signals = scan_for_prompt_injection(EVT_CLEAN)
    assert signals == []
    finding = build_prompt_injection_finding(signals, event=EVT_CLEAN)
    assert finding is None


def test_A4_finding_evidence_has_only_redacted_excerpts():
    """The finding evidence must not contain the raw input verbatim — only
    bounded redacted excerpts."""
    signals = scan_for_prompt_injection(EVT_PROMPT_INJECTION)
    finding = build_prompt_injection_finding(signals, event=EVT_PROMPT_INJECTION)
    assert finding is not None
    # Evidence keys must NOT include the raw input.
    assert "raw_input_text" not in finding.evidence
    assert "input_text" not in finding.evidence
    excerpts = finding.evidence.get("redacted_excerpts", [])
    assert isinstance(excerpts, list)
    # Each excerpt is bounded (PromptInjectionSignal.redacted_excerpt max=512;
    # detector caps at 480).
    for excerpt in excerpts:
        assert len(excerpt) <= 512


# ---------------------------------------------------------------------------
# A5–A7: Shadow agent / shadow MCP discovery
# ---------------------------------------------------------------------------


def test_A5_shadow_inventory_flags_shadow_and_skips_managed():
    """Shadow workloads + unmanaged identities flagged; managed agent NOT flagged."""
    findings = detect_shadow_agents(AGENTIC_WORKLOAD_INVENTORY, identities=AGENT_IDENTITY_REGISTRY)
    flagged_resource_ids = {
        entity.value for f in findings for entity in f.entities if entity.kind == "agentic_workload"
    }
    # Managed agent must NOT be flagged.
    managed_id = f"arn:aws:bedrock:us-east-1:{TRUSTED_ACCOUNT}:agent/AGENT_TRIAGE"
    assert managed_id not in flagged_resource_ids
    # Shadow Cloud Run MCP + shadow Lambda must be flagged.
    assert "projects/my-project/locations/us-central1/services/mcp-shadow" in flagged_resource_ids
    assert (
        f"arn:aws:lambda:us-east-1:{TRUSTED_ACCOUNT}:function:rogue-llm-fn" in flagged_resource_ids
    )


def test_A6_unmanaged_kind_agent_identity_is_flagged():
    """An AgentIdentity with kind=UNMANAGED is itself flagged as shadow."""
    findings = detect_shadow_agents([], identities=AGENT_IDENTITY_REGISTRY)
    # Only identity-side sweep runs (workloads empty); should still yield the
    # unmanaged on-prem bridge identity.
    detection_kinds = {f.evidence.get("detection") for f in findings}
    assert "shadow_agent_identity" in detection_kinds
    identity_flagged_refs = {
        f.evidence["identity_ref"]
        for f in findings
        if f.evidence.get("detection") == "shadow_agent_identity"
    }
    assert f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/OnPremBridgeAgent" in identity_flagged_refs


def test_A7_shadow_findings_carry_governance_routing_marker():
    """Every shadow-agent finding must carry evidence['shadow_workload']=True
    so the governance workflow routes cloud- and agentic-side findings together
    (the single shared-surface point with #117)."""
    findings = detect_shadow_agents(AGENTIC_WORKLOAD_INVENTORY, identities=AGENT_IDENTITY_REGISTRY)
    assert findings, "expected at least one shadow finding"
    for f in findings:
        assert f.evidence.get("shadow_workload") is True, (
            f"finding missing governance routing marker: {f.evidence}"
        )


# ---------------------------------------------------------------------------
# A8–A11: Agent identity abuse
# ---------------------------------------------------------------------------


def test_A8_out_of_toolset_invocation_flagged():
    """An agent invoking a tool outside its declared catalogue is flagged."""
    findings = detect_agent_identity_abuse([EVT_OUT_OF_TOOLSET], AGENT_IDENTITY_REGISTRY)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["out_of_toolset"] is True
    assert f.evidence["invoked_tool"] == "delete_ticket"
    assert "T1059" in f.technique_ids


def test_A9_privileged_role_escalation_is_high():
    """Observed role escalation into AdminRole produces HIGH severity finding."""
    findings = detect_agent_identity_abuse([EVT_ROLE_ESCALATION], AGENT_IDENTITY_REGISTRY)
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.HIGH
    assert f.evidence["privileged_escalation"] is True
    assert "T1078.004" in f.technique_ids
    assert "T1606" in f.technique_ids


def test_A10_unregistered_identity_is_flagged_distinctly():
    """An event for an identity with no AgentIdentity record yields a distinct finding."""
    findings = detect_agent_identity_abuse([EVT_UNREGISTERED], AGENT_IDENTITY_REGISTRY)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["detection"] == "agent_identity_abuse.unregistered"
    assert f.severity == Severity.HIGH


def test_A11_role_mismatch_without_privilege_is_low():
    """A declared/observed role mismatch where the observed role is NOT
    privileged downgrades the finding to LOW severity."""
    benign_mismatch = EVT_ROLE_ESCALATION.model_copy(
        update={
            "observed_role": f"arn:aws:iam::{TRUSTED_ACCOUNT}:role/SiblingNonPrivilegedRole",
            "invoked_tool": "kb_search",  # in declared toolset, so no out-of-toolset
            "invoked_api": "kb:Search",
        }
    )
    findings = detect_agent_identity_abuse([benign_mismatch], AGENT_IDENTITY_REGISTRY)
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["role_mismatch"] is True
    assert f.evidence["privileged_escalation"] is False
    assert f.evidence["out_of_toolset"] is False
    assert f.severity == Severity.LOW


# ---------------------------------------------------------------------------
# A12: Convergence with #117 cloud primitives
# ---------------------------------------------------------------------------


def test_A12_shadow_classification_reused_from_117():
    """The agentic shadow detector must use the IDENTICAL #117 classifier so a
    workload classified shadow by cloud is also classified shadow by agentic."""
    untagged = AgenticWorkload(
        id="x",
        org_id=ORG_ID,
        provider=CloudProvider.AWS,
        kind=AgenticWorkloadKind.BEDROCK_AGENTCORE,
        resource_id="arn:test:res",
        identity_ref="arn:test:role",
        governance_tagged=False,  # derived-shadow
        is_shadow=False,
        has_overprivileged_identity=False,
        internet_reachable=False,
        last_activity=None,
        risk_score=0.0,
    )
    assert classify_workload(untagged) is True
    # Agentic detector emits a finding for the same workload.
    findings = detect_shadow_agents([untagged])
    assert len(findings) == 1
    assert findings[0].evidence["shadow_workload"] is True


# ---------------------------------------------------------------------------
# A13: Integration sweep (run_all_detectors)
# ---------------------------------------------------------------------------


def test_A13_run_all_detectors_integration():
    """run_all_detectors over the full fixture bundle returns findings from
    every detector."""
    findings = run_all_detectors(
        events=AGENT_CALL_EVENTS,
        identities=AGENT_IDENTITY_REGISTRY,
        workloads=AGENTIC_WORKLOAD_INVENTORY,
    )
    detections = {f.evidence.get("detection") for f in findings}
    assert "prompt_injection" in detections
    assert "shadow_agent_workload" in detections
    assert "shadow_agent_identity" in detections
    # agent_identity_abuse detector contributes either the abuse or the
    # unregistered variant (both are valid).
    abuse_detections = {d for d in detections if d and d.startswith("agent_identity_abuse")}
    assert abuse_detections, f"expected an agent_identity_abuse* detection, got {detections}"


# ---------------------------------------------------------------------------
# A14: Output shape validation
# ---------------------------------------------------------------------------


def test_A14_all_outputs_are_valid_pydantic_models():
    """Every detector output is a valid RecordFindingRequest with the right
    source / domain."""
    findings = run_all_detectors(
        events=AGENT_CALL_EVENTS,
        identities=AGENT_IDENTITY_REGISTRY,
        workloads=AGENTIC_WORKLOAD_INVENTORY,
    )
    assert findings
    for f in findings:
        assert isinstance(f, RecordFindingRequest)
        dumped = f.model_dump()
        assert dumped["source"] == "agentic"
        assert dumped["domain"] == "agentic"
        assert isinstance(dumped["technique_ids"], list)
        assert 0.0 <= dumped["confidence"] <= 1.0


# ---------------------------------------------------------------------------
# A15: Pack-loader discovery
# ---------------------------------------------------------------------------


def test_A15_agentic_pack_loads_via_builtin_loader():
    """The agentic_misuse pack loads through btagent_engine's builtin loader."""
    from btagent_engine.hunting import HuntPack, load_builtin_pack
    from btagent_engine.hunting.pack import BUILTIN_PACKS_DIR

    pack = load_builtin_pack("agentic_misuse")
    assert isinstance(pack, HuntPack)
    assert pack.id.startswith("hpack_")
    assert pack.name == "Agentic-AI Misuse Hunt Pack"
    assert pack.version == "1.0.0"

    # 5 native Sigma rules + 3 code-descriptor Sigma-shaped rules = 8 total.
    # The test is intentionally written as ≥ 5 (per the spec: "≥ N rules") so
    # adding additional rules later doesn't break the check.
    assert len(pack.rules) >= 5
    rule_files = {r.file for r in pack.rules}
    # Spot-check a network Sigma rule and a code-descriptor.
    assert "bedrock_invoke_from_unmanaged_role.yml" in rule_files
    assert "agent_assumerole_above_declared.yml" in rule_files
    assert "_code_prompt_injection_scan.yml" in rule_files
    assert "_code_shadow_agent_inventory.yml" in rule_files
    assert "_code_agent_identity_abuse.yml" in rule_files
    # No .py file is loaded as a Sigma rule.
    assert not any(str(f).endswith(".py") for f in rule_files)

    # The code-based detector modules ship alongside the pack.
    pack_dir = BUILTIN_PACKS_DIR / "agentic_misuse"
    assert (pack_dir / "detectors" / "prompt_injection_scan.py").is_file()
    assert (pack_dir / "detectors" / "shadow_agent_inventory.py").is_file()
    assert (pack_dir / "detectors" / "agent_identity_abuse.py").is_file()

    # The deferred LLM-credential-output rule ships disabled.
    by_file = {r.file: r for r in pack.rules}
    assert by_file["llm_credential_in_prompt_output.yml"].enabled is False


# ---------------------------------------------------------------------------
# A16: MITRE mapper AGENTIC keywords
# ---------------------------------------------------------------------------


def test_A16_mitre_mapper_agentic_keywords():
    """The AGENTIC keyword block resolves to the expected technique IDs."""
    from btagent_agents.mitre.mapper import MitreMapper

    mapper = MitreMapper()
    cases = [
        ("detected prompt injection on agent input", "T1059"),
        ("shadow mcp server discovered", "T1078.004"),
        ("agent role escalation into admin", "T1078.004"),
        ("unregistered agent calling sts", "T1078"),
        ("agent token forgery suspected", "T1606"),
        ("system prompt leak observed", "T1552"),
    ]
    for text, expected_technique in cases:
        suggestions = mapper.suggest_techniques(text, max_results=10)
        technique_ids = [s.technique_id for s in suggestions]
        assert expected_technique in technique_ids, (
            f"Expected {expected_technique!r} in suggestions for {text!r}, got: {technique_ids}"
        )


# ---------------------------------------------------------------------------
# A17: Detector ignores unregistered identity gracefully in the abuse sweep
# (regression — make sure detect_prompt_injection doesn't accidentally trigger
# on the benign event in the same batch)
# ---------------------------------------------------------------------------


def test_A17_full_event_batch_only_flags_attack_events():
    """In a batch with one clean event + several attack events, only the
    attack events produce findings."""
    findings = detect_prompt_injection(AGENT_CALL_EVENTS)
    flagged_event_ids = {f.evidence["event_id"] for f in findings}
    assert EVT_CLEAN.event_id not in flagged_event_ids
    assert EVT_PROMPT_INJECTION.event_id in flagged_event_ids
    assert EVT_ENCODED_PAYLOAD.event_id in flagged_event_ids


# ---------------------------------------------------------------------------
# A18–A21: LLM-exfil detector (#121 Phase A4)
# ---------------------------------------------------------------------------

from btagent_shared.hunt.agentic import detect_llm_exfil  # noqa: E402


def _exfil_event(**overrides) -> AgentCallEvent:
    base = dict(
        event_id="evt_exfil_001",
        org_id="org_01TESTAGENTIC",
        agent_identity_ref="arn:aws:iam::111111111111:role/TestAgent",
        observed_at=datetime(2026, 6, 22, 12, 0, 0, tzinfo=UTC),
        input_text="Summarize the deployment configuration.",
        output_text="",
        invoked_tool="kb_search",
        invoked_api="kb:Search",
        observed_role="arn:aws:iam::111111111111:role/TestAgent",
        metadata={"source": "fixture"},
    )
    base.update(overrides)
    return AgentCallEvent(**base)


def test_A18_leaked_aws_key_in_output_is_critical_and_masked():
    """The issue-#121 acceptance case: a response leaking an AWS key pattern
    is flagged, escalated (output direction), and masked in evidence."""
    event = _exfil_event(
        output_text="Bucket uses access key AKIAIOSFODNN7EXAMPLE — rotate after audit."
    )
    findings = detect_llm_exfil([event])
    assert len(findings) == 1
    f = findings[0]
    assert f.evidence["detection"] == "llm_exfil"
    assert f.severity == Severity.CRITICAL  # secret flowing outward escalates
    assert "aws_access_key_id" in f.evidence["patterns"]
    assert "T1552" in f.technique_ids and "T1567" in f.technique_ids
    # The raw key must never appear in the finding.
    import json

    assert "AKIAIOSFODNN7EXAMPLE" not in json.dumps(f.evidence)
    assert any(s["masked"].startswith("AKIAIO") for s in f.evidence["signals"])


def test_A19_clean_event_produces_no_exfil_finding():
    assert detect_llm_exfil([_exfil_event()]) == []


def test_A20_oversized_prompt_alone_is_medium():
    event = _exfil_event(input_text="A" * 9000)
    findings = detect_llm_exfil([event])
    assert len(findings) == 1
    f = findings[0]
    assert f.severity == Severity.MEDIUM
    assert f.evidence["oversized_outbound_prompt"] is True
    assert f.evidence["patterns"] == ["oversized_outbound_prompt"]


def test_A21_private_key_block_in_input_is_critical():
    event = _exfil_event(
        input_text=(
            "Please store this for me: -----BEGIN RSA PRIVATE KEY----- "
            "MIIEowIBAAKCAQEA -----END RSA PRIVATE KEY-----"
        )
    )
    findings = detect_llm_exfil([event])
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert "private_key_block" in findings[0].evidence["patterns"]


def test_A22_run_all_detectors_includes_llm_exfil():
    event = _exfil_event(
        output_text="key AKIAIOSFODNN7EXAMPLE",
        event_id="evt_exfil_sweep",
    )
    findings = run_all_detectors(events=[event])
    detections = {f.evidence.get("detection") for f in findings}
    assert "llm_exfil" in detections
