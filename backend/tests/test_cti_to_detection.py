"""Tests for the STIX → Sigma detection-proposal pipeline (issue #113 slice).

Covers:
* :func:`extract_detectable_indicators` — 5-indicator synthetic bundle parsed correctly.
* :func:`propose_sigma_rule` — generated Sigma YAML is valid and structurally correct.
* :func:`process_stix_bundle` — full pipeline: proposals generated, TLP:RED refused,
  dedup works, non-indicator objects are in ``skipped``.
* Determinism — identical input produces identical output.
* MITRE technique tags attached when kill_chain_phases present.
* API endpoint ``POST /api/v1/cti/propose-detections`` — 200 with proposals,
  403 on TLP:RED, 422 on malformed, 404 on unknown bundle_id.

The fixture STIX bundle contains 5 indicators of different types:
  1. IPv4 address  (ip)
  2. Domain name   (domain)
  3. SHA-256 hash  (hash_sha256)
  4. URL           (url)
  5. IPv4 address duplicate (dedup test — only one proposal expected)
plus one attack-pattern object (non-indicator → skipped).
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
import yaml

# Ensure imports work with test PYTHONPATH
# (PYTHONPATH=$WT/backend:$WT/shared:$WT/engine:$WT/agents)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

# Minimal STIX 2.1 marking definition IDs
_TLP_GREEN_REF = "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da"
_TLP_RED_REF = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"

_SAMPLE_BUNDLE: dict = {
    "type": "bundle",
    "id": "bundle--aaaabbbb-cccc-dddd-eeee-000000000001",
    "objects": [
        # 1. IPv4 address indicator with MITRE kill-chain phase
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--11111111-1111-1111-1111-111111111111",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Malicious C2 IP",
            "description": "Known C2 server used by APT-X campaign",
            "pattern": "[ipv4-addr:value = '198.51.100.10']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 85,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "T1071.001"},
            ],
            "object_marking_refs": [_TLP_GREEN_REF],
        },
        # 2. Domain name indicator
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--22222222-2222-2222-2222-222222222222",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Phishing Domain",
            "description": "Phishing domain mimicking a banking portal",
            "pattern": "[domain-name:value = 'secure-banking-verify.example.com']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 90,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "T1566.002"},
            ],
            "object_marking_refs": [_TLP_GREEN_REF],
        },
        # 3. SHA-256 hash indicator
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--33333333-3333-3333-3333-333333333333",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Ransomware Dropper",
            "description": "SHA-256 hash of known ransomware dropper payload",
            "pattern": "[file:hashes.'SHA-256' = "
            "'a3f5b2c1d9e84f7c6b0a1234567890abcdef1234567890abcdef1234567890ab']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 95,
            "kill_chain_phases": [
                {"kill_chain_name": "mitre-attack", "phase_name": "T1486"},
            ],
            "object_marking_refs": [_TLP_GREEN_REF],
        },
        # 4. URL indicator
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--44444444-4444-4444-4444-444444444444",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Malware Download URL",
            "description": "URL serving second-stage malware payload",
            "pattern": "[url:value = 'http://198.51.100.20/payload/stage2.exe']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 75,
            "object_marking_refs": [_TLP_GREEN_REF],
        },
        # 5. Duplicate IPv4 — should be skipped by dedup logic
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--55555555-5555-5555-5555-555555555555",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Duplicate C2 IP (same value as indicator--111...)",
            "description": "Same IP, different STIX object — should deduplicate",
            "pattern": "[ipv4-addr:value = '198.51.100.10']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 80,
            "object_marking_refs": [_TLP_GREEN_REF],
        },
        # 6. Non-indicator STIX object (attack-pattern) — goes to skipped
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "Spearphishing Link",
            "description": "T1566.002 — Spearphishing Link (contextual, not a detection target)",
        },
    ],
}

_TLP_RED_BUNDLE: dict = {
    "type": "bundle",
    "id": "bundle--aaaabbbb-cccc-dddd-eeee-000000000099",
    "objects": [
        {
            "type": "indicator",
            "spec_version": "2.1",
            "id": "indicator--red000-0000-0000-0000-000000000001",
            "created": "2026-01-01T00:00:00.000Z",
            "modified": "2026-01-01T00:00:00.000Z",
            "name": "TLP:RED Indicator",
            "description": "Should be refused by the TLP gate",
            "pattern": "[ipv4-addr:value = '10.0.0.200']",
            "pattern_type": "stix",
            "valid_from": "2026-01-01T00:00:00.000Z",
            "confidence": 70,
            "object_marking_refs": [_TLP_RED_REF],
        },
    ],
}


# ---------------------------------------------------------------------------
# Unit tests: extract_detectable_indicators
# ---------------------------------------------------------------------------


def test_extract_indicators_count():
    """5 STIX indicator objects → 5 extracted (before dedup)."""
    from btagent_shared.hunt.cti_to_detection import extract_detectable_indicators

    indicators = extract_detectable_indicators(_SAMPLE_BUNDLE)
    # indicators 1-5 all have parseable patterns
    assert len(indicators) == 5


def test_extract_indicator_types():
    """Each indicator has the correct ioc_type."""
    from btagent_shared.hunt.cti_to_detection import extract_detectable_indicators

    indicators = extract_detectable_indicators(_SAMPLE_BUNDLE)
    types = [i.ioc_type for i in indicators]
    assert "ip" in types
    assert "domain" in types
    assert "hash_sha256" in types
    assert "url" in types


def test_extract_logsources():
    """IP/domain → network/proxy logsource; SHA-256 → process_creation."""
    from btagent_shared.hunt.cti_to_detection import extract_detectable_indicators

    indicators = extract_detectable_indicators(_SAMPLE_BUNDLE)
    by_type = {i.ioc_type: i for i in indicators}

    assert by_type["ip"].logsource_category == "network_connection"
    assert by_type["domain"].logsource_category == "proxy"
    assert by_type["hash_sha256"].logsource_category == "process_creation"
    assert by_type["hash_sha256"].logsource_product == "windows"


def test_extract_confidence_conversion():
    """STIX confidence 85 → BTagent 0.85."""
    from btagent_shared.hunt.cti_to_detection import extract_detectable_indicators

    indicators = extract_detectable_indicators(_SAMPLE_BUNDLE)
    by_id = {i.stix_id: i for i in indicators}
    ip_ind = by_id["indicator--11111111-1111-1111-1111-111111111111"]
    assert ip_ind.confidence == 0.85


def test_extract_kill_chain_phases():
    """Kill chain phases are preserved on extracted indicators."""
    from btagent_shared.hunt.cti_to_detection import extract_detectable_indicators

    indicators = extract_detectable_indicators(_SAMPLE_BUNDLE)
    by_id = {i.stix_id: i for i in indicators}
    ip_ind = by_id["indicator--11111111-1111-1111-1111-111111111111"]
    assert len(ip_ind.kill_chain_phases) == 1
    assert ip_ind.kill_chain_phases[0]["phase_name"] == "T1071.001"


# ---------------------------------------------------------------------------
# Unit tests: propose_sigma_rule
# ---------------------------------------------------------------------------


def test_propose_sigma_rule_valid_yaml():
    """Generated Sigma YAML must parse as valid YAML."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    indicator = _ExtractedIndicator(
        stix_id="indicator--11111111-1111-1111-1111-111111111111",
        ioc_type="ip",
        value="198.51.100.10",
        logsource_category="network_connection",
        logsource_product="",
        confidence=0.85,
        name="Test IP",
        description="Test C2 IP",
        kill_chain_phases=[],
    )
    proposal = propose_sigma_rule(
        indicator,
        ["T1071.001"],
        generated_at=datetime(2026, 6, 22, 0, 0, 0, tzinfo=UTC),
    )

    parsed = yaml.safe_load(proposal.sigma_yaml)
    assert isinstance(parsed, dict), "Sigma YAML must parse to a dict"
    assert "title" in parsed
    assert "detection" in parsed
    assert "logsource" in parsed


def test_propose_sigma_rule_required_fields():
    """Generated Sigma YAML has all required Sigma schema fields."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    indicator = _ExtractedIndicator(
        stix_id="indicator--22222222-2222-2222-2222-222222222222",
        ioc_type="domain",
        value="evil.example.com",
        logsource_category="proxy",
        logsource_product="",
        confidence=0.9,
        name="Evil Domain",
        description="Phishing domain",
        kill_chain_phases=[],
    )
    proposal = propose_sigma_rule(indicator, ["T1566.002"])
    parsed = yaml.safe_load(proposal.sigma_yaml)

    required_keys = {
        "title",
        "id",
        "status",
        "description",
        "references",
        "author",
        "date",
        "logsource",
        "detection",
        "falsepositives",
        "level",
        "tags",
    }
    missing = required_keys - set(parsed.keys())
    assert not missing, f"Sigma YAML missing required keys: {missing}"


def test_propose_sigma_rule_technique_tags():
    """MITRE technique IDs appear in the Sigma rule tags."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    indicator = _ExtractedIndicator(
        stix_id="indicator--33333333-3333-3333-3333-333333333333",
        ioc_type="hash_sha256",
        value="a3f5b2c1d9e84f7c6b0a1234567890abcdef1234567890abcdef1234567890ab",
        logsource_category="process_creation",
        logsource_product="windows",
        confidence=0.95,
        name="Ransomware hash",
        description="SHA-256 of ransomware dropper",
        kill_chain_phases=[],
    )
    proposal = propose_sigma_rule(indicator, ["T1486"])
    parsed = yaml.safe_load(proposal.sigma_yaml)

    tags: list[str] = parsed.get("tags", [])
    assert any("t1486" in t.lower() for t in tags), f"T1486 not found in tags: {tags}"


def test_propose_sigma_rule_deterministic():
    """Same input always produces identical Sigma YAML (no random state)."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    indicator = _ExtractedIndicator(
        stix_id="indicator--44444444-4444-4444-4444-444444444444",
        ioc_type="url",
        value="http://198.51.100.20/payload/stage2.exe",
        logsource_category="proxy",
        logsource_product="",
        confidence=0.75,
        name="Malware URL",
        description="Payload URL",
        kill_chain_phases=[],
    )
    ts = datetime(2026, 6, 22, 0, 0, 0, tzinfo=UTC)
    p1 = propose_sigma_rule(indicator, [], generated_at=ts)
    p2 = propose_sigma_rule(indicator, [], generated_at=ts)
    assert p1.sigma_yaml == p2.sigma_yaml, "Sigma YAML is not deterministic"
    assert p1.id == p2.id, "Proposal ID is not deterministic"


def test_propose_sigma_rule_hash_detection_block():
    """SHA-256 detection block references the hash value."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    sha256 = "a3f5b2c1d9e84f7c6b0a1234567890abcdef1234567890abcdef1234567890ab"
    indicator = _ExtractedIndicator(
        stix_id="indicator--33333333-3333-3333-3333-333333333333",
        ioc_type="hash_sha256",
        value=sha256,
        logsource_category="process_creation",
        logsource_product="windows",
        confidence=0.95,
        name="Hash",
        description="",
        kill_chain_phases=[],
    )
    proposal = propose_sigma_rule(indicator, ["T1486"])
    # Hash value must appear in the YAML so the rule has actionable detection content
    assert sha256 in proposal.sigma_yaml


def test_propose_sigma_rule_logsource_ip():
    """IP indicator → logsource.category = network_connection."""
    from btagent_shared.hunt.cti_to_detection import (
        _ExtractedIndicator,
        propose_sigma_rule,
    )

    indicator = _ExtractedIndicator(
        stix_id="indicator--11111111-1111-1111-1111-111111111111",
        ioc_type="ip",
        value="198.51.100.10",
        logsource_category="network_connection",
        logsource_product="",
        confidence=0.85,
        name="C2 IP",
        description="",
        kill_chain_phases=[],
    )
    proposal = propose_sigma_rule(indicator, [])
    parsed = yaml.safe_load(proposal.sigma_yaml)
    assert parsed["logsource"]["category"] == "network_connection"


# ---------------------------------------------------------------------------
# Unit tests: process_stix_bundle (orchestrator)
# ---------------------------------------------------------------------------


def test_process_bundle_proposal_count():
    """Sample bundle: 5 indicators (1 duplicate) → 4 proposals, 1 dedup-skipped + 1 obj-skipped."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    # 4 unique indicators → 4 proposals
    assert len(response.proposals) == 4
    # 1 duplicate + 1 non-indicator attack-pattern → at least 2 skipped
    assert len(response.skipped) >= 2


def test_process_bundle_tlp_red_refused():
    """A bundle with TLP:RED marking references must raise TLPViolation."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.security.tlp import TLPViolation
    from btagent_shared.types.config import TLP

    with pytest.raises(TLPViolation):
        process_stix_bundle(_TLP_RED_BUNDLE, active_tlp=TLP.GREEN)


def test_process_bundle_active_tlp_red_refused():
    """active_tlp=TLP.RED must also be refused even if bundle has no RED marking."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.security.tlp import TLPViolation
    from btagent_shared.types.config import TLP

    # Use the clean green bundle but set active_tlp=RED
    with pytest.raises(TLPViolation):
        process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.RED)


def test_process_bundle_technique_ids_from_kill_chain():
    """MITRE technique from kill_chain_phases is attached to the proposal."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    # indicator--111 has T1071.001 in kill_chain_phases
    ip_proposals = [
        p
        for p in response.proposals
        if p.source_stix_id == "indicator--11111111-1111-1111-1111-111111111111"
    ]
    assert len(ip_proposals) == 1
    assert "T1071.001" in ip_proposals[0].technique_ids


def test_process_bundle_all_proposals_have_valid_sigma():
    """Every proposal's Sigma YAML must parse as valid YAML with required keys."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    required = {"title", "id", "status", "description", "logsource", "detection", "level"}

    for proposal in response.proposals:
        parsed = yaml.safe_load(proposal.sigma_yaml)
        assert isinstance(parsed, dict), f"Not a dict for {proposal.source_stix_id}"
        missing = required - set(parsed.keys())
        assert not missing, f"Sigma YAML for {proposal.source_stix_id} missing keys: {missing}"


def test_process_bundle_proposals_are_proposed_state():
    """All freshly generated proposals must have state='proposed'."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    for proposal in response.proposals:
        assert proposal.state == "proposed"


def test_process_bundle_dedup_in_skipped():
    """The duplicate IP indicator is recorded in skipped with a reason."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    dup_skipped = [
        s
        for s in response.skipped
        if s.stix_id == "indicator--55555555-5555-5555-5555-555555555555"
    ]
    assert len(dup_skipped) == 1
    assert "duplicate" in dup_skipped[0].reason.lower()


def test_process_bundle_non_indicator_in_skipped():
    """The attack-pattern object is reported in skipped with a reason."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    response = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    ap_skipped = [
        s
        for s in response.skipped
        if s.stix_id == "attack-pattern--aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    ]
    assert len(ap_skipped) == 1
    assert "attack-pattern" in ap_skipped[0].reason


def test_process_bundle_deterministic():
    """Same bundle always produces same proposal IDs and same Sigma YAML."""
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    r1 = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)
    r2 = process_stix_bundle(_SAMPLE_BUNDLE, active_tlp=TLP.GREEN)

    ids1 = sorted(p.id for p in r1.proposals)
    ids2 = sorted(p.id for p in r2.proposals)
    assert ids1 == ids2, "Proposal IDs changed between runs"

    yaml1 = sorted(p.sigma_yaml for p in r1.proposals)
    yaml2 = sorted(p.sigma_yaml for p in r2.proposals)
    assert yaml1 == yaml2, "Sigma YAML changed between runs"


# ---------------------------------------------------------------------------
# Unit tests: schema validation
# ---------------------------------------------------------------------------


def test_detection_proposal_schema():
    """DetectionProposal validates cleanly with all required fields."""
    from btagent_shared.types.detection_proposal import DetectionProposal

    p = DetectionProposal(
        id="prop_abc123",
        source_stix_id="indicator--11111111-1111-1111-1111-111111111111",
        title="Test Detection",
        sigma_yaml="title: test\ndetection:\n  selection:\n    a: b\n  condition: selection\n",
        technique_ids=["T1071"],
        confidence=0.9,
        source_indicators=["[ipv4-addr:value = '1.2.3.4']"],
        rationale="Test rationale",
        state="proposed",
        generated_at=datetime(2026, 6, 22, 0, 0, 0, tzinfo=UTC),
    )
    assert p.state == "proposed"
    assert p.confidence == 0.9


def test_cti_request_schema_forbids_extra():
    """CTIToDetectionRequest forbids extra fields."""
    from btagent_shared.types.detection_proposal import CTIToDetectionRequest
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        CTIToDetectionRequest(
            stix_bundle={"type": "bundle", "objects": []},
            extra_field="not allowed",  # type: ignore[call-arg]
        )


# ---------------------------------------------------------------------------
# API endpoint tests (async, requires the conftest client fixture)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_api_propose_detections_returns_proposals(client, analyst_token):
    """POST /api/v1/cti/propose-detections returns proposals for a valid bundle."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={
            "stix_bundle": _SAMPLE_BUNDLE,
            "active_tlp": "green",
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "proposals" in body
    assert "skipped" in body
    assert len(body["proposals"]) == 4


@pytest.mark.asyncio
async def test_api_propose_detections_tlp_red_403(client, analyst_token):
    """POST /api/v1/cti/propose-detections returns 403 for TLP:RED bundle."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={
            "stix_bundle": _TLP_RED_BUNDLE,
            "active_tlp": "green",
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_api_propose_detections_active_tlp_red_403(client, analyst_token):
    """POST /api/v1/cti/propose-detections returns 403 when active_tlp=red."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={
            "stix_bundle": _SAMPLE_BUNDLE,
            "active_tlp": "red",
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 403, resp.text


@pytest.mark.asyncio
async def test_api_propose_detections_unknown_bundle_id_404(client, analyst_token):
    """An unknown stix_bundle_id now 404s (bundle-by-id resolution, #113 — the
    former 501 stub is replaced by the stix_bundles store)."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={
            "stix_bundle_id": "bundle--some-id-here",
            "active_tlp": "green",
        },
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404, resp.text


@pytest.mark.asyncio
async def test_api_propose_detections_missing_bundle_422(client, analyst_token):
    """POST /api/v1/cti/propose-detections returns 422 when no bundle supplied."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"active_tlp": "green"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 422, resp.text


@pytest.mark.asyncio
async def test_api_propose_detections_unauthenticated_401(client):
    """POST /api/v1/cti/propose-detections returns 401 without auth."""
    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle": _SAMPLE_BUNDLE, "active_tlp": "green"},
    )
    assert resp.status_code == 401, resp.text


@pytest.mark.asyncio
async def test_api_proposals_have_sigma_yaml(client, analyst_token):
    """Every proposal in the API response has non-empty sigma_yaml."""
    from helpers import auth_header

    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle": _SAMPLE_BUNDLE, "active_tlp": "green"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    for proposal in resp.json()["proposals"]:
        assert proposal["sigma_yaml"], f"Empty sigma_yaml for proposal {proposal['id']}"
        parsed = yaml.safe_load(proposal["sigma_yaml"])
        assert "detection" in parsed, f"sigma_yaml missing 'detection' for {proposal['id']}"


# ---------------------------------------------------------------------------
# Codex #213 regression — unsupported indicators must surface as SkippedIndicator
# ---------------------------------------------------------------------------


def test_unsupported_indicator_pattern_recorded_as_skipped():
    """A STIX indicator whose pattern isn't in ``_PATTERN_MAP`` (e.g.
    ``file:name``, ``x-custom:foo``) MUST appear in
    ``CTIToDetectionResponse.skipped`` with a reason explaining why it
    couldn't be converted. Before Codex #213 these were silently dropped.
    """
    from btagent_shared.hunt.cti_to_detection import process_stix_bundle
    from btagent_shared.types.config import TLP

    bundle = {
        "type": "bundle",
        "id": "bundle--reg-codex-213",
        "objects": [
            # 1) Unsupported pattern shape — currently outside _PATTERN_MAP.
            {
                "type": "indicator",
                "id": "indicator--unsupported-001",
                "spec_version": "2.1",
                "pattern": "[file:name = 'definitely_evil.exe']",
                "pattern_type": "stix",
                "valid_from": "2026-06-22T00:00:00Z",
                "name": "Suspicious filename",
            },
            # 2) Custom STIX-extension pattern — also unsupported.
            {
                "type": "indicator",
                "id": "indicator--unsupported-002",
                "spec_version": "2.1",
                "pattern": "[x-custom-object:foo = 'bar']",
                "pattern_type": "stix",
                "valid_from": "2026-06-22T00:00:00Z",
            },
        ],
    }
    resp = process_stix_bundle(bundle, active_tlp=TLP.GREEN)

    # No proposal generated (both indicators unparseable).
    assert resp.proposals == []
    # Both indicators surface as SkippedIndicator entries with the raw pattern
    # and a reason that mentions "Unsupported STIX pattern".
    unsupported = [s for s in resp.skipped if "Unsupported STIX pattern" in s.reason]
    assert len(unsupported) == 2, (
        f"expected 2 unsupported-pattern SkippedIndicators, got: {resp.skipped}"
    )
    stix_ids = {s.stix_id for s in unsupported}
    assert stix_ids == {"indicator--unsupported-001", "indicator--unsupported-002"}
    # Raw patterns are preserved so reviewers can extend the parser.
    patterns = {s.pattern for s in unsupported}
    assert "[file:name = 'definitely_evil.exe']" in patterns
    assert "[x-custom-object:foo = 'bar']" in patterns
