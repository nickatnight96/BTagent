"""Tests for the agentic CTI → Detection engineering path (#113 "do both").

Covers the three cooperating pieces in
:mod:`btagent_shared.hunt.detection_engineer`:

* **CTIExtractor** — mock-LLM extraction of behavioral TTP tuples from a prose
  report (report fenced in ``<external-data>``), plus the deterministic
  no-LLM fallback.
* **RuleDrafter** — deterministic templating vs. agentic LLM drafting, and the
  graceful degradation to templating when no model / an unusable reply.
* **DataSourceMatcher** — reconciles required OCSF classes against the *real*
  agents-side connector manifests and populates
  :attr:`DetectionDraft.data_sources_required` + the coverage gaps.

Plus the orchestrator + the DetectionEngineerPlugin wiring.

The suite lives under ``agents/tests`` because the DataSourceMatcher assertion
exercises the agents-side ``mcp.manifests`` registry directly; the pure logic
itself is dependency-free shared code.
"""

from __future__ import annotations

import yaml
from btagent_shared.hunt.detection_engineer import (
    CTIExtractor,
    DataSourceMatcher,
    RuleDrafter,
    connector_ocsf_emits,
    draft_detections_from_report,
    required_ocsf_classes,
)
from btagent_shared.types.connector import OCSFEventClass
from btagent_shared.types.detection_engineer import (
    BehavioralTTP,
    DetectionDraft,
    DraftMethod,
    IntelArtifact,
)

_REPORT = (
    "APT-Sample intrusion report. The actor spawned encoded PowerShell "
    "(-enc) from a macro-enabled document, used WMIC for remote execution, "
    "and staged tooling with certutil. C2 beacons matched T1071.001."
)


# --------------------------------------------------------------------------- #
# CTIExtractor — mock-LLM extraction + deterministic fallback
# --------------------------------------------------------------------------- #


async def test_extractor_mock_llm_parses_ttps() -> None:
    seen: dict[str, str] = {}

    async def mock_llm(system: str, user: str, tier: str) -> str:
        # The untrusted report must be fenced before it reaches the model.
        seen["user"] = user
        return (
            "Here are the TTPs:\n```json\n"
            '[{"technique_id": "T1059.001", "tactic": "execution", '
            '"behavior": "encoded PowerShell from Office", '
            '"observables": ["-enc", "FromBase64String"], '
            '"logsource_category": "process_creation", "confidence": 0.9},'
            '{"technique_id": "not-a-technique", "observables": []}]\n```'
        )

    ttps = await CTIExtractor().extract(_REPORT, llm=mock_llm)

    assert "<external-data>" in seen["user"]
    assert _REPORT in seen["user"]
    # The malformed second element is dropped; the good one parses fully.
    assert [t.technique_id for t in ttps] == ["T1059.001"]
    ttp = ttps[0]
    assert ttp.tactic == "execution"
    assert ttp.observables == ["-enc", "FromBase64String"]
    assert ttp.logsource_category == "process_creation"
    assert ttp.confidence == 0.9


async def test_extractor_degrades_to_deterministic_without_llm() -> None:
    ttps = await CTIExtractor().extract(_REPORT, llm=None)
    techniques = {t.technique_id for t in ttps}
    # Keyword hits + the explicit technique id are all surfaced.
    assert {"T1059.001", "T1047", "T1140", "T1071.001"} <= techniques
    # Keyworded TTPs carry a concrete observable for the drafter to key on.
    ps = next(t for t in ttps if t.technique_id == "T1059.001")
    assert ps.observables  # non-empty


async def test_extractor_bad_llm_reply_falls_back_to_deterministic() -> None:
    async def broken_llm(system: str, user: str, tier: str) -> str:
        return "sorry, I cannot help with that"

    ttps = await CTIExtractor().extract(_REPORT, llm=broken_llm)
    # Unusable reply → deterministic scan still yields the known behaviors.
    assert {t.technique_id for t in ttps} >= {"T1059.001", "T1047"}


async def test_extractor_llm_exception_is_swallowed() -> None:
    async def raising_llm(system: str, user: str, tier: str) -> str:
        raise RuntimeError("model exploded")

    ttps = await CTIExtractor().extract(_REPORT, llm=raising_llm)
    assert {t.technique_id for t in ttps} >= {"T1059.001"}


def test_extractor_dedupes_by_technique() -> None:
    raw = (
        '[{"technique_id": "T1059.001", "observables": ["-enc"]},'
        '{"technique_id": "T1059.001", "observables": ["iex"]}]'
    )
    ttps = CTIExtractor.parse_extraction(raw)
    assert len(ttps) == 1
    # Observables from both entries are merged onto the single tuple.
    assert set(ttps[0].observables) == {"-enc", "iex"}


# --------------------------------------------------------------------------- #
# RuleDrafter — deterministic vs. agentic
# --------------------------------------------------------------------------- #

_TTP = BehavioralTTP(
    technique_id="T1059.001",
    tactic="execution",
    behavior="encoded PowerShell",
    observables=["-enc", "FromBase64String"],
    logsource_category="process_creation",
    confidence=0.8,
)


async def test_deterministic_draft_is_valid_sigma_and_stable() -> None:
    draft = await RuleDrafter().draft(_TTP, method=DraftMethod.DETERMINISTIC)
    assert draft.method is DraftMethod.DETERMINISTIC
    parsed = yaml.safe_load(draft.sigma_yaml)
    assert parsed["title"] == draft.title
    assert parsed["detection"]["condition"] == "selection"
    assert parsed["detection"]["selection"]["CommandLine|contains"] == ["-enc", "FromBase64String"]
    assert "attack.t1059.001" in parsed["tags"]
    assert draft.ocsf_classes_required == [OCSFEventClass.PROCESS_ACTIVITY]

    # Deterministic: identical input → identical rule id + body.
    again = await RuleDrafter().draft(_TTP, method=DraftMethod.DETERMINISTIC)
    assert yaml.safe_load(again.sigma_yaml)["id"] == parsed["id"]


async def test_agentic_draft_uses_llm_yaml() -> None:
    async def draft_llm(system: str, user: str, tier: str) -> str:
        assert "<external-data>" in user
        return (
            "```yaml\n"
            "title: LLM Authored Rule\n"
            "id: 11111111-1111-1111-1111-111111111111\n"
            "status: experimental\n"
            "logsource:\n  category: process_creation\n"
            "detection:\n  selection:\n    CommandLine|contains: FromBase64String\n"
            "  condition: selection\n"
            "level: high\n"
            "```"
        )

    draft = await RuleDrafter().draft(_TTP, method=DraftMethod.AGENTIC, llm=draft_llm)
    assert draft.method is DraftMethod.AGENTIC
    parsed = yaml.safe_load(draft.sigma_yaml)
    assert parsed["title"] == "LLM Authored Rule"
    # Fence stripped; no stray backticks left in the body.
    assert "```" not in draft.sigma_yaml


async def test_agentic_without_llm_degrades_to_deterministic() -> None:
    draft = await RuleDrafter().draft(_TTP, method=DraftMethod.AGENTIC, llm=None)
    assert draft.method is DraftMethod.DETERMINISTIC
    assert yaml.safe_load(draft.sigma_yaml)["title"] == draft.title


async def test_agentic_unusable_reply_degrades_to_deterministic() -> None:
    async def junk_llm(system: str, user: str, tier: str) -> str:
        return "this is not yaml at all: [unclosed"

    draft = await RuleDrafter().draft(_TTP, method=DraftMethod.AGENTIC, llm=junk_llm)
    assert draft.method is DraftMethod.DETERMINISTIC
    # Still a valid rule (the template), never the junk.
    assert yaml.safe_load(draft.sigma_yaml)["detection"]["condition"] == "selection"


def test_parse_drafted_yaml_rejects_non_sigma() -> None:
    assert RuleDrafter.parse_drafted_yaml("") is None
    assert RuleDrafter.parse_drafted_yaml("just a string") is None
    # A mapping without the minimum Sigma keys is rejected.
    assert RuleDrafter.parse_drafted_yaml("foo: bar\n") is None
    assert RuleDrafter.parse_drafted_yaml("title: x\ndetection:\n  condition: selection\n")


# --------------------------------------------------------------------------- #
# DataSourceMatcher — reconcile against the real agents-side manifests
# --------------------------------------------------------------------------- #


async def test_matcher_populates_data_sources_from_real_manifests() -> None:
    draft = await RuleDrafter().draft(_TTP, method=DraftMethod.DETERMINISTIC)
    # No connectors matched until reconciliation runs.
    assert draft.data_sources_required == []

    # Default `connected=None` → every registered connector is treated as wired.
    matched = DataSourceMatcher().match(draft)

    # process_activity is emitted by the EDR/XDR connectors in the real registry.
    assert {"crowdstrike", "defender_endpoint", "sentinelone", "cortex"} <= set(
        matched.data_sources_required
    )
    assert matched.data_source_gaps == []
    assert matched.data_sources_required == sorted(matched.data_sources_required)
    # Per-class coverage detail is populated alongside the summary lists.
    assert len(matched.data_source_coverage) == 1
    cov = matched.data_source_coverage[0]
    assert cov.ocsf_class is OCSFEventClass.PROCESS_ACTIVITY
    assert cov.covered is True


async def test_matcher_flags_gap_when_connector_cannot_supply() -> None:
    email_ttp = BehavioralTTP(
        technique_id="T1566.001",
        tactic="initial-access",
        behavior="phishing lure",
        observables=["invoice.html"],
        logsource_category="email",
    )
    draft = await RuleDrafter().draft(email_ttp, method=DraftMethod.DETERMINISTIC)
    assert required_ocsf_classes(email_ttp) == [OCSFEventClass.EMAIL_ACTIVITY]

    # Only Splunk connected — it does not emit email_activity → a coverage gap.
    matched = DataSourceMatcher().match(draft, connected=["splunk"])
    assert matched.data_sources_required == []
    assert OCSFEventClass.EMAIL_ACTIVITY in matched.data_source_gaps

    # An email-security connector connected → gap closes.
    matched2 = DataSourceMatcher().match(draft, connected=["proofpoint", "splunk"])
    assert matched2.data_sources_required == ["proofpoint"]
    assert matched2.data_source_gaps == []


async def test_matcher_accepts_injected_manifests() -> None:
    # Injected manifest map (no agents import) proves the matcher is pure.
    emits = connector_ocsf_emits(connected=["crowdstrike"])
    assert OCSFEventClass.PROCESS_ACTIVITY in emits["crowdstrike"]


# --------------------------------------------------------------------------- #
# Orchestrator + plugin wiring
# --------------------------------------------------------------------------- #


async def test_orchestrator_end_to_end_deterministic() -> None:
    drafts = await draft_detections_from_report(
        _REPORT,
        method=DraftMethod.DETERMINISTIC,
        connected=["crowdstrike", "splunk"],
        title="APT-Sample",
    )
    assert drafts
    techniques = {t for d in drafts for t in d.technique_ids}
    assert {"T1059.001", "T1047"} <= techniques
    for d in drafts:
        assert isinstance(d, DetectionDraft)
        assert d.method is DraftMethod.DETERMINISTIC
        assert d.source_report_sha256  # provenance stamped
        # process_creation drafts reconcile to crowdstrike (splunk lacks process_activity).
        if OCSFEventClass.PROCESS_ACTIVITY in d.ocsf_classes_required:
            assert "crowdstrike" in d.data_sources_required


async def test_orchestrator_accepts_prebuilt_artifact() -> None:
    artifact = IntelArtifact.from_report(_REPORT, title="Named")
    drafts = await draft_detections_from_report(artifact, connected=["crowdstrike"])
    assert all(d.source_report_sha256 == artifact.sha256 for d in drafts)


async def test_plugin_draft_from_report_binds_manifests() -> None:
    from btagent_agents.plugins import load_plugin

    plugin = load_plugin("detection_engineer")
    assert plugin is not None
    drafts = await plugin.draft_from_report(
        "Actor used encoded PowerShell (-enc) and certutil (T1105).",
        agentic=False,
        connected=["crowdstrike", "splunk"],
    )
    assert drafts
    # Manifests were bound from the agents registry → process rules match EDR.
    ps = next((d for d in drafts if "T1059.001" in d.technique_ids), None)
    assert ps is not None
    assert "crowdstrike" in ps.data_sources_required
