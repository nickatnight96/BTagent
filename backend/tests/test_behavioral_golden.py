"""Golden detection test for the Behavioral Hunter (#114 Phase A).

End-to-end (service layer, in-memory SQLite, stubbed classifier): build a
benign baseline for a workstation, then inject a synthetic Living-off-the-
Land sequence — an encoded-PowerShell child of ``winword.exe`` — and assert
the OutlierDetector flags it and the (stubbed) IntentClassifier rates it
suspicious/malicious. A small, fast, deterministic subset of the real
pipeline; no embedding service or live model required.
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.types.behavioral import EntityKind, IntentLabel, ProfileType

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import behavioral_intent_service as intent_svc
from btagent_backend.services import behavioral_service as svc

# A 4-dim toy embedding space standing in for the real cmdline-embedding model.
# Benign developer/admin command lines cluster on the first axis; the LotL
# encoded-PowerShell command is orthogonal (worst-case cosine distance).
_BENIGN_VECTORS = [
    [1.0, 0.0, 0.0, 0.0],
    [0.98, 0.02, 0.0, 0.0],
    [0.95, 0.05, 0.0, 0.0],
    [0.97, 0.0, 0.03, 0.0],
]
_BENIGN_PATTERNS = [
    "explorer.exe>cmd.exe",
    "explorer.exe>code.exe",
    "services.exe>svchost.exe",
    "explorer.exe>cmd.exe",
]
# The malicious event: winword.exe spawning encoded PowerShell — a classic
# LotL parent/child anomaly that does not appear in the benign baseline.
_LOTL_VECTOR = [0.0, 0.0, 0.0, 1.0]
_LOTL_PATTERN = "winword.exe>powershell.exe -enc"
_LOTL_EXCERPT = (
    "winword.exe -> powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA..."
)


def _suspicious_then_malicious_llm():
    """Stub LLM: FAST screen rates suspicious, STANDARD promotion confirms malicious."""

    async def _call(system: str, user: str, tier: str) -> str:
        # The untrusted event excerpt must have reached the prompt, fenced.
        assert "<external-data>" in user
        assert "winword.exe" in user
        if tier == "fast":
            return '{"intent": "suspicious", "rationale": "encoded pwsh, rare parent/child"}'
        return (
            '{"intent": "malicious", "rationale": '
            '"LotL: winword.exe spawned encoded PowerShell, far from baseline"}'
        )

    return _call


async def test_lotl_sequence_is_detected_and_rated_malicious(db_session):
    # 1. Build a benign baseline for the workstation.
    entity = await svc.upsert_entity(
        db_session,
        org_id=DEFAULT_ORG_ID,
        kind=EntityKind.HOST,
        canonical_id="WS-GOLDEN",
    )
    now = datetime.now(UTC)
    profile = await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=_BENIGN_VECTORS,
        pattern_keys=_BENIGN_PATTERNS,
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    assert profile.sample_size == len(_BENIGN_VECTORS)
    assert _LOTL_PATTERN not in profile.frequency_map  # never observed benignly

    # 2. Inject the LotL event -> the OutlierDetector must flag it.
    outlier = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_lotl_golden",
        event_vector=_LOTL_VECTOR,
        event_pattern_key=_LOTL_PATTERN,
        raw_event_excerpt=_LOTL_EXCERPT,
    )
    assert outlier is not None, "LotL encoded-PowerShell sequence must be flagged as an outlier"
    assert outlier.cosine_distance > 0.9  # orthogonal to the benign centroid
    assert outlier.frequency_rank == 0  # never-before-seen parent/child pattern
    assert outlier.intent_label is None  # not yet classified

    # 3. The (stubbed) IntentClassifier rates it suspicious/malicious.
    classified = await intent_svc.classify_outlier(
        db_session, outlier_id=outlier.id, llm=_suspicious_then_malicious_llm()
    )
    assert classified is not None
    assert classified.intent_label in {IntentLabel.SUSPICIOUS.value, IntentLabel.MALICIOUS.value}
    assert classified.intent_label == IntentLabel.MALICIOUS.value  # confirming pass wins

    # 4. Promotion lands it in the #119 HuntFinding queue with high severity.
    finding_id = await svc.promote_outlier(
        db_session, outlier_id=outlier.id, technique_ids=["T1059.001", "T1566"]
    )
    assert finding_id.startswith("hfnd_")
    refreshed = await svc.get_outlier(db_session, outlier.id)
    assert refreshed.promoted_to_finding_id == finding_id


async def test_benign_variation_does_not_flag(db_session):
    # Control: a command line near the benign centroid (even with a slightly
    # new pattern) is NOT flagged — guards against the golden test passing
    # because everything trips the detector.
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-GOLDEN-CTRL"
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=_BENIGN_VECTORS,
        pattern_keys=_BENIGN_PATTERNS,
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db_session,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id="evt_benign_variation",
        event_vector=[0.99, 0.01, 0.0, 0.0],  # near the benign centroid
        event_pattern_key="explorer.exe>notepad.exe",
    )
    assert out is None
