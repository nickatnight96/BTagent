"""Tests for the Behavioral Hunter IntentClassifier chain (#114 Phase A).

Two layers, both model-free:

* Pure prompt-build / parse helpers (no DB, no LLM).
* The injectable ``classify_outlier`` orchestration against the in-memory
  SQLite DB with a deterministic stub LLM, including the Haiku-screen →
  Sonnet-promote tiering and graceful degradation.
"""

from datetime import UTC, datetime, timedelta

import pytest
from btagent_shared.types.behavioral import EntityKind, IntentLabel, ProfileType

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import behavioral_intent_service as intent_svc
from btagent_backend.services import behavioral_service as svc

# --- pure prompt-build ---


def test_build_prompt_wraps_event_in_external_data_tags():
    system, user = intent_svc.build_classification_prompt(
        entity_kind="host",
        canonical_id="WS-1",
        profile_type="cmdline_embedding",
        cosine_distance=0.97,
        frequency_rank=0,
        raw_event_excerpt="winword.exe -> powershell -enc <b64>",
    )
    assert "behavioral threat-hunting analyst" in system
    # Untrusted EDR text must be fenced (prompt-injection defense).
    assert user.startswith("<external-data>")
    assert user.rstrip().endswith("</external-data>")
    assert "winword.exe -> powershell -enc <b64>" in user
    assert "0.9700" in user  # distance formatted


def test_build_prompt_includes_recent_history_bounded():
    history = [f"evt {i}" for i in range(10)]
    _system, user = intent_svc.build_classification_prompt(
        entity_kind="user",
        canonical_id="alice",
        profile_type="cmdline_embedding",
        cosine_distance=0.5,
        frequency_rank=2,
        raw_event_excerpt="something",
        recent_history=history,
    )
    assert "recent prior outliers" in user
    # Bounded to _HISTORY_LIMIT (5).
    assert user.count("- evt ") == intent_svc._HISTORY_LIMIT


# --- pure parse ---


def test_parse_classification_extracts_json_with_surrounding_prose():
    raw = 'Sure! Here you go: {"intent": "malicious", "rationale": "encoded LotL"} thanks'
    parsed = intent_svc.parse_classification(raw)
    assert parsed == (IntentLabel.MALICIOUS, "encoded LotL")


def test_parse_classification_tolerates_code_fence():
    raw = '```json\n{"intent": "benign", "rationale": "admin tooling"}\n```'
    parsed = intent_svc.parse_classification(raw)
    assert parsed is not None
    assert parsed[0] == IntentLabel.BENIGN


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "no json here",
        '{"intent": "totally-unknown", "rationale": "x"}',
        '{"rationale": "missing label"}',
        "{not valid json",
    ],
)
def test_parse_classification_returns_none_on_bad_input(raw):
    assert intent_svc.parse_classification(raw) is None


# --- orchestration with injected stub LLM ---


def _stub_llm(responses: dict[str, str]):
    """Return an async LLMCallable that maps tier -> canned raw text."""
    calls: list[str] = []

    async def _call(system: str, user: str, tier: str) -> str:
        calls.append(tier)
        return responses.get(tier, "")

    _call.calls = calls  # type: ignore[attr-defined]
    return _call


async def _make_outlier(db, *, canonical_id: str, excerpt: str = "powershell -enc <b64>"):
    entity = await svc.upsert_entity(
        db, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id=canonical_id
    )
    now = datetime.now(UTC)
    await svc.build_baseline(
        db,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        vectors=[[1.0, 0.0]],
        pattern_keys=["common_pwsh"],
        window_start=now - timedelta(days=30),
        window_end=now,
    )
    out = await svc.detect_outlier(
        db,
        entity=entity,
        profile_type=ProfileType.CMDLINE_EMBEDDING,
        event_id=f"evt_{canonical_id}",
        event_vector=[0.0, 1.0],
        event_pattern_key="encoded_pwsh_payload",
        raw_event_excerpt=excerpt,
    )
    assert out is not None
    return out


async def test_classify_benign_screen_skips_promotion(db_session):
    out = await _make_outlier(db_session, canonical_id="WS-BENIGN")
    llm = _stub_llm({"fast": '{"intent": "benign", "rationale": "sanctioned admin script"}'})

    updated = await intent_svc.classify_outlier(db_session, outlier_id=out.id, llm=llm)
    assert updated is not None
    assert updated.intent_label == "benign"
    # Benign screen -> NO promotion pass.
    assert llm.calls == ["fast"]


async def test_classify_escalates_non_benign_to_promotion_pass(db_session):
    out = await _make_outlier(db_session, canonical_id="WS-MAL")
    llm = _stub_llm(
        {
            "fast": '{"intent": "suspicious", "rationale": "rare encoded pwsh"}',
            "standard": '{"intent": "malicious", "rationale": "confirmed LotL: winword spawned encoded pwsh"}',
        }
    )

    updated = await intent_svc.classify_outlier(db_session, outlier_id=out.id, llm=llm)
    assert updated is not None
    # The STANDARD-tier confirming verdict wins over the FAST screen.
    assert updated.intent_label == "malicious"
    assert "LotL" in updated.intent_rationale
    assert llm.calls == ["fast", "standard"]


async def test_classify_keeps_screen_verdict_when_promotion_unparseable(db_session):
    out = await _make_outlier(db_session, canonical_id="WS-FALLBACK")
    llm = _stub_llm(
        {
            "fast": '{"intent": "suspicious", "rationale": "rare pattern"}',
            "standard": "garbage not-json",
        }
    )
    updated = await intent_svc.classify_outlier(db_session, outlier_id=out.id, llm=llm)
    assert updated is not None
    assert updated.intent_label == "suspicious"


async def test_classify_returns_none_when_no_model_available(db_session):
    out = await _make_outlier(db_session, canonical_id="WS-NOMODEL")
    # No llm passed and no engine client registered -> skip, row unchanged.
    updated = await intent_svc.classify_outlier(db_session, outlier_id=out.id, llm=None)
    assert updated is None
    refreshed = await svc.get_outlier(db_session, out.id)
    assert refreshed.intent_label is None


async def test_classify_unknown_outlier_raises(db_session):
    with pytest.raises(ValueError, match="not found"):
        await intent_svc.classify_outlier(db_session, outlier_id="bout_nope", llm=_stub_llm({}))
