"""Tests for the Behavioral Hunter embedding bridge + OCSF consumer (#114 Phase A).

Covers the last-mile wiring that turns raw EDR/OCSF process telemetry into the
vectors + pattern keys the baseline builder / outlier scorer consume:

* ``behavioral_ingest_service.build_baseline_from_events`` (task A)
* ``behavioral_ingest_service.score_event`` (task A)
* ``behavioral_ingest_service.consume_process_event`` — the OCSF process-
  activity consumer that live-scores via ``detect_outlier`` (task C)

A small deterministic "semantic" embedder stands in for the real cmdline model:
benign developer/admin commands cluster on one axis, Living-off-the-Land
tradecraft (encoded PowerShell, certutil, mshta, ...) lands on orthogonal axes.
This gives meaningful cosine distances (the hash-based ``MockEmbeddingService``
saturates distance, so it can't exercise the distance half of the detector).
"""

from datetime import UTC, datetime, timedelta

from btagent_shared.types.behavioral import EntityKind, ProfileType

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.db.models_behavioral import CENTROID_DIM
from btagent_backend.services import behavioral_ingest_service as ingest
from btagent_backend.services import behavioral_service as svc
from btagent_backend.services.embedding_service import EmbeddingService

# --------------------------------------------------------------------------- #
# A deterministic semantic toy embedder (benign clusters; LotL is orthogonal)
# --------------------------------------------------------------------------- #

# 6 orthonormal axes: [benign, encoded_pwsh, certutil, mshta, script_host, other]
_ENCODED_PWSH = (
    "-enc",
    "-encodedcommand",
    "frombase64",
    "downloadstring",
    "iex",
    "-w hidden",
    "-nop",
)
_SCRIPT_HOST = ("regsvr32", "rundll32", "bitsadmin", "wmic", "cscript", "wscript", "scrobj")


def _axis(cmdline: str) -> list[float]:
    c = cmdline.lower()
    if any(k in c for k in _ENCODED_PWSH):
        return [0.0, 1.0, 0.0, 0.0, 0.0, 0.0]
    if "certutil" in c:
        return [0.0, 0.0, 1.0, 0.0, 0.0, 0.0]
    if "mshta" in c or ".hta" in c:
        return [0.0, 0.0, 0.0, 1.0, 0.0, 0.0]
    if any(k in c for k in _SCRIPT_HOST):
        return [0.0, 0.0, 0.0, 0.0, 1.0, 0.0]
    return [1.0, 0.0, 0.0, 0.0, 0.0, 0.0]  # benign cluster


class _ToyEmbeddingService(EmbeddingService):
    """Maps cmdlines to a 6-dim semantic axis — benign vs LotL families."""

    @property
    def provider_name(self) -> str:
        return "toy-semantic"

    async def generate_embeddings(self, texts: list[str]) -> list[list[float]]:
        return [_axis(t) for t in texts]


def _benign_events() -> list[ingest.ProcessEvent]:
    return [
        ingest.ProcessEvent(
            event_id=f"evt_b_{i}",
            entity_canonical_id="WS-INGEST",
            entity_kind=EntityKind.HOST,
            cmdline=cmd,
            process_name=child,
            parent_name=parent,
        )
        for i, (parent, child, cmd) in enumerate(
            [
                ("explorer.exe", "cmd.exe", "cmd.exe /c dir"),
                ("explorer.exe", "chrome.exe", "chrome.exe --profile"),
                ("Code.exe", "git.exe", "git.exe fetch --all"),
                ("Code.exe", "python.exe", "python.exe -m pytest -q"),
                ("services.exe", "svchost.exe", "svchost.exe -k netsvcs"),
            ]
        )
    ]


async def _build_ingest_baseline(db, entity):
    now = datetime.now(UTC)
    return await ingest.build_baseline_from_events(
        db,
        entity=entity,
        events=_benign_events(),
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=_ToyEmbeddingService(),
    )


# --------------------------------------------------------------------------- #
# pattern-key helper
# --------------------------------------------------------------------------- #


def test_process_pattern_key_basenames_and_lowercase():
    assert (
        ingest.process_pattern_key(
            "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        )
        == "winword.exe>powershell.exe"
    )
    assert ingest.process_pattern_key("/usr/bin/bash", "/usr/bin/python3") == "bash>python3"
    assert ingest.process_pattern_key("", "") == ""


# --------------------------------------------------------------------------- #
# (A) build_baseline_from_events
# --------------------------------------------------------------------------- #


async def test_build_baseline_from_events_embeds_cmdlines(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-INGEST"
    )
    profile = await _build_ingest_baseline(db_session, entity)

    # Centroid is the elementwise mean of the 6-dim toy embeddings, widened to
    # the fixed pgvector column width (zero-padding is cosine-distance
    # preserving — see ``behavioral_service._to_centroid_vector``).
    assert profile.centroid is not None
    assert len(profile.centroid) == CENTROID_DIM
    assert all(x == 0.0 for x in profile.centroid[6:])
    # All five benign cmdlines land on the benign axis -> centroid ~ [1,0,...].
    assert profile.centroid[0] > 0.9
    # Frequency map keyed on parent>child lineage.
    assert "explorer.exe>cmd.exe" in profile.frequency_map
    assert "code.exe>git.exe" in profile.frequency_map
    assert profile.sample_size == 5


async def test_build_baseline_skips_blank_cmdlines(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-INGEST-BLANK"
    )
    now = datetime.now(UTC)
    events = [
        ingest.ProcessEvent(
            event_id="e1",
            entity_canonical_id="WS-INGEST-BLANK",
            cmdline="cmd.exe /c dir",
            process_name="cmd.exe",
            parent_name="explorer.exe",
        ),
        # A lineage with no captured cmdline: contributes a pattern, no vector.
        ingest.ProcessEvent(
            event_id="e2",
            entity_canonical_id="WS-INGEST-BLANK",
            cmdline="   ",
            process_name="svchost.exe",
            parent_name="services.exe",
        ),
    ]
    profile = await ingest.build_baseline_from_events(
        db_session,
        entity=entity,
        events=events,
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=_ToyEmbeddingService(),
    )
    # Only one cmdline embedded -> centroid built from one vector (then
    # zero-padded out to the fixed column width).
    assert list(profile.centroid[:6]) == [1.0, 0.0, 0.0, 0.0, 0.0, 0.0]
    assert len(profile.centroid) == CENTROID_DIM
    assert all(x == 0.0 for x in profile.centroid[6:])
    # Both lineages counted in the frequency map.
    assert set(profile.frequency_map) == {"explorer.exe>cmd.exe", "services.exe>svchost.exe"}


# --------------------------------------------------------------------------- #
# (A) score_event
# --------------------------------------------------------------------------- #


async def test_score_event_flags_lotl_cmdline(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-INGEST-SCORE"
    )
    now = datetime.now(UTC)
    await ingest.build_baseline_from_events(
        db_session,
        entity=entity,
        events=[
            ingest.ProcessEvent(
                event_id=f"b{i}",
                entity_canonical_id="WS-INGEST-SCORE",
                cmdline=cmd,
                process_name=child,
                parent_name=parent,
            )
            for i, (parent, child, cmd) in enumerate(
                [
                    ("explorer.exe", "cmd.exe", "cmd.exe /c dir"),
                    ("Code.exe", "git.exe", "git.exe status"),
                ]
            )
        ],
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=_ToyEmbeddingService(),
    )

    lotl = ingest.ProcessEvent(
        event_id="evt_lotl_ingest",
        entity_canonical_id="WS-INGEST-SCORE",
        cmdline="powershell.exe -nop -w hidden -enc SQBFAFgAIAA...",
        process_name="powershell.exe",
        parent_name="winword.exe",
        raw_excerpt="winword.exe -> powershell -enc ...",
    )
    outlier = await ingest.score_event(
        db_session, entity=entity, event=lotl, embedding_service=_ToyEmbeddingService()
    )
    assert outlier is not None
    assert outlier.event_pattern_key == "winword.exe>powershell.exe"
    assert outlier.cosine_distance > 0.9  # orthogonal to the benign axis
    assert outlier.frequency_rank == 0  # never-before-seen lineage
    assert outlier.raw_event_excerpt == "winword.exe -> powershell -enc ..."


async def test_score_event_benign_near_baseline_not_flagged(db_session):
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-INGEST-BEN"
    )
    now = datetime.now(UTC)
    await ingest.build_baseline_from_events(
        db_session,
        entity=entity,
        events=_benign_events(),
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=_ToyEmbeddingService(),
    )
    # A benign command near the baseline centroid: not distant -> not an outlier
    # even though its exact lineage is new.
    benign = ingest.ProcessEvent(
        event_id="evt_benign_ingest",
        entity_canonical_id="WS-INGEST-BEN",
        cmdline="notepad.exe C:\\Users\\jsmith\\notes.txt",
        process_name="notepad.exe",
        parent_name="explorer.exe",
    )
    out = await ingest.score_event(
        db_session, entity=entity, event=benign, embedding_service=_ToyEmbeddingService()
    )
    assert out is None


# --------------------------------------------------------------------------- #
# (C) consume_process_event — OCSF process-activity consumer
# --------------------------------------------------------------------------- #


def _ocsf_process_event(*, hostname="", user="", cmdline="", process="", parent="", uid="evt"):
    return {
        "class_uid": 1007,
        "uid": uid,
        "device": {"hostname": hostname} if hostname else {},
        "actor": {
            "process": {"name": parent} if parent else {},
            "user": {"name": user} if user else {},
        },
        "process": {"name": process, "cmd_line": cmdline},
    }


def test_process_event_from_ocsf_parses_lineage():
    ev = ingest.process_event_from_ocsf(
        _ocsf_process_event(
            hostname="WS-OCSF",
            user="ACME\\jsmith",
            cmdline="powershell -enc AAA",
            process="powershell.exe",
            parent="winword.exe",
            uid="evt_ocsf_1",
        )
    )
    assert ev is not None
    assert ev.entity_kind == EntityKind.HOST
    assert ev.entity_canonical_id == "WS-OCSF"
    assert ev.process_name == "powershell.exe"
    assert ev.parent_name == "winword.exe"
    assert ev.event_id == "evt_ocsf_1"


def test_process_event_from_ocsf_falls_back_to_user():
    ev = ingest.process_event_from_ocsf(
        _ocsf_process_event(user="ACME\\jsmith", cmdline="whoami", process="whoami.exe")
    )
    assert ev is not None
    assert ev.entity_kind == EntityKind.USER
    assert ev.entity_canonical_id == "ACME\\jsmith"


def test_process_event_from_ocsf_returns_none_without_entity():
    assert ingest.process_event_from_ocsf(_ocsf_process_event(cmdline="foo")) is None
    assert ingest.process_event_from_ocsf("not-a-dict") is None  # type: ignore[arg-type]


async def test_consume_process_event_flags_lotl_and_upserts_entity(db_session):
    # Seed a benign baseline for the host the consumer will auto-resolve.
    entity = await svc.upsert_entity(
        db_session, org_id=DEFAULT_ORG_ID, kind=EntityKind.HOST, canonical_id="WS-CONSUME"
    )
    now = datetime.now(UTC)
    await ingest.build_baseline_from_events(
        db_session,
        entity=entity,
        events=[
            ingest.ProcessEvent(
                event_id=f"b{i}",
                entity_canonical_id="WS-CONSUME",
                cmdline=cmd,
                process_name=child,
                parent_name=parent,
            )
            for i, (parent, child, cmd) in enumerate(
                [
                    ("explorer.exe", "cmd.exe", "cmd.exe /c dir"),
                    ("explorer.exe", "chrome.exe", "chrome.exe"),
                ]
            )
        ],
        window_start=now - timedelta(days=30),
        window_end=now,
        embedding_service=_ToyEmbeddingService(),
    )

    ocsf = _ocsf_process_event(
        hostname="WS-CONSUME",
        cmdline="powershell.exe -nop -w hidden -enc SQBFAFgA",
        process="powershell.exe",
        parent="winword.exe",
        uid="evt_consume_lotl",
    )
    outlier = await ingest.consume_process_event(
        db_session,
        org_id=DEFAULT_ORG_ID,
        ocsf_event=ocsf,
        embedding_service=_ToyEmbeddingService(),
    )
    assert outlier is not None
    assert outlier.event_id == "evt_consume_lotl"
    assert outlier.event_pattern_key == "winword.exe>powershell.exe"
    assert outlier.intent_label is None  # scoring only; classification is separate


async def test_consume_process_event_no_baseline_returns_none(db_session):
    # An unknown host has no baseline yet -> the consumer upserts the entity but
    # under-calls (returns None) rather than flagging a first-ever event.
    ocsf = _ocsf_process_event(
        hostname="WS-BRAND-NEW",
        cmdline="powershell -enc AAA",
        process="powershell.exe",
        parent="winword.exe",
    )
    outlier = await ingest.consume_process_event(
        db_session,
        org_id=DEFAULT_ORG_ID,
        ocsf_event=ocsf,
        embedding_service=_ToyEmbeddingService(),
    )
    assert outlier is None
    # ...but the entity was created so the next baseline sweep can profile it.
    from sqlalchemy import select

    from btagent_backend.db.models_behavioral import BehavioralEntityRow

    row = (
        await db_session.execute(
            select(BehavioralEntityRow).where(
                BehavioralEntityRow.org_id == DEFAULT_ORG_ID,
                BehavioralEntityRow.canonical_id == "WS-BRAND-NEW",
            )
        )
    ).scalar_one_or_none()
    assert row is not None


async def test_consume_process_event_unresolvable_entity_returns_none(db_session):
    out = await ingest.consume_process_event(
        db_session,
        org_id=DEFAULT_ORG_ID,
        ocsf_event=_ocsf_process_event(cmdline="orphan"),
        embedding_service=_ToyEmbeddingService(),
    )
    assert out is None
