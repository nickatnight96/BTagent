"""Backend-side TLP egress gate tests.

Covers the two backend egress points that route through
``btagent_shared.security.assert_tlp_allows_egress``:

* :func:`btagent_backend.services.stix_service.stix_bundle_from_iocs`
  -- STIX 2.1 bundle export.
* :class:`btagent_backend.services.knowledge_service.KnowledgeService`
  -- ``ingest_document`` and the two ``auto_index_*`` paths.

The corresponding agents-side tests (``agents/tests/test_tlp_egress.py``)
cover MCP-return and EventEmitter; together they exercise all four
egress kinds against the same shared helper.
"""

from __future__ import annotations

import pytest
from btagent_shared.security import TLPViolation
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import InvestigationRow, IOCRow
from btagent_backend.services.knowledge_service import KnowledgeService
from btagent_backend.services.stix_service import stix_bundle_from_iocs

# --------------------------------------------------------------------------- #
# STIX export
# --------------------------------------------------------------------------- #


def test_stix_bundle_red_context_raises():
    """A TLP:RED export context hard-blocks the bundle (was: silent empty)."""
    iocs = [{"type": "ip", "value": "10.0.0.1", "confidence": 0.9, "tlp_level": "green"}]
    with pytest.raises(TLPViolation):
        stix_bundle_from_iocs(iocs, tlp_level="red")


def test_stix_bundle_green_context_emits_indicators():
    """Non-RED contexts produce a non-empty bundle and pass the gate."""
    iocs = [
        {"type": "ip", "value": "10.0.0.2", "confidence": 0.8, "tlp_level": "green"},
        {"type": "domain", "value": "evil.example", "confidence": 0.7, "tlp_level": "amber"},
    ]
    bundle = stix_bundle_from_iocs(iocs, tlp_level="green")
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 2


def test_stix_bundle_red_tagged_payload_blocks_even_in_green_context():
    """The recursive payload scan trips on any embedded ``tlp_level: red``.

    Contract change vs prior behaviour: callers must pre-filter RED IOCs
    before calling ``stix_bundle_from_iocs``. The API layer already does
    this (see ``api/v1/iocs.py:export_stix``); the gate here is the
    defense-in-depth backstop that catches internal callers that forget.
    """
    iocs = [
        {"type": "ip", "value": "10.0.0.1", "confidence": 0.9, "tlp_level": "red"},
        {"type": "ip", "value": "10.0.0.2", "confidence": 0.8, "tlp_level": "green"},
    ]
    with pytest.raises(TLPViolation):
        stix_bundle_from_iocs(iocs, tlp_level="green")


def test_stix_bundle_pre_filtered_input_succeeds():
    """When the caller has pre-filtered RED IOCs (the API-layer pattern),
    the bundle is produced normally."""
    pre_filtered = [
        {"type": "ip", "value": "10.0.0.2", "confidence": 0.8, "tlp_level": "green"},
        {"type": "domain", "value": "evil.example", "confidence": 0.7, "tlp_level": "amber"},
    ]
    bundle = stix_bundle_from_iocs(pre_filtered, tlp_level="green")
    assert bundle["type"] == "bundle"
    assert len(bundle["objects"]) == 2
    patterns = [obj.get("pattern", "") for obj in bundle["objects"]]
    assert any("10.0.0.2" in p for p in patterns)
    assert any("evil.example" in p for p in patterns)


# --------------------------------------------------------------------------- #
# Knowledge ingest
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio
async def test_knowledge_ingest_red_classification_raises(db_session: AsyncSession):
    svc = KnowledgeService()
    with pytest.raises(TLPViolation):
        await svc.ingest_document(
            db_session,
            title="Restricted Note",
            content="some body",
            source_type="manual",
            classification="red",
        )


@pytest.mark.asyncio
async def test_knowledge_ingest_green_classification_succeeds(db_session: AsyncSession):
    svc = KnowledgeService()
    doc = await svc.ingest_document(
        db_session,
        title="Public Note",
        content="public threat brief",
        source_type="manual",
        classification="green",
    )
    assert doc.title == "Public Note"
    assert doc.source_type == "manual"


@pytest.mark.asyncio
async def test_knowledge_ingest_no_classification_defaults_to_green(
    db_session: AsyncSession,
):
    """Unset classification should not raise -- defaults to TLP.GREEN."""
    svc = KnowledgeService()
    doc = await svc.ingest_document(
        db_session,
        title="Untagged Note",
        content="content",
        source_type="manual",
    )
    assert doc.title == "Untagged Note"


@pytest.mark.asyncio
async def test_auto_index_investigation_red_blocks_ingest(
    db_session: AsyncSession,
    sample_user,
):
    """auto_index_investigation must propagate the investigation's TLP level."""
    from datetime import UTC, datetime

    from btagent_shared.types.enums import InvestigationStatus, Severity
    from btagent_shared.utils.ids import generate_id

    red_inv = InvestigationRow(
        id=generate_id("inv"),
        title="Restricted Case",
        description="restricted",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="red",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(red_inv)
    await db_session.commit()

    svc = KnowledgeService()
    with pytest.raises(TLPViolation):
        await svc.auto_index_investigation(db_session, red_inv.id)


@pytest.mark.asyncio
async def test_auto_index_investigation_green_succeeds(
    db_session: AsyncSession,
    sample_investigation,
):
    """A GREEN investigation auto-indexes without raising."""
    svc = KnowledgeService()
    doc = await svc.auto_index_investigation(db_session, sample_investigation.id)
    assert doc is not None
    assert "Investigation Report" in doc.title


@pytest.mark.asyncio
async def test_auto_index_enrichment_red_blocks(
    db_session: AsyncSession,
    sample_user,
):
    """auto_index_enrichment also fetches and propagates investigation TLP."""
    from datetime import UTC, datetime

    from btagent_shared.types.enums import InvestigationStatus, Severity
    from btagent_shared.utils.ids import generate_id

    red_inv = InvestigationRow(
        id=generate_id("inv"),
        title="Restricted Enrichment Case",
        description="restricted",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="red",
        assigned_to=sample_user.id,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(red_inv)
    ioc = IOCRow(
        id=generate_id("ioc"),
        investigation_id=red_inv.id,
        type="ip",
        value="10.0.0.5",
        confidence=0.8,
        source="manual",
        tlp_level="red",
        enrichment={"vt_score": 0.9},
        first_seen=datetime.now(UTC),
    )
    db_session.add(ioc)
    await db_session.commit()

    svc = KnowledgeService()
    with pytest.raises(TLPViolation):
        await svc.auto_index_enrichment(db_session, red_inv.id)
