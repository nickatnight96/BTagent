"""``GET /iocs/export`` honours the caller's TLP ceiling (#586).

The export dialog offers a "Maximum TLP Level" control. It sent that choice as
``tlp_max`` while the route declares ``tlp_level``, and FastAPI discards an
unknown query parameter silently — so the declared parameter always fell back
to its ``"green"`` default. Two consequences, both invisible:

* every bundle was marked TLP:GREEN regardless of what the analyst picked, and
* the org egress policy was only ever evaluated at green.

The route also only ever dropped TLP:RED, so an export "at GREEN" happily
shipped AMBER indicators under a GREEN marking — a downgrade, which is the
failure the whole TLP apparatus exists to prevent.

These tests pin the ceiling as behaviour rather than as a parameter name:
seed IOCs across several classifications, ask for a level, and assert what
comes back. ``test_api_query_param_parity`` covers the name.
"""

from __future__ import annotations

from datetime import UTC, datetime

from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id
from conftest import auth_header
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models import DEFAULT_ORG_ID, InvestigationRow, IOCRow

#: One IOC per classification, so every assertion below can name the exact
#: value it expects to survive the ceiling.
_SEEDED: dict[str, str] = {
    "white": "1.1.1.1",
    "green": "2.2.2.2",
    "amber": "3.3.3.3",
    "amber_strict": "4.4.4.4",
    "red": "5.5.5.5",
}


async def _seed(db: AsyncSession, *, assigned_to: str) -> InvestigationRow:
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=DEFAULT_ORG_ID,
        title="Export ceiling fixture",
        description="one IOC per TLP level",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="amber",
        assigned_to=assigned_to,
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db.add(inv)
    for tlp, value in _SEEDED.items():
        db.add(
            IOCRow(
                id=generate_id("ioc"),
                org_id=DEFAULT_ORG_ID,
                investigation_id=inv.id,
                type="ip",
                value=value,
                tlp_level=tlp,
                confidence=0.9,
                first_seen=datetime.now(UTC),
                last_seen=datetime.now(UTC),
            )
        )
    await db.commit()
    return inv


def _exported_values(bundle: dict) -> set[str]:
    """The IOC values present in a STIX bundle's indicator patterns."""
    return {
        value
        for obj in bundle.get("objects", [])
        if obj.get("type") == "indicator"
        for value in _SEEDED.values()
        if value in obj.get("pattern", "")
    }


async def _export(client: AsyncClient, token: str, inv_id: str, tlp: str):
    return await client.get(
        f"/api/v1/iocs/export?investigation_id={inv_id}&tlp_level={tlp}",
        headers=auth_header(token),
    )


async def test_green_ceiling_excludes_amber_and_stricter(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """The regression: exporting at GREEN must not ship AMBER indicators.

    Before #586 this returned all four non-RED IOCs, every one of them marked
    TLP:GREEN — so an AMBER indicator left the org labelled shareable.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export(client, analyst_token, inv.id, "green")
    assert resp.status_code == 200, resp.text

    exported = _exported_values(resp.json())
    assert exported == {_SEEDED["white"], _SEEDED["green"]}, exported


async def test_amber_ceiling_admits_amber_but_not_amber_strict(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """The ceiling is a rank comparison, not an equality check.

    AMBER admits everything at or below AMBER. ``amber_strict`` is *more*
    restricted despite the shared prefix, so a substring or prefix-based
    implementation would wrongly let it through here.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export(client, analyst_token, inv.id, "amber")
    assert resp.status_code == 200, resp.text

    exported = _exported_values(resp.json())
    assert exported == {_SEEDED["white"], _SEEDED["green"], _SEEDED["amber"]}, exported


async def test_amber_strict_ceiling_still_excludes_red(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """RED never leaves, even under the highest exportable ceiling."""
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export(client, analyst_token, inv.id, "amber_strict")
    assert resp.status_code == 200, resp.text

    exported = _exported_values(resp.json())
    assert _SEEDED["red"] not in exported
    assert _SEEDED["amber_strict"] in exported


async def test_red_ceiling_is_refused_outright(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export(client, analyst_token, inv.id, "red")
    assert resp.status_code == 403, resp.text
    assert "TLP:RED" in resp.json()["detail"]


async def test_unknown_tlp_is_rejected_rather_than_defaulted(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """A garbage ceiling must 422, not quietly fall back to green.

    This is the same failure mode as the parameter-name bug one level down: a
    value the backend cannot interpret must not become "the default", because
    the caller asked for something specific and would never learn it was
    ignored. ``amber+strict`` is the concrete case — it is what the old
    frontend produced by lowercasing its display string.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    for bad in ("amber+strict", "clear", "definitely-not-a-tlp"):
        resp = await _export(client, analyst_token, inv.id, bad)
        assert resp.status_code == 422, f"{bad}: {resp.status_code} {resp.text}"


async def test_indicators_carry_a_marking_at_the_requested_level(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """Every exported indicator is marked, and at the ceiling that was asked for.

    The bundle is uniformly marked at its declared classification rather than
    per-indicator: with the ceiling filter in place nothing included can be
    *more* restricted than the ceiling, so this can only ever over-mark, never
    downgrade. The default-to-green behaviour it replaces could do the latter.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export(client, analyst_token, inv.id, "amber")
    assert resp.status_code == 200, resp.text

    indicators = [o for o in resp.json()["objects"] if o.get("type") == "indicator"]
    assert indicators, "no indicators in the bundle"
    for indicator in indicators:
        refs = indicator.get("object_marking_refs")
        assert refs, f"indicator exported unmarked: {indicator.get('name')}"
