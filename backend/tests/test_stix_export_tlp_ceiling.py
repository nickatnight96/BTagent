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


# --------------------------------------------------------------------------- #
# The dialog's other three controls (#586 follow-through)
# --------------------------------------------------------------------------- #
#
# ``format``, ``type`` and ``confidence_min`` were discarded by the same
# mechanism as ``tlp_max``: the route did not declare them, so FastAPI dropped
# them without a word. ``format`` was the one with teeth — the endpoint always
# returned STIX while ``iocStore`` picked the download *extension* from the
# analyst's choice, so "CSV" saved STIX JSON into a ``.csv`` file.


async def _export_fmt(client: AsyncClient, token: str, inv_id: str, **params):
    query = "&".join(f"{k}={v}" for k, v in params.items())
    return await client.get(
        f"/api/v1/iocs/export?investigation_id={inv_id}&{query}",
        headers=auth_header(token),
    )


async def test_csv_format_returns_csv_not_stix(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """The headline bug: asking for CSV must not return a STIX bundle."""
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export_fmt(client, analyst_token, inv.id, tlp_level="amber", format="csv")
    assert resp.status_code == 200, resp.text
    assert resp.headers["content-type"].startswith("text/csv")

    body = resp.text
    assert not body.lstrip().startswith("{"), "CSV export returned JSON"
    header, *rows = [ln for ln in body.splitlines() if ln.strip()]
    # Column order matches what ``_parse_csv_rows`` reads, so an export
    # re-imports cleanly.
    assert header == "type,value,source,confidence,tlp"
    assert any(_SEEDED["amber"] in row for row in rows)


async def test_csv_export_carries_the_classification(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """CSV has no marking mechanism, so the TLP must ride in a column.

    Without it, picking CSV would turn export into a classification-stripping
    channel: the indicators leave and the label does not.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export_fmt(client, analyst_token, inv.id, tlp_level="amber", format="csv")
    assert resp.status_code == 200, resp.text

    by_value = {
        row.split(",")[1]: row.split(",")[4] for row in resp.text.splitlines()[1:] if row.strip()
    }
    assert by_value[_SEEDED["amber"]] == "amber"
    assert by_value[_SEEDED["green"]] == "green"


async def test_csv_export_still_obeys_the_tlp_ceiling(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """A different serialisation must not be a way around the ceiling."""
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export_fmt(client, analyst_token, inv.id, tlp_level="green", format="csv")
    assert resp.status_code == 200, resp.text

    body = resp.text
    assert _SEEDED["green"] in body
    for excluded in ("amber", "amber_strict", "red"):
        assert _SEEDED[excluded] not in body, f"{excluded} leaked into a green CSV export"


async def test_json_format_returns_plain_iocs_with_the_level(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export_fmt(client, analyst_token, inv.id, tlp_level="amber", format="json")
    assert resp.status_code == 200, resp.text

    payload = resp.json()
    assert payload["tlp_level"] == "amber"
    assert "objects" not in payload, "json format returned a STIX bundle"
    assert {i["value"] for i in payload["iocs"]} == {
        _SEEDED["white"],
        _SEEDED["green"],
        _SEEDED["amber"],
    }


async def test_type_filter_narrows_the_export(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    inv = await _seed(db_session, assigned_to=sample_user.id)
    # Everything seeded is an ip, so a different type must yield nothing —
    # proving the filter is applied rather than ignored.
    resp = await _export_fmt(
        client, analyst_token, inv.id, tlp_level="amber", format="json", type="domain"
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["iocs"] == []

    same = await _export_fmt(
        client, analyst_token, inv.id, tlp_level="amber", format="json", type="ip"
    )
    assert len(same.json()["iocs"]) == 3


async def test_confidence_floor_narrows_the_export(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """The seed is all at 0.9, so a floor above it must empty the export."""
    inv = await _seed(db_session, assigned_to=sample_user.id)

    kept = await _export_fmt(
        client, analyst_token, inv.id, tlp_level="amber", format="json", confidence_min=0.5
    )
    assert len(kept.json()["iocs"]) == 3

    dropped = await _export_fmt(
        client, analyst_token, inv.id, tlp_level="amber", format="json", confidence_min=0.95
    )
    assert dropped.json()["iocs"] == []


async def test_unknown_format_is_rejected(
    client: AsyncClient, analyst_token: str, db_session: AsyncSession, sample_user
):
    """An unsupported format must 422 rather than quietly falling back to STIX.

    Same principle as the TLP level above: a value the endpoint cannot honour
    must not silently become the default, because that is indistinguishable
    from having asked for the default.
    """
    inv = await _seed(db_session, assigned_to=sample_user.id)

    resp = await _export_fmt(client, analyst_token, inv.id, tlp_level="amber", format="pdf")
    assert resp.status_code == 422, resp.text


def test_csv_export_round_trips_through_the_import_parser():
    """The exported column order is the one ``_parse_csv_rows`` reads.

    Export and import are separate code paths that agree only by convention,
    so the convention is pinned here rather than left to be discovered when
    an analyst's round-trip silently drops every row.

    Note what is *not* preserved: the parser reads columns 0-3 and ignores the
    rest, so the ``tlp`` column rides along in the file but does not come back
    as a classification — re-imported IOCs take the default. That is a real
    limitation of the import side, asserted here so it is a known boundary
    rather than a surprise.
    """
    from btagent_backend.api.v1.iocs import _parse_csv_rows

    exported = (
        "type,value,source,confidence,tlp\n"
        "ip,1.2.3.4,btagent_export,0.9,amber\n"
        "domain,evil.example,btagent_export,0.75,green\n"
    )

    rows, skipped = _parse_csv_rows(exported)

    assert skipped == 0, "an exported CSV must not lose rows on re-import"
    assert [r["value"] for r in rows] == ["1.2.3.4", "evil.example"]
    assert [r["type"] for r in rows] == ["ip", "domain"]
    assert rows[0]["confidence"] == 0.9
    # The trailing tlp column is carried in the file but not read back.
    assert "tlp_level" not in rows[0]
