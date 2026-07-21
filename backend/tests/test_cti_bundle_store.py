"""Tests for the STIX bundle store + bundle-by-id propose path (#113).

Covers ``services.stix_bundle_store`` (store/get, upsert, skip-no-id) and the
``POST /cti/propose-detections`` ``stix_bundle_id`` resolution path that
replaced the old 501 stub:

* an inline-bundle propose stores the raw bundle;
* a follow-up propose by ``stix_bundle_id`` resolves it and returns proposals;
* an unknown ``stix_bundle_id`` returns 404.
"""

from typing import Any

from conftest import auth_header

from btagent_backend.db.models import DEFAULT_ORG_ID
from btagent_backend.services import stix_bundle_store as store


def _bundle(tag: str) -> dict[str, Any]:
    """A minimal 1-indicator STIX bundle with a per-test-unique id."""
    return {
        "type": "bundle",
        "id": f"bundle--ddddeeee-ffff-0000-1111-0000000{tag}",
        "objects": [
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{tag}1111-2222-3333-4444-555566667777",
                "name": f"Malicious IP {tag}",
                "pattern": "[ipv4-addr:value = '203.0.113.9']",
                "pattern_type": "stix",
                "valid_from": "2026-01-01T00:00:00Z",
                "labels": ["malicious-activity"],
                "external_references": [
                    {"source_name": "mitre-attack", "external_id": "T1071.001"}
                ],
            }
        ],
    }


# --- service ---


async def test_store_and_get_roundtrip(db_session):
    b = _bundle("aa01")
    row = await store.store_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle=b, tlp="green")
    assert row is not None
    fetched = await store.get_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle_id=b["id"])
    assert fetched == b


async def test_store_upserts_same_bundle_id(db_session):
    b = _bundle("aa02")
    r1 = await store.store_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle=b, tlp="green")
    b2 = {**b, "objects": []}  # same id, different content
    r2 = await store.store_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle=b2, tlp="amber")
    assert r1 is not None and r2 is not None
    assert r1.id == r2.id  # upsert, not a new row
    fetched = await store.get_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle_id=b["id"])
    assert fetched == b2


async def test_store_skips_bundle_with_no_id(db_session):
    row = await store.store_bundle(
        db_session, org_id=DEFAULT_ORG_ID, bundle={"type": "bundle", "objects": []}
    )
    assert row is None


async def test_get_unknown_bundle_returns_none(db_session):
    assert (
        await store.get_bundle(db_session, org_id=DEFAULT_ORG_ID, bundle_id="bundle--nope") is None
    )


# --- API: bundle-by-id propose ---


async def test_propose_by_bundle_id_resolves_stored_bundle(client, analyst_token):
    b = _bundle("bb01")
    # 1. Inline propose stores the bundle.
    inline = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle": b, "active_tlp": "green"},
        headers=auth_header(analyst_token),
    )
    assert inline.status_code == 200, inline.text
    inline_titles = {p["title"] for p in inline.json()["proposals"]}
    assert inline_titles

    # 2. Propose by id resolves the stored bundle and returns the same proposals.
    byid = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle_id": b["id"], "active_tlp": "green"},
        headers=auth_header(analyst_token),
    )
    assert byid.status_code == 200, byid.text
    assert {p["title"] for p in byid.json()["proposals"]} == inline_titles


async def test_propose_by_unknown_bundle_id_404(client, analyst_token):
    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle_id": "bundle--does-not-exist", "active_tlp": "green"},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 404, resp.text


async def test_propose_requires_auth(client):
    resp = await client.post(
        "/api/v1/cti/propose-detections",
        json={"stix_bundle_id": "bundle--x", "active_tlp": "green"},
    )
    assert resp.status_code in (401, 403)
