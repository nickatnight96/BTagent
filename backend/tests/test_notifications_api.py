"""Tests for the in-app notifications API.

Wires HTTP coverage over the previously-unexposed NotificationService read
helpers: list (with unread filter + unread badge count), mark-one-read (own
notifications only), and mark-all-read.
"""

from btagent_shared.utils.ids import generate_id
from conftest import auth_header

from btagent_backend.db.models import NotificationRow


async def _seed(db_session, user_id: str, *, unread: int, read: int = 0) -> list[NotificationRow]:
    rows: list[NotificationRow] = []
    for i in range(unread + read):
        row = NotificationRow(
            id=generate_id("ntf"),
            user_id=user_id,
            type="info",
            title=f"Notification {i}",
            message="body",
            read=i >= unread,
        )
        db_session.add(row)
        rows.append(row)
    await db_session.commit()
    return rows


async def test_list_returns_user_notifications_with_unread_count(
    client, analyst_token, sample_user, db_session
):
    await _seed(db_session, sample_user.id, unread=2, read=1)
    resp = await client.get("/api/v1/notifications", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["items"]) == 3
    assert data["unread"] == 2


async def test_unread_only_filter(client, analyst_token, sample_user, db_session):
    await _seed(db_session, sample_user.id, unread=2, read=2)
    resp = await client.get(
        "/api/v1/notifications?unread_only=true", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()
    assert len(data["items"]) == 2
    assert all(not item["read"] for item in data["items"])
    assert data["unread"] == 2


async def test_mark_one_read(client, analyst_token, sample_user, db_session):
    rows = await _seed(db_session, sample_user.id, unread=2)
    target = rows[0].id
    resp = await client.post(
        f"/api/v1/notifications/{target}/read", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 204, resp.text

    listing = await client.get("/api/v1/notifications", headers=auth_header(analyst_token))
    assert listing.json()["unread"] == 1


async def test_mark_read_unknown_404(client, analyst_token, sample_user):
    resp = await client.post(
        "/api/v1/notifications/ntf_does_not_exist/read", headers=auth_header(analyst_token)
    )
    assert resp.status_code == 404, resp.text


async def test_mark_all_read(client, analyst_token, sample_user, db_session):
    await _seed(db_session, sample_user.id, unread=3)
    resp = await client.post("/api/v1/notifications/read-all", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    assert resp.json()["marked"] == 3

    listing = await client.get("/api/v1/notifications", headers=auth_header(analyst_token))
    assert listing.json()["unread"] == 0


async def test_requires_auth(client):
    resp = await client.get("/api/v1/notifications")
    assert resp.status_code in (401, 403)


async def test_link_round_trips_through_the_api(client, analyst_token, sample_user, db_session):
    row = NotificationRow(
        id=generate_id("ntf"),
        user_id=sample_user.id,
        type="critical_finding",
        title="Critical Hunt Findings",
        message="deep-link roundtrip",
        link="/hunt",
        read=False,
    )
    db_session.add(row)
    await db_session.commit()

    listing = await client.get("/api/v1/notifications", headers=auth_header(analyst_token))
    assert listing.status_code == 200, listing.text
    items = {i["id"]: i for i in listing.json()["items"]}
    assert items[row.id]["link"] == "/hunt"
    # Rows without a link serialise it as null (bell falls back to the
    # investigation deep-link).
    others = await _seed(db_session, sample_user.id, unread=1)
    listing = await client.get("/api/v1/notifications", headers=auth_header(analyst_token))
    items = {i["id"]: i for i in listing.json()["items"]}
    assert items[others[0].id]["link"] is None


async def test_preferences_round_trip_with_dedup(client, analyst_token, sample_user):
    resp = await client.get("/api/v1/notifications/preferences", headers=auth_header(analyst_token))
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"muted_types": []}

    resp = await client.put(
        "/api/v1/notifications/preferences",
        json={"muted_types": ["noise_digest", " noise_digest ", "", "critical_finding"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text
    assert resp.json() == {"muted_types": ["noise_digest", "critical_finding"]}

    resp = await client.get("/api/v1/notifications/preferences", headers=auth_header(analyst_token))
    assert resp.json() == {"muted_types": ["noise_digest", "critical_finding"]}


async def test_muted_type_is_skipped_at_the_send_chokepoint(
    client, analyst_token, sample_user, db_session
):
    from btagent_backend.config import get_settings
    from btagent_backend.services.notification_service import NotificationService

    resp = await client.put(
        "/api/v1/notifications/preferences",
        json={"muted_types": ["noise_digest"]},
        headers=auth_header(analyst_token),
    )
    assert resp.status_code == 200, resp.text

    service = NotificationService(get_settings())
    muted = await service.send_inapp(
        db_session,
        user_id=sample_user.id,
        notification={"type": "noise_digest", "title": "Muted", "message": "m"},
    )
    assert muted is None

    delivered = await service.send_inapp(
        db_session,
        user_id=sample_user.id,
        notification={"type": "critical_finding", "title": "Not muted", "message": "m"},
    )
    assert delivered is not None
    assert delivered.type == "critical_finding"


async def test_producer_fanout_respects_mutes(client, admin_token, admin_user, db_session):
    """A senior who muted noise_digest is skipped by the digest fan-out."""
    from types import SimpleNamespace

    from btagent_backend.services.hunt_notifier import notify_newly_noisy_rules

    resp = await client.put(
        "/api/v1/notifications/preferences",
        json={"muted_types": ["noise_digest"]},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text

    rule = SimpleNamespace(
        pack_id="p", rule_id="r", rule_title="Muted digest probe", hit_rate=1.0, runs_observed=3
    )
    from btagent_backend.db.models import DEFAULT_ORG_ID

    rows = await notify_newly_noisy_rules(db_session, org_id=DEFAULT_ORG_ID, rules=[rule])
    assert admin_user.id not in {r.user_id for r in rows}

    # Reset so later tests in the shared org see the admin unmuted.
    resp = await client.put(
        "/api/v1/notifications/preferences",
        json={"muted_types": []},
        headers=auth_header(admin_token),
    )
    assert resp.status_code == 200, resp.text
