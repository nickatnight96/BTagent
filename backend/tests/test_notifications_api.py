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
