"""Live-mode dispatch is refused **and audited**, on every containment path.

``_dispatch`` fails closed when ``BTAGENT_MOCK_CONNECTORS`` is off: connectors
are mock-first and the live path is a guarded placeholder, so nothing
destructive can reach a real system. That property is load-bearing — it is the
reason the containment surface can ship at all, and the reason gaps found in it
(e.g. the unscreened ``disable_account``) were latent rather than exploitable.

Nothing pinned it. Worse, the refusal escaped uncaught. ``execute_response_action``
caught ``MCPPolicyRefused`` and nothing else; ``execute_bulk_block`` had no
handler at all. So with the mock switch off — the intended production posture —
every containment attempt raised past the route as an **unaudited 500**.

That breaks the module's own SAFETY rule #4:

    Every execute AND every denial writes a hash-chain audit row … Nothing
    runs, and nothing is refused, without a row.

and it is exactly the failure the adjacent comment already names ("A3/A7
lesson: a dispatch-layer refusal must land on the ledger, not surface as an
unaudited 500"). The lesson had been applied to one of the two refusals this
function can hit. The refusal itself was always correct — an operator's attempt
to isolate a host in production simply left no evidence that it happened, which
is the one thing an audit ledger exists to prevent.

Both directions are asserted here: live mode refuses *and* records, and mock
mode still executes (a fix that refused everything would satisfy the first half
while breaking the feature).
"""

from __future__ import annotations

import ast
import inspect
from datetime import UTC, datetime
from pathlib import Path

import pytest
from btagent_shared.utils.ids import generate_id
from httpx import AsyncClient
from sqlalchemy import select

from btagent_backend.auth.jwt import create_token_pair, hash_password
from btagent_backend.db.models import AuditLogRow, OrganizationRow, UserRow
from btagent_backend.services import containment_execute_service as svc
from tests.helpers import auth_header


@pytest.fixture()
def live_mode(monkeypatch):
    """Turn the fleet-wide mock switch off for one test."""
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", "false")


async def _seed_ic(db_session) -> tuple[str, str, str]:
    org_id, user_id = generate_id("org"), generate_id("usr")
    db_session.add(
        OrganizationRow(id=org_id, name=f"Live Org {org_id}", created_at=datetime.now(UTC))
    )
    db_session.add(
        UserRow(
            id=user_id,
            org_id=org_id,
            username=f"ic_{user_id}",
            email=f"{user_id}@btagent.test",
            password_hash=hash_password("IC-P@ss-123!"),
            role="incident_commander",
            created_at=datetime.now(UTC),
        )
    )
    await db_session.commit()
    token = create_token_pair(
        user_id, f"ic_{user_id}", "incident_commander", org_id=org_id
    ).access_token
    return org_id, user_id, token


async def _audit_rows(db_session, *, org_id: str) -> list[AuditLogRow]:
    result = await db_session.execute(
        select(AuditLogRow).where(AuditLogRow.org_id == org_id).order_by(AuditLogRow.seq.asc())
    )
    return list(result.scalars().all())


# --------------------------------------------------------------------------- #
# The switch itself
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("true", True),
        ("TRUE", True),
        ("  true  ", True),
        ("false", False),
        # Anything that is not "true" reads as live, and live refuses. A typo
        # therefore fails *closed* — the safe direction for this switch.
        ("1", False),
        ("yes", False),
        ("", False),
    ],
)
def test_mock_switch_parses_fail_closed(monkeypatch, value: str, expected: bool):
    monkeypatch.setenv("BTAGENT_MOCK_CONNECTORS", value)
    assert svc._mock_connectors_enabled() is expected


def test_mock_is_the_default_when_unset(monkeypatch):
    monkeypatch.delenv("BTAGENT_MOCK_CONNECTORS", raising=False)
    assert svc._mock_connectors_enabled() is True


async def test_dispatch_refuses_in_live_mode(live_mode):
    with pytest.raises(svc.LiveDispatchDisabled):
        await svc._dispatch("isolate_host", "crowdstrike", "WS-JSMITH-PC")


def test_live_refusal_is_still_a_not_implemented_error():
    """The dedicated type must not break callers that expect the old one."""
    assert issubclass(svc.LiveDispatchDisabled, NotImplementedError)


# --------------------------------------------------------------------------- #
# Both execute paths: refused AND audited
# --------------------------------------------------------------------------- #


async def test_response_action_in_live_mode_is_refused_and_audited(
    client: AsyncClient, db_session, live_mode
):
    org_id, user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_live_1",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text

    rows = await _audit_rows(db_session, org_id=org_id)
    denials = [r for r in rows if r.outcome == "denied"]
    assert len(denials) == 1
    assert denials[0].action == "execute:isolate_host"
    assert denials[0].details.get("approver_id") == user_id
    assert denials[0].details.get("mock_connectors") is False
    assert "live dispatch" in denials[0].details.get("reason", "").lower()
    # Nothing executed.
    assert not [r for r in rows if r.outcome == "success"]


async def test_bulk_block_in_live_mode_is_refused_and_audited(
    client: AsyncClient, db_session, live_mode
):
    """The path that had no handler at all."""
    org_id, user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/bulk-block",
        json={
            "action_id": "mit_live_1",
            "ioc_type": "ip",
            "ioc_value": "45.83.12.7",
            "tool": "panorama",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 403, resp.text

    rows = await _audit_rows(db_session, org_id=org_id)
    denials = [r for r in rows if r.outcome == "denied"]
    assert len(denials) == 1
    assert denials[0].details.get("mock_connectors") is False
    assert denials[0].details.get("ioc_type") == "ip"
    assert not [r for r in rows if r.outcome == "success"]


async def test_mock_mode_still_executes(client: AsyncClient, db_session):
    """Guard the guard: refusing everything would satisfy the tests above."""
    org_id, _user_id, token = await _seed_ic(db_session)
    resp = await client.post(
        "/api/v1/containment/execute/response-action",
        json={
            "action_id": "act_mock_1",
            "action_type": "isolate_host",
            "connector": "crowdstrike",
            "target": "WS-JSMITH-PC",
            "approved": True,
        },
        headers=auth_header(token),
    )
    assert resp.status_code == 200, resp.text
    rows = await _audit_rows(db_session, org_id=org_id)
    assert [r.outcome for r in rows] == ["success"]


# --------------------------------------------------------------------------- #
# Structural: a future execute path cannot skip the handler
# --------------------------------------------------------------------------- #


def test_every_dispatch_call_site_handles_the_live_refusal():
    """``execute_bulk_block`` reached production with a bare ``await _dispatch``.

    A third execute function would do the same by default — the omission is
    invisible, because the happy path works perfectly in mock mode, which is
    every developer's local posture. So the shape is asserted rather than
    trusted: every ``await _dispatch(...)`` must sit inside a ``try`` that
    handles ``LiveDispatchDisabled``.
    """
    source = Path(inspect.getfile(svc)).read_text()
    tree = ast.parse(source)

    def _handles_live_refusal(node: ast.Try) -> bool:
        for handler in node.handlers:
            names: list[ast.expr] = []
            if isinstance(handler.type, ast.Tuple):
                names = list(handler.type.elts)
            elif handler.type is not None:
                names = [handler.type]
            for name in names:
                if isinstance(name, ast.Name) and name.id == "LiveDispatchDisabled":
                    return True
        return False

    guarded: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Try) and _handles_live_refusal(node):
            for inner in ast.walk(ast.Module(body=node.body, type_ignores=[])):
                if isinstance(inner, ast.Call):
                    guarded.add(inner.lineno)

    unguarded: list[int] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if isinstance(func, ast.Name) and func.id == "_dispatch":
            if node.lineno not in guarded:
                unguarded.append(node.lineno)

    assert not unguarded, (
        f"_dispatch is called outside a LiveDispatchDisabled handler at "
        f"line(s) {sorted(unguarded)}. With the mock switch off that raises "
        "past the route as an unaudited 500 — SAFETY rule #4 requires every "
        "refusal to land on the ledger."
    )


def test_the_guard_can_see_the_real_call_sites():
    """Guard the guard: a parser that finds no call sites would pass vacuously."""
    source = Path(inspect.getfile(svc)).read_text()
    tree = ast.parse(source)
    call_sites = [
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_dispatch"
    ]
    assert len(call_sites) >= 2, (
        f"expected at least the two execute paths to call _dispatch, found "
        f"{len(call_sites)} — the AST scan is not seeing them"
    )
