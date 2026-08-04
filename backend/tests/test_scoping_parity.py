"""HTTP and WebSocket must answer "may this user see this case?" identically.

Two enforcement points guard the same investigation: ``assert_can_access_``
``investigation`` on the REST routes, and ``assert_can_subscribe`` on the
WebSocket connect/subscribe path. They speak different error languages — a
404 ``HTTPException`` versus an ``AccessDenied`` that becomes a 4404 close —
but the *decision* has to be one decision. A WebSocket carries the whole
event stream for a case, so a subscribe path that is even slightly more
permissive than the REST path is a way to read a case you were 404'd out of.

They were not one decision. ``ws/access.py`` kept its own copy of the role
set and its own org comparison, and the copies had drifted: the WS check only
denied cross-org when *both* org ids were non-``None``, treating a missing
org as same-org, where the HTTP check denies on any mismatch. That branch was
unreachable — ``InvestigationRow.org_id`` is ``nullable=False`` and
``TokenPayload`` defaults ``org_id`` to a string — so nothing leaked. The
point of this file is that the next divergence should not need someone to
notice it.

Both halves of each case are asserted:

* an **expected** verdict, so the pair cannot pass by being wrong together;
* **parity**, so neither can move without the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.types.enums import InvestigationStatus
from btagent_shared.utils.ids import generate_id
from fastapi import HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.auth.jwt import hash_password
from btagent_backend.auth.scoping import assert_can_access_investigation
from btagent_backend.db.models import InvestigationRow, OrganizationRow, UserRow
from btagent_backend.ws.access import AccessDenied, assert_can_subscribe

_ORG_A = "org_parity_a"
_ORG_B = "org_parity_b"

# Every role the product ships, plus one it does not, because the rule for an
# unrecognized role ("treat as least-privileged") is itself worth pinning.
_ROLES = ["analyst", "senior_analyst", "incident_commander", "admin", "unknown_role"]
_ORG_WIDE = {"senior_analyst", "incident_commander", "admin"}


class _FakeUser:
    """Stand-in for ``CurrentUser`` — the checks only read these three fields."""

    def __init__(self, *, user_id: str, role: str, org_id: str) -> None:
        self.id = user_id
        self.role = role
        self.org_id = org_id


@dataclass(frozen=True)
class _Case:
    label: str
    role: str
    user_org: str
    #: which seeded investigation to probe
    target: str

    @property
    def expected_allowed(self) -> bool:
        """The rule, restated independently of the implementation."""
        if self.user_org != _ORG_A:
            # Every seeded investigation lives in org A.
            return False
        if self.role in _ORG_WIDE:
            return True
        # Non-org-wide roles need ownership.
        return self.target == "own"


_CASES = [
    *(_Case(f"{role}-same-org-own", role, _ORG_A, "own") for role in _ROLES),
    *(_Case(f"{role}-same-org-other", role, _ORG_A, "other") for role in _ROLES),
    *(_Case(f"{role}-cross-org-own", role, _ORG_B, "own") for role in _ROLES),
    *(_Case(f"{role}-cross-org-other", role, _ORG_B, "other") for role in _ROLES),
]


@pytest_asyncio.fixture()
async def parity_setup(db_session: AsyncSession):
    """Two orgs, a probing user id, and two org-A investigations.

    ``own`` is assigned to the probing user id; ``other`` is assigned to
    somebody else. The probing user is re-roled and re-orged per case, which
    is what lets one pair of rows cover the whole matrix.
    """
    for org_id in (_ORG_A, _ORG_B):
        if await db_session.get(OrganizationRow, org_id) is None:
            db_session.add(OrganizationRow(id=org_id, name=org_id, created_at=datetime.now(UTC)))
    await db_session.commit()

    def _user(label: str) -> UserRow:
        suffix = generate_id("usr").split("_", 1)[1]
        return UserRow(
            id=generate_id("usr"),
            username=f"{label}_{suffix}",
            email=f"{label}_{suffix}@btagent.test",
            password_hash=hash_password("Test-P@ss-789!"),
            # Role and org on the *row* are irrelevant here — the checks read
            # them off the caller (``_FakeUser``), which is re-roled per case.
            # These rows exist only to satisfy the ``assigned_to`` foreign key.
            role="analyst",
            org_id=_ORG_A,
            created_at=datetime.now(UTC),
        )

    prober = _user("prober")
    stranger = _user("stranger")
    db_session.add_all([prober, stranger])
    await db_session.commit()
    prober_id = prober.id

    def _inv(assigned_to: str) -> InvestigationRow:
        return InvestigationRow(
            id=generate_id("inv"),
            title="Parity case",
            description="",
            status=InvestigationStatus.INVESTIGATING.value,
            severity="medium",
            tlp_level="green",
            assigned_to=assigned_to,
            org_id=_ORG_A,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )

    own = _inv(prober_id)
    other = _inv(stranger.id)
    db_session.add_all([own, other])
    await db_session.commit()

    return {"prober_id": prober_id, "own": own, "other": other}


def _http_allows(user: _FakeUser, inv: InvestigationRow) -> bool:
    try:
        assert_can_access_investigation(user, inv)  # type: ignore[arg-type]
    except HTTPException as exc:
        # A scoping denial must be the existence-masking 404, never a 403.
        assert exc.status_code == 404, f"scoping denial leaked a {exc.status_code}"
        return False
    return True


async def _ws_allows(db: AsyncSession, user: _FakeUser, inv: InvestigationRow) -> bool:
    try:
        await assert_can_subscribe(db, user, inv.id)  # type: ignore[arg-type]
    except AccessDenied:
        return False
    return True


@pytest.mark.asyncio
@pytest.mark.parametrize("case", _CASES, ids=[c.label for c in _CASES])
async def test_http_and_ws_agree(case: _Case, db_session: AsyncSession, parity_setup):
    inv: InvestigationRow = parity_setup[case.target]
    user = _FakeUser(user_id=parity_setup["prober_id"], role=case.role, org_id=case.user_org)

    http_allowed = _http_allows(user, inv)
    ws_allowed = await _ws_allows(db_session, user, inv)

    # Correctness first — otherwise the pair could agree by being wrong twice.
    assert http_allowed is case.expected_allowed, (
        f"{case.label}: HTTP said {http_allowed}, rule says {case.expected_allowed}"
    )
    # Then parity.
    assert ws_allowed == http_allowed, (
        f"{case.label}: WebSocket said {ws_allowed} but HTTP said {http_allowed}. "
        "These two guard the same case and must not diverge — the rule lives in "
        "auth.scoping.can_access_investigation and both should be calling it."
    )


@pytest.mark.asyncio
async def test_ws_denies_a_missing_investigation_the_same_way(
    db_session: AsyncSession, parity_setup
):
    """A nonexistent id and an out-of-scope one are indistinguishable.

    Otherwise the close code becomes an existence oracle: probe an id, and a
    "denied" that differs from "no such case" confirms the case is real in
    some other tenant.
    """
    user = _FakeUser(user_id=parity_setup["prober_id"], role="analyst", org_id=_ORG_A)

    with pytest.raises(AccessDenied) as missing:
        await assert_can_subscribe(db_session, user, "inv_does_not_exist")  # type: ignore[arg-type]
    with pytest.raises(AccessDenied) as forbidden:
        await assert_can_subscribe(db_session, user, parity_setup["other"].id)  # type: ignore[arg-type]

    assert missing.value.reason == forbidden.value.reason == "not found"


@pytest.mark.asyncio
async def test_both_paths_call_the_shared_predicate(db_session: AsyncSession, parity_setup):
    """Patching the shared rule must flip *both* answers.

    This is what makes the parity above structural rather than coincidental:
    if either enforcement point re-inlines its own copy of the rule, it stops
    responding to the predicate and this fails.
    """
    from btagent_backend.auth import scoping as scoping_mod
    from btagent_backend.ws import access as ws_access_mod

    inv: InvestigationRow = parity_setup["own"]
    user = _FakeUser(user_id=parity_setup["prober_id"], role="admin", org_id=_ORG_A)

    assert _http_allows(user, inv) is True
    assert await _ws_allows(db_session, user, inv) is True

    def _deny_everything(_user, _investigation):  # noqa: ANN001, ANN202
        return False

    original_scoping = scoping_mod.can_access_investigation
    original_ws = ws_access_mod.can_access_investigation
    scoping_mod.can_access_investigation = _deny_everything
    ws_access_mod.can_access_investigation = _deny_everything
    try:
        assert _http_allows(user, inv) is False, "HTTP path is not using the shared predicate"
        assert await _ws_allows(db_session, user, inv) is False, (
            "WebSocket path is not using the shared predicate"
        )
    finally:
        scoping_mod.can_access_investigation = original_scoping
        ws_access_mod.can_access_investigation = original_ws
