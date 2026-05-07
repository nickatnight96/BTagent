"""Shared fixtures + auto-cleanup for the UAT suite.

The audit-cleanup PR added httpOnly cookie auth alongside the
``Authorization: Bearer ...`` header transport. The pre-existing UAT
files use a ``scope="module"`` ``httpx.Client()`` — every login response
sets ``btagent_access`` / ``btagent_refresh`` cookies that ``httpx``
auto-retains in the client jar. Subsequent "no token" / "wrong token"
tests in the same module inherit the cookies and the dual-transport
middleware lets them through, breaking assertions that expect 401/403.

This autouse fixture clears the client cookie jar before every test so
each test sees a clean transport state. Tests that genuinely need the
cookie path can establish it via a fresh ``client.post("/auth/login")``
call inside the test body.
"""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _reset_uat_client_cookies(request: pytest.FixtureRequest):
    """Wipe the module-scoped ``client`` cookie jar between tests.

    Looks up the ``client`` fixture lazily — most UAT files define it at
    module scope via ``httpx.Client``. Files that don't have a ``client``
    fixture (e.g. pure-import unit tests) yield without doing anything.
    """
    client = None
    try:
        client = request.getfixturevalue("client")
    except pytest.FixtureLookupError:
        client = None
    if client is not None and hasattr(client, "cookies"):
        client.cookies.clear()
    yield
    if client is not None and hasattr(client, "cookies"):
        client.cookies.clear()
