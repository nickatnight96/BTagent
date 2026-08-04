"""WebSocket access-control checks.

Phase B2 (auth-hardening): server-side authorization for WS subscribers.

Audit ref: ``ws/routes.py:39-66`` accepted any authenticated user onto any
investigation channel without verifying ownership. This module supplies
:func:`assert_can_subscribe` which is invoked from the connect handler before
the hub registers the client.

Policy
------
* ``analyst``                 — same-org *and* ``assigned_to == user.id``
* ``senior_analyst``,
  ``incident_commander``,
  ``admin``                   — same-org access only

On any failure the WebSocket is closed with code **4404** (custom: "not
found"). 4404 is used uniformly so the existence of an investigation in
another org is not leaked. Some browser clients reject custom codes outside
4000-4999 cleanly, but 4404 is in range; if a future client rejects it we'll
fall back to 1008 in the route handler.

Note
----
This module used to keep its own copy of the rule — deliberately, while
Phase B1 was still in flight. Both phases have landed, so the follow-up
clean-up that note promised is done: the policy now lives once, in
``auth.scoping.can_access_investigation``, and this module only translates a
denial into the WebSocket close code.

That matters beyond tidiness. The duplicated checks had already drifted:
this one only denied cross-org when *both* org ids were non-``None``,
treating a missing org as same-org, where the HTTP check denies on any
mismatch. Nothing was leaking (neither id can be ``None`` since Phase A1
made the column ``nullable=False`` and ``TokenPayload`` defaults ``org_id``
to a string) — but a WebSocket carries the whole event stream for a case,
and two copies of a tenant rule are how the next divergence gets in.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.websockets import WebSocket, WebSocketState

from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.auth.scoping import can_access_investigation
from btagent_backend.db.models import InvestigationRow

logger = logging.getLogger("btagent.ws.access")


# WebSocket close codes (RFC 6455 + custom 4xxx range)
WS_CLOSE_NOT_FOUND = 4404  # custom — does not leak existence
WS_CLOSE_POLICY_FALLBACK = 1008  # standard "policy violation" — used if 4404 rejected


class AccessDenied(Exception):
    """Raised when a user is not allowed to subscribe to an investigation."""

    def __init__(self, reason: str = "not found") -> None:
        super().__init__(reason)
        self.reason = reason


def _inv_org_id(inv: InvestigationRow) -> str | None:
    """Return the investigation's ``org_id``.

    Not an access check — ``ws/routes.py`` uses it to stamp the connected
    client with an org for per-message fan-out filtering, *after*
    :func:`assert_can_subscribe` has already decided the subscribe is
    allowed. The ``getattr`` default survives the test doubles that stand in
    for a row without hydrating every column.
    """
    return getattr(inv, "org_id", None)


async def assert_can_subscribe(
    db: AsyncSession,
    user: CurrentUser,
    investigation_id: str,
) -> InvestigationRow:
    """Verify ``user`` may subscribe to events for ``investigation_id``.

    Returns the loaded :class:`InvestigationRow` on success so callers can
    extract ``org_id`` for per-client filtering without a second query.

    Raises :class:`AccessDenied` on any failure (missing investigation, wrong
    org, role-restricted assignment mismatch). The route handler converts the
    exception into a WebSocket close with code 4404 (or 1008 fallback).

    The allow/deny decision is :func:`~btagent_backend.auth.scoping.can_access_investigation`
    — the same predicate the HTTP routes enforce — so a subscriber can never
    stream a case they would have been 404'd out of over REST.
    """
    stmt = select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    result = await db.execute(stmt)
    inv = result.scalar_one_or_none()

    # "not found" for a missing row *and* for an out-of-scope one, so a
    # cross-org probe cannot enumerate investigation ids by close code.
    if inv is None or not can_access_investigation(user, inv):
        raise AccessDenied("not found")

    return inv


async def close_with_access_denied(websocket: WebSocket, exc: AccessDenied) -> None:
    """Accept-then-close the WS after :class:`AccessDenied`.

    We accept the WS first so the close frame carries a real WS close code
    (4404 / 1008). Without ``accept()``, Starlette would respond to the
    handshake with HTTP 403, which some clients surface as a generic
    ``WebSocketDisconnect`` with code 1006 — losing the policy signal.
    Falls back to 1008 if the custom 4404 code is rejected by the transport.
    """
    try:
        # Only accept if we haven't already; CONNECTING is the pre-accept state.
        if websocket.client_state != WebSocketState.CONNECTED:
            try:
                await websocket.accept()
            except Exception:
                pass
        await websocket.close(code=WS_CLOSE_NOT_FOUND, reason=exc.reason)
    except Exception:
        try:
            await websocket.close(code=WS_CLOSE_POLICY_FALLBACK, reason=exc.reason)
        except Exception:
            logger.debug("WS close failed during access-deny", exc_info=True)
