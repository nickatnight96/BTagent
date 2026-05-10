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
We intentionally do **not** import from ``auth/scoping.py`` (Phase B1's
territory). The role rule is duplicated here in three lines; a follow-up
clean-up will de-duplicate after both phases land.
"""

from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.websockets import WebSocket, WebSocketState

from btagent_backend.auth.middleware import CurrentUser
from btagent_backend.db.models import InvestigationRow

logger = logging.getLogger("btagent.ws.access")


# WebSocket close codes (RFC 6455 + custom 4xxx range)
WS_CLOSE_NOT_FOUND = 4404  # custom — does not leak existence
WS_CLOSE_POLICY_FALLBACK = 1008  # standard "policy violation" — used if 4404 rejected


# Roles that are *not* restricted to their own assigned investigations
_ROLES_FULL_ORG_VIEW = frozenset({"senior_analyst", "incident_commander", "admin"})


class AccessDenied(Exception):
    """Raised when a user is not allowed to subscribe to an investigation."""

    def __init__(self, reason: str = "not found") -> None:
        super().__init__(reason)
        self.reason = reason


def _user_org_id(user: CurrentUser) -> str | None:
    """Return the user's org_id if Phase A1's JWT claim is present, else None."""
    return getattr(user, "org_id", None)


def _inv_org_id(inv: InvestigationRow) -> str | None:
    """Return the investigation's org_id if Phase A1's column is present, else None."""
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
    """
    stmt = select(InvestigationRow).where(InvestigationRow.id == investigation_id)
    result = await db.execute(stmt)
    inv = result.scalar_one_or_none()

    if inv is None:
        raise AccessDenied("not found")

    # --- Org-scope check -------------------------------------------------
    # Defensive against Phase A1 not yet being merged in this branch: if
    # neither user nor row carries org_id, treat as same-org (no-op). When
    # A1 lands the comparison becomes meaningful.
    user_org = _user_org_id(user)
    inv_org = _inv_org_id(inv)
    if user_org is not None and inv_org is not None and user_org != inv_org:
        # Same code as "not found" so cross-org probes can't enumerate IDs.
        raise AccessDenied("not found")

    # --- Role-restricted assignment check --------------------------------
    if user.role not in _ROLES_FULL_ORG_VIEW:
        # plain analyst or unknown role — must be assigned
        if inv.assigned_to != user.id:
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
