"""Commit the request's DB session *before* the response leaves the server.

The bug this closes
-------------------
``get_session`` yields a session to the route and commits in dependency
teardown — and FastAPI runs teardown **after the response has been sent**.
Every write endpoint therefore told its client "201 Created" while the
transaction was still uncommitted. Two consequences:

* **Read-after-write races.** A client that POSTs and immediately GETs can
  miss its own write: the follow-up request opens a new session before the
  first one's commit lands. Invisible on a fast machine; on a loaded CI
  runner it produced a months-long trail of "flaky" failures with one shared
  signature — *write accepted, immediate read empty/404*: four E2E shard
  incidents seeding an investigation and 404ing on its IOCs, and a UAT run
  where a freshly registered user's login 401'd and an org-profile PUT read
  back blank.
* **The success status could be a lie.** If the commit itself failed
  (constraint violation, connection drop), the client had already been told
  the write succeeded and there was no channel left to say otherwise.

The fix
-------
The session dependency stashes its session on ``request.state``; this pure
ASGI middleware intercepts the first ``http.response.start`` message and
commits the stashed session *before forwarding it* — so by the time the
status line reaches the client, the data is durable.

Semantics preserved exactly:

* **Success (status < 400) → commit.** Previously teardown committed after
  sending; now the same commit happens before sending.
* **Error responses (>= 400) → no commit here.** A raised ``HTTPException``
  propagates through the dependency's ``except`` and rolls back, as before.
  (FastAPI's exception handlers produce the 4xx/5xx response; any writes the
  handler made before raising are rolled back in teardown, unchanged.)
* **Commit failure → 500, not a false success.** The exception is raised
  before ``http.response.start`` is forwarded, so Starlette's outermost
  error handling emits a 500 instead of the now-untrue 2xx.

The teardown commit in ``get_session`` stays: after this middleware has
committed, it is a no-op on a clean session, and it remains the path for
anything that bypasses HTTP (WebSockets, background jobs, scripts).

Known boundary: a ``StreamingResponse`` whose *generator* keeps using the
request session would see the commit at stream start. No current endpoint
does that — DB-backed exports buffer fully before responding.
"""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import Any

logger = logging.getLogger("btagent.middleware.commit")

# The key the session dependency uses to stash the request session.
DB_SESSION_STATE_KEY = "db_session"

Scope = dict[str, Any]
Message = dict[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]


class CommitBeforeResponseMiddleware:
    """Pure ASGI middleware — see module docstring.

    Pure ASGI rather than ``BaseHTTPMiddleware`` so the commit happens
    synchronously in the send path with no wrapper task, and WebSocket
    scopes pass through untouched.
    """

    def __init__(self, app: Callable) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        committed = False

        async def commit_then_send(message: Message) -> None:
            nonlocal committed
            if message["type"] == "http.response.start" and not committed:
                committed = True
                session = scope.get("state", {}).get(DB_SESSION_STATE_KEY)
                if session is not None and message["status"] < 400:
                    # Raising here (before response.start is forwarded) turns
                    # a failed commit into a 500 from the outer error
                    # middleware — never a 2xx for data that didn't land.
                    await session.commit()
            await send(message)

        await self.app(scope, receive, commit_then_send)
