"""Request-ID middleware.

Assigns a unique UUID to every inbound HTTP request, stores it in
:pydata:`contextvars` for correlation in logs, and echoes it back in the
response ``X-Request-ID`` header.
"""

from __future__ import annotations

import uuid
from typing import Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from btagent_backend.observability.logging import request_id_ctx

_HEADER = "X-Request-ID"


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Inject a request ID into every request/response cycle."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Honour a client-supplied ID if present; otherwise generate one.
        rid = request.headers.get(_HEADER) or str(uuid.uuid4())

        # Store in contextvar so loggers can include it automatically.
        token = request_id_ctx.set(rid)
        try:
            response: Response = await call_next(request)
            response.headers[_HEADER] = rid
            return response
        finally:
            request_id_ctx.reset(token)
