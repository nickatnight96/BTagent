"""Structured JSON logging for BTagent.

Produces one JSON object per log line with correlation IDs (request_id,
trace_id, investigation_id) and redacts sensitive fields.
"""

from __future__ import annotations

import json
import logging
import re
from contextvars import ContextVar
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from btagent_backend.config import Settings

# ── Context variables (populated by middleware / handlers) ──────────────────
request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)
investigation_id_ctx: ContextVar[str | None] = ContextVar("investigation_id", default=None)

# ── Sensitive-field filter ──────────────────────────────────────────────────
_SENSITIVE_PATTERN = re.compile(
    r"(password|token|secret|api_key|apikey|authorization|credential|private_key)",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"


def _redact(obj: Any) -> Any:  # noqa: ANN401
    """Recursively redact values whose keys match the sensitive pattern."""
    if isinstance(obj, dict):
        return {
            k: (_REDACTED if _SENSITIVE_PATTERN.search(k) else _redact(v)) for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return [_redact(item) for item in obj]
    if isinstance(obj, str) and _SENSITIVE_PATTERN.search(obj):
        return _REDACTED
    return obj


def _get_trace_id() -> str | None:
    """Extract the current OTEL trace ID, returning ``None`` if unavailable."""
    try:
        from opentelemetry import trace

        span = trace.get_current_span()
        ctx = span.get_span_context()
        if ctx and ctx.trace_id:
            return format(ctx.trace_id, "032x")
    except Exception:
        pass
    return None


# ── JSON formatter ──────────────────────────────────────────────────────────
class JSONFormatter(logging.Formatter):
    """Emit each log record as a single JSON line."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": request_id_ctx.get(None),
            "trace_id": _get_trace_id(),
            "investigation_id": investigation_id_ctx.get(None),
        }

        if record.exc_info and record.exc_info[1] is not None:
            payload["exception"] = self.formatException(record.exc_info)

        # Attach extra fields (e.g. from ``logger.info("msg", extra={...})``)
        for key in ("data", "extra"):
            val = getattr(record, key, None)
            if val is not None:
                payload[key] = _redact(val)

        return json.dumps(payload, default=str)


# ── Sensitive-data log filter ───────────────────────────────────────────────
class SensitiveFilter(logging.Filter):
    """Scrub known sensitive args from log records before they reach the formatter."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            if isinstance(record.args, dict):
                record.args = _redact(record.args)
            elif isinstance(record.args, tuple):
                record.args = tuple(_redact(list(record.args)))
        return True


# ── Public setup ────────────────────────────────────────────────────────────
def setup_logging(settings: Settings) -> None:
    """Configure Python logging for structured JSON output.

    Call once during application startup (before any request handling).
    """
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    handler = logging.StreamHandler()
    handler.setFormatter(JSONFormatter())
    handler.addFilter(SensitiveFilter())

    root = logging.getLogger()
    root.setLevel(level)

    # Remove any pre-existing handlers to avoid duplicate output.
    root.handlers.clear()
    root.addHandler(handler)

    # Quiet noisy third-party loggers.
    for noisy in ("uvicorn.access", "sqlalchemy.engine", "httpcore", "httpx"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    logging.getLogger("btagent").info(
        "Structured JSON logging initialised (level=%s)", settings.log_level.upper()
    )
