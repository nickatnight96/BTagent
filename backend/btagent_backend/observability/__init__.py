"""Observability: OpenTelemetry tracing, structured logging, Prometheus metrics."""

from .logging import setup_logging
from .metrics import metrics_endpoint
from .otel import get_tracer, setup_otel, shutdown_otel

__all__ = [
    "get_tracer",
    "metrics_endpoint",
    "setup_logging",
    "setup_otel",
    "shutdown_otel",
]
