"""OpenTelemetry setup for BTagent.

Configures tracing (TracerProvider with OTLP gRPC exporter) and metrics
(MeterProvider with OTLP exporter), plus auto-instrumentation for FastAPI.
Gracefully degrades when the OTEL collector is unreachable.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from opentelemetry import metrics, trace
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor

if TYPE_CHECKING:
    from fastapi import FastAPI

    from btagent_backend.config import Settings

logger = logging.getLogger("btagent.observability.otel")

_SERVICE_NAME = "btagent-backend"
_tracer_provider: TracerProvider | None = None


def setup_otel(app: FastAPI, settings: Settings) -> None:
    """Initialise OpenTelemetry tracing and metrics.

    Does nothing when ``settings.otel_enabled`` is ``False``.
    Never crashes the application -- all failures are logged as warnings.
    """
    global _tracer_provider  # noqa: PLW0603

    if not settings.otel_enabled:
        logger.info("OpenTelemetry disabled (otel_enabled=False)")
        return

    try:
        resource = Resource.create(
            {
                "service.name": _SERVICE_NAME,
                "service.version": "0.1.0",
                "deployment.environment": settings.env,
            }
        )

        # --- Tracing -----------------------------------------------------------
        span_exporter = OTLPSpanExporter(
            endpoint=settings.otel_endpoint,
            insecure=True,
        )
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(tracer_provider)
        _tracer_provider = tracer_provider

        # --- Metrics ------------------------------------------------------------
        metric_exporter = OTLPMetricExporter(
            endpoint=settings.otel_endpoint,
            insecure=True,
        )
        metric_reader = PeriodicExportingMetricReader(
            metric_exporter,
            export_interval_millis=15_000,
        )
        meter_provider = MeterProvider(resource=resource, metric_readers=[metric_reader])
        metrics.set_meter_provider(meter_provider)

        # --- FastAPI auto-instrumentation ---------------------------------------
        FastAPIInstrumentor.instrument_app(app)

        logger.info(
            "OpenTelemetry initialised (endpoint=%s, service=%s)",
            settings.otel_endpoint,
            _SERVICE_NAME,
        )

    except Exception:
        logger.warning(
            "Failed to initialise OpenTelemetry -- tracing/metrics will be unavailable",
            exc_info=True,
        )


async def shutdown_otel() -> None:
    """Flush and shut down the tracer provider.

    Safe to call even when OTEL was never initialised.
    """
    global _tracer_provider  # noqa: PLW0603

    if _tracer_provider is not None:
        try:
            _tracer_provider.shutdown()
            logger.info("OpenTelemetry tracer provider shut down")
        except Exception:
            logger.warning("Error shutting down OpenTelemetry", exc_info=True)
        finally:
            _tracer_provider = None


def get_tracer(name: str = _SERVICE_NAME) -> trace.Tracer:
    """Return a tracer bound to the current provider (or a no-op tracer)."""
    return trace.get_tracer(name)
