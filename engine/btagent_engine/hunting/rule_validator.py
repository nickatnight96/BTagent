"""Single-rule historical telemetry validator (#113 back half, slice 2).

``validate_rule(sigma_yaml, backends, ctx)`` answers the detection engineer's
question about one proposed Sigma rule: *does this rule match anything in the
telemetry we already have?* Per backend it transpiles the rule (the same
pySigma path the #112 pack runner uses) and executes the query through the
existing integration nodes over a lookback window, returning hit counts.

Interpretation is the caller's job — hits against historical telemetry can
mean "true positives already in the environment" or "noisy rule", which is
exactly the review signal the #113 proposal store surfaces to the analyst.

Failure discipline mirrors :mod:`btagent_engine.hunting.runner`: a transpile
or execution failure on one backend is captured as that backend's ``error``
and never aborts the rest. This module is persistence-free; the backend's
``cti_detection_service.validate_proposal`` stores the outcome on the
proposal row.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.hunting.plan_runner import _BACKEND_ADAPTERS
from btagent_engine.hunting.transpile import (
    SUPPORTED_BACKENDS,
    SigmaBackendName,
    SigmaTranspileError,
    transpile,
)
from btagent_engine.node import NodeContext

# Re-exported for callers picking a default fan-out.
DEFAULT_VALIDATION_BACKENDS: tuple[SigmaBackendName, ...] = SUPPORTED_BACKENDS

# Backend enum values → the shared Backend enum keys the adapters are keyed on.
_ADAPTERS_BY_NAME = {backend.value: fn for backend, fn in _BACKEND_ADAPTERS.items()}


class BackendValidation(BaseModel):
    """Outcome of validating one rule against one backend's history."""

    model_config = ConfigDict(extra="forbid")

    backend: str
    query: str | None = None
    hit_count: int = 0
    error: str | None = None


class RuleValidationResult(BaseModel):
    """Full outcome of validating one Sigma rule against historical telemetry."""

    model_config = ConfigDict(extra="forbid")

    validated_at: datetime
    lookback_hours: int
    backends: list[BackendValidation] = Field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return sum(b.hit_count for b in self.backends)

    @property
    def error_count(self) -> int:
        return sum(1 for b in self.backends if b.error is not None)

    @property
    def verdict(self) -> str:
        """``matched`` (any historical hits) / ``clean`` / ``error`` (nothing ran)."""
        if self.total_hits > 0:
            return "matched"
        if self.backends and self.error_count == len(self.backends):
            return "error"
        return "clean"


async def validate_rule(
    sigma_yaml: str,
    backends: list[str] | None,
    ctx: NodeContext,
    *,
    lookback_hours: int = 24 * 30,
    max_hits_per_query: int = 100,
) -> RuleValidationResult:
    """Transpile + execute one Sigma rule per backend, collecting hit counts.

    Args:
        sigma_yaml: The canonical Sigma rule as a YAML string.
        backends: Backend names to validate against; ``None`` fans out to all
            supported names. Unknown names degrade to a per-backend error.
        ctx: Engine node context (org scoping for the integration nodes).
        lookback_hours: Historical window (default 30 days — proposal
            validation looks further back than the pack runner's daily tick).
        max_hits_per_query: Cap per backend; the verdict needs "any hits",
            not the full result set.
    """
    names = list(backends) if backends else list(DEFAULT_VALIDATION_BACKENDS)
    result = RuleValidationResult(
        validated_at=datetime.now(UTC),
        lookback_hours=lookback_hours,
        backends=[],
    )

    for name in names:
        adapter = _ADAPTERS_BY_NAME.get(name)
        if adapter is None:
            result.backends.append(
                BackendValidation(backend=name, error=f"unsupported backend '{name}'")
            )
            continue
        try:
            query = transpile(sigma_yaml, name)  # type: ignore[arg-type]
        except (SigmaTranspileError, ValueError) as exc:
            result.backends.append(
                BackendValidation(backend=name, error=f"transpile failed: {exc}")
            )
            continue
        try:
            events: list[dict[str, Any]] = await adapter(
                query, ctx, lookback_hours, max_hits_per_query
            )
        except Exception as exc:  # one unreachable backend must not kill the run
            result.backends.append(
                BackendValidation(backend=name, query=query, error=f"execution failed: {exc}")
            )
            continue
        result.backends.append(BackendValidation(backend=name, query=query, hit_count=len(events)))

    return result
