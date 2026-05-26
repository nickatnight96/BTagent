"""NoiseBaselineNode — estimate expected hit volume for a hunt query.

The Phase B counterpart that fills the ``NoiseProfile`` slot on each
TTP runbook entry (#99). Before an analyst runs a hunt query, they want
to know roughly how noisy it will be: a query that returns 50k hits/day
needs tuning before it's worth executing; one that returns 3/day is
immediately actionable.

In production this node issues a *count-only* query against the target
backend over a sample window (the connector's ``count_only_supported``
capability from the manifest, #100). In mock mode it returns a
deterministic synthetic estimate derived from the TTP + backend so the
pipeline and UI can be exercised without a live SIEM.

Design notes:

1. **Count-only, never enumerate.** The whole point is to estimate
   volume cheaply. The real path must use the backend's count mode;
   enumerating results would defeat the purpose and risk a DoS.

2. **Mock estimates are stable + plausible.** A hash of (ttp, backend)
   seeds a deterministic value in a believable range (single digits to
   low thousands per day). Tests assert on determinism, not on a
   specific number.

3. **Deterministic across re-runs** so RunbookCompiler output stays
   stable for diff / replay views.
"""

from __future__ import annotations

import hashlib
import os
from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)
from btagent_shared.types.hunt import Backend, NoiseProfile


def _mock_mode_enabled() -> bool:
    # Reuses the connector mock flag — NoiseBaseline hits a SIEM in prod,
    # so it's gated by the same switch as the integration nodes.
    return os.getenv("BTAGENT_MOCK_CONNECTORS", "true").lower() == "true"


# Default sample window for the count query.
_DEFAULT_WINDOW_DAYS = 30

# Mock estimate ceiling. Synthetic counts land in [1, _MOCK_CEILING].
_MOCK_CEILING = 2000


def _mock_estimate(ttp_id: str, backend: Backend) -> float:
    """Deterministic synthetic hits/day for (ttp, backend).

    Hash-seeded so the same input always yields the same estimate (keeps
    RunbookCompiler output stable for replay / diff). Range is biased
    toward plausible hunt-query volumes.
    """
    seed = f"{ttp_id}:{backend.value}".encode("utf-8")
    digest = hashlib.sha256(seed).digest()
    # Take 2 bytes -> 0..65535, scale into [1, _MOCK_CEILING].
    raw = int.from_bytes(digest[:2], "big")
    scaled = 1 + (raw % _MOCK_CEILING)
    # Round to a "reportable" precision (analysts don't care about
    # 1473.0 vs 1473.7).
    return float(scaled)


class NoiseBaselineInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str = Field(..., description="ATT&CK technique id (for the mock seed + provenance).")
    backend: Backend = Field(..., description="Which backend the query targets.")
    query: str = Field(
        default="",
        description="The query to estimate. Used by the real count-only path; "
        "ignored in mock mode.",
    )
    sample_window_days: int = Field(
        default=_DEFAULT_WINDOW_DAYS,
        ge=1,
        le=365,
        description="How many days of telemetry to sample for the estimate.",
    )


class NoiseBaselineOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ttp_id: str
    backend: Backend
    profile: NoiseProfile
    mock_mode: bool


class NoiseBaselineNode(Node[NoiseBaselineInput, NoiseBaselineOutput]):
    """Estimate expected hits/day for a hunt query (count-only)."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.noise_baseline",
        name="Noise Baseline",
        version="0.1.0",
        category=NodeCategory.DATA,
        description=(
            "Estimate expected hit volume for a hunt query via a count-only "
            "query against a sample window of telemetry."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = NoiseBaselineInput
    output_schema: ClassVar[type[BaseModel]] = NoiseBaselineOutput

    async def run(
        self,
        input: NoiseBaselineInput,
        ctx: NodeContext,
    ) -> NoiseBaselineOutput:
        if not _mock_mode_enabled():
            raise NotImplementedError(
                "Live count-only baseline queries land with the SIEM "
                "count-mode connector wiring. Set BTAGENT_MOCK_CONNECTORS=true "
                "for the deterministic mock path."
            )

        estimate = _mock_estimate(input.ttp_id, input.backend)
        profile = NoiseProfile(
            expected_hits_per_day=estimate,
            sample_window_days=input.sample_window_days,
            computed_at=datetime.utcnow(),
        )
        return NoiseBaselineOutput(
            ttp_id=input.ttp_id,
            backend=input.backend,
            profile=profile,
            mock_mode=True,
        )


NodeRegistry.register(NoiseBaselineNode)


__all__ = [
    "NoiseBaselineInput",
    "NoiseBaselineNode",
    "NoiseBaselineOutput",
]
