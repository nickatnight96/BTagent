"""Runtime context passed to every Node.run() call.

Holds the per-execution state the node needs to do its job: identifiers
for audit / replay, tenancy / classification for authz, plus an opaque
metadata bag for node-specific use.

The context is intentionally narrow -- callables (event emit, secret
resolution, logging) are passed in via the Runner / Registry rather
than stuffed into the model so the data is JSON-serialisable and
suitable for snapshot / replay storage.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class NodeContext(BaseModel):
    """Per-execution state for a single Node.run invocation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str = Field(
        ..., description="ULID of this node execution; unique per run, used for audit."
    )
    workflow_run_id: str | None = Field(
        default=None,
        description="ULID of the parent workflow run, when the node is part of one.",
    )
    investigation_id: str | None = Field(
        default=None,
        description="Investigation this run belongs to, if any.",
    )
    org_id: str = Field(
        ...,
        description="Tenant scope from the auth layer; nodes that emit egress must "
        "match payload TLP against this and never let data escape the org.",
    )
    user_id: str | None = Field(
        default=None,
        description="Initiating user; ``None`` for system / scheduled triggers.",
    )
    tlp_level: str = Field(
        default="green",
        description="Investigation classification, one of red / amber_strict / amber / "
        "green / white. The egress middleware uses this to gate non-LLM channels.",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form bag for node-specific runtime state. Avoid putting "
        "credentials or secrets here -- use the secret resolver injected via "
        "the registry instead.",
    )
