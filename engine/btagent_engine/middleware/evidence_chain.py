"""Evidence-chain middleware -- hash-link audit trail of node executions.

Writes one :class:`EvidenceRecord` per successful node run to an injected
list. Each record's ``link_hash`` is a SHA-256 over ``(input, output,
run_id, prev_hash)`` so the chain is tamper-evident in the same way a
git commit graph is: changing one record invalidates every record after.

Departure from the legacy hook (``evidence_chain_hook.py``):

* The legacy version emitted ``EVIDENCE_COLLECTED`` events through Redis
  and only fired on tool calls whose name matched a heuristic
  ("pcap", "export", "dump", ...). The middleware version is *unconditional*:
  every node run that produces output is recorded. The Sprint 3 audit-log
  consumer is the single place that decides which records get persisted
  long-term, which is much easier to test than a heuristic spread across
  the hook + the consumer.
* Errors are *not* chained -- the chain is the record of what data flowed
  through the workflow successfully. ``on_error`` is a no-op.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel as _BaseModel
from pydantic import ConfigDict, Field

from btagent_engine.middleware.base import Middleware

if TYPE_CHECKING:
    from btagent_engine.node import Node, NodeContext


# Value used as ``prev_hash`` for the very first record in a chain.
# Sixty-four zeros -- standard "empty parent" convention used by git, IPFS,
# blockchain prior-art etc.
GENESIS_HASH: str = "0" * 64


class EvidenceRecord(_BaseModel):
    """One link in the audit chain for a Node execution."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    node_id: str
    prev_hash: str = Field(
        ...,
        description=(
            "SHA-256 of the previous record in this chain, or GENESIS_HASH "
            "for the first."
        ),
    )
    link_hash: str = Field(
        ...,
        description="SHA-256 over (input, output, run_id, prev_hash).",
    )
    input_hash: str
    output_hash: str
    timestamp: datetime


def _sha256_of(payload: Any) -> str:
    """Stable SHA-256 over a JSON-serialisable payload."""
    import json

    encoded = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _link_hash(
    input_hash: str,
    output_hash: str,
    run_id: str,
    prev_hash: str,
) -> str:
    """Hash the four chain inputs in a fixed order, separator-delimited.

    The separator (``\\x00``) cannot appear in any of the four inputs --
    they are all SHA-256 hex strings or a ULID -- so there's no prefix
    ambiguity (``a + b == aa + b``-style collision).
    """
    parts = "\x00".join((input_hash, output_hash, run_id, prev_hash))
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()


class EvidenceChainMiddleware(Middleware):
    """Append a hash-linked record to *records* per successful node run."""

    name = "evidence_chain"

    def __init__(self, records: list[EvidenceRecord]) -> None:
        self._records = records

    async def before_run(self, node, input, ctx):  # noqa: D401 -- inherited contract
        # No-op; chaining happens in after_run when both sides are known.
        return

    async def after_run(
        self,
        node: Node,
        input: _BaseModel,
        output: _BaseModel,
        ctx: NodeContext,
    ) -> None:
        prev_hash = self._records[-1].link_hash if self._records else GENESIS_HASH
        in_h = _sha256_of(input.model_dump(mode="json"))
        out_h = _sha256_of(output.model_dump(mode="json"))
        record = EvidenceRecord(
            run_id=ctx.run_id,
            node_id=node.meta.id,
            prev_hash=prev_hash,
            link_hash=_link_hash(in_h, out_h, ctx.run_id, prev_hash),
            input_hash=in_h,
            output_hash=out_h,
            timestamp=datetime.now(UTC),
        )
        self._records.append(record)


__all__ = ["EvidenceChainMiddleware", "EvidenceRecord", "GENESIS_HASH"]
