"""Externalisation helpers for the context cascade.

Layer 0 of the cascade replaces large message contents with a stable
hash reference (``artifact:<sha256>``) and emits the original content
as an :class:`ArtifactRef` so the caller can persist it in the artifact
store. The hash is the *content* hash -- identical content always
produces the same reference, which means deduplication is automatic
and replays are deterministic.

The hash truncation length (16 hex chars / 64 bits) is a deliberate
trade-off: short enough to fit comfortably in a transcript, long
enough that the birthday probability of collision across a single
investigation's artifacts is negligible.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

ARTIFACT_HASH_LENGTH = 16
ARTIFACT_PREFIX = "artifact:"


class ArtifactRef(BaseModel):
    """An externalised piece of content + its stable reference.

    ``ref`` is the short ``artifact:<hash>`` token that replaces the
    original content in the message stream. ``sha256`` is the full
    hash for callers that want to verify integrity. ``content`` is the
    raw payload as a string -- the cascade JSON-encodes structured
    payloads before hashing for stability.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    ref: str = Field(..., description="Short reference token, e.g. 'artifact:abcd...'")
    sha256: str = Field(..., description="Full SHA-256 hex digest of content.")
    content: str = Field(..., description="Original content (verbatim, UTF-8 string).")
    byte_size: int = Field(..., description="Original byte length, for budget accounting.")
    tool_name: str = Field(default="", description="Tool/role this content came from.")


def content_byte_length(content: Any) -> int:
    """Approximate byte length of a message ``content`` field.

    Handles the three shapes the cascade sees in the wild:
    plain string, list of multimodal content blocks (dicts/strings),
    or anything else (treated as 0).
    """
    if isinstance(content, str):
        return len(content.encode("utf-8"))
    if isinstance(content, list):
        total = 0
        for block in content:
            if isinstance(block, dict):
                total += len(json.dumps(block, default=str).encode("utf-8"))
            elif isinstance(block, str):
                total += len(block.encode("utf-8"))
        return total
    return 0


def _stringify(content: Any) -> str:
    if isinstance(content, str):
        return content
    return json.dumps(content, default=str)


def make_artifact_ref(content: Any, *, tool_name: str = "") -> ArtifactRef:
    """Hash *content* and build the externalisation record.

    The hash is computed over the UTF-8 encoding of the *stringified*
    content (JSON-encoded for non-string inputs) so dict ordering
    differences after a round-trip won't change the ref -- json.dumps
    sorts keys for stability *only if asked*, so callers that need
    ordering invariance should pre-canonicalise. We don't sort here
    because tool outputs are usually already-canonical strings.
    """
    payload = _stringify(content)
    encoded = payload.encode("utf-8")
    full_hash = hashlib.sha256(encoded).hexdigest()
    short = full_hash[:ARTIFACT_HASH_LENGTH]
    return ArtifactRef(
        ref=f"{ARTIFACT_PREFIX}{short}",
        sha256=full_hash,
        content=payload,
        byte_size=len(encoded),
        tool_name=tool_name,
    )
