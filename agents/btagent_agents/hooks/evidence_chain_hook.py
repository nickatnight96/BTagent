"""Evidence chain hook — hashes artifacts at collection for forensic integrity.

When a tool produces output that contains file references or artifact data, this
hook computes a SHA-256 hash and emits an EVIDENCE_COLLECTED event. This creates
an auditable chain of custody for all evidence gathered during an investigation.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Any
from uuid import UUID

from langchain_core.callbacks import AsyncCallbackHandler, BaseCallbackHandler

from btagent_agents.events.emitter import RedisEmitter
from btagent_agents.hooks.base import HookProvider
from btagent_shared.types.events import EventType

logger = logging.getLogger("btagent.hooks.evidence_chain")

# Patterns that suggest the tool output contains an evidence artifact
_FILE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"(?:file|path|artifact)[:\s]+[\"']?([/\\][\w./\\-]+)", re.IGNORECASE),
    re.compile(r"(?:saved|wrote|exported|downloaded)\s+(?:to\s+)?[\"']?([/\\][\w./\\-]+)", re.I),
    re.compile(r"s3://[\w./-]+", re.IGNORECASE),
    re.compile(r"minio://[\w./-]+", re.IGNORECASE),
]

# Tool names that typically produce evidence artifacts
_EVIDENCE_TOOL_PATTERNS: list[str] = [
    "pcap",
    "capture",
    "export",
    "dump",
    "download",
    "collect",
    "evidence",
    "snapshot",
    "image",
    "forensic",
    "memory",
    "disk",
    "log_export",
    "query",  # SIEM query results are evidence
]

# Minimum output size to be considered evidence-worthy (bytes)
_MIN_EVIDENCE_SIZE = 64


def _extract_file_refs(text: str) -> list[str]:
    """Extract file/artifact path references from tool output text."""
    refs: list[str] = []
    for pattern in _FILE_PATTERNS:
        for match in pattern.finditer(text):
            ref = match.group(0)
            if ref not in refs:
                refs.append(ref)
    return refs


def _is_evidence_tool(tool_name: str) -> bool:
    """Check if the tool name suggests it produces evidence artifacts."""
    lower = tool_name.lower()
    return any(pattern in lower for pattern in _EVIDENCE_TOOL_PATTERNS)


def _compute_sha256(data: str) -> str:
    """Compute SHA-256 hash of a string (UTF-8 encoded)."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


class EvidenceChainCallback(AsyncCallbackHandler):
    """LangChain callback that hashes tool outputs and emits evidence events."""

    def __init__(self, emitter: RedisEmitter, investigation_id: str) -> None:
        super().__init__()
        self._emitter = emitter
        self._investigation_id = investigation_id
        self._tool_names: dict[str, str] = {}  # run_id -> tool_name

    async def on_tool_start(
        self,
        serialized: dict[str, Any],
        input_str: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        tool_name = serialized.get("name", "unknown_tool")
        self._tool_names[str(run_id)] = tool_name

    async def on_tool_end(
        self,
        output: str,
        *,
        run_id: UUID,
        parent_run_id: UUID | None = None,
        **kwargs: Any,
    ) -> None:
        run_key = str(run_id)
        tool_name = self._tool_names.pop(run_key, "unknown_tool")

        # Skip tiny outputs that are unlikely to be meaningful evidence
        if len(output) < _MIN_EVIDENCE_SIZE:
            return

        # Check if this tool or its output looks like evidence
        file_refs = _extract_file_refs(output)
        is_evidence_tool = _is_evidence_tool(tool_name)

        if not file_refs and not is_evidence_tool:
            return

        # Compute hash of the full output
        content_hash = _compute_sha256(output)

        # Hash individual file references as well
        ref_hashes: list[dict[str, str]] = []
        for ref in file_refs:
            ref_hashes.append({
                "reference": ref,
                "ref_hash": _compute_sha256(ref),
            })

        await self._emitter.emit(
            EventType.EVIDENCE_COLLECTED,
            tool_name=tool_name,
            content_hash_sha256=content_hash,
            content_size_bytes=len(output.encode("utf-8")),
            file_references=ref_hashes,
            file_reference_count=len(file_refs),
            run_id=run_key,
        )

        logger.info(
            "Evidence collected: tool=%s hash=%s refs=%d size=%d",
            tool_name,
            content_hash[:16] + "...",
            len(file_refs),
            len(output),
        )


class EvidenceChainHook(HookProvider):
    """Hook that computes SHA-256 hashes for evidence artifacts at collection time.

    Usage::

        hook = EvidenceChainHook(emitter, investigation_id)
        registry.register(hook)
    """

    def __init__(self, emitter: RedisEmitter, investigation_id: str) -> None:
        self._emitter = emitter
        self._investigation_id = investigation_id

    def get_callbacks(self) -> list[BaseCallbackHandler]:
        return [EvidenceChainCallback(self._emitter, self._investigation_id)]
