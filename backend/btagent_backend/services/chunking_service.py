"""Text chunking service for knowledge base document ingestion.

Token-based chunking that preserves paragraph boundaries and markdown
headers where possible. Each chunk carries metadata about its position
and section context within the source document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any


@dataclass
class Chunk:
    """A single text chunk produced by the chunking service."""

    content: str
    index: int
    token_count: int
    metadata: dict[str, Any] = field(default_factory=dict)


def estimate_tokens(text: str) -> int:
    """Rough token estimate using the chars/4 heuristic.

    This is a fast approximation; for accurate counts, use tiktoken.

    Parameters
    ----------
    text : str
        Input text.

    Returns
    -------
    int
        Estimated token count.
    """
    return max(1, len(text) // 4)


# Regex to detect markdown headers
_HEADER_RE = re.compile(r"^(#{1,6})\s+(.+)$", re.MULTILINE)


def _extract_section_header(text: str) -> str | None:
    """Extract the last markdown header found in a text fragment."""
    matches = list(_HEADER_RE.finditer(text))
    if matches:
        return matches[-1].group(2).strip()
    return None


def chunk_text(
    text: str,
    chunk_size: int = 512,
    overlap: int = 64,
) -> list[Chunk]:
    """Split text into overlapping token-based chunks.

    The chunker tries to respect paragraph boundaries and markdown
    headers. When a clean split at a paragraph boundary is not possible
    within the target chunk_size, it falls back to a hard token split
    with the specified overlap.

    Parameters
    ----------
    text : str
        Full text to chunk.
    chunk_size : int
        Target chunk size in estimated tokens (default 512).
    overlap : int
        Number of overlap tokens between consecutive chunks (default 64).

    Returns
    -------
    list[Chunk]
        Ordered list of chunks with content, index, token_count, and
        metadata (including section_header when found).
    """
    if not text or not text.strip():
        return []

    # Split into paragraphs (double newline or markdown header boundaries)
    paragraphs = _split_paragraphs(text)

    chunks: list[Chunk] = []
    current_parts: list[str] = []
    current_tokens = 0
    current_header: str | None = None
    chunk_index = 0

    for para in paragraphs:
        para_tokens = estimate_tokens(para)

        # Track current section header
        header_match = _HEADER_RE.match(para.strip())
        if header_match:
            current_header = header_match.group(2).strip()

        # If this single paragraph exceeds chunk_size, split it
        if para_tokens > chunk_size:
            # Flush any accumulated content first
            if current_parts:
                chunk_text_content = "\n\n".join(current_parts)
                chunks.append(
                    Chunk(
                        content=chunk_text_content,
                        index=chunk_index,
                        token_count=estimate_tokens(chunk_text_content),
                        metadata=_chunk_metadata(current_header, chunk_index),
                    )
                )
                chunk_index += 1
                current_parts = []
                current_tokens = 0

            # Split the large paragraph into sub-chunks
            sub_chunks = _split_large_text(para, chunk_size, overlap, chunk_index, current_header)
            chunks.extend(sub_chunks)
            chunk_index += len(sub_chunks)
            continue

        # Would adding this paragraph exceed the target chunk size?
        if current_tokens + para_tokens > chunk_size and current_parts:
            # Flush current chunk
            chunk_text_content = "\n\n".join(current_parts)
            chunks.append(
                Chunk(
                    content=chunk_text_content,
                    index=chunk_index,
                    token_count=estimate_tokens(chunk_text_content),
                    metadata=_chunk_metadata(current_header, chunk_index),
                )
            )
            chunk_index += 1

            # Start new chunk with overlap from the end of the previous
            overlap_text = _get_overlap_text(current_parts, overlap)
            if overlap_text:
                current_parts = [overlap_text, para]
                current_tokens = estimate_tokens(overlap_text) + para_tokens
            else:
                current_parts = [para]
                current_tokens = para_tokens
        else:
            current_parts.append(para)
            current_tokens += para_tokens

    # Flush remaining content
    if current_parts:
        chunk_text_content = "\n\n".join(current_parts)
        chunks.append(
            Chunk(
                content=chunk_text_content,
                index=chunk_index,
                token_count=estimate_tokens(chunk_text_content),
                metadata=_chunk_metadata(current_header, chunk_index),
            )
        )

    return chunks


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _split_paragraphs(text: str) -> list[str]:
    """Split text into paragraphs on double-newlines and header boundaries."""
    parts: list[str] = []
    raw_parts = re.split(r"\n{2,}", text.strip())
    for part in raw_parts:
        stripped = part.strip()
        if stripped:
            parts.append(stripped)
    return parts


def _get_overlap_text(parts: list[str], overlap_tokens: int) -> str:
    """Extract the trailing overlap from a list of paragraph parts."""
    if not parts or overlap_tokens <= 0:
        return ""

    # Join and take the tail
    full = "\n\n".join(parts)
    # Approximate character count for overlap_tokens
    overlap_chars = overlap_tokens * 4
    if len(full) <= overlap_chars:
        return full
    return full[-overlap_chars:]


def _split_large_text(
    text: str,
    chunk_size: int,
    overlap: int,
    start_index: int,
    section_header: str | None,
) -> list[Chunk]:
    """Split a large text block into fixed-size token chunks."""
    chunks: list[Chunk] = []
    # Work in character space (chunk_size * 4 chars per token)
    char_chunk = chunk_size * 4
    char_overlap = overlap * 4
    pos = 0
    idx = start_index

    while pos < len(text):
        end = min(pos + char_chunk, len(text))
        chunk_content = text[pos:end].strip()
        if chunk_content:
            chunks.append(
                Chunk(
                    content=chunk_content,
                    index=idx,
                    token_count=estimate_tokens(chunk_content),
                    metadata=_chunk_metadata(section_header, idx),
                )
            )
            idx += 1
        pos = end - char_overlap if end < len(text) else end

    return chunks


def _chunk_metadata(section_header: str | None, chunk_index: int) -> dict[str, Any]:
    """Build metadata dict for a chunk."""
    meta: dict[str, Any] = {"chunk_index": chunk_index}
    if section_header:
        meta["section_header"] = section_header
    return meta
