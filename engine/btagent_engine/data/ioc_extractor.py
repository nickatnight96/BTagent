"""IOCExtractorNode — pull indicators out of advisory text (UC-2.2, #105).

Extracts IPs, domains, URLs, file hashes (MD5/SHA1/SHA256), emails, and
CVEs from free-form advisory text (a CISA bulletin, vendor report, ISAC
note). Handles common *defanging* (hxxp://, 1[.]2[.]3[.]4, evil[.]com,
foo(at)bar.com) by normalizing before extraction.

Pure deterministic parsing — no LLM, no mock gate. The PDF/CSV → text
step (binary decode + OCR) is the dep-needing follow-up; this node takes
text and is the testable core.

Extraction order matters: URLs are pulled first and their host removed
from the remaining text so a URL's domain/IP isn't double-counted as a
standalone indicator.
"""

from __future__ import annotations

import re
from typing import ClassVar

from btagent_shared.types.enums import IOCType
from pydantic import BaseModel, ConfigDict, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# --- defang normalization --------------------------------------------------- #

_DEFANG_SUBS = [
    (re.compile(r"h(?:xx|XX)p(s?)://", re.I), r"http\1://"),
    (re.compile(r"\[\.\]"), "."),
    (re.compile(r"\(\.\)"), "."),
    (re.compile(r"\[dot\]", re.I), "."),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[/\]"), "/"),
    (re.compile(r"\(at\)", re.I), "@"),
    (re.compile(r"\[at\]", re.I), "@"),
]


def _defang_normalize(text: str) -> str:
    for pat, repl in _DEFANG_SUBS:
        text = pat.sub(repl, text)
    return text


# --- extraction patterns ---------------------------------------------------- #

_URL_RE = re.compile(r"https?://[^\s\"'<>\)\]]+", re.I)
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_SHA1_RE = re.compile(r"\b[a-fA-F0-9]{40}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+\b")
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
# Domain: label(s) + a TLD of 2+ alpha. Conservative to limit false positives.
_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")

# TLDs that are almost always false positives in prose (file extensions).
_NON_DOMAIN_TLDS = {"exe", "dll", "doc", "docx", "pdf", "txt", "zip", "ps1", "py", "sh", "bat"}


class ExtractedIOC(BaseModel):
    model_config = ConfigDict(extra="forbid")

    type: IOCType
    value: str
    was_defanged: bool = False


class IOCExtractorInput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    text: str = Field(..., description="Advisory text (already decoded from PDF/CSV).")


class IOCExtractorOutput(BaseModel):
    model_config = ConfigDict(extra="forbid")

    iocs: list[ExtractedIOC] = Field(default_factory=list)
    deduped_count: int = Field(default=0, description="Duplicates removed during extraction.")


class IOCExtractorNode(Node[IOCExtractorInput, IOCExtractorOutput]):
    """Extract + defang + dedup indicators from advisory text."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="data.ioc_extractor",
        name="IOC Extractor",
        version="0.1.0",
        category=NodeCategory.DATA,
        description=(
            "Extract IPs / domains / URLs / hashes / emails / CVEs from "
            "advisory text, handling common defanging, and dedupe."
        ),
    )
    input_schema: ClassVar[type[BaseModel]] = IOCExtractorInput
    output_schema: ClassVar[type[BaseModel]] = IOCExtractorOutput

    async def run(
        self,
        input: IOCExtractorInput,
        ctx: NodeContext,
    ) -> IOCExtractorOutput:
        raw = input.text
        text = _defang_normalize(raw)
        was_defanged = text != raw

        found: list[tuple[IOCType, str]] = []
        consumed_spans: list[tuple[int, int]] = []

        # 1. URLs first; remember their spans so we don't re-extract their host.
        for m in _URL_RE.finditer(text):
            found.append((IOCType.URL, m.group(0).rstrip(".,;")))
            consumed_spans.append((m.start(), m.end()))

        def _outside_url(m: re.Match) -> bool:
            return not any(s <= m.start() < e for s, e in consumed_spans)

        # 2. Hashes (length-disjoint; order doesn't matter, but check sha256
        #    before sha1/md5 to avoid a 64-hex also matching the 32/40 res).
        for rx, t in (
            (_SHA256_RE, IOCType.HASH_SHA256),
            (_SHA1_RE, IOCType.HASH_SHA1),
            (_MD5_RE, IOCType.HASH_MD5),
        ):
            for m in rx.finditer(text):
                if _outside_url(m) and not any(s <= m.start() < e for s, e in consumed_spans):
                    found.append((t, m.group(0).lower()))
                    consumed_spans.append((m.start(), m.end()))

        # 3. Emails (before domains so the domain part isn't double-counted).
        for m in _EMAIL_RE.finditer(text):
            if _outside_url(m):
                found.append((IOCType.EMAIL, m.group(0)))
                consumed_spans.append((m.start(), m.end()))

        # 4. IPs
        for m in _IPV4_RE.finditer(text):
            if _outside_url(m):
                found.append((IOCType.IP, m.group(0)))

        # 5. CVEs
        for m in _CVE_RE.finditer(text):
            found.append((IOCType.CVE, m.group(0).upper()))

        # 6. Domains (outside URLs/emails; drop file-extension false positives)
        for m in _DOMAIN_RE.finditer(text):
            if not _outside_url(m):
                continue
            if any(s <= m.start() < e for s, e in consumed_spans):
                continue
            val = m.group(0).rstrip(".")
            tld = val.rsplit(".", 1)[-1].lower()
            if tld in _NON_DOMAIN_TLDS:
                continue
            found.append((IOCType.DOMAIN, val))

        # Dedupe on (type, value), preserve first-seen order.
        seen: set[tuple[IOCType, str]] = set()
        unique: list[ExtractedIOC] = []
        dupes = 0
        for t, v in found:
            key = (t, v)
            if key in seen:
                dupes += 1
                continue
            seen.add(key)
            unique.append(ExtractedIOC(type=t, value=v, was_defanged=was_defanged))

        return IOCExtractorOutput(iocs=unique, deduped_count=dupes)


NodeRegistry.register(IOCExtractorNode)


__all__ = [
    "ExtractedIOC",
    "IOCExtractorInput",
    "IOCExtractorNode",
    "IOCExtractorOutput",
]
