"""IOC extraction Node -- regex pattern scan over arbitrary analyst text.

Ports the legacy ``_IOC_PATTERNS`` dict / ``_extract_iocs`` helper that
lived in ``agents/btagent_agents/orchestrator/nodes.py``. Re-implemented
here as a standalone Node so:

* The compiler can wire it into any workflow YAML, not just the hard-
  coded triage subgraph.
* The canvas UI can drag-and-drop it as a palette item.
* Unit tests have no dependency on ``btagent_agents`` -- the engine
  package must be standalone-shippable per Sprint 1's design rules.

Strengthened over the legacy version:

* Adds **ipv6**, **hash_sha1**, and **file_path** patterns the legacy
  helper lacked. The legacy ``_IOC_PATTERNS`` only carried ip / domain /
  hash_sha256 / hash_md5 / email / cve / url -- those leave entire
  classes of analyst-relevant artefacts on the floor.
* **Defangs** common IOC obfuscations (``[.]``, ``hxxp``, ``(.)``,
  ``[://]``) before matching so analyst paste-ins from CTI feeds match
  cleanly without a manual cleanup step.
* **Skips RFC-1918 / loopback / link-local** IPs unless the caller
  explicitly opts in via ``types=["ip"]`` -- the legacy helper happily
  reported ``192.168.0.1`` from a sysmon log as an IOC, which produced
  a lot of analyst noise.
* Records the **first match offset** so a future highlight UI can mark
  the source span without a second regex pass.

Sprint 4B; bumps a TODO from Sprint 3D's workflow templates.
"""

from __future__ import annotations

import ipaddress
import re
from typing import ClassVar

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

# ---------------------------------------------------------------------------
# Defang -> refang
# ---------------------------------------------------------------------------
# Order matters: do the multi-character substitutions first so the simpler
# ``[.] -> .`` doesn't half-rewrite ``[://]`` into ``[://``.

_DEFANG_SUBSTITUTIONS: tuple[tuple[str, str], ...] = (
    ("hxxps://", "https://"),
    ("hxxp://", "http://"),
    ("[://]", "://"),
    ("[:]", ":"),
    ("[.]", "."),
    ("(.)", "."),
    ("{.}", "."),
    ("[dot]", "."),
    ("(dot)", "."),
    ("[at]", "@"),
    ("(at)", "@"),
)


def _refang(text: str) -> str:
    """Reverse common analyst defang notations so regex patterns match."""
    out = text
    for needle, replacement in _DEFANG_SUBSTITUTIONS:
        # Case-insensitive replace via lower-cased lookup; cheap because
        # the defang tokens are all ASCII and the search space is small.
        if needle.lower() in out.lower():
            # Re-walk char-by-char to preserve original casing where the
            # surrounding text is mixed-case (URLs commonly are).
            pattern = re.compile(re.escape(needle), re.IGNORECASE)
            out = pattern.sub(replacement, out)
    return out


# ---------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------
# Legacy patterns (ip / domain / hash_sha256 / hash_md5 / email / url)
# ported as-is from agents/btagent_agents/orchestrator/nodes.py:_IOC_PATTERNS,
# with the additions called out in the module docstring.

_IOC_PATTERNS: dict[str, re.Pattern[str]] = {
    "ipv4": re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|1?\d\d?)\b"),
    # IPv6 -- a deliberately permissive pattern that matches the common
    # forms (full, compressed ``::``, mixed v4-mapped). Anything fancier
    # gets validated by ipaddress in the dedup Node downstream.
    #
    # Pattern: lookbehind to avoid matching mid-token, then either the
    # full 8-group form OR something containing a ``::`` shortener.
    "ipv6": re.compile(
        r"(?<![A-Za-z0-9:])"
        r"(?:"
        # Full 8-group form: group:group:...:group
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|"
        # Shortened form with one ``::`` somewhere; both halves optional.
        r"(?:[A-Fa-f0-9]{1,4}:){1,7}:(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?"
        r"|"
        # Leading-shortened form starting ``::group...``
        r"::(?:[A-Fa-f0-9]{1,4}(?::[A-Fa-f0-9]{1,4})*)?"
        r")"
        r"(?![A-Za-z0-9:])"
    ),
    # URL FIRST so domain-inside-URL is captured as a URL (the consumer
    # can post-process if it wants the bare host).
    "url": re.compile(r"https?://[^\s\"'<>]+"),
    "domain": re.compile(
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
        r"(?:com|net|org|io|info|biz|xyz|ru|cn|tk|top|cc|pw|uk|de|fr|jp|gov|edu|mil)"
        r"\b"
    ),
    "hash_sha256": re.compile(r"\b[0-9a-fA-F]{64}\b"),
    "hash_sha1": re.compile(r"\b[0-9a-fA-F]{40}\b"),
    "hash_md5": re.compile(r"\b[0-9a-fA-F]{32}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    # Windows path: drive letter + backslash separators. Accepts mixed
    # quoting analysts paste from event viewer.
    "file_path_windows": re.compile(r"[A-Za-z]:\\(?:[^\s<>:\"|?*\\/]+\\)*[^\s<>:\"|?*\\/]+"),
    # Unix path: starts with / and has at least one further segment to
    # avoid grabbing every URL fragment. Excludes spaces.
    "file_path_unix": re.compile(r"(?<![A-Za-z0-9])/(?:[A-Za-z0-9._-]+/)+[A-Za-z0-9._-]+"),
}

_KNOWN_TYPES: frozenset[str] = frozenset(_IOC_PATTERNS.keys())


def _is_private_ipv4(value: str) -> bool:
    """RFC-1918 / loopback / link-local check; tolerant of garbage input."""
    try:
        addr = ipaddress.IPv4Address(value)
    except ValueError:
        return False
    return addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_multicast


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class ExtractIOCsInput(BaseModel):
    text: str = Field(
        ...,
        description="Free-form text to scan for IOCs. Defanged forms "
        "(``[.]``, ``hxxp``, etc.) are normalised before matching.",
    )
    types: list[str] | None = Field(
        default=None,
        description="Optional whitelist of IOC types to keep. None = all "
        "known types. Pass ``['ip']`` (or include 'ipv4'/'ipv6') to allow "
        "RFC-1918 / private IPs through.",
    )


class ExtractedIOC(BaseModel):
    type: str = Field(
        ...,
        description="IOC kind: 'ipv4' / 'ipv6' / 'domain' / 'url' / "
        "'hash_md5' / 'hash_sha1' / 'hash_sha256' / 'email' / "
        "'file_path_windows' / 'file_path_unix'.",
    )
    value: str
    first_offset: int = Field(
        ...,
        description="Byte offset of the first occurrence in the (refanged) "
        "source text. Useful for highlight UI.",
    )


class ExtractIOCsOutput(BaseModel):
    iocs: list[ExtractedIOC]
    by_type: dict[str, int] = Field(
        ...,
        description="Counts per IOC type for the kept (post-dedup) results. "
        "``sum(by_type.values()) == len(iocs)``.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class ExtractIOCsNode(Node[ExtractIOCsInput, ExtractIOCsOutput]):
    """Regex-based IOC extractor with defang normalisation."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="enrichment.extract_iocs",
        name="Enrichment: Extract IOCs",
        version="0.1.0",
        # TODO(post-sprint4B): once a fourth+ enrichment Node lands, add a
        # NodeCategory.ENRICHMENT bucket and re-tag these three. DATA is
        # the closest match in the current enum.
        category=NodeCategory.DATA,
        description="Scan free-form text for IOCs (IPs, domains, URLs, "
        "hashes, emails, file paths). Refangs analyst defang notations "
        "before matching; skips RFC-1918 IPs unless explicitly requested.",
    )
    input_schema: ClassVar[type[BaseModel]] = ExtractIOCsInput
    output_schema: ClassVar[type[BaseModel]] = ExtractIOCsOutput

    async def run(
        self,
        input: ExtractIOCsInput,
        ctx: NodeContext,
    ) -> ExtractIOCsOutput:
        # Resolve the type filter. ``["ip"]`` is sugar for both ipv4+ipv6
        # AND the opt-in for private/RFC-1918 IPs.
        explicit_ip_request = False
        if input.types is None:
            wanted: set[str] = set(_KNOWN_TYPES)
        else:
            wanted = set()
            for t in input.types:
                if t == "ip":
                    wanted.update({"ipv4", "ipv6"})
                    explicit_ip_request = True
                elif t in _KNOWN_TYPES:
                    wanted.add(t)
                # silently ignore unknown types -- callers should not be
                # able to crash extraction by mistyping a filter.

        refanged = _refang(input.text)

        # Dedup within this single call: same (type, value) collapses,
        # first-occurrence wins (lowest offset).
        seen: dict[tuple[str, str], ExtractedIOC] = {}

        for ioc_type, pattern in _IOC_PATTERNS.items():
            if ioc_type not in wanted:
                continue
            for match in pattern.finditer(refanged):
                value = match.group()

                # RFC-1918 / loopback / link-local skip for ipv4 unless
                # the caller asked for ip-class results explicitly.
                if ioc_type == "ipv4" and not explicit_ip_request and _is_private_ipv4(value):
                    continue

                key = (ioc_type, value)
                if key in seen:
                    continue
                seen[key] = ExtractedIOC(
                    type=ioc_type,
                    value=value,
                    first_offset=match.start(),
                )

        iocs = list(seen.values())
        by_type: dict[str, int] = {}
        for ioc in iocs:
            by_type[ioc.type] = by_type.get(ioc.type, 0) + 1

        return ExtractIOCsOutput(iocs=iocs, by_type=by_type)
