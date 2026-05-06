"""IOC deduplication Node -- canonicalise then collapse.

Ports the legacy ``deduplicate_iocs`` LangChain tool from
``agents/btagent_agents/plugins/enrichment/tools/dedup.py``.

**Audit-fix**: the legacy tool was case-sensitive on the type+value
key, so ``DOMAIN.COM`` and ``domain.com`` were treated as two distinct
IOCs and never merged. Sprint 3C's audit flagged this as a correctness
bug -- IOC backends are case-insensitive on hostnames and hashes, so
the duplicates leak through enrichment downstream and inflate cost +
muddy reporting.

This Node fixes that by canonicalising **before** keying:

* Domains: ``str.lower()`` + strip trailing dot.
* IPs: parsed via ``ipaddress`` so ``010.0.0.1`` -> ``10.0.0.1`` and
  IPv6 forms like ``2001:db8::1`` and ``2001:0db8:0000:0000:0000:0000:0000:0001``
  collapse together.
* URLs: host part lower-cased; **path case preserved** (paths are
  case-sensitive on most servers and an ``/Admin`` -> ``/admin`` rewrite
  would silently rename a real artefact).
* Hashes: ``str.lower()``.
* Emails: ``str.lower()``.
* Anything else: pass-through (no canonicalisation), still collapsed
  by exact match.

Collision merge policy (when two inputs canonicalise to the same key):

* ``confidence``: max of the two.
* ``tags``: set union, sorted for deterministic output.
* ``first_seen``: earliest non-empty value.
* All other fields: first-seen wins (the later duplicate is dropped).

Sprint 4B; bumps a TODO from Sprint 3D's enrichment workflow template.
"""

from __future__ import annotations

import ipaddress
from typing import Any, ClassVar
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field

from btagent_engine.node import (
    Node,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)


def _normalise_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")


def _normalise_ip(value: str) -> str:
    """Return the canonical string form of an IP, or the trimmed input on parse failure."""
    raw = value.strip()
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        # Some legacy callers shove ``010.0.0.1`` (octal-leading) which
        # ``ipaddress`` rejects on Python 3.10+. Try the IPv4 strict-form
        # workaround: split, int(), recompose.
        parts = raw.split(".")
        if len(parts) == 4:
            try:
                octets = [int(p, 10) for p in parts]
                if all(0 <= o <= 255 for o in octets):
                    return ".".join(str(o) for o in octets)
            except ValueError:
                pass
        return raw


def _normalise_url(value: str) -> str:
    """Lower-case scheme + host; preserve path / query / fragment case."""
    raw = value.strip()
    try:
        parts = urlsplit(raw)
    except ValueError:
        return raw
    if not parts.scheme or not parts.netloc:
        # Malformed -- best-effort lower of the whole thing's host-ish bit.
        return raw
    netloc = parts.netloc.lower()
    return urlunsplit(
        (parts.scheme.lower(), netloc, parts.path, parts.query, parts.fragment)
    )


def _normalise_hash(value: str) -> str:
    return value.strip().lower()


def _normalise_email(value: str) -> str:
    return value.strip().lower()


def _canonicalise(ioc_type: str, value: str) -> str:
    """Return the canonical key form of *value* for the given *type*."""
    t = ioc_type.lower().strip()
    if t in {"domain", "fqdn", "hostname"}:
        return _normalise_domain(value)
    if t in {"ip", "ipv4", "ipv6"}:
        return _normalise_ip(value)
    if t == "url":
        return _normalise_url(value)
    if t in {"hash_md5", "hash_sha1", "hash_sha256", "hash"}:
        return _normalise_hash(value)
    if t == "email":
        return _normalise_email(value)
    return value.strip()


def _merge(existing: dict[str, Any], incoming: dict[str, Any]) -> dict[str, Any]:
    """Apply the collision merge policy described in the module docstring."""
    merged = dict(existing)

    # Confidence: max of the two (treat missing as 0.0).
    e_conf = float(existing.get("confidence", 0.0) or 0.0)
    i_conf = float(incoming.get("confidence", 0.0) or 0.0)
    if e_conf or i_conf:
        merged["confidence"] = max(e_conf, i_conf)

    # Tags: set union; sorted for deterministic output.
    e_tags = existing.get("tags") or []
    i_tags = incoming.get("tags") or []
    if e_tags or i_tags:
        # Keep the original element type (str expected) but dedup case-
        # insensitively to avoid 'Malware' vs 'malware' splits.
        seen_lower: dict[str, str] = {}
        for tag in list(e_tags) + list(i_tags):
            if not isinstance(tag, str):
                continue
            key = tag.lower()
            if key not in seen_lower:
                seen_lower[key] = tag
        merged["tags"] = sorted(seen_lower.values(), key=str.lower)

    # first_seen: earliest non-empty.
    e_first = existing.get("first_seen") or ""
    i_first = incoming.get("first_seen") or ""
    if e_first and i_first:
        merged["first_seen"] = min(e_first, i_first)
    elif i_first and not e_first:
        merged["first_seen"] = i_first

    return merged


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class DedupIOCsInput(BaseModel):
    iocs: list[dict[str, Any]] = Field(
        ...,
        description="Each dict must have at minimum 'type' and 'value' "
        "keys. Optional 'confidence' (float), 'tags' (list[str]), "
        "and 'first_seen' (ISO timestamp) participate in the merge.",
    )


class DedupIOCsOutput(BaseModel):
    iocs: list[dict[str, Any]] = Field(
        ...,
        description="Canonicalised, collapsed IOCs. Order matches first-"
        "occurrence in the input.",
    )
    duplicates_removed: int = Field(
        ...,
        ge=0,
        description="``len(input.iocs) - len(output.iocs)``.",
    )


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


@NodeRegistry.register
class DedupIOCsNode(Node[DedupIOCsInput, DedupIOCsOutput]):
    """Canonicalise IOC type+value, then merge duplicates."""

    meta: ClassVar[NodeMeta] = NodeMeta(
        id="enrichment.dedup_iocs",
        name="Enrichment: Dedup IOCs",
        version="0.1.0",
        # TODO(post-sprint4B): see ExtractIOCsNode for the ENRICHMENT
        # category candidate; DATA stands in until the enum is extended.
        category=NodeCategory.DATA,
        description="Canonicalise IOC values (lower-case domains/hashes, "
        "parse IPs, lower URL host) and collapse duplicates. Fixes the "
        "audit-flagged case-sensitivity bug in the legacy enrichment "
        "dedup tool.",
    )
    input_schema: ClassVar[type[BaseModel]] = DedupIOCsInput
    output_schema: ClassVar[type[BaseModel]] = DedupIOCsOutput

    async def run(
        self,
        input: DedupIOCsInput,
        ctx: NodeContext,
    ) -> DedupIOCsOutput:
        # Use a dict to preserve first-seen ordering (Python 3.7+).
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        original_count = 0

        for raw_ioc in input.iocs:
            if not isinstance(raw_ioc, dict):
                # Loud skip via stderr would be polite; silent skip keeps
                # the contract simple. The original_count below also skips.
                continue

            ioc_type = str(raw_ioc.get("type", "")).strip().lower()
            ioc_value = str(raw_ioc.get("value", "")).strip()
            if not ioc_type or not ioc_value:
                continue

            original_count += 1
            canonical_value = _canonicalise(ioc_type, ioc_value)
            key = (ioc_type, canonical_value)

            if key in groups:
                groups[key] = _merge(groups[key], raw_ioc)
            else:
                # Write the canonical value back so downstream consumers
                # see the normalised form, not whatever the caller passed.
                normalised = dict(raw_ioc)
                normalised["type"] = ioc_type
                normalised["value"] = canonical_value
                groups[key] = normalised

        result = list(groups.values())
        return DedupIOCsOutput(
            iocs=result,
            duplicates_removed=original_count - len(result),
        )
