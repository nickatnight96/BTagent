"""STIX 2.1 conversion service for BTagent IOCs.

Provides bidirectional mapping between BTagent IOC records and STIX 2.1
Indicator / Observable objects for import and export.
"""

from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import Any
from uuid import uuid5, NAMESPACE_URL

logger = logging.getLogger("btagent.services.stix")

# STIX 2.1 spec version
STIX_SPEC_VERSION = "2.1"

# BTagent IOC type -> STIX SCO (Cyber-observable Object) type mapping
_IOC_TYPE_TO_STIX_SCO: dict[str, str] = {
    "ip": "ipv4-addr",
    "domain": "domain-name",
    "url": "url",
    "hash_md5": "file",
    "hash_sha1": "file",
    "hash_sha256": "file",
    "email": "email-addr",
    "file_path": "file",
    "process_name": "process",
    "mutex": "mutex",
    "user_agent": "user-agent",  # Not standard STIX, but we include as extension
}

# Reverse mapping: STIX pattern type -> BTagent IOC type
_STIX_PATTERN_TO_IOC_TYPE: dict[str, str] = {
    "ipv4-addr:value": "ip",
    "ipv6-addr:value": "ip",
    "domain-name:value": "domain",
    "url:value": "url",
    "file:hashes.'MD5'": "hash_md5",
    "file:hashes.'SHA-1'": "hash_sha1",
    "file:hashes.'SHA-256'": "hash_sha256",
    "email-addr:value": "email",
}

# TLP -> STIX TLP marking definition IDs
_TLP_MARKING_DEFS: dict[str, str] = {
    "white": "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    "green": "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da",
    "amber": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "amber_strict": "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82",
    "red": "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed",
}


def _deterministic_id(prefix: str, value: str) -> str:
    """Generate a deterministic STIX identifier from a value."""
    ns = NAMESPACE_URL
    return f"{prefix}--{uuid5(ns, value)}"


def _build_stix_pattern(ioc_type: str, value: str) -> str:
    """Build a STIX 2.1 pattern string from an IOC type and value.

    Examples:
        ip, 1.2.3.4 -> "[ipv4-addr:value = '1.2.3.4']"
        hash_sha256, abc123 -> "[file:hashes.'SHA-256' = 'abc123']"
    """
    if ioc_type == "ip":
        return f"[ipv4-addr:value = '{value}']"
    if ioc_type == "domain":
        return f"[domain-name:value = '{value}']"
    if ioc_type == "url":
        return f"[url:value = '{value}']"
    if ioc_type == "hash_md5":
        return f"[file:hashes.'MD5' = '{value}']"
    if ioc_type == "hash_sha1":
        return f"[file:hashes.'SHA-1' = '{value}']"
    if ioc_type == "hash_sha256":
        return f"[file:hashes.'SHA-256' = '{value}']"
    if ioc_type == "email":
        return f"[email-addr:value = '{value}']"
    # Fallback: custom pattern
    return f"[x-btagent-ioc:value = '{value}']"


def ioc_to_stix_indicator(
    ioc: dict[str, Any],
    *,
    tlp_level: str = "green",
) -> dict[str, Any]:
    """Convert a BTagent IOC dict to a STIX 2.1 Indicator object.

    Parameters
    ----------
    ioc : dict
        BTagent IOC with keys: id, type, value, confidence, context, etc.
    tlp_level : str
        TLP level for marking. IOCs at TLP:RED are excluded from export
        by the caller, not by this function.

    Returns
    -------
    dict
        STIX 2.1 Indicator SDO.
    """
    ioc_type = ioc.get("type", "unknown")
    ioc_value = ioc.get("value", "")
    confidence_raw = ioc.get("confidence", 0.5)

    # STIX confidence is 0-100 integer
    stix_confidence = min(100, max(0, int(confidence_raw * 100)))

    pattern = _build_stix_pattern(ioc_type, ioc_value)
    stix_id = _deterministic_id("indicator", f"{ioc_type}:{ioc_value}")

    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    indicator: dict[str, Any] = {
        "type": "indicator",
        "spec_version": STIX_SPEC_VERSION,
        "id": stix_id,
        "created": ioc.get("first_seen", now_iso),
        "modified": now_iso,
        "name": f"BTagent IOC: {ioc_type} - {ioc_value}",
        "description": ioc.get("context", f"IOC of type {ioc_type}"),
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ioc.get("first_seen", now_iso),
        "confidence": stix_confidence,
        "labels": [ioc_type],
    }

    # Add TLP marking
    marking_ref = _TLP_MARKING_DEFS.get(tlp_level)
    if marking_ref:
        indicator["object_marking_refs"] = [marking_ref]

    # Add enrichment as custom extension if present
    enrichment = ioc.get("enrichment")
    if enrichment:
        indicator["x_btagent_enrichment"] = enrichment

    return indicator


def stix_bundle_from_iocs(
    iocs: list[dict[str, Any]],
    *,
    tlp_level: str = "green",
) -> dict[str, Any]:
    """Build a STIX 2.1 Bundle from a list of BTagent IOCs.

    Parameters
    ----------
    iocs : list[dict]
        BTagent IOC dicts.
    tlp_level : str
        TLP level. IOCs at TLP:RED are excluded from export.

    Returns
    -------
    dict
        STIX 2.1 Bundle object.
    """
    # Enforce TLP: never export TLP:RED indicators
    if tlp_level == "red":
        logger.warning("Refusing to export TLP:RED IOCs to STIX bundle")
        return {
            "type": "bundle",
            "id": _deterministic_id("bundle", "empty-tlp-red"),
            "objects": [],
        }

    indicators = [
        ioc_to_stix_indicator(ioc, tlp_level=tlp_level)
        for ioc in iocs
        if ioc.get("tlp_level", "green") != "red"
    ]

    bundle_id = _deterministic_id(
        "bundle",
        hashlib.sha256(
            json.dumps(sorted(i["id"] for i in indicators)).encode()
        ).hexdigest(),
    )

    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": indicators,
    }


def _parse_stix_pattern(pattern: str) -> tuple[str, str] | None:
    """Extract IOC type and value from a STIX pattern string.

    Examples:
        "[ipv4-addr:value = '1.2.3.4']" -> ("ip", "1.2.3.4")
        "[file:hashes.'SHA-256' = 'abc']" -> ("hash_sha256", "abc")

    Returns None if the pattern cannot be parsed.
    """
    # Strip brackets
    pattern = pattern.strip().strip("[]")

    for stix_path, ioc_type in _STIX_PATTERN_TO_IOC_TYPE.items():
        if stix_path in pattern:
            # Extract the value between quotes
            parts = pattern.split("=", 1)
            if len(parts) == 2:
                value = parts[1].strip().strip("'\"")
                return ioc_type, value

    return None


def stix_to_iocs(
    bundle: dict[str, Any],
    *,
    investigation_id: str = "",
    source: str = "stix_import",
) -> list[dict[str, Any]]:
    """Convert a STIX 2.1 Bundle into a list of BTagent IOC dicts.

    Parameters
    ----------
    bundle : dict
        STIX 2.1 Bundle object.
    investigation_id : str
        Investigation to associate imported IOCs with.
    source : str
        Source label for the imported IOCs.

    Returns
    -------
    list[dict]
        BTagent IOC dicts ready for create_ioc / create_iocs_bulk.
    """
    objects = bundle.get("objects", [])
    iocs: list[dict[str, Any]] = []

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        pattern = obj.get("pattern", "")
        parsed = _parse_stix_pattern(pattern)
        if parsed is None:
            logger.warning("Could not parse STIX pattern: %s", pattern[:100])
            continue

        ioc_type, ioc_value = parsed

        # Convert STIX confidence (0-100) to BTagent confidence (0.0-1.0)
        stix_confidence = obj.get("confidence", 50)
        confidence = round(stix_confidence / 100.0, 2)

        # Determine TLP from marking refs
        tlp_level = "green"
        marking_refs = obj.get("object_marking_refs", [])
        for tlp_name, tlp_ref in _TLP_MARKING_DEFS.items():
            if tlp_ref in marking_refs:
                tlp_level = tlp_name
                break

        ioc: dict[str, Any] = {
            "type": ioc_type,
            "value": ioc_value,
            "confidence": confidence,
            "context": obj.get("description", ""),
            "source": source,
            "tlp_level": tlp_level,
            "investigation_id": investigation_id,
        }

        # Preserve enrichment extension if present
        enrichment = obj.get("x_btagent_enrichment")
        if enrichment:
            ioc["enrichment"] = enrichment

        iocs.append(ioc)

    logger.info(
        "Parsed %d indicators from STIX bundle (%d total objects)",
        len(iocs),
        len(objects),
    )
    return iocs
