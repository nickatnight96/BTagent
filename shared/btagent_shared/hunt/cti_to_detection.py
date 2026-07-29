"""STIX 2.1 → Sigma rule proposal pipeline — pure-logic core (issue #113 slice).

Provides three public functions:

* :func:`extract_detectable_indicators` — pull domains, IPs, file hashes, and
  command-line patterns from a STIX 2.1 bundle, reusing the parsing
  primitives already present in
  ``btagent_backend.services.stix_service._parse_stix_pattern``.
  Because that function lives in the backend package (which carries DB deps
  not appropriate in ``shared/``), we inline the same regex-free parsing logic
  here as a thin, dependency-free copy.

* :func:`propose_sigma_rule` — deterministic Sigma YAML generation from a
  single extracted indicator + resolved MITRE technique IDs.

* :func:`process_stix_bundle` — orchestrator that applies TLP gating (refusing
  TLP:RED bundles identically to the existing STIX importer) then calls
  extract → map → propose for every indicator in the bundle.

Design constraints
------------------
- Zero heavy deps: only stdlib + pydantic (already a shared dep).
- No UUIDs or timestamps inside the generated Sigma rule YAML — deterministic
  for identical input, so rule ids are stable across re-runs.
- The ``MitreMapper`` from ``agents/btagent_agents/mitre/mapper.py`` is
  imported at call-time with a lazy fallback so the module remains importable
  in environments where the ``agents`` package is not installed.
- All ``classification_ctx`` checks mirror the existing
  ``stix_bundle_from_iocs`` / ``assert_tlp_allows_egress`` contract:
  TLP:RED → :class:`btagent_shared.security.TLPViolation`.
- External data (STIX bundle content) is **never** passed to an LLM here.

STIX library note
-----------------
The project does **not** vendor a full ``stix2`` Python library.  Instead
``backend/btagent_backend/services/stix_service.py`` implements bespoke,
regex-free pattern parsing against the subset of STIX 2.1 patterns the
BTagent importer emits.  We reuse the same pattern-parsing approach here
so no new STIX library is added.
"""

from __future__ import annotations

import hashlib
import logging
import uuid as _uuid
from datetime import UTC, datetime
from typing import Any

import yaml

from btagent_shared.security.tlp import TLPViolation, assert_tlp_allows_egress
from btagent_shared.types.config import TLP
from btagent_shared.types.detection_proposal import (
    CTIToDetectionResponse,
    DetectionProposal,
    SkippedIndicator,
)

logger = logging.getLogger("btagent.hunt.cti_to_detection")

# ---------------------------------------------------------------------------
# STIX pattern parsing (mirrors btagent_backend.services.stix_service)
# We duplicate only the pattern-parse table — no new STIX library needed.
# ---------------------------------------------------------------------------

# STIX pattern path → (btagent ioc_type, logsource category, logsource product)
_PATTERN_MAP: list[tuple[str, str, str, str]] = [
    # (stix_path_fragment, ioc_type, logsource_category, logsource_product)
    ("ipv4-addr:value", "ip", "network_connection", ""),
    ("ipv6-addr:value", "ip", "network_connection", ""),
    ("domain-name:value", "domain", "proxy", ""),
    ("url:value", "url", "proxy", ""),
    ("file:hashes.'MD5'", "hash_md5", "process_creation", "windows"),
    ("file:hashes.'SHA-1'", "hash_sha1", "process_creation", "windows"),
    ("file:hashes.'SHA-256'", "hash_sha256", "process_creation", "windows"),
    ("process:command_line", "cmdline", "process_creation", "windows"),
    ("email-addr:value", "email", "email", ""),
]


def _parse_stix_pattern(pattern: str) -> tuple[str, str, str, str] | None:
    """Extract (ioc_type, value, logsource_category, logsource_product) from a STIX pattern.

    Returns ``None`` if the pattern is not in a form we can convert.
    """
    stripped = pattern.strip().strip("[]")
    for stix_path, ioc_type, logsource_cat, logsource_prod in _PATTERN_MAP:
        if stix_path in stripped:
            parts = stripped.split("=", 1)
            if len(parts) == 2:
                value = parts[1].strip().strip("'\"")
                return ioc_type, value, logsource_cat, logsource_prod
    return None


# ---------------------------------------------------------------------------
# Internal data-class for extracted indicators
# ---------------------------------------------------------------------------


class _ExtractedIndicator:
    """Lightweight container for a parsed STIX indicator."""

    __slots__ = (
        "stix_id",
        "ioc_type",
        "value",
        "logsource_category",
        "logsource_product",
        "confidence",
        "name",
        "description",
        "kill_chain_phases",
    )

    def __init__(
        self,
        *,
        stix_id: str,
        ioc_type: str,
        value: str,
        logsource_category: str,
        logsource_product: str,
        confidence: float,
        name: str,
        description: str,
        kill_chain_phases: list[dict[str, str]],
    ) -> None:
        self.stix_id = stix_id
        self.ioc_type = ioc_type
        self.value = value
        self.logsource_category = logsource_category
        self.logsource_product = logsource_product
        self.confidence = confidence
        self.name = name
        self.description = description
        self.kill_chain_phases = kill_chain_phases


class _UnsupportedIndicator:
    """Surfaces a STIX indicator whose pattern shape isn't yet supported.

    Returned by :func:`extract_detectable_indicators` in the SAME list as
    successfully-parsed ``_ExtractedIndicator`` entries so the caller
    (:func:`process_stix_bundle`) can record an explicit ``SkippedIndicator``
    instead of silently dropping the input (Codex #213 P2). Carries the raw
    STIX pattern verbatim for audit/review.
    """

    __slots__ = ("stix_id", "pattern", "reason")

    def __init__(self, *, stix_id: str, pattern: str, reason: str = "unsupported_pattern") -> None:
        self.stix_id = stix_id
        self.pattern = pattern
        self.reason = reason


# ---------------------------------------------------------------------------
# Step 1 — Extract indicators
# ---------------------------------------------------------------------------


def extract_detectable_indicators(
    stix_bundle: dict[str, Any],
) -> list[_ExtractedIndicator | _UnsupportedIndicator]:
    """Pull detectable indicators from a STIX 2.1 bundle.

    Processes STIX ``indicator`` objects whose pattern can be parsed into one
    of: IPv4/IPv6 address, domain-name, URL, file hash (MD5/SHA-1/SHA-256),
    process command-line, or email address.

    Parameters
    ----------
    stix_bundle:
        A STIX 2.1 bundle dict (``{"type": "bundle", "objects": [...]}``)

    Returns
    -------
    list[_ExtractedIndicator | _UnsupportedIndicator]
        Parsed indicators, one per valid STIX Indicator SDO.  Empty list if no
        parseable indicators are found.
    """
    objects: list[dict[str, Any]] = stix_bundle.get("objects", [])
    results: list[_ExtractedIndicator | _UnsupportedIndicator] = []

    for obj in objects:
        if obj.get("type") != "indicator":
            continue

        stix_id: str = obj.get("id", "")
        pattern: str = obj.get("pattern", "")
        name: str = obj.get("name", "")
        description: str = obj.get("description", "")
        kill_chain_phases_raw = obj.get("kill_chain_phases", [])
        # A malformed bundle may carry ``kill_chain_phases`` as something other
        # than a list of objects (a bare string, a dict, …). Normalise to a list
        # here so the technique resolver never does ``phase.get`` on a non-dict
        # (which raised AttributeError → HTTP 500). Non-dict items are dropped
        # downstream in ``_technique_ids_from_kill_chain``.
        kill_chain_phases: list[dict[str, str]] = (
            kill_chain_phases_raw if isinstance(kill_chain_phases_raw, list) else []
        )

        # STIX confidence 0-100 → BTagent 0.0-1.0. A malformed ``confidence``
        # (non-numeric string, null, list, …) must not raise TypeError/ValueError
        # → HTTP 500; coerce defensively and fall back to the neutral 50 default.
        stix_conf = obj.get("confidence", 50)
        try:
            conf_int = int(stix_conf)
        except (TypeError, ValueError):
            logger.debug("Malformed STIX confidence %r; defaulting to 50", stix_conf)
            conf_int = 50
        confidence = round(min(100, max(0, conf_int)) / 100.0, 2)

        parsed = _parse_stix_pattern(pattern)
        if parsed is None:
            # Codex #213: don't silently drop indicators whose pattern shape
            # we don't yet support (e.g. ``file:name``, ``x-custom:foo``).
            # Surface them as ``_UnsupportedIndicator`` so process_stix_bundle
            # can record an explicit SkippedIndicator with the original
            # pattern, preserving audit/review visibility for CTI inputs the
            # pipeline did not convert.
            logger.debug("Recording unparseable STIX pattern as skipped: %s", pattern[:80])
            results.append(
                _UnsupportedIndicator(
                    stix_id=stix_id, pattern=pattern, reason="unsupported_pattern"
                )
            )
            continue

        ioc_type, value, logsource_category, logsource_product = parsed

        results.append(
            _ExtractedIndicator(
                stix_id=stix_id,
                ioc_type=ioc_type,
                value=value,
                logsource_category=logsource_category,
                logsource_product=logsource_product,
                confidence=confidence,
                name=name,
                description=description,
                kill_chain_phases=kill_chain_phases,
            )
        )

    logger.info(
        "Extracted %d detectable indicators from STIX bundle (%d total objects)",
        len(results),
        len(objects),
    )
    return results


# ---------------------------------------------------------------------------
# Step 2 — MITRE technique resolution
# ---------------------------------------------------------------------------


def _technique_ids_from_kill_chain(kill_chain_phases: Any) -> list[str]:
    """Extract ATT&CK technique IDs from STIX kill_chain_phases.

    STIX bundles from ATT&CK-aware CTI feeds often carry entries like::

        {"kill_chain_name": "mitre-attack", "phase_name": "t1071.001"}

    We surface those directly.  ATT&CK Navigator exports may also embed the
    technique id in ``phase_name`` in the form ``t<nnnn>`` or ``t<nnnn>.<nnn>``.

    Defensive: ``kill_chain_phases`` from a malformed indicator may not be a list
    of dicts (a bare string, a list of strings, …). Non-list input yields no IDs
    and non-dict / non-string-``phase_name`` items are skipped rather than raising
    AttributeError (which previously surfaced as an HTTP 500).
    """
    ids: list[str] = []
    if not isinstance(kill_chain_phases, list):
        return ids
    for phase in kill_chain_phases:
        if not isinstance(phase, dict):
            continue
        if phase.get("kill_chain_name") != "mitre-attack":
            continue
        phase_name = phase.get("phase_name", "")
        if not isinstance(phase_name, str):
            continue
        # phase_name may already be a technique-id (t1059.001) or a tactic
        # name (execution).  Technique IDs start with 't' followed by digits.
        if phase_name and phase_name[0].lower() == "t" and any(c.isdigit() for c in phase_name):
            ids.append(phase_name.upper())
    return ids


def _resolve_technique_ids(
    indicator: _ExtractedIndicator,
    *,
    mapper: Any | None,
) -> list[str]:
    """Return a deduplicated list of MITRE technique IDs for this indicator.

    Priority:
    1. Kill-chain phases from the STIX indicator itself (most authoritative).
    2. Keyword-based mapper suggestions derived from the indicator name,
       description, IOC type, and value.
    """
    ids: list[str] = _technique_ids_from_kill_chain(indicator.kill_chain_phases)

    if not ids and mapper is not None:
        combined = " ".join(
            [indicator.ioc_type, indicator.value, indicator.name, indicator.description]
        )
        suggestions = mapper.suggest_techniques(combined, max_results=3, min_confidence=0.5)
        ids = [s.technique_id for s in suggestions]

    # Deduplicate preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for t in ids:
        if t not in seen:
            seen.add(t)
            deduped.append(t)

    return deduped


# ---------------------------------------------------------------------------
# Step 3 — Sigma YAML generation
# ---------------------------------------------------------------------------

# Fixed RFC-4122 namespace UUID for BTagent Sigma rule ID derivation.
# All-hex, deterministic, stable across versions.
_SIGMA_NS = _uuid.UUID("a1b2c3d4-0000-5000-a000-bb7a9e000001")


def _rule_id_from_stix(stix_id: str) -> str:
    """Derive a deterministic RFC-4122 UUID from a STIX indicator id."""
    return str(_uuid.uuid5(_SIGMA_NS, stix_id))


_TACTIC_FOR_LOGSOURCE: dict[str, str] = {
    "network_connection": "command-and-control",
    "proxy": "command-and-control",
    "process_creation": "execution",
    "email": "initial-access",
}

_LEVEL_FOR_IOC_TYPE: dict[str, str] = {
    "ip": "high",
    "domain": "high",
    "url": "medium",
    "hash_md5": "high",
    "hash_sha1": "high",
    "hash_sha256": "critical",
    "cmdline": "high",
    "email": "medium",
}

# Short label used in rule title
_LABEL_FOR_IOC_TYPE: dict[str, str] = {
    "ip": "IP Address",
    "domain": "Domain Name",
    "url": "URL",
    "hash_md5": "MD5 Hash",
    "hash_sha1": "SHA-1 Hash",
    "hash_sha256": "SHA-256 Hash",
    "cmdline": "Command Line",
    "email": "Email Address",
}


def _build_detection_block(indicator: _ExtractedIndicator) -> dict[str, Any]:
    """Return a dict representing the Sigma ``detection:`` block for this indicator."""
    ioc_type = indicator.ioc_type
    value = indicator.value

    if ioc_type == "ip":
        return {
            "selection": {
                "DestinationIp": value,
            },
            "condition": "selection",
        }
    if ioc_type == "domain":
        return {
            "selection": {
                "cs-host|endswith": f".{value}" if not value.startswith(".") else value,
            },
            "selection_exact": {
                "cs-host": value,
            },
            "condition": "selection or selection_exact",
        }
    if ioc_type == "url":
        return {
            "selection": {
                "cs-uri|contains": value,
            },
            "condition": "selection",
        }
    if ioc_type in ("hash_md5", "hash_sha1", "hash_sha256"):
        hash_field_map = {
            "hash_md5": "Hashes|contains",
            "hash_sha1": "Hashes|contains",
            "hash_sha256": "Hashes|contains",
        }
        return {
            "selection": {
                hash_field_map[ioc_type]: value,
            },
            "condition": "selection",
        }
    if ioc_type == "cmdline":
        return {
            "selection": {
                "CommandLine|contains": value,
            },
            "condition": "selection",
        }
    if ioc_type == "email":
        return {
            "selection": {
                "SenderFromAddress|contains": value,
            },
            "condition": "selection",
        }
    # Fallback
    return {
        "selection": {
            "value|contains": value,
        },
        "condition": "selection",
    }


def _build_logsource(indicator: _ExtractedIndicator) -> dict[str, str]:
    """Return a Sigma ``logsource:`` block for this indicator type."""
    cat = indicator.logsource_category
    prod = indicator.logsource_product

    source: dict[str, str] = {}
    if cat:
        source["category"] = cat
    if prod:
        source["product"] = prod
    # Fallback — ensure at least one key is present
    if not source:
        source["category"] = "generic"
    return source


def _build_tags(technique_ids: list[str], tactic: str) -> list[str]:
    """Build Sigma tag list from MITRE technique IDs + tactic name."""
    tags: list[str] = []
    if tactic:
        tags.append(f"attack.{tactic}")
    for tid in technique_ids:
        normalized = tid.lower().replace(".", ".")
        tags.append(f"attack.{normalized}")
    return tags


def _build_references(technique_ids: list[str]) -> list[str]:
    """Build MITRE ATT&CK reference URLs from technique IDs."""
    refs: list[str] = []
    for tid in technique_ids:
        # Normalise: T1071.001 → T1071/001 in the ATT&CK URL
        url_path = tid.replace(".", "/")
        refs.append(f"https://attack.mitre.org/techniques/{url_path}/")
    return refs or ["https://attack.mitre.org/"]


def propose_sigma_rule(
    indicator: _ExtractedIndicator,
    technique_ids: list[str],
    *,
    generated_at: datetime | None = None,
) -> DetectionProposal:
    """Build a deterministic :class:`DetectionProposal` from one indicator.

    The generated Sigma YAML is deterministic: given the same ``indicator``
    and ``technique_ids``, the output is identical across invocations.  No
    random UUIDs or live timestamps appear inside the rule YAML itself.

    Parameters
    ----------
    indicator:
        Parsed STIX indicator (from :func:`extract_detectable_indicators`).
    technique_ids:
        MITRE ATT&CK technique IDs to attach as ``tags:`` (already resolved
        by :func:`_resolve_technique_ids`).
    generated_at:
        UTC timestamp for the ``DetectionProposal.generated_at`` field.
        Defaults to ``datetime.now(UTC)``.  Does NOT appear in the Sigma YAML.

    Returns
    -------
    DetectionProposal
        Fully populated proposal with ``state="proposed"``.
    """
    _generated_at = generated_at or datetime.now(UTC)

    ioc_type = indicator.ioc_type
    label = _LABEL_FOR_IOC_TYPE.get(ioc_type, ioc_type.replace("_", " ").title())
    tactic = _TACTIC_FOR_LOGSOURCE.get(indicator.logsource_category, "")
    level = _LEVEL_FOR_IOC_TYPE.get(ioc_type, "medium")

    title = f"CTI-Derived Detection: {label} IOC — {indicator.value[:60]}"

    rule_id = _rule_id_from_stix(indicator.stix_id)

    logsource = _build_logsource(indicator)
    detection = _build_detection_block(indicator)
    tags = _build_tags(technique_ids, tactic)
    references = _build_references(technique_ids)

    # Build the Sigma rule as a plain Python dict, then dump to YAML.
    # We use an explicit ordered representation to keep the schema stable.
    rule: dict[str, Any] = {
        "title": title,
        "id": rule_id,
        "status": "experimental",
        "description": (
            indicator.description
            or f"CTI-derived detection for {label} indicator: {indicator.value[:200]}. "
            f"Source: {indicator.stix_id}. Auto-generated by the BTagent "
            f"STIX→Sigma pipeline — review and approve before promoting to production."
        ),
        "references": references,
        "author": "BTagent CTI Pipeline (auto-generated, pending analyst review)",
        "date": "2026-06-22",
        "logsource": logsource,
        "detection": detection,
        "falsepositives": [
            "Legitimate traffic to the indicated host/address if it has been repurposed "
            "or if the CTI intelligence is stale.",
            "Shared hosting or CDN infrastructure where the malicious actor and "
            "legitimate services co-reside on the same IP.",
        ],
        "level": level,
        "tags": tags,
    }

    sigma_yaml = yaml.dump(
        rule,
        default_flow_style=False,
        sort_keys=False,
        allow_unicode=True,
        width=100,
    )

    # Proposal id: deterministic hash of the STIX id
    proposal_id = "prop_" + hashlib.sha256(indicator.stix_id.encode()).hexdigest()[:24]

    rationale = (
        f"STIX indicator '{indicator.name or indicator.stix_id}' "
        f"of type '{ioc_type}' with value '{indicator.value[:60]}' "
        f"maps to logsource.category='{indicator.logsource_category}'. "
        f"MITRE techniques: {', '.join(technique_ids) or 'none resolved'}."
    )

    return DetectionProposal(
        id=proposal_id,
        source_stix_id=indicator.stix_id,
        title=title,
        sigma_yaml=sigma_yaml,
        technique_ids=technique_ids,
        confidence=indicator.confidence,
        source_indicators=[
            f"[{indicator.ioc_type}:{indicator.value}]"
            if ":" not in indicator.value
            else indicator.value
        ],
        rationale=rationale,
        state="proposed",
        generated_at=_generated_at,
    )


# ---------------------------------------------------------------------------
# Step 4 — TLP gating
# ---------------------------------------------------------------------------

_TLP_MARKING_DEFS: dict[str, str] = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "white",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "green",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "amber",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "red",
}


def _bundle_has_red_marking(bundle: dict[str, Any]) -> bool:
    """Return True if any object in the bundle carries a TLP:RED marking ref."""
    objects = bundle.get("objects", [])
    red_ref = "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed"
    for obj in objects:
        if red_ref in obj.get("object_marking_refs", []):
            return True
    return False


# ---------------------------------------------------------------------------
# Step 5 — Orchestrator
# ---------------------------------------------------------------------------


def process_stix_bundle(
    bundle: dict[str, Any],
    active_tlp: TLP = TLP.GREEN,
) -> CTIToDetectionResponse:
    """Convert a STIX 2.1 bundle into a list of Sigma rule proposals.

    This is the main entry point for the STIX → Sigma pipeline.  It:

    1. Enforces TLP gating — raises :class:`TLPViolation` for TLP:RED bundles
       (identical policy to the existing STIX importer in
       ``stix_service.stix_bundle_from_iocs``).
    2. Extracts detectable indicators from the bundle.
    3. Resolves MITRE ATT&CK technique IDs via kill-chain phases and the
       keyword mapper.
    4. Generates a deterministic Sigma rule proposal for each indicator.

    Parameters
    ----------
    bundle:
        Raw STIX 2.1 bundle dict.
    active_tlp:
        The TLP context for this operation.  ``TLP.RED`` is refused.

    Returns
    -------
    CTIToDetectionResponse
        Proposals + skipped records.

    Raises
    ------
    TLPViolation
        If ``active_tlp`` is :attr:`TLP.RED` or any object in the bundle
        carries a TLP:RED marking reference.
    """
    # --- TLP gate (mirrors stix_bundle_from_iocs policy) ---
    assert_tlp_allows_egress(bundle, "stix_export", classification_ctx=active_tlp)

    if _bundle_has_red_marking(bundle):
        logger.error("TLP:RED marking found inside STIX bundle — refusing CTI detection pipeline")
        raise TLPViolation(TLP.RED, "egress:stix_export")

    # --- Lazy-import MITRE mapper (agents package may not be installed) ---
    mapper: Any | None = None
    try:
        from btagent_agents.mitre.mapper import MitreMapper  # type: ignore[import-untyped]

        mapper = MitreMapper()
    except ImportError:
        logger.debug("btagent_agents not available; MITRE keyword mapping disabled")

    # --- Extract indicators ---
    extracted = extract_detectable_indicators(bundle)

    proposals: list[DetectionProposal] = []
    skipped: list[SkippedIndicator] = []
    now = datetime.now(UTC)

    # --- Track already-seen raw patterns to avoid duplicates ---
    seen_values: set[str] = set()

    for indicator in extracted:
        # Codex #213: surface unsupported indicators as explicit SkippedIndicator
        # entries rather than dropping them silently.
        if isinstance(indicator, _UnsupportedIndicator):
            skipped.append(
                SkippedIndicator(
                    stix_id=indicator.stix_id,
                    pattern=indicator.pattern,
                    reason=(
                        f"Unsupported STIX pattern shape: {indicator.pattern[:200]} "
                        f"(not in _PATTERN_MAP — extend the parser to add support)."
                    ),
                )
            )
            continue
        dedup_key = f"{indicator.ioc_type}:{indicator.value}"
        if dedup_key in seen_values:
            skipped.append(
                SkippedIndicator(
                    stix_id=indicator.stix_id,
                    pattern=f"[{indicator.ioc_type}:value = '{indicator.value}']",
                    reason=f"Duplicate indicator value already proposed: {dedup_key}",
                )
            )
            continue
        seen_values.add(dedup_key)

        technique_ids = _resolve_technique_ids(indicator, mapper=mapper)

        proposal = propose_sigma_rule(indicator, technique_ids, generated_at=now)
        proposals.append(proposal)

    # --- Record indicators that couldn't be parsed (already skipped in extract) ---
    # We also record STIX objects that are not indicators
    for obj in bundle.get("objects", []):
        if obj.get("type") == "indicator":
            continue
        # Non-indicator STIX objects (attack-patterns, campaigns, etc.) are
        # informational — skip with a note
        skipped.append(
            SkippedIndicator(
                stix_id=obj.get("id", ""),
                pattern="",
                reason=f"Non-indicator STIX object type '{obj.get('type', 'unknown')}' "
                f"— not directly convertible to a detection rule in this slice.",
            )
        )

    logger.info(
        "CTI→Detection: %d proposals generated, %d items skipped from bundle",
        len(proposals),
        len(skipped),
    )

    return CTIToDetectionResponse(proposals=proposals, skipped=skipped)


# ---------------------------------------------------------------------------
# Unstructured CTI report → synthetic STIX bundle (#113 back half)
# ---------------------------------------------------------------------------
#
# CTI rarely arrives as clean STIX — it arrives as prose: vendor blog posts,
# ISAC advisories, incident write-ups, usually with defanged IOCs. This
# converter turns that prose into a *synthetic* STIX 2.1 bundle so the entire
# existing pipeline (TLP gate, dedup, technique resolution via the keyword
# mapper, Sigma generation, persistence, review, validation, PR compose)
# runs unchanged — extraction is a pre-processor, not a parallel pipeline.

import re as _re  # noqa: E402  (section-local import, matches file's late-import convention)

# Defang conventions seen in the wild, most specific first. Refanging is
# applied to a COPY used for extraction; the original text is never mutated.
_REFANG_RULES: list[tuple[str, str]] = [
    (r"hxxps://", "https://"),
    (r"hxxp://", "http://"),
    (r"\[\.\]", "."),
    (r"\(\.\)", "."),
    (r"\[dot\]", "."),
    (r"\(dot\)", "."),
    (r"\[at\]", "@"),
    (r"\(at\)", "@"),
    (r"\[:\]", ":"),
    (r"\[://\]", "://"),
]

# Extraction order matters: hashes longest-first so a SHA-256 is never
# double-counted as its embedded hex substrings (\b guards the boundaries),
# and URLs before domains so a domain inside an extracted URL is dropped.
_REPORT_IOC_PATTERNS: list[tuple[str, _re.Pattern[str]]] = [
    ("hash_sha256", _re.compile(r"\b[a-fA-F0-9]{64}\b")),
    ("hash_sha1", _re.compile(r"\b[a-fA-F0-9]{40}\b")),
    ("hash_md5", _re.compile(r"\b[a-fA-F0-9]{32}\b")),
    ("url", _re.compile(r"\bhttps?://[^\s\"'<>\)\]]+", _re.IGNORECASE)),
    ("email", _re.compile(r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")),
    ("ip", _re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")),
    (
        "domain",
        _re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"),
    ),
]

_IOC_TYPE_TO_STIX_PATH: dict[str, str] = {
    "ip": "ipv4-addr:value",
    "domain": "domain-name:value",
    "url": "url:value",
    "hash_md5": "file:hashes.'MD5'",
    "hash_sha1": "file:hashes.'SHA-1'",
    "hash_sha256": "file:hashes.'SHA-256'",
    "email": "email-addr:value",
}

# Private / loopback / link-local ranges: in report prose these are almost
# always the VICTIM's internal addressing, not an indicator worth a rule.
_NON_ROUTABLE_IP = _re.compile(
    r"^(?:10\.|127\.|169\.254\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|0\.|255\.)"
)

# Common file names / TLD-lookalikes that the bare-domain regex over-matches
# in prose ("update.exe", "index.php"). Anything whose final label is one of
# these is not a domain.
_NOT_TLDS = frozenset(
    {
        "exe",
        "dll",
        "bat",
        "ps1",
        "php",
        "asp",
        "aspx",
        "js",
        "vbs",
        "zip",
        "rar",
        "doc",
        "docx",
        "xls",
        "xlsx",
        "pdf",
        "txt",
        "log",
        "tmp",
        "dat",
        "bin",
        "sh",
        "py",
        "yml",
        "yaml",
        "json",
        "xml",
        "html",
        "htm",
        "local",
        "internal",
        "lan",
    }
)


def _refang(text: str) -> str:
    for pattern, replacement in _REFANG_RULES:
        text = _re.sub(pattern, replacement, text, flags=_re.IGNORECASE)
    return text


def _context_window(text: str, value: str, *, radius: int = 160) -> str:
    """Return the prose surrounding *value*'s first occurrence.

    This becomes the synthetic indicator's ``description``, which is exactly
    what :func:`_resolve_technique_ids` feeds the keyword mapper — so each
    proposal inherits the techniques the report describes AROUND its IOC,
    not a blanket technique list for the whole report.
    """
    idx = text.find(value)
    if idx < 0:
        return ""
    start = max(0, idx - radius)
    end = min(len(text), idx + len(value) + radius)
    return " ".join(text[start:end].split())


def stix_bundle_from_report_text(
    report_text: str,
    *,
    report_name: str = "",
) -> dict[str, Any]:
    """Build a synthetic STIX 2.1 bundle from unstructured CTI report text.

    Deterministic: the same text yields the same bundle id and indicator ids
    (UUIDv5 over the refanged value), so re-submitting a report upserts the
    same proposals instead of duplicating them — identical semantics to
    re-importing the same STIX bundle.

    Raises ``ValueError`` when no supported IOCs are found: an empty synthetic
    bundle would 200 with zero proposals, and "we found nothing to act on" is
    information the analyst must see, not swallow.
    """
    if not report_text or not report_text.strip():
        raise ValueError("report_text is empty")

    text = _refang(report_text)

    # Extract with de-dup and URL-shadowing (a domain that only appears inside
    # an extracted URL is the URL's host, not an independent indicator).
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    url_values: list[str] = []
    for ioc_type, pattern in _REPORT_IOC_PATTERNS:
        for match in pattern.finditer(text):
            value = match.group(0).rstrip(".,;")
            if ioc_type == "ip" and _NON_ROUTABLE_IP.match(value):
                continue
            if ioc_type == "domain":
                if value.rsplit(".", 1)[-1].lower() in _NOT_TLDS:
                    continue
                if any(value in url for url in url_values):
                    continue
                # The email regex ran earlier; an email's domain part is not
                # an independent indicator either.
                if any(value in v for t, v in found if t == "email"):
                    continue
            key = f"{ioc_type}:{value.lower()}"
            if key in seen:
                continue
            seen.add(key)
            found.append((ioc_type, value))
            if ioc_type == "url":
                url_values.append(value)

    if not found:
        raise ValueError(
            "No supported IOCs (IP / domain / URL / file hash / email) were found in "
            "the report text. Check that indicators are present (defanged forms like "
            "hxxp:// and [.] are handled)."
        )

    label = report_name.strip() or "unstructured CTI report"
    objects: list[dict[str, Any]] = []
    for ioc_type, value in found:
        stix_path = _IOC_TYPE_TO_STIX_PATH[ioc_type]
        escaped = value.replace("\\", "\\\\").replace("'", "\\'")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": f"indicator--{_uuid.uuid5(_uuid.NAMESPACE_URL, f'btagent-report:{ioc_type}:{value.lower()}')}",
                "name": f"{ioc_type} extracted from {label}",
                "description": _context_window(text, value),
                "pattern": f"[{stix_path} = '{escaped}']",
                "pattern_type": "stix",
                "valid_from": "1970-01-01T00:00:00Z",
            }
        )

    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    return {
        "type": "bundle",
        "id": f"bundle--{_uuid.uuid5(_uuid.NAMESPACE_URL, f'btagent-report:{digest}')}",
        "objects": objects,
    }


__all__ = [
    "extract_detectable_indicators",
    "process_stix_bundle",
    "propose_sigma_rule",
    "stix_bundle_from_report_text",
]
