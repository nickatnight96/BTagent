"""Hunt pack model + directory loader (#112 Hunt Pack Runner, transpile/execute core).

A *hunt pack* is a versioned bundle of Sigma rules. On disk a pack is a
directory:

.. code-block:: text

    packs/<pack>/
        pack.yaml          # manifest: id / name / version + per-rule metadata
        rules/*.yml        # one canonical SigmaHQ-style rule per file

``pack.yaml`` shape::

    id: hpack_01JX...        # optional; generated when omitted
    name: Windows Baseline
    version: 1.0.0
    description: ...
    rules:                   # optional per-rule metadata, keyed by filename
      - file: encoded_powershell.yml
        enabled: true
        notes: "Noisy where CI bootstraps via -enc; tune on runner host prefix."
        mitre_techniques: [T1059.001]   # optional override of the rule's tags

Rule files not listed under ``rules:`` are still loaded with defaults
(enabled, no notes, techniques derived from the rule's ``attack.t*`` tags).

This mirrors the shared #112 contract (:mod:`btagent_shared.types.huntpack`)
but is the engine-portable form: the engine pack carries the *raw* Sigma YAML
plus tuning metadata only — compiled backend queries and noise baselines are
runtime state owned by the runner / integration layer, not the pack bundle.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml
from btagent_shared.types.enums import Severity
from btagent_shared.utils.ids import generate_id
from pydantic import BaseModel, ConfigDict, Field

# ``attack.t1059`` / ``attack.t1059.001`` style SigmaHQ tags -> technique ids.
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)

# Sigma ``level`` -> BTagent Severity. Unknown / missing levels default to
# MEDIUM so an untagged community rule never lands as silently-critical.
_LEVEL_TO_SEVERITY: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}


class PackLoadError(ValueError):
    """A pack directory is missing, malformed, or internally inconsistent."""


class HuntPackRule(BaseModel):
    """One Sigma rule in a pack: raw YAML + tuning metadata.

    ``sigma_yaml`` is kept verbatim — the transpiler is the only component
    that interprets it, so a rule that fails to transpile on one backend is
    still a valid pack member (the runner records the error per-backend).
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, description="Sigma rule id (UUID) or generated hrule_ ULID.")
    title: str = Field(..., min_length=1, max_length=300)
    file: str | None = Field(default=None, description="Source filename within rules/.")
    sigma_yaml: str = Field(..., min_length=1, description="Raw canonical Sigma rule YAML.")
    logsource: dict[str, str] = Field(
        default_factory=dict,
        description="The rule's Sigma logsource (category/product/service), used by "
        "the runner to pick e.g. an Elastic index pattern.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="ATT&CK technique ids (T1059.001 style), from attack.t* tags "
        "unless overridden in pack.yaml.",
    )
    severity: Severity = Field(
        default=Severity.MEDIUM, description="Derived from the Sigma rule's level."
    )
    enabled: bool = True
    notes: str = Field(default="", description="Analyst noise / tuning notes for this rule.")


class HuntPack(BaseModel):
    """A versioned bundle of Sigma hunt rules."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(..., min_length=1, max_length=200)
    name: str = Field(..., min_length=1, max_length=200)
    version: str = Field(..., min_length=1, max_length=64)
    description: str = ""
    rules: list[HuntPackRule] = Field(default_factory=list)

    @property
    def enabled_rules(self) -> list[HuntPackRule]:
        return [r for r in self.rules if r.enabled]


# Packs shipped with the engine (e.g. ``windows_baseline``).
BUILTIN_PACKS_DIR = Path(__file__).resolve().parent / "packs"


def extract_techniques(tags: list[Any]) -> list[str]:
    """Pull ATT&CK technique ids out of SigmaHQ ``attack.t*`` tags."""
    techniques: list[str] = []
    for tag in tags:
        if not isinstance(tag, str):
            continue
        match = _ATTACK_TAG_RE.match(tag.strip())
        if match:
            technique = match.group(1).upper()
            if technique not in techniques:
                techniques.append(technique)
    return techniques


def _parse_rule_file(path: Path) -> tuple[dict[str, Any], str]:
    """Load one Sigma rule file -> (parsed mapping, raw yaml text)."""
    raw = path.read_text(encoding="utf-8")
    try:
        parsed = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        raise PackLoadError(f"rule file {path.name!r} is not valid YAML: {exc}") from exc
    if not isinstance(parsed, dict):
        raise PackLoadError(f"rule file {path.name!r} must contain a YAML mapping")
    if not str(parsed.get("title") or "").strip():
        raise PackLoadError(f"rule file {path.name!r} has no 'title'")
    return parsed, raw


def _rule_from_file(path: Path, meta: dict[str, Any]) -> HuntPackRule:
    parsed, raw = _parse_rule_file(path)

    logsource_raw = parsed.get("logsource") or {}
    logsource = (
        {str(k): str(v) for k, v in logsource_raw.items()}
        if isinstance(logsource_raw, dict)
        else {}
    )

    tags = parsed.get("tags") or []
    techniques = meta.get("mitre_techniques") or extract_techniques(
        tags if isinstance(tags, list) else []
    )

    level = str(parsed.get("level") or "").strip().lower()

    return HuntPackRule(
        id=str(parsed.get("id") or generate_id("hrule")),
        title=str(parsed["title"]),
        file=path.name,
        sigma_yaml=raw,
        logsource=logsource,
        mitre_techniques=list(techniques),
        severity=_LEVEL_TO_SEVERITY.get(level, Severity.MEDIUM),
        enabled=bool(meta.get("enabled", True)),
        notes=str(meta.get("notes") or ""),
    )


def load_pack(pack_dir: Path | str) -> HuntPack:
    """Load a hunt pack from a ``pack.yaml`` + ``rules/*.yml`` directory.

    Raises :class:`PackLoadError` on a missing/malformed manifest, an
    unparseable rule file, a ``rules:`` entry pointing at a file that does
    not exist, or duplicate rule ids. Load-time strictness is deliberate:
    a pack either loads whole or not at all — *transpile/execution* failures
    are the per-rule, per-backend concern of the runner instead.
    """
    pack_dir = Path(pack_dir)
    manifest_path = pack_dir / "pack.yaml"
    if not manifest_path.is_file():
        raise PackLoadError(f"no pack.yaml in {pack_dir}")

    try:
        manifest = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise PackLoadError(f"pack.yaml is not valid YAML: {exc}") from exc
    if not isinstance(manifest, dict):
        raise PackLoadError("pack.yaml must contain a YAML mapping")

    meta_by_file: dict[str, dict[str, Any]] = {}
    for entry in manifest.get("rules") or []:
        if not isinstance(entry, dict) or not entry.get("file"):
            raise PackLoadError("each pack.yaml rules entry must be a mapping with a 'file' key")
        meta_by_file[str(entry["file"])] = entry

    rules_dir = pack_dir / "rules"
    rule_paths = sorted(
        p
        for p in ([] if not rules_dir.is_dir() else rules_dir.iterdir())
        if p.suffix in (".yml", ".yaml") and p.is_file()
    )
    if not rule_paths:
        raise PackLoadError(f"no rule files under {rules_dir}")

    missing = sorted(set(meta_by_file) - {p.name for p in rule_paths})
    if missing:
        raise PackLoadError(f"pack.yaml references missing rule files: {missing}")

    rules = [_rule_from_file(path, meta_by_file.get(path.name, {})) for path in rule_paths]

    seen: set[str] = set()
    dupes = sorted({r.id for r in rules if r.id in seen or seen.add(r.id)})  # type: ignore[func-returns-value]
    if dupes:
        raise PackLoadError(f"duplicate rule ids in pack: {dupes}")

    try:
        return HuntPack(
            id=str(manifest.get("id") or generate_id("hpack")),
            name=str(manifest.get("name") or pack_dir.name),
            version=str(manifest.get("version") or "0.0.0"),
            description=str(manifest.get("description") or ""),
            rules=rules,
        )
    except ValueError as exc:  # pydantic ValidationError is a ValueError
        raise PackLoadError(f"invalid pack manifest: {exc}") from exc


def load_builtin_pack(name: str) -> HuntPack:
    """Load one of the packs shipped under ``btagent_engine/hunting/packs/``."""
    return load_pack(BUILTIN_PACKS_DIR / name)
