"""Tests for the Wave-D builtin hunt packs (#100/#112 content authoring).

Ten new packs added in Wave D, covering cloud control-plane attack families
(exfiltration, detection-evasion, lateral movement, enumeration, credential
access, supply-chain), Kubernetes (workload + cluster-attack), Windows
living-off-the-land, and non-AWS multi-cloud compute.

These assert the same invariants the existing builtin-pack tests assert for
``windows_baseline`` / ``cloud_control_plane``:
- the pack loads via ``load_builtin_pack`` (bare-basename ``file:`` discovery),
- the expected rule / enabled counts,
- every rule carries MITRE techniques derived from its ``attack.t*`` tags,
- no ``.py`` detector leaks into the Sigma ``rules:`` list,
- every rule transpiles on the three non-Windows-pipeline backends
  (splunk / elastic / crowdstrike). The Sentinel/Kusto pipeline targets
  Windows XDR tables, so it is only required for the Windows LotL pack and is
  treated as best-effort for the cloud/k8s packs (matching the
  ``cloud_control_plane`` precedent).
"""

from __future__ import annotations

import pytest

from btagent_engine.hunting import BUILTIN_PACKS_DIR, HuntPack, load_builtin_pack
from btagent_engine.hunting.transpile import SigmaTranspileError, transpile

# Backends every rule must transpile to. Sentinel/Kusto is excluded here because
# its pipeline maps Windows XDR tables and cannot resolve a table for AWS
# CloudTrail / GCP / Azure / Kubernetes-audit logsources — the same limitation
# the cloud_control_plane pack already tolerates.
_REQUIRED_BACKENDS = ("splunk", "elastic", "crowdstrike")

# (pack name, total rule count, enabled rule count)
_WAVE_D_PACKS: list[tuple[str, int, int]] = [
    ("data_exfiltration_cloud", 5, 5),
    ("detection_evasion_cloud", 5, 4),  # guardduty_detector_disabled is deferred
    ("lateral_movement_cloud", 5, 5),
    ("enumeration_reconnaissance", 4, 4),
    ("credential_access_cloud", 5, 5),
    ("supply_chain_cloud", 4, 4),
    ("container_kubernetes", 5, 5),
    ("kubernetes_cluster_attack", 5, 5),
    ("windows_lotl_behavioral", 6, 6),
    ("multi_cloud_compute", 5, 5),
]

_WAVE_D_NAMES = [p[0] for p in _WAVE_D_PACKS]


@pytest.mark.parametrize(("name", "n_rules", "n_enabled"), _WAVE_D_PACKS)
def test_wave_d_pack_loads_with_expected_counts(name: str, n_rules: int, n_enabled: int) -> None:
    pack = load_builtin_pack(name)
    assert isinstance(pack, HuntPack)
    assert pack.id.startswith("hpack_")
    assert pack.version == "1.0.0"
    assert pack.name  # non-empty human label
    assert len(pack.rules) == n_rules
    assert len(pack.enabled_rules) == n_enabled


@pytest.mark.parametrize("name", _WAVE_D_NAMES)
def test_wave_d_pack_dir_is_packaged(name: str) -> None:
    assert (BUILTIN_PACKS_DIR / name / "pack.yaml").is_file()
    assert (BUILTIN_PACKS_DIR / name / "__init__.py").is_file()
    assert (BUILTIN_PACKS_DIR / name / "rules").is_dir()


@pytest.mark.parametrize("name", _WAVE_D_NAMES)
def test_wave_d_rules_are_sigma_only(name: str) -> None:
    """The Sigma ``rules:`` list must contain no ``.py`` detector modules."""
    pack = load_builtin_pack(name)
    assert pack.rules, f"{name} loaded zero rules"
    assert not any(str(r.file).endswith(".py") for r in pack.rules)


@pytest.mark.parametrize("name", _WAVE_D_NAMES)
def test_wave_d_rules_have_mitre_techniques(name: str) -> None:
    """Every rule derives at least one ATT&CK technique from its tags."""
    pack = load_builtin_pack(name)
    for rule in pack.rules:
        assert rule.mitre_techniques, f"{name}:{rule.file} has no MITRE techniques"
        # technique ids are normalised to the T#### / T####.### form
        for tid in rule.mitre_techniques:
            assert tid.startswith("T") and tid[1:5].isdigit(), f"{name}:{rule.file} bad tid {tid}"


@pytest.mark.parametrize("name", _WAVE_D_NAMES)
def test_wave_d_rules_transpile_on_required_backends(name: str) -> None:
    """Every rule (enabled or not) transpiles on splunk/elastic/crowdstrike.

    A disabled rule is still a valid pack member, so we transpile all of them.
    """
    pack = load_builtin_pack(name)
    for rule in pack.rules:
        for backend in _REQUIRED_BACKENDS:
            try:
                query = transpile(rule.sigma_yaml, backend)
            except SigmaTranspileError as exc:  # pragma: no cover - failure path
                pytest.fail(f"{name}:{rule.file} failed to transpile on {backend}: {exc}")
            assert query, f"{name}:{rule.file} produced an empty {backend} query"


def test_wave_d_windows_lotl_transpiles_on_sentinel() -> None:
    """The Windows LotL pack targets process_creation telemetry, so the
    Sentinel/Kusto (Windows XDR) pipeline must also resolve a table for it —
    unlike the cloud packs."""
    pack = load_builtin_pack("windows_lotl_behavioral")
    for rule in pack.rules:
        query = transpile(rule.sigma_yaml, "sentinel")
        assert query, f"windows_lotl:{rule.file} produced an empty sentinel query"


def test_wave_d_rule_ids_are_globally_unique() -> None:
    """No two rules across the Wave-D packs (or vs. existing builtin packs)
    share a Sigma UUID — a collision would make findings ambiguous."""
    import yaml

    seen: dict[str, str] = {}
    existing_packs = ["windows_baseline", "cloud_control_plane", "identity", "agentic_misuse"]
    for name in existing_packs + _WAVE_D_NAMES:
        pack = load_builtin_pack(name)
        for rule in pack.rules:
            rid = yaml.safe_load(rule.sigma_yaml).get("id")
            assert rid, f"{name}:{rule.file} missing a rule id"
            assert rid not in seen, f"duplicate rule id {rid}: {seen.get(rid)} vs {name}:{rule.file}"
            seen[rid] = f"{name}:{rule.file}"
