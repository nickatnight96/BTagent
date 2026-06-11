"""Tests for hunt-pack directory loading (#112 transpile/execute core)."""

from __future__ import annotations

from pathlib import Path

import pytest
from btagent_shared.types.enums import Severity

from btagent_engine.hunting import (
    BUILTIN_PACKS_DIR,
    HuntPack,
    PackLoadError,
    load_builtin_pack,
    load_pack,
)
from btagent_engine.hunting.pack import extract_techniques

_MINIMAL_RULE = """\
title: Test Rule {n}
id: 00000000-0000-4000-8000-00000000000{n}
logsource:
  category: process_creation
  product: windows
detection:
  sel:
    Image|endswith: '\\\\evil{n}.exe'
  condition: sel
level: {level}
tags:
  - attack.execution
  - attack.t1059
"""


def _write_pack(tmp_path: Path, manifest: str, rules: dict[str, str]) -> Path:
    pack_dir = tmp_path / "pack"
    (pack_dir / "rules").mkdir(parents=True)
    (pack_dir / "pack.yaml").write_text(manifest)
    for name, body in rules.items():
        (pack_dir / "rules" / name).write_text(body)
    return pack_dir


# --- builtin example pack ---


def test_builtin_windows_baseline_pack_loads():
    pack = load_builtin_pack("windows_baseline")
    assert isinstance(pack, HuntPack)
    assert pack.id.startswith("hpack_")
    assert pack.name == "Windows Baseline Hunts"
    assert pack.version == "1.0.0"
    assert len(pack.rules) == 4
    assert all(r.enabled for r in pack.rules)

    by_file = {r.file: r for r in pack.rules}
    ps = by_file["encoded_powershell.yml"]
    assert ps.severity == Severity.HIGH
    assert ps.mitre_techniques == ["T1059.001", "T1027"]
    assert "Noisy" in ps.notes  # pack.yaml tuning note merged in
    assert "EncodedCommand" in ps.sigma_yaml  # raw YAML kept verbatim

    spray = by_file["failed_logon_spray.yml"]
    assert spray.mitre_techniques == ["T1110.003"]
    assert spray.logsource == {"product": "windows", "service": "security"}


def test_builtin_packs_dir_is_packaged():
    assert (BUILTIN_PACKS_DIR / "windows_baseline" / "pack.yaml").is_file()


# --- fixture-dir loading ---


def test_load_pack_from_fixture_dir(tmp_path):
    pack_dir = _write_pack(
        tmp_path,
        manifest=(
            "name: Fixture Pack\n"
            "version: 2.1.0\n"
            "description: test\n"
            "rules:\n"
            "  - file: a.yml\n"
            "    enabled: false\n"
            "    notes: too noisy in dev\n"
            "  - file: b.yml\n"
            "    mitre_techniques: [T9999]\n"
        ),
        rules={
            "a.yml": _MINIMAL_RULE.format(n=1, level="high"),
            "b.yml": _MINIMAL_RULE.format(n=2, level="informational"),
        },
    )
    pack = load_pack(pack_dir)

    assert pack.id.startswith("hpack_")  # generated when manifest omits it
    assert pack.name == "Fixture Pack"
    assert pack.version == "2.1.0"
    assert [r.file for r in pack.rules] == ["a.yml", "b.yml"]

    a, b = pack.rules
    assert a.enabled is False
    assert a.notes == "too noisy in dev"
    assert a.severity == Severity.HIGH
    assert a.mitre_techniques == ["T1059"]  # from attack.t* tags
    assert b.enabled is True
    assert b.severity == Severity.INFO
    assert b.mitre_techniques == ["T9999"]  # manifest override wins
    assert pack.enabled_rules == [b]


def test_load_pack_missing_manifest_raises(tmp_path):
    (tmp_path / "rules").mkdir()
    with pytest.raises(PackLoadError, match="pack.yaml"):
        load_pack(tmp_path)


def test_load_pack_no_rule_files_raises(tmp_path):
    pack_dir = tmp_path / "pack"
    (pack_dir / "rules").mkdir(parents=True)
    (pack_dir / "pack.yaml").write_text("name: empty\nversion: 1.0.0\n")
    with pytest.raises(PackLoadError, match="no rule files"):
        load_pack(pack_dir)


def test_load_pack_manifest_referencing_missing_rule_raises(tmp_path):
    pack_dir = _write_pack(
        tmp_path,
        manifest="name: p\nversion: 1.0.0\nrules:\n  - file: ghost.yml\n",
        rules={"a.yml": _MINIMAL_RULE.format(n=1, level="low")},
    )
    with pytest.raises(PackLoadError, match="ghost.yml"):
        load_pack(pack_dir)


def test_load_pack_unparseable_rule_yaml_raises(tmp_path):
    pack_dir = _write_pack(
        tmp_path,
        manifest="name: p\nversion: 1.0.0\n",
        rules={"bad.yml": "title: [unclosed\n"},
    )
    with pytest.raises(PackLoadError, match="bad.yml"):
        load_pack(pack_dir)


def test_load_pack_duplicate_rule_ids_raises(tmp_path):
    rule = _MINIMAL_RULE.format(n=1, level="low")
    pack_dir = _write_pack(
        tmp_path,
        manifest="name: p\nversion: 1.0.0\n",
        rules={"a.yml": rule, "b.yml": rule},
    )
    with pytest.raises(PackLoadError, match="duplicate rule ids"):
        load_pack(pack_dir)


# --- tag extraction ---


@pytest.mark.parametrize(
    ("tags", "expected"),
    [
        (["attack.execution", "attack.t1059.001"], ["T1059.001"]),
        (["attack.T1105"], ["T1105"]),
        (["attack.t1059", "attack.t1059"], ["T1059"]),
        (["cve.2021.44228", "detection.threat-hunting"], []),
        ([], []),
    ],
)
def test_extract_techniques(tags, expected):
    assert extract_techniques(tags) == expected


# --- deterministic IDs (Codex #198 P2) -------------------------------------


def test_load_pack_assigns_deterministic_ids_when_manifest_omits(tmp_path: Path) -> None:
    """A pack.yaml without ``id`` and a rule without ``id`` must yield the
    same pack/rule IDs across reloads — otherwise scheduled runs treat the
    same versioned pack as new entities every cycle, breaking persisted
    finding + noise-baseline correlation."""
    pack_dir = tmp_path / "stable_ids"
    (pack_dir / "rules").mkdir(parents=True)
    (pack_dir / "pack.yaml").write_text(
        "name: stable-ids\nversion: 1.0.0\nrules:\n  - file: r1.yml\n"
    )
    # Rule has no 'id' key — exercises the deterministic-rule-id branch.
    (pack_dir / "rules" / "r1.yml").write_text(
        "title: An anonymous rule\n"
        "logsource: {category: process_creation, product: windows}\n"
        "detection:\n"
        "  selection: {Image|endswith: 'powershell.exe'}\n"
        "  condition: selection\n"
        "level: medium\n"
    )

    a = load_pack(pack_dir)
    b = load_pack(pack_dir)

    assert a.id == b.id, "pack id must be stable across reloads"
    assert a.rules[0].id == b.rules[0].id, "rule id must be stable across reloads"
    assert a.id.startswith("hpack_")
    assert a.rules[0].id.startswith("hrule_")


def test_load_pack_deterministic_id_varies_by_version(tmp_path: Path) -> None:
    """Same name, different version → different pack id (so a re-versioned
    pack doesn't collide with its predecessor's persisted findings)."""

    def _make(version: str) -> Path:
        d = tmp_path / f"v{version.replace('.', '_')}"
        (d / "rules").mkdir(parents=True)
        (d / "pack.yaml").write_text(
            f"name: stable-ids\nversion: {version}\nrules:\n  - file: r1.yml\n"
        )
        (d / "rules" / "r1.yml").write_text(
            "title: r1\n"
            "logsource: {category: process_creation, product: windows}\n"
            "detection:\n"
            "  selection: {Image|endswith: 'cmd.exe'}\n"
            "  condition: selection\n"
        )
        return d

    p1 = load_pack(_make("1.0.0"))
    p2 = load_pack(_make("2.0.0"))
    assert p1.id != p2.id
