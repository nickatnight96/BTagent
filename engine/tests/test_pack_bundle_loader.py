"""Tests for ``load_pack_from_bundle`` (#112 org-custom packs, slice 1).

The whole point of the bundle loader is that it is the SAME loader as the
directory path — a pack uploaded by an org must pass exactly the checks a
builtin passes and keep identical deterministic ids for identical content
(the noise baseline and run history correlate on those ids, Codex #198).
The equivalence test against a real shipped pack pins that; the rest covers
the bundle-specific edge (untrusted filenames) and the shared error paths.
"""

from __future__ import annotations

import pytest

from btagent_engine.hunting import BUILTIN_PACKS_DIR, load_pack, load_pack_from_bundle
from btagent_engine.hunting.pack import PackLoadError

MANIFEST = """\
name: Org Custom Pack
version: 1.2.3
description: Uploaded by an org.
rules:
  - file: encoded_ps.yml
    enabled: true
    notes: tuned for runner hosts
"""

RULE = """\
title: Encoded PowerShell
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: "-enc"
  condition: selection
level: high
tags:
  - attack.t1059.001
"""


def test_bundle_equivalent_to_directory_loader_on_shipped_pack():
    """Round-tripping a real builtin pack through the bundle form must yield
    the identical pack — same id, same rule ids, same content."""
    pack_dir = BUILTIN_PACKS_DIR / "windows_baseline"
    from_dir = load_pack(pack_dir)

    manifest_yaml = (pack_dir / "pack.yaml").read_text(encoding="utf-8")
    rule_files = {
        p.name: p.read_text(encoding="utf-8")
        for p in (pack_dir / "rules").iterdir()
        if p.suffix in (".yml", ".yaml")
    }
    from_bundle = load_pack_from_bundle(manifest_yaml, rule_files)

    assert from_bundle.id == from_dir.id
    assert from_bundle.version == from_dir.version
    assert [r.id for r in from_bundle.rules] == [r.id for r in from_dir.rules]
    assert [r.sigma_yaml for r in from_bundle.rules] == [r.sigma_yaml for r in from_dir.rules]


def test_bundle_happy_path_carries_manifest_meta():
    pack = load_pack_from_bundle(MANIFEST, {"encoded_ps.yml": RULE})

    assert pack.name == "Org Custom Pack"
    assert pack.version == "1.2.3"
    assert len(pack.rules) == 1
    rule = pack.rules[0]
    assert rule.title == "Encoded PowerShell"
    assert rule.notes == "tuned for runner hosts"
    assert rule.mitre_techniques == ["T1059.001"]
    # Deterministic ids: same content -> same ids on a re-load.
    again = load_pack_from_bundle(MANIFEST, {"encoded_ps.yml": RULE})
    assert again.id == pack.id
    assert again.rules[0].id == rule.id


@pytest.mark.parametrize(
    "filename",
    ["../escape.yml", "rules/nested.yml", "sneaky\\win.yml", ".hidden.yml", "notyaml.txt", ""],
)
def test_bundle_rejects_untrusted_filenames(filename):
    """Bundle filenames arrive from an upload, not a directory listing —
    anything that is not a plain *.yml/*.yaml name is refused up front."""
    with pytest.raises(PackLoadError, match="invalid rule filename"):
        load_pack_from_bundle(MANIFEST, {filename: RULE})


def test_bundle_manifest_must_be_yaml_mapping():
    with pytest.raises(PackLoadError, match="pack.yaml"):
        load_pack_from_bundle("- just\n- a\n- list\n", {"encoded_ps.yml": RULE})
    with pytest.raises(PackLoadError, match="not valid YAML"):
        load_pack_from_bundle("{unclosed", {"encoded_ps.yml": RULE})


def test_bundle_requires_rule_files():
    with pytest.raises(PackLoadError, match="no rule files"):
        load_pack_from_bundle(MANIFEST, {})


def test_bundle_manifest_referencing_missing_rule_raises():
    with pytest.raises(PackLoadError, match="missing rule files"):
        load_pack_from_bundle(MANIFEST, {"other.yml": RULE})


def test_bundle_rule_without_title_raises():
    with pytest.raises(PackLoadError, match="has no 'title'"):
        load_pack_from_bundle(
            "name: p\nversion: '1'\nrules:\n  - file: r.yml\n",
            {"r.yml": "detection:\n  condition: selection\n"},
        )


def test_bundle_duplicate_rule_ids_raise():
    ruled = "title: A\nid: hrule_same\ndetection:\n  condition: sel\n"
    with pytest.raises(PackLoadError, match="duplicate rule ids"):
        load_pack_from_bundle(
            "name: p\nversion: '1'\nrules:\n  - file: a.yml\n  - file: b.yml\n",
            {"a.yml": ruled, "b.yml": ruled},
        )
