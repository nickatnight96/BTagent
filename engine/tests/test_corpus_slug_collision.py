"""Corpus import must not silently drop rules on filename collision.

Regression cover for the 2026-07 review finding: ``_rule_slug`` folded the
nested corpus path into a flat filename but then truncated it, so two rules
whose paths agreed on a long prefix produced the same filename. The second
overwrote the first at install time, the manifest (keyed by filename) still
validated, and the import reported both as installed — an invisible loss of
detection coverage on exactly the large corpora the feature targets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from btagent_engine.hunting.corpus import _rule_slug, import_sigma_corpus, write_pack_dir
from btagent_engine.hunting.pack import load_pack

# A realistic SigmaHQ-shaped directory. The prefix alone eats 31 characters.
_DEEP = "rules/windows/process_creation"

_RULE_TEMPLATE = """\
title: {title}
id: {rule_id}
status: test
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\{binary}.exe'
    condition: selection
level: medium
"""


def _write_rule(root: Path, rel: str, rule_id: str, title: str, binary: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _RULE_TEMPLATE.format(rule_id=rule_id, title=title, binary=binary),
        encoding="utf-8",
    )


def test_long_sibling_paths_do_not_collide_on_slug() -> None:
    """Two long paths sharing a prefix must produce distinct filenames."""
    shared = "suspicious_execution_of_a_very_long_and_descriptive_rule_name"
    a = Path(f"windows/process_creation/{shared}_variant_alpha.yml")
    b = Path(f"windows/process_creation/{shared}_variant_bravo.yml")

    assert _rule_slug(a) != _rule_slug(b)


def test_slug_stays_within_the_filename_budget() -> None:
    deep = Path("windows/process_creation/" + ("x" * 400) + ".yml")
    slug = _rule_slug(deep)
    assert len(slug) <= 124  # 120 budget + ".yml"


def test_every_imported_rule_survives_install(tmp_path: Path) -> None:
    """The reported install count must equal what the pack loader reads back."""
    corpus = tmp_path / "sigma"
    shared = "suspicious_execution_of_a_very_long_and_descriptive_rule_name"
    _write_rule(
        corpus,
        f"{_DEEP}/{shared}_variant_alpha.yml",
        "11111111-1111-4111-8111-111111111111",
        "Variant Alpha",
        "alpha",
    )
    _write_rule(
        corpus,
        f"{_DEEP}/{shared}_variant_bravo.yml",
        "22222222-2222-4222-8222-222222222222",
        "Variant Bravo",
        "bravo",
    )

    result = import_sigma_corpus(corpus, name="collision-check")
    assert len(result.pack.rules) == 2, "both rules should parse"
    assert not result.skipped, f"nothing should be skipped: {result.skipped}"

    dest = write_pack_dir(result, tmp_path / "installed")
    loaded = load_pack(dest)

    # The bug: this read back 1 while the import reported 2, with no skip entry.
    assert len(loaded.rules) == len(result.pack.rules)
    assert {r.id for r in loaded.rules} == {
        "11111111-1111-4111-8111-111111111111",
        "22222222-2222-4222-8222-222222222222",
    }


def test_install_refuses_rather_than_overwriting_on_duplicate_file_name(
    tmp_path: Path,
) -> None:
    """Defence in depth: if a collision ever recurs, fail loudly, never silently."""
    corpus = tmp_path / "sigma"
    _write_rule(
        corpus,
        f"{_DEEP}/alpha.yml",
        "33333333-3333-4333-8333-333333333333",
        "Alpha",
        "alpha",
    )
    _write_rule(
        corpus,
        f"{_DEEP}/bravo.yml",
        "44444444-4444-4444-8444-444444444444",
        "Bravo",
        "bravo",
    )
    result = import_sigma_corpus(corpus, name="forced-collision")
    assert len(result.pack.rules) == 2

    # Force the pathological case the slug fix now prevents.
    object.__setattr__(result.pack.rules[1], "file", result.pack.rules[0].file)

    with pytest.raises(Exception, match="same file name"):
        write_pack_dir(result, tmp_path / "installed")
