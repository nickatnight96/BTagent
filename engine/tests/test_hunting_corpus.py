"""External Sigma corpus import + transpile-coverage measurement (#112).

Two things are pinned here:

1. **Import discipline** — a community corpus contains rules this platform
   cannot use. The importer must skip each of them *with a reason* and install
   the rest, never abort. Every skip stage has a dedicated fixture file in
   ``fixtures/sigmahq_sample`` (see its README).
2. **Transpile coverage** — the per-backend success rate over the vendored
   sample, asserted against explicit floors so a pySigma/pipeline regression
   (or a change to our rule handling) that quietly halves coverage fails the
   build instead of shipping.

Zero egress: the corpus is **committed**, never downloaded. Fetching the full
~1000-rule SigmaHQ catalog at build/run time is deliberately out of scope.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from btagent_engine.hunting import SUPPORTED_BACKENDS, load_pack
from btagent_engine.hunting.corpus import (
    import_sigma_corpus,
    iter_sigma_rule_files,
    slugify,
    transpile_coverage,
    write_pack_dir,
)
from btagent_engine.hunting.pack import PackLoadError

CORPUS = Path(__file__).parent / "fixtures" / "sigmahq_sample"

# Per-backend floors for the vendored sample. Measured rates at the time of
# writing: splunk/elastic/crowdstrike 10/11 (90.9%), sentinel 9/11 (81.8% — the
# DNS rule has no Advanced Hunting table mapping). Floors sit just under the
# measured values so normal upstream drift doesn't flap the suite, but a real
# regression — a backend dropping to "expresses half the corpus" — trips it.
COVERAGE_FLOORS: dict[str, float] = {
    "splunk": 0.85,
    "sentinel": 0.75,
    "elastic": 0.85,
    "crowdstrike": 0.85,
}

# The bar the #112 plan commits to: "sigma transpile goldens (≥80% of sample
# SigmaHQ set × 4 backends)". Measured aggregate at the time of writing: 39/44
# = 88.6%.
AGGREGATE_FLOOR = 0.80

# Rule files in the fixture corpus that must NOT survive an import, and why.
EXPECTED_SKIPS = {
    "proc_creation_win_broken_yaml.yml": "parse",
    "proc_creation_win_missing_title.yml": "parse",
    "proc_creation_win_pipe_aggregation.yml": "transpile",
    "proc_creation_win_certutil_encode_copy.yml": "duplicate",
}


@pytest.fixture(scope="module")
def imported():
    """One import of the vendored corpus, shared by the module (pySigma is slow)."""
    return import_sigma_corpus(CORPUS, name="SigmaHQ Sample", version="2026.07")


# --------------------------------------------------------------------------- #
# Walking a SigmaHQ-layout tree
# --------------------------------------------------------------------------- #


def test_walker_finds_nested_rule_trees_and_prunes_deprecated():
    files = [p.relative_to(CORPUS).as_posix() for p in iter_sigma_rule_files(CORPUS)]

    # Nested category dirs under rules/ and the sibling threat-hunting tree.
    assert "rules/windows/process_creation/proc_creation_win_certutil_encode.yml" in files
    assert "rules/linux/process_creation/proc_creation_lnx_curl_pipe_shell.yml" in files
    assert (
        "rules-threat-hunting/windows/process_creation/proc_creation_win_msbuild_susp_parent.yml"
        in files
    )
    # SigmaHQ's graveyard is pruned.
    assert not any(f.startswith("deprecated/") for f in files)


def test_walker_rejects_a_non_directory(tmp_path):
    missing = tmp_path / "nope"
    with pytest.raises(PackLoadError):
        iter_sigma_rule_files(missing)


def test_walker_handles_a_flat_rule_directory(tmp_path):
    """ "An external Sigma rule directory" may be flat, not a SigmaHQ tree."""
    (tmp_path / "a.yml").write_text("title: A\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("not a rule", encoding="utf-8")
    assert [p.name for p in iter_sigma_rule_files(tmp_path)] == ["a.yml"]


# --------------------------------------------------------------------------- #
# Skip-with-reason, install the rest
# --------------------------------------------------------------------------- #


def test_import_installs_the_good_rules_and_skips_the_rest_with_reasons(imported):
    assert imported.scanned == 14  # deprecated/ pruned, everything else scanned
    assert imported.installed == 10
    assert len(imported.skipped) == 4

    by_file = {Path(s.file).name: s for s in imported.skipped}
    assert set(by_file) == set(EXPECTED_SKIPS)
    for filename, stage in EXPECTED_SKIPS.items():
        skip = by_file[filename]
        assert skip.stage == stage, f"{filename} skipped at {skip.stage}, expected {stage}"
        # A reason an operator can act on, not an empty string.
        assert skip.reason.strip()

    assert imported.skip_reasons() == {"parse": 2, "transpile": 1, "duplicate": 1}


def test_skip_reasons_name_the_actual_cause(imported):
    by_file = {Path(s.file).name: s for s in imported.skipped}
    assert "not valid YAML" in by_file["proc_creation_win_broken_yaml.yml"].reason
    assert "no 'title'" in by_file["proc_creation_win_missing_title.yml"].reason
    assert "already imported" in by_file["proc_creation_win_certutil_encode_copy.yml"].reason
    transpile_skip = by_file["proc_creation_win_pipe_aggregation.yml"]
    assert "no supported backend" in transpile_skip.reason
    # Names each backend's complaint so the operator can tell "unsupported
    # everywhere" from "our pipeline is broken".
    for backend in SUPPORTED_BACKENDS:
        assert backend in transpile_skip.reason


def test_a_bad_rule_never_aborts_the_import(imported):
    """The four broken fixtures sit *between* good rules in walk order."""
    titles = {r.title for r in imported.pack.rules}
    assert "Suspicious Certutil Encode Command" in titles
    assert "Whoami Execution For Local Discovery" in titles
    assert "Curl Piped Directly Into A Shell" in titles
    assert "MSBuild Spawned By A Script Interpreter" in titles


def test_imported_rules_keep_sigma_identity_and_metadata(imported):
    rule = next(r for r in imported.pack.rules if r.title == "Shadow Copy Deletion Via WMIC")
    assert rule.id == "1f0a55c8-8e37-4f6a-bd41-5a3d9e2b7c04"  # the Sigma UUID, not a new one
    assert rule.mitre_techniques == ["T1490"]
    assert rule.severity.value == "critical"
    assert rule.logsource == {"category": "process_creation", "product": "windows"}
    assert "shadowcopy" in rule.sigma_yaml  # raw YAML kept verbatim


def test_nested_paths_are_flattened_without_collisions(imported):
    files = [r.file for r in imported.pack.rules]
    assert len(files) == len(set(files))
    assert "rules_windows_process_creation_proc_creation_win_certutil_encode.yml" in files


def test_duplicate_ids_are_dropped_so_the_pack_stays_loadable(imported):
    ids = [r.id for r in imported.pack.rules]
    assert len(ids) == len(set(ids))


def test_pack_id_is_deterministic_across_imports():
    a = import_sigma_corpus(CORPUS, name="Same", version="1.0.0", check_transpile=False)
    b = import_sigma_corpus(CORPUS, name="Same", version="1.0.0", check_transpile=False)
    assert a.pack.id == b.pack.id
    other = import_sigma_corpus(CORPUS, name="Same", version="2.0.0", check_transpile=False)
    assert other.pack.id != a.pack.id


def test_parse_only_import_keeps_untranspilable_rules():
    """``check_transpile=False`` is the cheap path — no pySigma, no skips."""
    result = import_sigma_corpus(CORPUS, check_transpile=False)
    assert result.installed == 11  # the pipe-aggregation rule survives
    assert {s.stage for s in result.skipped} == {"parse", "duplicate"}
    assert result.transpiled == []


def test_max_rules_caps_the_import():
    result = import_sigma_corpus(CORPUS, max_rules=3, check_transpile=False)
    assert result.scanned == 3


# --------------------------------------------------------------------------- #
# Transpile coverage — the anti-regression metric
# --------------------------------------------------------------------------- #


def test_transpile_rate_per_backend_meets_its_floor(imported):
    coverage = imported.coverage()
    assert set(coverage) == set(SUPPORTED_BACKENDS)

    measured = {b: round(c.rate, 3) for b, c in coverage.items()}
    for backend, floor in COVERAGE_FLOORS.items():
        cov = coverage[backend]
        assert cov.total == 11, "coverage denominator = rules that parsed"
        assert cov.rate >= floor, (
            f"{backend} transpile coverage regressed to {cov.rate:.2%} "
            f"(floor {floor:.0%}); measured across backends: {measured}"
        )


def test_aggregate_transpile_rate_meets_the_documented_bar(imported):
    """``rules × backends`` success rate — the #112 plan's ≥80% commitment."""
    coverage = imported.coverage()
    ok = sum(c.ok for c in coverage.values())
    total = sum(c.total for c in coverage.values())
    rate = ok / total
    assert rate >= AGGREGATE_FLOOR, (
        f"aggregate transpile coverage {rate:.2%} ({ok}/{total}) fell below "
        f"{AGGREGATE_FLOOR:.0%}: {[(b, c.ok, c.total) for b, c in coverage.items()]}"
    )


def test_every_installed_rule_transpiles_somewhere(imported):
    """The install contract: a rule no backend can express is not installed."""
    by_id = {r.rule_id: r for r in imported.transpiled}
    for rule in imported.pack.rules:
        report = by_id[rule.id]
        assert report.ok, f"{rule.file} installed but transpiles to nothing"


def test_coverage_records_the_per_backend_failure(imported):
    """Sentinel cannot map the DNS rule — recorded, not silently dropped."""
    dns = next(r for r in imported.transpiled if "dyndns" in r.file)
    assert "sentinel" in dns.errors
    assert "splunk" in dns.ok


def test_transpile_coverage_is_injectable_for_cheap_measurement(imported):
    """The measurement helper takes a fake transpiler (no pySigma cost)."""

    def only_splunk(_yaml: str, backend: str) -> str:
        if backend != "splunk":
            raise RuntimeError("nope")
        return "index=main"

    coverage, reports = transpile_coverage(
        imported.pack.rules, ["splunk", "elastic"], transpile_fn=only_splunk
    )
    assert coverage["splunk"].rate == 1.0
    assert coverage["elastic"].rate == 0.0
    assert all("elastic" in r.errors for r in reports)


def test_backend_coverage_of_an_empty_set_is_zero_not_a_crash():
    coverage, reports = transpile_coverage([], ["splunk"])
    assert reports == []
    assert coverage["splunk"].rate == 0.0
    assert coverage["splunk"].failed == 0


# --------------------------------------------------------------------------- #
# Materialising the pack on disk
# --------------------------------------------------------------------------- #


def test_written_pack_reloads_through_the_normal_loader(imported, tmp_path):
    dest = write_pack_dir(imported, tmp_path / "sigmahq_sample")
    reloaded = load_pack(dest)

    assert reloaded.id == imported.pack.id
    assert reloaded.name == "SigmaHQ Sample"
    assert reloaded.version == "2026.07"
    assert len(reloaded.rules) == imported.installed
    assert {r.id for r in reloaded.rules} == {r.id for r in imported.pack.rules}


def test_written_manifest_records_which_rules_transpile_per_backend(imported, tmp_path):
    dest = write_pack_dir(imported, tmp_path / "pack")
    manifest = yaml.safe_load((dest / "pack.yaml").read_text(encoding="utf-8"))

    entries = {e["file"]: e for e in manifest["rules"]}
    dns = entries["rules_network_dns_net_dns_susp_dyndns_lookup.yml"]
    assert "splunk" in dns["transpiles"]
    assert "sentinel" in dns["transpile_errors"]
    assert manifest["source"].endswith("sigmahq_sample")


def test_install_report_is_written_next_to_the_pack(imported, tmp_path):
    dest = write_pack_dir(imported, tmp_path / "pack")
    report = json.loads((dest / "install_report.json").read_text(encoding="utf-8"))

    assert report["installed"] == imported.installed
    assert report["skipped_count"] == 4
    assert {s["stage"] for s in report["skipped"]} == {"parse", "transpile", "duplicate"}
    assert report["coverage"]["splunk"]["total"] == 11


def test_write_refuses_to_clobber_without_overwrite(imported, tmp_path):
    dest = write_pack_dir(imported, tmp_path / "pack")
    with pytest.raises(PackLoadError):
        write_pack_dir(imported, dest)

    # …and an overwrite drops rule files the new import no longer has.
    stale = dest / "rules" / "zz_stale_rule.yml"
    stale.write_text("title: Stale\n", encoding="utf-8")
    write_pack_dir(imported, dest, overwrite=True)
    assert not stale.exists()


def test_write_refuses_an_empty_pack(tmp_path):
    empty = tmp_path / "corpus"
    empty.mkdir()
    (empty / "junk.yml").write_text("title:\n", encoding="utf-8")  # parses, no title -> skipped
    result = import_sigma_corpus(empty, check_transpile=False)
    assert result.installed == 0
    with pytest.raises(PackLoadError):
        write_pack_dir(result, tmp_path / "dest")


def test_slugify_produces_a_safe_directory_name():
    assert slugify("SigmaHQ core rules 2026.07") == "sigmahq_core_rules_2026_07"
    assert slugify("../../etc/passwd") == "etc_passwd"
    assert slugify("") == "pack"


# --------------------------------------------------------------------------- #
# E7: install cap with an explicit truncated signal
# --------------------------------------------------------------------------- #


def _write_valid_rule(path, rule_id: str) -> None:
    path.write_text(
        "title: Cap Probe\n"
        f"id: {rule_id}\n"
        "logsource:\n  category: process_creation\n  product: windows\n"
        "detection:\n  sel:\n    Image|endswith: '\\\\x.exe'\n  condition: sel\n"
        "level: low\n",
        encoding="utf-8",
    )


def test_import_caps_at_max_rules_and_signals_truncation(tmp_path):
    for i in range(5):
        _write_valid_rule(tmp_path / f"r{i}.yml", f"00000000-0000-4000-8000-00000000000{i}")

    result = import_sigma_corpus(
        tmp_path, name="Capped", version="1.0.0", check_transpile=False, max_rules=2
    )
    assert result.truncated is True
    assert result.found == 5
    assert result.scanned == 2
    assert result.installed <= 2


def test_import_uncapped_processes_every_file(tmp_path):
    for i in range(5):
        _write_valid_rule(tmp_path / f"r{i}.yml", f"00000000-0000-4000-8000-00000000000{i}")

    result = import_sigma_corpus(
        tmp_path, name="Uncapped", version="1.0.0", check_transpile=False, max_rules=None
    )
    assert result.truncated is False
    assert result.found == 5
    assert result.scanned == 5
