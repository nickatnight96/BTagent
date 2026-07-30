"""External-corpus install + the ``bt huntpack`` CLI (#112).

Two gaps closed in one round, tested together because the CLI is a thin shell
over the install service:

* **Install path** — point the store at an external Sigma rule directory
  (SigmaHQ layout) and it becomes a hunt pack for *one org*: rules that cannot
  be parsed or transpiled are skipped **with a reason**, the rest are
  installed, and the enable state reuses the existing ``org_hunt_packs`` table
  (no new migration).
* **CLI** — ``bt huntpack list / install / enable / disable`` wired to that
  service, org-scoped and explicit about which org it acted on.

Shared-DB discipline: every count/identity assertion runs against a dedicated
per-test org (``generate_id("org")``), never ``DEFAULT_ORG_ID`` — the backend
suite shares one session-scoped SQLite and committed rows outlive the test.

Zero egress: the corpora here are written to ``tmp_path`` by the fixtures
below; nothing is downloaded. (The vendored SigmaHQ-shaped sample corpus and
the transpile-rate measurement live in ``engine/tests/test_hunting_corpus.py``,
next to the importer.)
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest
import pytest_asyncio
from btagent_shared.utils.ids import generate_id

from btagent_backend.cli import huntpack as cli_huntpack
from btagent_backend.cli import main as cli_main
from btagent_backend.config import get_settings
from btagent_backend.db.models import DEFAULT_ORG_ID, OrganizationRow
from btagent_backend.db.models_hunt import OrgHuntPackRow
from btagent_backend.services import hunt_pack_store as store

NOW = datetime(2026, 7, 26, 12, 0, tzinfo=UTC)

GOOD_RULE = """\
title: {title}
id: {rule_id}
status: test
description: A well-formed rule that transpiles everywhere.
tags:
  - attack.execution
  - attack.t1059.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\{binary}'
  condition: selection
level: high
"""

BROKEN_YAML = """\
title: Broken
id: 11111111-0000-4000-8000-000000000001
detection:
  selection:
    Image|endswith: [ '\\evil.exe'
  condition: selection
"""

NO_TITLE = """\
id: 11111111-0000-4000-8000-000000000002
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\nothing.exe'
  condition: selection
"""

PIPE_AGGREGATION = """\
title: Legacy Pipe Aggregation
id: 11111111-0000-4000-8000-000000000003
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4625
  timeframe: 30m
  condition: selection | count(TargetUserName) by IpAddress > 30
level: medium
"""


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #


@pytest.fixture()
def install_dir(tmp_path, monkeypatch):
    """Point the install root at a temp dir for the duration of one test."""
    root = tmp_path / "installed"
    monkeypatch.setenv("BTAGENT_HUNT_PACK_INSTALL_DIR", str(root))
    get_settings.cache_clear()
    try:
        yield root
    finally:
        get_settings.cache_clear()


@pytest.fixture()
def corpus(tmp_path):
    """A tiny SigmaHQ-layout corpus: 3 usable rules + one of each failure mode."""
    root = tmp_path / "sigma"
    rules = root / "rules" / "windows" / "process_creation"
    rules.mkdir(parents=True)
    for idx, (title, binary) in enumerate(
        [
            ("Certutil Download", "certutil.exe"),
            ("Rundll32 Execution", "rundll32.exe"),
            ("Whoami Discovery", "whoami.exe"),
        ],
        start=1,
    ):
        (rules / f"good_{idx}.yml").write_text(
            GOOD_RULE.format(
                title=title, rule_id=f"22222222-0000-4000-8000-00000000000{idx}", binary=binary
            ),
            encoding="utf-8",
        )
    (rules / "broken_yaml.yml").write_text(BROKEN_YAML, encoding="utf-8")
    (rules / "no_title.yml").write_text(NO_TITLE, encoding="utf-8")
    (rules / "pipe_aggregation.yml").write_text(PIPE_AGGREGATION, encoding="utf-8")
    # A duplicate of good_1 (same Sigma id) in a sibling tree.
    dupe_dir = root / "rules-threat-hunting" / "windows" / "process_creation"
    dupe_dir.mkdir(parents=True)
    (dupe_dir / "good_1_copy.yml").write_text(
        GOOD_RULE.format(
            title="Certutil Download (copy)",
            rule_id="22222222-0000-4000-8000-000000000001",
            binary="certutil.exe",
        ),
        encoding="utf-8",
    )
    # SigmaHQ's graveyard must be pruned.
    deprecated = root / "deprecated"
    deprecated.mkdir()
    (deprecated / "retired.yml").write_text(
        GOOD_RULE.format(
            title="Retired", rule_id="22222222-0000-4000-8000-000000000099", binary="retired.exe"
        ),
        encoding="utf-8",
    )
    return root


@pytest_asyncio.fixture()
async def fresh_org(db_session):
    """A dedicated per-test org (FK target for the pack row)."""
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"CLI Org {oid}", created_at=NOW))
    await db_session.commit()
    return oid


@pytest_asyncio.fixture()
async def second_org(db_session):
    oid = generate_id("org")
    db_session.add(OrganizationRow(id=oid, name=f"CLI Org {oid}", created_at=NOW))
    await db_session.commit()
    return oid


# --------------------------------------------------------------------------- #
# Install: skip-with-reason, install the rest
# --------------------------------------------------------------------------- #


async def test_install_skips_unusable_rules_with_reasons_and_installs_the_rest(
    db_session, fresh_org, corpus, install_dir
):
    result = await store.install_corpus_pack(
        db_session,
        org_id=fresh_org,
        source_dir=corpus,
        pack_id="sigma_sample",
        name="Sigma Sample",
        version="2026.07",
        updated_by="cli:test",
    )

    assert result.scanned == 7  # deprecated/ pruned
    assert result.installed == 3
    assert result.skipped_count == 4

    stages = {s["stage"] for s in result.skipped}
    assert stages == {"parse", "transpile", "duplicate"}
    by_file = {s["file"].rsplit("/", 1)[-1]: s for s in result.skipped}
    assert "not valid YAML" in by_file["broken_yaml.yml"]["reason"]
    assert "no 'title'" in by_file["no_title.yml"]["reason"]
    assert "already imported" in by_file["good_1_copy.yml"]["reason"]
    assert "no supported backend" in by_file["pipe_aggregation.yml"]["reason"]
    # Every skip explains itself — a silent drop is the failure mode this guards.
    assert all(s["reason"].strip() for s in result.skipped)


async def test_install_records_transpile_coverage_per_backend(
    db_session, fresh_org, corpus, install_dir
):
    result = await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample"
    )

    assert set(result.coverage) == {"splunk", "sentinel", "elastic", "crowdstrike"}
    for backend, cov in result.coverage.items():
        assert cov["total"] == 4, backend  # the 4 rules that parsed
        assert cov["ok"] >= 3, backend  # the 3 good ones at minimum
        assert 0.0 <= cov["rate"] <= 1.0

    # The per-rule record is durable on disk, next to the pack.
    report = json.loads(
        (install_dir / fresh_org / "sigma_sample" / "install_report.json").read_text()
    )
    assert report["installed"] == 3
    assert report["skipped_count"] == 4
    manifest_rules = report["coverage"]["splunk"]
    assert manifest_rules["ok"] >= 3


async def test_install_writes_a_loadable_pack_and_records_the_org_row(
    db_session, fresh_org, corpus, install_dir
):
    result = await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample", name="Sigma Sample"
    )

    pack_dir = install_dir / fresh_org / "sigma_sample"
    assert (pack_dir / "pack.yaml").is_file()
    assert len(list((pack_dir / "rules").glob("*.yml"))) == 3

    # Loadable by the same loader the scheduled runner uses.
    pack = store.load_pack_for_org("sigma_sample", org_id=fresh_org)
    assert pack.id == result.manifest_pack_id
    assert len(pack.rules) == 3

    row = await db_session.get(OrgHuntPackRow, (fresh_org, "sigma_sample"))
    assert row is not None and row.enabled is True
    assert result.enabled is True


async def test_installed_pack_joins_the_catalog_and_the_runner_pack_list(
    db_session, fresh_org, corpus, install_dir
):
    await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample"
    )

    catalog = await store.pack_catalog(db_session, org_id=fresh_org)
    entry = next(i for i in catalog.items if i.pack_id == "sigma_sample")
    assert entry.source == "installed"
    assert entry.enabled is True
    assert entry.installed is True
    assert entry.rule_count == 3
    # Builtins are still there, and still distinguishable.
    assert any(i.source == "builtin" for i in catalog.items)

    # The runner's question: the imported pack runs alongside the default set.
    enabled = await store.enabled_pack_names(db_session, org_id=fresh_org)
    assert "sigma_sample" in enabled
    assert set(store.DEFAULT_BUILTIN_PACKS).issubset(set(enabled))


async def test_install_with_no_enable_leaves_the_pack_off(
    db_session, fresh_org, corpus, install_dir
):
    result = await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample", enable=False
    )
    assert result.enabled is False
    assert "sigma_sample" not in await store.enabled_pack_names(db_session, org_id=fresh_org)


async def test_reinstall_requires_overwrite(db_session, fresh_org, corpus, install_dir):
    await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample"
    )
    with pytest.raises(ValueError):
        await store.install_corpus_pack(
            db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample"
        )
    again = await store.install_corpus_pack(
        db_session,
        org_id=fresh_org,
        source_dir=corpus,
        pack_id="sigma_sample",
        version="2.0.0",
        overwrite=True,
    )
    assert again.version == "2.0.0"
    # The cached catalog must see the reinstall, not serve the old version.
    catalog = await store.pack_catalog(db_session, org_id=fresh_org)
    assert next(i for i in catalog.items if i.pack_id == "sigma_sample").version == "2.0.0"


# --------------------------------------------------------------------------- #
# Security invariants: org scoping + path safety
# --------------------------------------------------------------------------- #


async def test_installed_pack_is_invisible_to_another_org(
    db_session, fresh_org, second_org, corpus, install_dir
):
    await store.install_corpus_pack(
        db_session, org_id=fresh_org, source_dir=corpus, pack_id="sigma_sample"
    )

    other = await store.pack_catalog(db_session, org_id=second_org)
    assert all(i.pack_id != "sigma_sample" for i in other.items)
    assert "sigma_sample" not in store.known_pack_names(second_org)

    # …and the other org cannot enable it either.
    with pytest.raises(store.UnknownPackError):
        await store.set_pack_enabled(
            db_session, org_id=second_org, pack_id="sigma_sample", enabled=True
        )


async def test_install_refuses_to_shadow_a_builtin_pack(db_session, fresh_org, corpus, install_dir):
    with pytest.raises(store.UnknownPackError):
        await store.install_corpus_pack(
            db_session, org_id=fresh_org, source_dir=corpus, pack_id="windows_baseline"
        )


@pytest.mark.parametrize("bad", ["../escape", "a/b", "..", ".", "with space", "pack\x00"])
async def test_install_rejects_a_traversing_pack_id(
    db_session, fresh_org, corpus, install_dir, bad
):
    with pytest.raises(store.UnknownPackError):
        await store.install_corpus_pack(
            db_session, org_id=fresh_org, source_dir=corpus, pack_id=bad
        )
    assert not (install_dir / fresh_org).exists() or not list((install_dir / fresh_org).iterdir())


def test_org_install_dir_rejects_a_traversing_org_id(install_dir):
    with pytest.raises(store.UnknownPackError):
        store.org_install_dir("../../etc")
    # …and a scan for one returns empty rather than exploding.
    assert store.list_installed_packs("../../etc") == ()


def test_load_pack_for_org_falls_back_to_the_builtin_catalog(install_dir):
    pack = store.load_pack_for_org("windows_baseline", org_id=generate_id("org"))
    assert pack.rules


# --------------------------------------------------------------------------- #
# CLI — parser
# --------------------------------------------------------------------------- #


def test_parser_builds_the_documented_command_tree():
    parser = cli_main.build_parser()

    args = parser.parse_args(["huntpack", "list"])
    assert (args.group, args.command) == ("huntpack", "list")

    args = parser.parse_args(
        ["huntpack", "--org", "org_x", "install", "/tmp/sigma", "--name", "N", "--no-enable"]
    )
    assert args.command == "install"
    assert args.org == "org_x"
    assert args.path == "/tmp/sigma"
    assert args.no_enable is True

    args = parser.parse_args(["huntpack", "enable", "windows_baseline"])
    assert (args.command, args.pack_id) == ("enable", "windows_baseline")

    args = parser.parse_args(["huntpack", "disable", "windows_baseline"])
    assert (args.command, args.pack_id) == ("disable", "windows_baseline")


def test_parser_requires_a_subcommand():
    with pytest.raises(SystemExit):
        cli_main.build_parser().parse_args([])
    with pytest.raises(SystemExit):
        cli_main.build_parser().parse_args(["huntpack"])


def test_install_backends_flag_is_repeatable():
    args = cli_main.build_parser().parse_args(
        ["huntpack", "install", "/tmp/s", "--backend", "splunk", "--backend", "elastic"]
    )
    assert args.backends == ["splunk", "elastic"]


# --------------------------------------------------------------------------- #
# CLI — org resolution (explicit about which tenant it touched)
# --------------------------------------------------------------------------- #


def test_org_resolution_order(monkeypatch):
    monkeypatch.delenv("BTAGENT_ORG_ID", raising=False)
    assert cli_huntpack.resolve_org(None) == (DEFAULT_ORG_ID, "default")

    monkeypatch.setenv("BTAGENT_ORG_ID", "org_env")
    assert cli_huntpack.resolve_org(None) == ("org_env", "BTAGENT_ORG_ID")
    assert cli_huntpack.resolve_org("org_flag") == ("org_flag", "--org")


async def test_commands_say_which_org_they_acted_on(db_session, fresh_org, install_dir):
    result = await cli_huntpack.cmd_list(db_session, org_id=fresh_org, org_source="--org")
    assert result.exit_code == 0
    assert f"org: {fresh_org} (from --org)" in result.lines[0]

    default_run = await cli_huntpack.cmd_list(db_session, org_id=DEFAULT_ORG_ID)
    assert "default — pass --org" in default_run.lines[0]


# --------------------------------------------------------------------------- #
# CLI — dispatch against the real service layer
# --------------------------------------------------------------------------- #


async def _dispatch(db, argv):
    args = cli_main.build_parser().parse_args(argv)
    return await cli_main.dispatch(args, db)


async def test_cli_install_then_list_then_disable_then_enable(
    db_session, fresh_org, corpus, install_dir
):
    installed = await _dispatch(
        db_session,
        [
            "huntpack",
            "--org",
            fresh_org,
            "install",
            str(corpus),
            "--pack-id",
            "sigma_sample",
            "--name",
            "Sigma Sample",
        ],
    )
    assert installed.exit_code == 0
    text = "\n".join(installed.lines)
    assert "installed pack 'sigma_sample'" in text
    assert "skipped:   4" in text
    assert "[parse]" in text and "[duplicate]" in text and "[transpile]" in text
    assert "transpile coverage" in text
    assert installed.data["installed"] == 3

    listed = await _dispatch(db_session, ["huntpack", "--org", fresh_org, "list"])
    assert listed.exit_code == 0
    assert any("sigma_sample" in line and "installed" in line for line in listed.lines)

    disabled = await _dispatch(
        db_session, ["huntpack", "--org", fresh_org, "disable", "sigma_sample"]
    )
    assert disabled.exit_code == 0
    assert disabled.data["enabled"] is False
    assert "sigma_sample" not in await store.enabled_pack_names(db_session, org_id=fresh_org)

    enabled = await _dispatch(
        db_session, ["huntpack", "--org", fresh_org, "enable", "sigma_sample"]
    )
    assert enabled.exit_code == 0
    assert enabled.data["enabled"] is True
    assert "sigma_sample" in await store.enabled_pack_names(db_session, org_id=fresh_org)


async def test_cli_install_honours_no_enable_and_a_single_backend(
    db_session, fresh_org, corpus, install_dir
):
    result = await _dispatch(
        db_session,
        [
            "huntpack",
            "--org",
            fresh_org,
            "install",
            str(corpus),
            "--pack-id",
            "sigma_sample",
            "--backend",
            "splunk",
            "--no-enable",
        ],
    )
    assert result.exit_code == 0
    assert list(result.data["coverage"]) == ["splunk"]
    assert result.data["enabled"] is False


async def test_cli_install_rejects_an_unknown_backend(db_session, fresh_org, corpus, install_dir):
    """A typo'd backend is a usage error, not "your whole corpus is unusable"."""
    result = await _dispatch(
        db_session,
        ["huntpack", "--org", fresh_org, "install", str(corpus), "--backend", "elk"],
    )
    assert result.exit_code == 2
    assert "unknown backend(s): elk" in result.lines[0]
    assert "splunk" in result.lines[1]
    assert not (install_dir / fresh_org).exists()


async def test_install_service_rejects_an_unknown_backend(
    db_session, fresh_org, corpus, install_dir
):
    with pytest.raises(ValueError, match="unknown backend"):
        await store.install_corpus_pack(
            db_session,
            org_id=fresh_org,
            source_dir=corpus,
            pack_id="sigma_sample",
            backends=["splunk", "elk"],
        )


async def test_cli_install_rejects_a_missing_directory(db_session, fresh_org, tmp_path):
    result = await _dispatch(
        db_session, ["huntpack", "--org", fresh_org, "install", str(tmp_path / "nope")]
    )
    assert result.exit_code == 2
    assert "not a directory" in result.lines[0]


async def test_cli_enable_of_an_unknown_pack_exits_nonzero_and_lists_known_packs(
    db_session, fresh_org, install_dir
):
    result = await _dispatch(db_session, ["huntpack", "--org", fresh_org, "enable", "nope_pack"])
    assert result.exit_code == 2
    assert "unknown hunt pack" in result.lines[0]
    assert "known packs:" in result.lines[1]
    assert await db_session.get(OrgHuntPackRow, (fresh_org, "nope_pack")) is None


async def test_cli_list_falls_back_to_the_default_org(db_session, monkeypatch, install_dir):
    monkeypatch.delenv("BTAGENT_ORG_ID", raising=False)
    result = await _dispatch(db_session, ["huntpack", "list"])
    assert result.exit_code == 0
    assert DEFAULT_ORG_ID in result.lines[0]


# --------------------------------------------------------------------------- #
# CLI — rendering
# --------------------------------------------------------------------------- #


def test_render_json_is_machine_readable():
    result = cli_huntpack.CommandResult(lines=["hello"], data={"pack_id": "p"})
    payload = json.loads(cli_main.render(result, as_json=True))
    assert payload == {"ok": True, "messages": ["hello"], "data": {"pack_id": "p"}}


def test_render_text_is_the_joined_lines():
    result = cli_huntpack.CommandResult(lines=["a", "b"])
    assert cli_main.render(result, as_json=False) == "a\nb"


class _SessionHandle:
    """Async CM handing ``_run`` the suite's session instead of a new one.

    The backend suite shares ONE in-memory SQLite whose schema lives on a
    single pooled connection; letting ``_run`` check out a *second* connection
    would land it on an empty database. Substituting the factory keeps the code
    path under test (dispatch + commit) without that second connection.
    """

    def __init__(self, session):
        self._session = session
        self.committed = False
        self.rolled_back = False

    async def __aenter__(self):
        session = self._session
        original_commit, original_rollback = session.commit, session.rollback

        async def _commit():
            self.committed = True
            await original_commit()

        async def _rollback():
            self.rolled_back = True
            await original_rollback()

        session.commit, session.rollback = _commit, _rollback
        return session

    async def __aexit__(self, *exc_info):
        return False


async def test_run_opens_a_session_and_commits(db_session, fresh_org, install_dir, monkeypatch):
    """``_run`` is the session lifecycle the console script actually uses."""
    import btagent_backend.db.engine as engine_mod

    handle = _SessionHandle(db_session)
    monkeypatch.setattr(engine_mod, "async_session_factory", lambda: handle, raising=False)

    args = cli_main.build_parser().parse_args(["huntpack", "--org", fresh_org, "list"])
    result = await cli_main._run(args)

    assert result.exit_code == 0
    assert fresh_org in result.lines[0]
    assert handle.committed is True  # a successful command commits its work
    assert handle.rolled_back is False


async def test_run_rolls_back_a_failed_command(db_session, fresh_org, install_dir, monkeypatch):
    import btagent_backend.db.engine as engine_mod

    handle = _SessionHandle(db_session)
    monkeypatch.setattr(engine_mod, "async_session_factory", lambda: handle, raising=False)

    args = cli_main.build_parser().parse_args(
        ["huntpack", "--org", fresh_org, "enable", "nope_pack"]
    )
    result = await cli_main._run(args)

    assert result.exit_code == 2
    assert handle.committed is False
    assert handle.rolled_back is True


def test_main_entrypoint_returns_the_exit_code_and_prints(capsys):
    """End-to-end through ``main``: parse -> asyncio.run -> render -> exit code.

    Uses the argument-validation failure path so the assertion is about the
    entrypoint's plumbing, not about database state.
    """
    code = cli_main.main(["huntpack", "--org", "org_cli_smoke", "install", "/nonexistent/sigma"])
    assert code == 2
    captured = capsys.readouterr()
    assert "not a directory" in captured.err


def test_console_script_is_declared():
    """``bt`` must exist as an entrypoint, not just as an importable module."""
    import tomllib
    from pathlib import Path

    pyproject = Path(__file__).resolve().parents[1] / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    assert data["project"]["scripts"]["bt"] == "btagent_backend.cli.main:main"
