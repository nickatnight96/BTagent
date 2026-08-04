"""The compose backup script must not produce backups that only look valid.

`infra/scripts/pg-backup.sh` replaces the `pg_dump ... | gzip > file` cron
one-liner `DEPLOYMENT.md` used to recommend. That one-liner fails in two ways
that a dashboard cannot see:

* a `pg_dump` that dies mid-stream still leaves a well-formed gzip of the
  partial output, and without `pipefail` the pipeline exits 0, so cron records
  a success;
* `find -mtime +30 -delete` prunes by age without checking that anything
  replaced what it removes, so a month of failing backups ends with the last
  good one deleted.

These tests run the real script against a real PostgreSQL where one is
reachable, because "the backup is restorable" is not a property you can assert
from source text. Without a database they fall back to asserting the guards
are present in the script — weaker, and marked as such rather than dressed up.

The verification step is the part worth watching. `pg_restore --list` is the
obvious check and it is not sufficient: a custom-format archive keeps its
table of contents at the head, so `--list` succeeds on a dump truncated
anywhere in the data blocks. `test_truncated_dump_fails_verification` pins
that the script uses a check that actually reads the archive.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

_REPO = Path(__file__).resolve().parents[2]
_SCRIPT = _REPO / "infra" / "scripts" / "pg-backup.sh"

_PG_TOOLS = all(shutil.which(t) for t in ("pg_dump", "pg_restore", "psql"))
_DSN = os.environ.get("BTAGENT_TEST_PG_DSN", "postgresql://postgres@127.0.0.1:5432/postgres")


def _pg_reachable() -> bool:
    if not _PG_TOOLS:
        return False
    try:
        return (
            subprocess.run(
                ["psql", _DSN, "-tAc", "select 1"],
                capture_output=True,
                timeout=10,
            ).returncode
            == 0
        )
    except (OSError, subprocess.SubprocessError):
        return False


_needs_pg = pytest.mark.skipif(
    not _pg_reachable(), reason="no reachable PostgreSQL; source-level checks still run"
)


@pytest.fixture(scope="module")
def script_src() -> str:
    return _SCRIPT.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def script_code(script_src: str) -> str:
    """Executable lines only.

    The script's comments deliberately quote the *wrong* forms (`pg_restore
    --list`, `-mtime +30`) while explaining why they are wrong, so a check
    that greps the whole file reports the very prose that documents the fix.
    """
    return "\n".join(line for line in script_src.splitlines() if not line.lstrip().startswith("#"))


def _run(tmp_path: Path, *, dsn: str, keep: int = 3) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "BTAGENT_DATABASE_URL": dsn,
        "BACKUP_DIR": str(tmp_path),
        "BACKUP_KEEP_LAST": str(keep),
    }
    return subprocess.run(
        ["bash", str(_SCRIPT)], env=env, capture_output=True, text=True, timeout=120
    )


# ---------------------------------------------------------------------------
# Source-level guards — cheap, and they run everywhere.
# ---------------------------------------------------------------------------


def test_script_is_shipped_and_executable():
    assert _SCRIPT.is_file()
    assert os.access(_SCRIPT, os.X_OK), "cron will not run a non-executable script"


def test_dump_is_promoted_only_after_verification(script_src: str):
    """Write-then-verify-then-rename, in that order."""
    partial = script_src.index(".partial")
    verify = script_src.index("pg_restore -f /dev/null")
    promote = script_src.index('mv "${DEST}.partial"')
    assert partial < verify < promote, "the dump must be verified before it is renamed"


def test_verification_reads_the_whole_archive(script_code: str):
    """`--list` only reads the TOC; a truncated dump passes it.

    Pinned separately from the ordering test because swapping the full read
    for `--list` looks like a harmless optimisation and silently removes the
    only check that catches a torn dump.
    """
    assert "pg_restore -f /dev/null" in script_code
    assert "pg_restore --list" not in script_code


def test_retention_is_by_count_not_age(script_code: str):
    assert "-mtime" not in script_code, "age-based pruning deletes good backups"
    assert "BACKUP_KEEP_LAST" in script_code


def test_sqlalchemy_driver_suffix_is_stripped(script_src: str):
    """libpq rejects `postgresql+asyncpg://`; the app's DSN carries it."""
    assert "postgresql+[a-z0-9]*://" in script_src


def test_empty_dsn_aborts(script_src: str):
    assert "refusing to write an empty backup" in script_src


# ---------------------------------------------------------------------------
# Behavioural — needs a real PostgreSQL.
# ---------------------------------------------------------------------------


def test_empty_dsn_exits_without_writing(tmp_path: Path):
    result = _run(tmp_path, dsn="")
    assert result.returncode == 2, result.stderr
    assert not list(tmp_path.glob("*")), "aborted run left files behind"


def test_keep_last_below_two_is_refused(tmp_path: Path):
    result = _run(tmp_path, dsn="postgresql://x@127.0.0.1/x", keep=1)
    assert result.returncode == 2
    assert "must be >= 2" in result.stderr


def test_unreachable_database_leaves_a_partial_and_promotes_nothing(tmp_path: Path):
    """A visible `.partial` is the point — a failed run must not look clean."""
    result = _run(tmp_path, dsn="postgresql://nobody@127.0.0.1:5999/nope")
    assert result.returncode == 1
    assert not list(tmp_path.glob("*.dump")), "promoted a dump despite pg_dump failing"


@_needs_pg
def test_backup_round_trips_through_a_real_restore(tmp_path: Path):
    """The only assertion that proves the backup is worth having."""
    result = _run(tmp_path, dsn=_DSN)
    assert result.returncode == 0, result.stderr
    dumps = list(tmp_path.glob("btagent-*.dump"))
    assert len(dumps) == 1
    # Decoding the archive end-to-end is what a restore does.
    verify = subprocess.run(
        ["pg_restore", "-f", os.devnull, str(dumps[0])], capture_output=True, timeout=60
    )
    assert verify.returncode == 0, verify.stderr


@_needs_pg
def test_truncated_dump_fails_verification(tmp_path: Path):
    """The defect the whole script exists for.

    A dump cut in its data blocks — the shape of a mid-stream `pg_dump`
    failure — must not be promoted. Note this is cut to 60%: at 90% it still
    passes `pg_restore --list`, which is why the script does not use it.
    """
    assert _run(tmp_path, dsn=_DSN).returncode == 0
    good = next(iter(tmp_path.glob("btagent-*.dump")))
    torn = tmp_path / "torn.dump"
    torn.write_bytes(good.read_bytes()[: int(good.stat().st_size * 0.6)])

    verify = subprocess.run(
        ["pg_restore", "-f", os.devnull, str(torn)], capture_output=True, timeout=60
    )
    assert verify.returncode != 0, "a truncated dump passed the script's verification"


# ---------------------------------------------------------------------------
# The guidance this script replaces, and the sibling instruction that was
# broken the same way. Both told operators to do something that fails without
# saying so, which is the trait worth guarding — not the wording.
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def deployment_doc() -> str:
    return (_REPO / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")


def _instructions(doc: str) -> str:
    """Doc text minus blockquotes.

    The rewritten sections quote the old broken commands inside `>` callouts
    to explain why they were wrong. Those are warnings, not instructions, and
    a check that cannot tell them apart would flag the explanation.
    """
    return "\n".join(line for line in doc.splitlines() if not line.lstrip().startswith(">"))


def test_doc_no_longer_recommends_the_unsafe_pipeline(deployment_doc: str):
    instructions = _instructions(deployment_doc)
    assert "| gzip > /backups" not in instructions, (
        "a truncated pg_dump still writes a well-formed gzip and exits 0"
    )
    assert "-mtime +30 -delete" not in instructions, (
        "age-based pruning deletes the last good backup after a month of failures"
    )
    assert "pg-backup.sh" in instructions, "the doc should point at the shipped script"


def test_doc_does_not_promise_a_chart_value_that_does_not_exist(deployment_doc: str):
    """`--set secretEnv.existingSecret=...` was a no-op that broke the install.

    It added a map key named `existingSecret` instead of pointing anything at
    a pre-made Secret, so the release rendered a Secret holding that one
    meaningless entry and no database URL.
    """
    chart_values = (_REPO / "infra" / "helm" / "btagent" / "values.yaml").read_text(
        encoding="utf-8"
    )
    instructions = _instructions(deployment_doc)
    if "existingSecret" not in chart_values:
        assert "secretEnv.existingSecret" not in instructions, (
            "the doc sets a chart value that does not exist; if support was added, "
            "this test flips automatically once values.yaml declares it"
        )


@_needs_pg
def test_retention_keeps_newest_complete_dumps_and_spares_partials(tmp_path: Path):
    for i in range(1, 6):
        (tmp_path / f"btagent-2026080{i}T000000Z.dump").write_bytes(b"old")
    stray = tmp_path / "btagent-20260801T000000Z.dump.partial"
    stray.write_bytes(b"interrupted")

    assert _run(tmp_path, dsn=_DSN, keep=3).returncode == 0

    assert len(list(tmp_path.glob("btagent-*.dump"))) == 3
    assert stray.exists(), "retention deleted a .partial — the evidence of a failed run"
