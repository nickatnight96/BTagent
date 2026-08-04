"""The Postgres backup CronJob is shipped, and shipped off by default.

EPIC-8's Definition of Done lists "PG backup CronJob scheduled" as a
production-readiness item; the chart had no CronJob of any kind. This adds one
and pins the two properties that make it trustworthy rather than decorative.

**Why it defaults to disabled.** The default volume is an ``emptyDir``, which
dies with the pod. A backup that runs nightly, reports success, and leaves
nothing restorable behind is worse than no backup at all — it looks identical
to a working one on any dashboard, right up until a restore is attempted. So
the operator has to supply a durable volume and turn it on deliberately.

There is no ``helm`` binary in CI, so the chart is validated the way
``test_env_normalization.py`` validates it: by reading the shipped YAML. The
template carries Go templating and is not parseable as YAML, so its assertions
are on source text. That is weaker than a rendered-manifest test and is called
out here rather than dressed up — the properties worth guarding (default-off,
retention wired, dump-then-rename) are all visible in the source.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_CHART = Path(__file__).resolve().parents[2] / "infra" / "helm" / "btagent"
_VALUES = _CHART / "values.yaml"
_CRONJOB = _CHART / "templates" / "backup-cronjob.yaml"


@pytest.fixture(scope="module")
def values() -> dict:
    return yaml.safe_load(_VALUES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def cronjob_src() -> str:
    return _CRONJOB.read_text(encoding="utf-8")


def test_backup_cronjob_template_is_shipped():
    assert _CRONJOB.is_file(), "EPIC-8 DoD requires a PG backup CronJob in the chart"


def test_backup_is_disabled_by_default(values: dict):
    """The default destination is ephemeral, so the default must be off.

    If this ever flips to true while `volume` is still an emptyDir, the chart
    starts producing backups that cannot be restored from.
    """
    backup = values["backup"]
    assert backup["enabled"] is False
    assert "emptyDir" in backup["volume"], (
        "default volume changed; if it is now durable, enabling by default is "
        "reasonable — update this test deliberately rather than flipping it"
    )


def test_schedule_is_a_five_field_cron_expression(values: dict):
    schedule = values["backup"]["schedule"]
    assert len(schedule.split()) == 5, f"not a cron expression: {schedule!r}"


def test_retention_keeps_more_than_one_dump(values: dict):
    """keepLast=1 would delete the only good backup the moment a new one lands."""
    assert values["backup"]["keepLast"] >= 2


def test_mount_path_matches_the_configured_dump_path(values: dict, cronjob_src: str):
    """A mismatch writes dumps to the container filesystem, not the volume.

    That failure is silent: the job succeeds, the dump exists for the lifetime
    of the pod, and the volume stays empty.
    """
    assert ".Values.backup.path" in cronjob_src
    assert "mountPath: {{ .Values.backup.path }}" in cronjob_src


def test_dump_is_renamed_only_after_success(cronjob_src: str):
    """Write-then-rename is what keeps a truncated dump from looking valid."""
    assert ".partial" in cronjob_src
    assert re.search(r"mv\s+\"\$\{DEST\}\.partial\"\s+\"\$DEST\"", cronjob_src), (
        "the dump must land on a .partial name and be renamed only on success"
    )


def test_empty_database_url_fails_rather_than_writing_an_empty_dump(cronjob_src: str):
    """An unset DSN must abort, not produce a 0-byte 'backup'."""
    assert "refusing to write an empty backup" in cronjob_src


def test_credentials_come_from_the_app_secret(cronjob_src: str):
    """Reusing the app's Secret is what stops the backup targeting a stale DB."""
    assert "secretRef" in cronjob_src
    assert "BTAGENT_DATABASE_URL" in cronjob_src


def test_concurrent_dumps_are_forbidden(cronjob_src: str):
    assert "concurrencyPolicy: Forbid" in cronjob_src


def test_production_values_do_not_silently_enable_an_ephemeral_backup():
    """values-production.yaml may enable backups, but not onto an emptyDir."""
    prod = yaml.safe_load((_CHART / "values-production.yaml").read_text(encoding="utf-8"))
    backup = (prod or {}).get("backup")
    if backup is None or not backup.get("enabled"):
        pytest.skip("production values do not enable backups")
    assert "emptyDir" not in backup.get("volume", {}), (
        "production enables backups onto an ephemeral volume — the dumps would not survive the pod"
    )


def test_writable_scratch_survives_the_read_only_root_filesystem(values: dict, cronjob_src: str):
    """`readOnlyRootFilesystem: true` means every write needs a mounted volume.

    The dump goes to the backup volume, but pg_dump/gzip also touch /tmp, which
    the chart supplies via `extraVolumeMounts`. Dropping that inclusion would
    fail only at runtime, inside a CronJob nobody watches.
    """
    assert values["securityContext"]["readOnlyRootFilesystem"] is True
    assert "extraVolumeMounts" in cronjob_src
    assert "extraVolumes" in cronjob_src


def test_mounted_volume_is_writable_by_the_non_root_user(values: dict):
    """runAsUser without a matching fsGroup makes the mount unwritable.

    The dump would then fail on permission denied every night. Both halves are
    asserted because either one drifting alone reintroduces that.
    """
    assert values["securityContext"]["runAsUser"] == values["podSecurityContext"]["fsGroup"]
