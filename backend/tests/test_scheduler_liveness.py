"""A wedged arq worker must get restarted, not sit there looking healthy.

The scheduler container runs every recurring job in the product: scheduled
hunt-pack runs, the TAXII poll sweep, behavioural baselines, memory
consolidation, the noise digest. It is not an HTTP server, so it had no probes
at all — and that is the worst case for this failure mode. A worker whose
event loop wedges (a deadlocked coroutine, a Redis connection it cannot
recover) keeps its process alive, so the container stays ``Running``, nothing
restarts it, and every scheduled job silently stops firing until a human
notices findings dried up.

``arq --check`` exists for exactly this: it reads the health key the worker
stamps in Redis on each heartbeat and exits non-zero when it is missing or
stale.

**The coupling is the fragile part**, and it is what most of this file pins.
The probe and ``WorkerSettings.health_check_interval`` are two numbers in two
files that have to stay in a relationship:

* ``periodSeconds x failureThreshold`` must exceed the stamp interval with
  margin, or one slow heartbeat kills a healthy worker;
* ``initialDelaySeconds`` must clear process start plus the first stamp, or
  every worker crash-loops from birth.

arq's own default interval is 3600s. Inheriting it would make the key useless
as a liveness signal — a worker that wedged five minutes ago would still look
healthy for another fifty-five — so the interval is overridden, and
``test_health_check_interval_is_not_arq_default`` fails if that override is
ever dropped.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_VALUES = _REPO / "infra" / "helm" / "btagent" / "values.yaml"
_DEPLOYMENT = _REPO / "infra" / "helm" / "btagent" / "templates" / "deployment.yaml"

#: arq's own default, in seconds. Inheriting it defeats the probe.
_ARQ_DEFAULT_HEALTH_CHECK_INTERVAL = 3600


@pytest.fixture(scope="module")
def values() -> dict:
    return yaml.safe_load(_VALUES.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def probe(values: dict) -> dict:
    return values["scheduler"]["livenessProbe"]


@pytest.fixture(scope="module")
def stamp_interval() -> int:
    from btagent_backend.scheduler.worker import WorkerSettings

    return int(WorkerSettings.health_check_interval)


def _scheduler_block(*, comments: bool = True) -> str:
    """The scheduler container's spec, to the end of its Deployment document.

    Bounded on the next ``---`` rather than end-of-file: the scheduler is the
    last document today, but appending another Deployment below it would
    silently widen every assertion here to the whole file.
    """
    src = _DEPLOYMENT.read_text(encoding="utf-8")
    block = src[src.index("- name: scheduler") :]
    end = block.find("\n---")
    if end != -1:
        block = block[:end]
    if not comments:
        block = "\n".join(line for line in block.splitlines() if not line.lstrip().startswith("#"))
    return block


# ---------------------------------------------------------------------------
# The worker stamps often enough for the key to mean something.
# ---------------------------------------------------------------------------


def test_health_check_interval_is_not_arq_default(stamp_interval: int):
    assert stamp_interval < _ARQ_DEFAULT_HEALTH_CHECK_INTERVAL, (
        "WorkerSettings.health_check_interval is back at arq's 3600s default; the "
        "health key is written with a TTL of interval+1, so a worker that wedged "
        "minutes ago would still pass `arq --check` for the rest of the hour"
    )


def test_health_check_interval_detects_a_wedge_within_a_couple_of_minutes(
    stamp_interval: int,
):
    """The number that decides how long a silent outage lasts."""
    assert stamp_interval <= 120, (
        f"a {stamp_interval}s stamp interval means a wedged scheduler can go "
        "undetected for that long; scheduled hunts stop firing in the meantime"
    )


# ---------------------------------------------------------------------------
# The probe is wired, and wired to the right command.
# ---------------------------------------------------------------------------


def test_scheduler_has_a_liveness_probe(probe: dict):
    assert probe["enabled"] is True, (
        "without it a wedged worker is never restarted — the process stays alive, "
        "so Kubernetes sees nothing wrong"
    )


def test_probe_runs_arq_check_against_the_real_worker_settings():
    scheduler_block = _scheduler_block()
    assert "livenessProbe:" in scheduler_block
    assert '"--check"' in scheduler_block, "the probe must use arq's health check"
    assert "btagent_backend.scheduler.worker.WorkerSettings" in scheduler_block

    # Same settings class the container actually runs, or the probe checks a
    # queue nothing writes to and fails forever.
    command_line = re.search(r'command: \["arq", "(btagent_backend[\w.]+)"\]', scheduler_block)
    assert command_line, "the scheduler command changed shape"
    assert command_line.group(1) in scheduler_block.split("livenessProbe:", 1)[1]


def test_scheduler_has_no_readiness_probe():
    """Nothing routes traffic to the worker, so "ready" has no meaning here.

    A readinessProbe on it would be noise at best; at worst someone later
    points it at a deep check and a dependency blip starts flapping a pod that
    no Service is fronting anyway.

    Comments are stripped first: the template explains the absence in a
    ``# No readinessProbe: ...`` note, and a naive grep flags the very prose
    documenting the decision.
    """
    assert "readinessProbe:" not in _scheduler_block(comments=False)


# ---------------------------------------------------------------------------
# The coupling. Two numbers in two files that must stay in a relationship.
# ---------------------------------------------------------------------------


def test_failure_window_is_wider_than_the_stamp_interval(probe: dict, stamp_interval: int):
    """Otherwise one slow heartbeat restarts a healthy worker.

    A restart mid-job is not free: an in-flight hunt sweep dies partway, and
    the cron tick it was serving does not come back around until its next
    scheduled instant.
    """
    window = probe["periodSeconds"] * probe["failureThreshold"]
    assert window >= stamp_interval * 2, (
        f"probe tolerates only {window}s of silence against a {stamp_interval}s "
        "stamp interval — too tight; a single delayed heartbeat kills the pod"
    )


def test_initial_delay_clears_the_first_stamp(probe: dict, stamp_interval: int):
    """arq writes the key on its first heartbeat, but the process has to boot first.

    Too short and every worker is killed before it can ever pass, which looks
    like a crash-looping scheduler with no error in the logs.
    """
    assert probe["initialDelaySeconds"] > stamp_interval, (
        f"initialDelaySeconds={probe['initialDelaySeconds']} does not clear the "
        f"{stamp_interval}s stamp interval plus process start"
    )


def test_probe_timeout_allows_for_starting_a_python_process(probe: dict):
    """`arq --check` is not a socket poke — it boots an interpreter and hits Redis."""
    assert probe["timeoutSeconds"] >= 5, (
        f"timeoutSeconds={probe['timeoutSeconds']} is likely to time out on a "
        "loaded node before the check can run, killing healthy workers"
    )
    assert probe["timeoutSeconds"] < probe["periodSeconds"], (
        "a timeout at or beyond the period lets checks overlap"
    )
