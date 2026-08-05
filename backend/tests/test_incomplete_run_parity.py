"""One definition of "which pack runs count as observations" (#112).

Three surfaces classify a hunt-pack rule's health from the same
``hunt_pack_runs.rule_stats`` substrate: the noise baseline
(``GET /hunt/noise-baseline`` + ``/hunt/under-firing``), the Coverage Console's
broken-rule list, and the HuntPacks page's per-rule badges. A rule's state is a
function of *how many runs observed it*, so the three agree only while they
admit the same runs. One module admitting an extra status counts observations
its neighbours do not and reaches a different verdict about the same rule —
and every layer still passes its own tests, because each is internally
consistent. Nothing checks that they agree with each other.

This is that check.

It is not hypothetical. ``abandoned`` was added as a run status without
updating ``coverage_console_service``, which kept a private ``_FAILED = "failed"``
literal. From then on a pack whose worker kept restarting had the partial
``rule_stats`` of its abandoned sweeps counted as real observations; once three
accumulated, its rules crossed the under-firing floor and the Coverage Console
reported them as detections to review, while ``GET /hunt/under-firing`` —
correctly — said nothing about them. The over-firing half of the *same
function* stayed right, because ``compute_noise_baseline`` re-filters the rows
it is handed. So the two halves of one function disagreed about which runs had
happened.

What is checked:

* every backend module that filters pack runs uses
  :data:`INCOMPLETE_RUN_STATUSES` rather than its own status literal;
* the TypeScript mirror in ``huntPacksStore.ts`` lists exactly the same
  statuses — a cross-language drift lock, since a new status added in Python
  would otherwise leave the browser counting runs the API refuses to;
* the constant is non-empty and every member is a real terminal status on
  ``HuntPackRunRow``, so the guard cannot pass by comparing two empty lists.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from btagent_backend.services.noise_baseline import INCOMPLETE_RUN_STATUSES

_REPO = Path(__file__).resolve().parents[2]
_SERVICES = _REPO / "backend" / "btagent_backend" / "services"
_STORE_TS = _REPO / "frontend" / "src" / "stores" / "huntPacksStore.ts"

# Modules that read pack-run history to say something about a rule's health.
# Adding a fourth such surface means adding it here.
_RULE_HEALTH_MODULES = (
    "noise_baseline.py",
    "coverage_console_service.py",
)

# The terminal statuses `HuntPackRunRow.status` can hold (see models_hunt.py).
_TERMINAL_STATUSES = frozenset({"completed", "completed_with_errors", "failed", "abandoned"})


def _strip_comments_and_docstrings(source: str) -> str:
    """Drop ``#`` comments and triple-quoted blocks.

    Without this the scan matches the prose *explaining* why a bare ``"failed"``
    literal is wrong — a guard that passes by reading its own rationale. (Twice
    learned the hard way: `test_pg_backup_script`, `test_scheduler_liveness`.)
    """
    source = re.sub(r'""".*?"""', "", source, flags=re.DOTALL)
    source = re.sub(r"'''.*?'''", "", source, flags=re.DOTALL)
    return re.sub(r"#[^\n]*", "", source)


def test_the_constant_is_real_and_non_vacuous():
    """Guard the guard: an empty or bogus list would make every check below pass."""
    assert INCOMPLETE_RUN_STATUSES, "the exclusion set must not be empty"
    assert set(INCOMPLETE_RUN_STATUSES) <= _TERMINAL_STATUSES, (
        "INCOMPLETE_RUN_STATUSES names a status HuntPackRunRow cannot hold"
    )
    # It must exclude *some* runs and admit *some* runs, or the analyses are
    # either blind or unfiltered.
    assert set(INCOMPLETE_RUN_STATUSES) < _TERMINAL_STATUSES


def test_incomplete_statuses_are_exactly_failed_and_abandoned():
    """Pin the membership so a change is a deliberate edit to this test.

    ``completed_with_errors`` in particular must NOT be here: some of its
    rule x backend executions succeeded, and those are real observations.
    """
    assert set(INCOMPLETE_RUN_STATUSES) == {"failed", "abandoned"}


@pytest.mark.parametrize("module_name", _RULE_HEALTH_MODULES)
def test_no_rule_health_module_keeps_its_own_status_literal(module_name: str):
    """A bare ``"failed"`` / ``"abandoned"`` literal is how the two drift apart.

    ``noise_baseline`` is allowed the two module-level definitions that build
    the constant; nothing else may name a status inline.
    """
    path = _SERVICES / module_name
    code = _strip_comments_and_docstrings(path.read_text())

    if module_name == "noise_baseline.py":
        # The one legitimate site: `_FAILED = "failed"` / `_ABANDONED = "abandoned"`.
        code = re.sub(r"_(?:FAILED|ABANDONED)\s*=\s*\"[a-z_]+\"", "", code)

    for status in INCOMPLETE_RUN_STATUSES:
        assert f'"{status}"' not in code, (
            f"{module_name} names the run status {status!r} inline; import "
            "INCOMPLETE_RUN_STATUSES from noise_baseline instead, so this "
            "module cannot drift from the surfaces it must agree with"
        )


def test_coverage_console_filters_on_the_shared_constant():
    """The specific regression: the console must not re-filter on its own set."""
    code = _strip_comments_and_docstrings((_SERVICES / "coverage_console_service.py").read_text())
    assert "INCOMPLETE_RUN_STATUSES" in code, (
        "coverage_console_service must import and use the shared exclusion set"
    )
    assert "status.not_in(INCOMPLETE_RUN_STATUSES)" in code, (
        "coverage_console_service's pack-run query must exclude every "
        "incomplete status, not just 'failed'"
    )


def test_typescript_mirror_lists_the_same_statuses():
    """Cross-language drift lock for the browser's copy of the rule.

    The HuntPacks page classifies rules client-side from run history it fetched
    itself. If Python gains a status the TypeScript list lacks, the page counts
    runs the API has already excluded and contradicts the advisory rendered
    beside it.
    """
    ts = _STORE_TS.read_text()
    match = re.search(
        r"INCOMPLETE_RUN_STATUSES\s*:\s*readonly\s+string\[\]\s*=\s*\[([^\]]*)\]",
        ts,
    )
    assert match, (
        "could not find INCOMPLETE_RUN_STATUSES in huntPacksStore.ts — if it "
        "was renamed or reshaped, update this guard rather than deleting it"
    )
    mirrored = set(re.findall(r'"([^"]+)"', match.group(1)))
    assert mirrored == set(INCOMPLETE_RUN_STATUSES), (
        f"TypeScript mirror {sorted(mirrored)} has drifted from Python "
        f"{sorted(INCOMPLETE_RUN_STATUSES)}"
    )


def test_the_store_actually_applies_the_exclusion():
    """The list existing is not the same as the store using it."""
    ts = _STORE_TS.read_text()
    assert "export function completedRuns(" in ts, (
        "huntPacksStore must expose the filter helper the guard describes"
    )
    # classifyRuleState is the function whose verdict the backend mirrors.
    body = ts.split("export function classifyRuleState(", 1)
    assert len(body) == 2, "classifyRuleState not found in huntPacksStore.ts"
    assert "completedRuns(" in body[1].split("\n}", 1)[0], (
        "classifyRuleState must drop incomplete runs before counting "
        "observations, or the page reaches a verdict the API would not"
    )
