"""Every suppressed vulnerability keeps its justification and its safety net.

``.trivyignore.yaml`` suppresses findings in the container image scan. That is
a security gate, and an ignore list is the classic place for a temporary
exception to quietly become permanent: the reason rots, the compensating
control is refactored away, and what remains is a CVE nobody is watching.

Both current entries are suppressed on the same grounds — the finding is
SBOM-sourced (``PkgPath: null`` plus a ``BOMRef``, which Trivy sets only for
packages ingested from a CycloneDX document) and describes a wheel's *build*
environment rather than our installed inventory. The image genuinely ships
patched versions.

That argument only holds while the build keeps proving it. ``Dockerfile.backend``
upgrades both packages in the final stage, enumerates every ``dist-info`` /
``egg-info`` directory image-wide, deletes any that is not the resolved
version, and **fails the build** unless exactly one remains at or above the
floor. Delete that step and the suppression becomes a genuine blind spot.

So this file ties the two together: the ignore entries may exist only while
the Dockerfile assertion that replaces them does. It also refuses an entry
with no statement, no expiry, or an expiry already past — the three ways an
exception outlives its reason.

Deliberately not checked: whether the CVEs are still real upstream. That is
the scanner's job, and re-encoding advisory data here would just be a second
copy to go stale.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml

_REPO = Path(__file__).resolve().parents[2]
_IGNOREFILE = _REPO / ".trivyignore.yaml"
_DOCKERFILE = _REPO / "infra" / "docker" / "Dockerfile.backend"
_WORKFLOW = _REPO / ".github" / "workflows" / "ci.yml"

#: Suppressed id -> the package whose build-time floor justifies it.
_COMPENSATING_FLOOR = {
    "CVE-2025-47273": ("setuptools", "78.1.1"),
    "GHSA-6v7p-g79w-8964": ("msgpack", "1.2.1"),
}


@pytest.fixture(scope="module")
def entries() -> list[dict]:
    data = yaml.safe_load(_IGNOREFILE.read_text())
    return list(data.get("vulnerabilities") or [])


def test_the_ignore_file_is_actually_wired_into_the_scan():
    """An ignore file the scanner never reads is a comment, not a control.

    Trivy runs inside a container, so the file has to be mounted *and* named
    with ``--ignorefile``. Both the gating scan and the diagnostic run must use
    it, or the two disagree about what counts as a finding.
    """
    workflow = _WORKFLOW.read_text()
    assert workflow.count("--ignorefile /.trivyignore.yaml") == 2, (
        "expected both Trivy invocations (diagnostic + gate) to pass "
        "--ignorefile; a mismatch makes the two report different findings"
    )
    assert workflow.count(".trivyignore.yaml:/.trivyignore.yaml:ro") == 2, (
        "the ignore file must be mounted into the Trivy container, read-only"
    )


def test_every_entry_states_its_reasoning(entries: list[dict]):
    for entry in entries:
        statement = (entry.get("statement") or "").strip()
        assert len(statement) > 40, (
            f"{entry.get('id')} is suppressed without a substantive statement; "
            "an exception with no argument cannot be reviewed"
        )


def test_every_entry_expires(entries: list[dict]):
    """No open-ended suppressions — an exception has to come back for review."""
    for entry in entries:
        assert entry.get("expired_at"), f"{entry.get('id')} has no expiry"


def test_no_entry_has_already_expired(entries: list[dict]):
    """Fails the build once an exception is past its review date.

    This is the point of the expiry: it converts "someone should look at this
    again" into a scheduled failure rather than an intention.
    """
    today = date.today()
    stale = [
        e["id"]
        for e in entries
        if isinstance(e.get("expired_at"), date) and e["expired_at"] < today
    ]
    assert not stale, (
        f"suppressions past their review date: {stale}. Re-verify the finding "
        "is still a false positive and set a new expiry, or delete the entry."
    )


@pytest.mark.parametrize(("cve", "pkg_floor"), sorted(_COMPENSATING_FLOOR.items()))
def test_the_compensating_build_floor_still_exists(cve: str, pkg_floor: tuple[str, str]):
    """The suppression is only safe while the build asserts the real version.

    Each entry's argument is "the image ships a patched version, and the build
    proves it". If that proof is removed, the entry stops being a false-positive
    suppression and becomes an unwatched CVE.
    """
    pkg, floor = pkg_floor
    dockerfile = _DOCKERFILE.read_text()
    assert f'"{pkg}>={floor}"' in dockerfile, (
        f"{cve} is suppressed on the grounds that the build enforces "
        f"{pkg}>={floor}, but that floor is no longer in Dockerfile.backend. "
        "Restore it or remove the suppression — right now the CVE is simply "
        "unwatched."
    )


def test_the_build_still_fails_on_an_unmet_floor():
    """The floor has to be *asserted*, not merely requested.

    ``pip install "setuptools>=78.1.1"`` can succeed while the image still
    carries a superseded copy — that is precisely what happened on #584, four
    times. The assertion after the install is what makes the floor load-bearing.
    """
    dockerfile = _DOCKERFILE.read_text()
    assert "assert v('setuptools') >= (78, 1, 1)" in dockerfile
    assert "assert v('msgpack') >= (1, 2, 1)" in dockerfile
    assert "expected exactly 1 $pkg metadata dir" in dockerfile, (
        "the single-metadata-directory check is part of the compensating "
        "control: a stale dist-info alongside a patched one is how the "
        "original finding survived several 'fixes'"
    )


def test_suppressions_are_limited_to_the_documented_set(entries: list[dict]):
    """A ratchet: adding a suppression is a deliberate edit to this test.

    Without it the file is an easy place to quietly park a red finding.
    """
    assert {e["id"] for e in entries} == set(_COMPENSATING_FLOOR), (
        "the suppression set changed. Add the new id here together with the "
        "compensating control that justifies it, or remove the entry."
    )
