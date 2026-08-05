"""Every operator-tunable setting is findable in the deployment reference.

``Settings`` had 70 fields and the ``Environment Variables Reference`` in
``docs/DEPLOYMENT.md`` named 37 of them. The missing 33 were not internals —
they were the scheduled-hunt cadences, the behavioural and pattern sweep
windows, the TAXII poll knobs, the MFA secret-at-rest key, the SSO provider
maps, the webhook HMAC secret, and the token gating the Prometheus scrape.

An operator cannot tune what they cannot find. Worse, several of those
settings are the ones you reach for precisely when something is wrong at 3am:
"why has no hunt run since Tuesday" is answered by
``BTAGENT_HUNT_SCHEDULE_ENABLED`` deriving from ``BTAGENT_MOCK_CONNECTORS``,
which the reference did not mention at all.

Documentation rots because nothing forces a new setting to appear in it. This
is that force. It is deliberately mechanical — presence of the env-var name,
not the quality of the prose — because a test that pins wording gets deleted
the first time someone improves a sentence.

Anything genuinely internal goes in ``UNDOCUMENTED_BY_DESIGN`` with a reason.
It ships **empty**: every field of ``Settings`` today is something an operator
could reasonably want to set.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from btagent_backend.config import Settings

_DOC = Path(__file__).resolve().parents[2] / "docs" / "DEPLOYMENT.md"
_ENV_VAR = re.compile(r"`BTAGENT_([A-Z0-9_]+)`")

#: Settings deliberately absent from the operator reference, with the reason.
#: Ratchet: entries come off, never on. A field belongs here only if setting it
#: could never be the right answer for someone running this in production.
UNDOCUMENTED_BY_DESIGN: dict[str, str] = {}


def _documented_names() -> set[str]:
    return {m.group(1).lower() for m in _ENV_VAR.finditer(_DOC.read_text(encoding="utf-8"))}


def test_every_setting_is_documented_or_declared_internal():
    documented = _documented_names()
    missing = sorted(
        name
        for name in Settings.model_fields
        if name not in documented and name not in UNDOCUMENTED_BY_DESIGN
    )
    assert not missing, (
        "setting(s) absent from the Environment Variables Reference in "
        "docs/DEPLOYMENT.md:\n  "
        + "\n  ".join(f"BTAGENT_{n.upper()}" for n in missing)
        + "\n\nAdd a row (variable, default, required, one-line purpose) or, if it "
        "is genuinely internal, declare it in UNDOCUMENTED_BY_DESIGN with a reason."
    )


def test_declared_internal_settings_still_exist():
    """A stale exemption silently un-documents a field that was renamed."""
    stale = sorted(set(UNDOCUMENTED_BY_DESIGN) - set(Settings.model_fields))
    assert not stale, f"exemption(s) name settings that no longer exist: {stale}"


def test_the_reference_does_not_document_settings_that_were_removed():
    """A row for a deleted setting sends operators to configure nothing.

    Scoped to the reference table's own rows rather than the whole document,
    because the prose legitimately mentions env vars from compose files and
    worked examples that are not ``Settings`` fields.
    """
    text = _DOC.read_text(encoding="utf-8")
    start = text.find("## Environment Variables Reference")
    assert start != -1, "the Environment Variables Reference section is gone"

    fields = set(Settings.model_fields)
    phantom = [
        name
        for line in text[start:].splitlines()
        if line.startswith("| `BTAGENT_")
        for name in _ENV_VAR.findall(line)
        if name.lower() not in fields
    ]
    assert not phantom, (
        "the reference has a row for setting(s) that do not exist in Settings: "
        f"{sorted(set(phantom))}"
    )


# ---------------------------------------------------------------------------
# Guard the guard.
# ---------------------------------------------------------------------------


def test_the_scan_finds_the_reference_table():
    """A regex matching nothing would make every assertion above vacuous."""
    documented = _documented_names()
    assert len(documented) > 50, (
        f"only {len(documented)} BTAGENT_* names found in the doc; the scan or the "
        "reference table has drifted"
    )
    # Spot-check a few that must always be there.
    assert {"database_url", "jwt_secret", "cors_origins"} <= documented


def test_settings_has_a_plausible_number_of_fields():
    assert len(Settings.model_fields) > 40, (
        "Settings looks nearly empty; the import is probably resolving to a stub"
    )


@pytest.mark.parametrize(
    "name",
    ["hunt_run_resume_window_minutes", "hunt_schedule_enabled", "metrics_token"],
)
def test_specific_operator_facing_settings_are_present(name: str):
    """Named individually because each answers a real 3am question.

    - the resume window decides whether a sweep's coverage is silently dropped
    - the schedule gate explains "why has nothing run since we disabled mocks"
    - the metrics token is the difference between an open and a gated scrape
    """
    assert name in _documented_names(), f"BTAGENT_{name.upper()} is not in the reference"
