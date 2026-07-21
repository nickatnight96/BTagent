"""Product-side default simulation scenarios for detection validation (#118).

The ``POST /validation/runs`` route replays these deterministic, fully synthetic,
MITRE-tagged scenarios through the ``windows_baseline`` Sigma pack to produce a
coverage report — the mock-first stand-in until live Atomic Red Team / Caldera
execution is wired (deferred). Event field names match the Windows
``process_creation`` logsource dialect the pack rules use (``Image`` /
``CommandLine`` / ``EventID``).

Defensive-facing: every payload is a benign detection-signature probe, not a
weaponizable technique — the encoded-PowerShell blob decodes to inert text.
Mirrors the golden-test scenario fixtures, kept in product code so the route
does not depend on the test tree.
"""

from __future__ import annotations

from btagent_shared.types.detection_validation import (
    SimulatedAttackEvent,
    SimulationScenario,
)

# Base64 of "echo" — inert, well under any real payload; present only so the
# ``encoded_powershell`` rule's ``-EncodedCommand`` signature matches.
_INERT_ENCODED_BLOB = "ZQBjAGgAbwA="


def _scenario_encoded_powershell() -> SimulationScenario:
    """T1059.001 — PowerShell ``-EncodedCommand`` (expected to fire)."""
    return SimulationScenario(
        id="default_encoded_powershell",
        name="Encoded PowerShell",
        description="PowerShell invoked with -EncodedCommand (T1059.001).",
        technique_ids=["T1059.001"],
        events=[
            SimulatedAttackEvent(
                event_id="default_evt_encoded_ps",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": f"powershell.exe -EncodedCommand {_INERT_ENCODED_BLOB}",
                    "EventID": 1,
                },
                expected_to_fire=True,
            )
        ],
    )


def _scenario_benign_powershell() -> SimulationScenario:
    """T1059.001 — benign PowerShell control (expected NOT to fire)."""
    return SimulationScenario(
        id="default_benign_powershell",
        name="Benign PowerShell",
        description="Plain PowerShell with no encoded command — a false-positive control.",
        technique_ids=["T1059.001"],
        events=[
            SimulatedAttackEvent(
                event_id="default_evt_benign_ps",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    "CommandLine": "powershell.exe -Command Get-Process",
                    "EventID": 1,
                },
                expected_to_fire=False,
            )
        ],
    )


def default_validation_scenarios() -> list[SimulationScenario]:
    """The built-in scenario set the validation route replays in mock mode."""
    return [_scenario_encoded_powershell(), _scenario_benign_powershell()]
