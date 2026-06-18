"""Pure-logic cloud control-plane hunt detections (Phase 6 #117).

Dependency-free (no DB, no network, no LLM) — operates solely on:
  * :mod:`btagent_shared.types.cloud_hunt` inventory models
  * Fixture-loaded IAM / CloudTrail / inventory data (see agents/tests/fixtures/cloud/)

Every public function either:
  1. Builds or traverses graph structures from identity inventory, or
  2. Runs a detection and returns :class:`~btagent_shared.types.hunt_finding.RecordFindingRequest`
     objects for the #119 triage queue.

Detections implemented (connector-independent, fixture-based):
  D1  STS AssumeRole chaining — transitive multi-hop attack paths from fixture IAM.
  D2  IAM persistence — new access key / inline policy / trust-policy mutation.
  D3  Cross-account trust abuse — untrusted external account in trust policy.
  D4  Snapshot / AMI external share — resource shared with external AWS account.
  D5  CloudTrail logging tamper — StopLogging correlated with prior suspicious auth.
  D6  Shadow agentic workload discovery — AI workloads without governance tags.
  D7  Overprivileged agentic identity — workload running as admin/broad-scope role.

Deferred (blocked on #100 CloudTrail/GuardDuty MCP connectors):
  - Live CloudTrail event ingestion
  - Real-time GuardDuty finding correlation
  - IAM Access Analyzer live-query
  - Cross-region control-plane anomaly detection
  - Live STS temporal analysis (after-hours AssumeRole, unusual source IP)
"""

from __future__ import annotations

import logging
from collections import defaultdict
from collections.abc import Iterable
from typing import Any

from btagent_shared.types.cloud_hunt import (
    AgenticWorkload,
    AgenticWorkloadKind,
    CloudIdentity,
    CloudProvider,
)
from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import HuntEntity, HuntObservable, RecordFindingRequest

logger = logging.getLogger("btagent.hunt.cloud")

# ── Constants ────────────────────────────────────────────────────────────────

# Risk score component weights (must sum ≤ 1.0 so the result stays in [0, 1]).
_SHADOW_WEIGHT = 0.4
_OVERPRIVILEGE_WEIGHT = 0.3
_INTERNET_WEIGHT = 0.2
_NO_ACTIVITY_WEIGHT = 0.1

# Maximum transitive hop depth for STS chaining analysis.
# Prevents pathological traversal of cyclic or very dense trust graphs.
_MAX_HOP_DEPTH = 10

# Technique IDs referenced across detections.
_T_ASSUME_ROLE = "T1550.001"  # Use Alternate Authentication Material: Application Access Token
_T_STS_CHAINING = "T1078.004"  # Valid Accounts: Cloud Accounts
_T_IAM_PERSISTENCE = "T1098.001"  # Account Manipulation: Additional Cloud Credentials
_T_TRUST_MUTATION = "T1098.003"  # Account Manipulation: Additional Cloud Roles
_T_SNAPSHOT_SHARE = "T1537"  # Transfer Data to Cloud Account
_T_CLOUDTRAIL_TAMPER = "T1562.008"  # Impair Defenses: Disable or Modify Cloud Logs
_T_SHADOW_WORKLOAD = "T1078.004"  # Valid Accounts: Cloud Accounts (shadow-AI context)
_T_OVERPRIVILEGED = "T1098.001"  # Account Manipulation: Additional Cloud Credentials

# ---------------------------------------------------------------------------
# Trust-graph construction
# ---------------------------------------------------------------------------


def build_trust_graph(
    identities: Iterable[CloudIdentity],
) -> dict[str, set[str]]:
    """Build an adjacency map of ``arn_or_id → set[direct trustees]``.

    The graph is directed: an edge A → B means "B can directly assume/impersonate A".
    Transitive paths are resolved by :func:`find_assumption_paths`.

    Parameters
    ----------
    identities:
        Iterable of :class:`~btagent_shared.types.cloud_hunt.CloudIdentity` records
        from a fixture or connector inventory.

    Returns
    -------
    dict[str, set[str]]
        Adjacency map.  Keys are ``arn_or_id`` values; values are the set of
        trustees that can directly assume the key principal.
    """
    graph: dict[str, set[str]] = defaultdict(set)
    for identity in identities:
        # Ensure every node appears in the map even if it has no trustees.
        if identity.arn_or_id not in graph:
            graph[identity.arn_or_id] = set()
        for trustee in identity.can_be_assumed_by:
            graph[identity.arn_or_id].add(trustee)
    return dict(graph)


def find_assumption_paths(
    graph: dict[str, set[str]],
    source: str,
    target: str,
    *,
    max_depth: int = _MAX_HOP_DEPTH,
) -> list[list[str]]:
    """Find all simple paths from ``source`` to ``target`` in the trust graph.

    A path [A, B, C, D] means: source A can assume B, B can assume C,
    C can assume target D — a three-hop chain.

    Uses BFS up to ``max_depth`` hops to avoid infinite traversal in
    dense/cyclic graphs.  Cycles are detected by tracking visited nodes
    per path (simple-path guarantee).

    Parameters
    ----------
    graph:
        Output of :func:`build_trust_graph`.
    source:
        Starting principal ARN/ID (the attacker-controlled or compromised identity).
    target:
        Destination principal ARN/ID (the high-value target).
    max_depth:
        Maximum number of hops before a path is abandoned.

    Returns
    -------
    list[list[str]]
        All simple paths from source to target.  Empty if unreachable.
    """
    # Invert graph: we want "who can source assume?" not "who can assume source?"
    # The graph stores assumes[target] = {trustees that can assume target}.
    # We need: reachable[source] = {targets that source can assume}.
    reachable: dict[str, set[str]] = defaultdict(set)
    for assumed, trustees in graph.items():
        for trustee in trustees:
            reachable[trustee].add(assumed)

    # BFS — queue entries are partial paths.
    paths: list[list[str]] = []
    queue: list[list[str]] = [[source]]

    while queue:
        path = queue.pop(0)
        current = path[-1]

        if current == target and len(path) > 1:
            paths.append(list(path))
            continue

        if len(path) > max_depth:
            continue

        for neighbor in reachable.get(current, set()):
            if neighbor not in path:  # simple-path: no cycles
                queue.append(path + [neighbor])

    return paths


def transitive_reachable(
    graph: dict[str, set[str]],
    source: str,
    *,
    max_depth: int = _MAX_HOP_DEPTH,
) -> set[str]:
    """All principals that ``source`` can reach transitively (BFS).

    Parameters
    ----------
    graph:
        Output of :func:`build_trust_graph`.
    source:
        Starting principal.
    max_depth:
        Max traversal depth.

    Returns
    -------
    set[str]
        All ARN/IDs reachable from source (excluding source itself).
    """
    reachable_map: dict[str, set[str]] = defaultdict(set)
    for assumed, trustees in graph.items():
        for trustee in trustees:
            reachable_map[trustee].add(assumed)

    visited: set[str] = set()
    queue = [(source, 0)]
    while queue:
        node, depth = queue.pop(0)
        if node in visited:
            continue
        visited.add(node)
        if depth >= max_depth:
            continue
        for neighbor in reachable_map.get(node, set()):
            if neighbor not in visited:
                queue.append((neighbor, depth + 1))

    visited.discard(source)
    return visited


# ---------------------------------------------------------------------------
# Risk scoring for agentic workloads
# ---------------------------------------------------------------------------


def score_workload_risk(workload: AgenticWorkload) -> float:
    """Compute deterministic risk score for an agentic workload.

    Score components (additive, capped at 1.0):
    - Shadow (untagged / outside sanctioned patterns): +0.4
    - Overprivileged identity (broad/wildcard perms): +0.3
    - Internet-reachable ingress: +0.2
    - No observed activity (data gap / dormant but running): +0.1

    Returns
    -------
    float
        Risk score in [0.0, 1.0].
    """
    score = 0.0
    # Codex #207: score the workload's *derived* shadow classification, not just
    # the separately-supplied ``is_shadow`` flag. A default untagged (or
    # UNMANAGED-kind) workload is emitted as shadow by detect_shadow_workloads()
    # via classify_workload(); the score must use the same predicate so such a
    # workload is not under-scored when its is_shadow flag was never set.
    if classify_workload(workload) or workload.is_shadow:
        score += _SHADOW_WEIGHT
    if workload.has_overprivileged_identity:
        score += _OVERPRIVILEGE_WEIGHT
    if workload.internet_reachable:
        score += _INTERNET_WEIGHT
    if workload.last_activity is None:
        score += _NO_ACTIVITY_WEIGHT
    return min(score, 1.0)


def classify_workload(workload: AgenticWorkload) -> bool:
    """Return ``True`` if the workload should be treated as *shadow*.

    A workload is shadow when:
    - ``governance_tagged`` is False, OR
    - ``kind`` is :attr:`~AgenticWorkloadKind.UNMANAGED`.

    Both conditions are evaluated independently so unmanaged *and* untagged
    workloads are caught even if one flag is somehow set correctly.
    """
    return not workload.governance_tagged or workload.kind == AgenticWorkloadKind.UNMANAGED


# ---------------------------------------------------------------------------
# D1 — STS AssumeRole chaining (transitive attack-path detection)
# ---------------------------------------------------------------------------


def detect_sts_chaining(
    identities: list[CloudIdentity],
    *,
    high_value_targets: set[str] | None = None,
    min_hops: int = 2,
) -> list[RecordFindingRequest]:
    """Detect multi-hop STS AssumeRole chaining attack paths.

    Scans the trust graph for paths where a low-privilege or external principal
    can reach a high-value target through ≥ ``min_hops`` intermediate roles.

    Parameters
    ----------
    identities:
        All CloudIdentity records in the scoped inventory.
    high_value_targets:
        Set of ARN/IDs considered high-value (e.g. admin roles, billing roles).
        Defaults to any role with ``admin`` / ``root`` / ``billing`` in its name.
    min_hops:
        Minimum chain length to report (≥2 means at least one intermediate hop).

    Returns
    -------
    list[RecordFindingRequest]
        One finding per discovered attack path.
    """
    graph = build_trust_graph(identities)
    identity_by_arn = {i.arn_or_id: i for i in identities}

    if high_value_targets is None:
        high_value_targets = {
            arn
            for arn in graph
            if any(
                kw in arn.lower() for kw in ("admin", "root", "billing", "orgadmin", "poweruser")
            )
        }

    findings: list[RecordFindingRequest] = []

    for target_arn in high_value_targets:
        for source_arn in graph:
            if source_arn == target_arn:
                continue
            paths = find_assumption_paths(graph, source_arn, target_arn)
            for path in paths:
                if len(path) < min_hops + 1:
                    continue
                hop_count = len(path) - 1
                target_identity = identity_by_arn.get(target_arn)
                source_identity = identity_by_arn.get(source_arn)
                sev = Severity.CRITICAL if hop_count >= 3 else Severity.HIGH
                findings.append(
                    RecordFindingRequest(
                        source=HuntSource.CLOUD,
                        domain=HuntDomain.CLOUD,
                        title=(
                            f"STS AssumeRole chain: {source_arn} → {target_arn} ({hop_count} hops)"
                        ),
                        description=(
                            f"Transitive role-assumption path detected: "
                            f"{' → '.join(path)}. "
                            f"A compromised or external principal at {source_arn!r} "
                            f"can reach high-value role {target_arn!r} via "
                            f"{hop_count} AssumeRole hops."
                        ),
                        severity=sev,
                        confidence=0.85,
                        technique_ids=[_T_STS_CHAINING, _T_ASSUME_ROLE],
                        entities=[
                            HuntEntity(kind="cloud_identity", value=source_arn),
                            HuntEntity(kind="cloud_identity", value=target_arn),
                        ],
                        observables=[
                            HuntObservable(type="aws_arn", value=arn)
                            for arn in path
                            if identity_by_arn.get(arn)
                        ],
                        evidence={
                            "detection": "sts_chaining",
                            "hop_count": hop_count,
                            "path": path,
                            "provider": (
                                target_identity or source_identity or identities[0]
                            ).provider.value
                            if identities
                            else "aws",
                            "high_value_target": target_arn,
                        },
                    )
                )

    return findings


# ---------------------------------------------------------------------------
# D2 — IAM persistence (new access key / inline policy / trust mutation)
# ---------------------------------------------------------------------------


def detect_iam_persistence(
    events: list[dict[str, Any]],
) -> list[RecordFindingRequest]:
    """Detect IAM persistence tactics from CloudTrail-style fixture events.

    Looks for:
    - ``CreateAccessKey`` — new long-lived credential added to an IAM user.
    - ``PutUserPolicy`` / ``PutRolePolicy`` — inline policy attached (no SCP guardrail).
    - ``UpdateAssumeRolePolicy`` — trust-policy mutation enabling a new trustee.

    Parameters
    ----------
    events:
        List of CloudTrail-style event dicts.  Required keys per event:
        ``{"eventName": str, "userIdentity": {"arn": str}, "requestParameters": dict,
           "eventTime": str, "awsRegion": str}``.

    Returns
    -------
    list[RecordFindingRequest]
    """
    findings: list[RecordFindingRequest] = []
    persistence_events = {
        "CreateAccessKey": (_T_IAM_PERSISTENCE, Severity.HIGH, 0.90),
        "PutUserPolicy": (_T_TRUST_MUTATION, Severity.HIGH, 0.85),
        "PutRolePolicy": (_T_TRUST_MUTATION, Severity.HIGH, 0.85),
        "UpdateAssumeRolePolicy": (_T_TRUST_MUTATION, Severity.CRITICAL, 0.92),
        "CreateVirtualMFADevice": (_T_IAM_PERSISTENCE, Severity.MEDIUM, 0.70),
        "DeactivateMFADevice": (_T_IAM_PERSISTENCE, Severity.HIGH, 0.88),
    }

    for event in events:
        event_name = event.get("eventName", "")
        if event_name not in persistence_events:
            continue
        technique, sev, confidence = persistence_events[event_name]
        actor_arn = (event.get("userIdentity") or {}).get("arn", "unknown")
        target_resource = str(
            (event.get("requestParameters") or {}).get("userName")
            or (event.get("requestParameters") or {}).get("roleName")
            or "unknown"
        )
        findings.append(
            RecordFindingRequest(
                source=HuntSource.CLOUD,
                domain=HuntDomain.CLOUD,
                title=f"IAM persistence activity: {event_name} by {actor_arn}",
                description=(
                    f"CloudTrail recorded {event_name!r} performed by {actor_arn!r} "
                    f"on resource {target_resource!r}. This is a known IAM persistence "
                    f"technique that may establish long-lived backdoor access."
                ),
                severity=sev,
                confidence=confidence,
                technique_ids=[technique, _T_IAM_PERSISTENCE],
                entities=[
                    HuntEntity(kind="cloud_identity", value=actor_arn),
                    HuntEntity(kind="iam_resource", value=target_resource),
                ],
                evidence={
                    "detection": "iam_persistence",
                    "event_name": event_name,
                    "event_time": event.get("eventTime"),
                    "aws_region": event.get("awsRegion"),
                    "request_parameters": event.get("requestParameters"),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# D3 — Cross-account trust abuse
# ---------------------------------------------------------------------------


def detect_cross_account_trust_abuse(
    identities: list[CloudIdentity],
    *,
    trusted_account_ids: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Flag roles/identities with trust relationships to unexpected external accounts.

    Parameters
    ----------
    identities:
        Scoped CloudIdentity inventory.
    trusted_account_ids:
        Set of AWS account IDs (12-digit strings) that are *expected* trustees.
        Any trustee outside this set is flagged.  Defaults to empty (all
        cross-account trust is suspicious).

    Returns
    -------
    list[RecordFindingRequest]
    """
    if trusted_account_ids is None:
        trusted_account_ids = set()

    findings: list[RecordFindingRequest] = []

    for identity in identities:
        if not identity.has_cross_account_trust:
            continue

        # Extract account IDs from trustee ARNs.
        # AWS ARN format: arn:aws:iam::<account-id>:root or arn:aws:sts::<account-id>:...
        external_trustees: list[str] = []
        for trustee in identity.can_be_assumed_by:
            parts = trustee.split(":")
            # Minimal ARN has at least 6 colon-separated parts; account ID is index 4.
            if len(parts) >= 6:
                account_id = parts[4]
                if account_id and account_id not in trusted_account_ids:
                    external_trustees.append(trustee)
            elif trustee not in trusted_account_ids:
                # Non-ARN format trustee (e.g. service principal) — flag if not whitelisted.
                external_trustees.append(trustee)

        if not external_trustees:
            continue

        findings.append(
            RecordFindingRequest(
                source=HuntSource.CLOUD,
                domain=HuntDomain.CLOUD,
                title=(
                    f"Cross-account trust abuse: {identity.arn_or_id} trusted by "
                    f"{len(external_trustees)} external principal(s)"
                ),
                description=(
                    f"Identity {identity.arn_or_id!r} ({identity.kind}) has trust "
                    f"relationships with external principals not in the approved list: "
                    f"{', '.join(external_trustees[:5])}. "
                    "Cross-account trust abuse allows lateral movement across AWS accounts."
                ),
                severity=Severity.HIGH,
                confidence=0.88,
                technique_ids=[_T_STS_CHAINING, _T_ASSUME_ROLE],
                entities=[
                    HuntEntity(kind="cloud_identity", value=identity.arn_or_id),
                    *[HuntEntity(kind="external_trustee", value=t) for t in external_trustees],
                ],
                observables=[
                    HuntObservable(type="aws_arn", value=identity.arn_or_id),
                    *[HuntObservable(type="external_aws_arn", value=t) for t in external_trustees],
                ],
                evidence={
                    "detection": "cross_account_trust_abuse",
                    "identity_arn": identity.arn_or_id,
                    "provider": identity.provider.value,
                    "external_trustees": external_trustees,
                    "trusted_account_ids": list(trusted_account_ids),
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# D4 — Snapshot / AMI external share
# ---------------------------------------------------------------------------


def detect_snapshot_external_share(
    resource_events: list[dict[str, Any]],
    *,
    trusted_account_ids: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Detect EBS snapshot or AMI shared with an external AWS account.

    Parameters
    ----------
    resource_events:
        List of CloudTrail-style resource-sharing events.
        Expected keys: ``{"eventName": str, "requestParameters": dict,
                          "userIdentity": {"arn": str}, "eventTime": str}``.
    trusted_account_ids:
        AWS account IDs that are approved for cross-account sharing.

    Returns
    -------
    list[RecordFindingRequest]
    """
    if trusted_account_ids is None:
        trusted_account_ids = set()

    share_events = {
        "ModifySnapshotAttribute",
        "ModifyImageAttribute",
        "ModifyDBSnapshotAttribute",
    }

    findings: list[RecordFindingRequest] = []

    for event in resource_events:
        event_name = event.get("eventName", "")
        if event_name not in share_events:
            continue

        params = event.get("requestParameters") or {}
        # AWS ModifySnapshotAttribute uses launchPermission / createVolumePermission.
        add_perms = (
            params.get("createVolumePermission", {}).get("add", {}).get("items", [])
            or params.get("launchPermission", {}).get("add", {}).get("items", [])
            or params.get("valuesToAdd", [])
        )

        external_accounts: list[str] = []
        for perm in add_perms:
            # Codex #207: ModifyDBSnapshotAttribute's ``valuesToAdd`` is a list of
            # account-ID *strings*, whereas Modify{Snapshot,Image}Attribute carry
            # permission *mappings* ({"userId": ...} / {"group": ...}). Handle both
            # shapes so a string entry doesn't raise AttributeError and abort the
            # whole detection sweep.
            if isinstance(perm, str):
                account_id = perm
            elif isinstance(perm, dict):
                account_id = perm.get("userId") or perm.get("group") or ""
            else:
                account_id = ""
            if account_id == "all" or (account_id and account_id not in trusted_account_ids):
                external_accounts.append(account_id)

        if not external_accounts:
            continue

        resource_id = str(
            params.get("snapshotId")
            or params.get("imageId")
            or params.get("dBSnapshotIdentifier")
            or "unknown"
        )
        actor_arn = (event.get("userIdentity") or {}).get("arn", "unknown")
        is_public = "all" in external_accounts

        findings.append(
            RecordFindingRequest(
                source=HuntSource.CLOUD,
                domain=HuntDomain.CLOUD,
                title=(
                    f"{'PUBLIC' if is_public else 'External'} snapshot/AMI share: "
                    f"{resource_id} via {event_name}"
                ),
                description=(
                    f"Resource {resource_id!r} was shared {'publicly' if is_public else 'externally'} "
                    f"by {actor_arn!r} using {event_name}. "
                    "Sharing snapshots/AMIs externally can exfiltrate sensitive data "
                    "or enable cross-account resource abuse."
                ),
                severity=Severity.CRITICAL if is_public else Severity.HIGH,
                confidence=0.95,
                technique_ids=[_T_SNAPSHOT_SHARE],
                entities=[
                    HuntEntity(kind="cloud_identity", value=actor_arn),
                    HuntEntity(kind="cloud_resource", value=resource_id),
                ],
                observables=[
                    HuntObservable(type="aws_resource_id", value=resource_id),
                    *[
                        HuntObservable(type="external_aws_account", value=a)
                        for a in external_accounts
                    ],
                ],
                evidence={
                    "detection": "snapshot_external_share",
                    "event_name": event_name,
                    "event_time": event.get("eventTime"),
                    "resource_id": resource_id,
                    "external_accounts": external_accounts,
                    "is_public": is_public,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# D5 — CloudTrail logging tamper (StopLogging correlated with prior suspicious auth)
# ---------------------------------------------------------------------------


def detect_cloudtrail_tamper(
    events: list[dict[str, Any]],
    *,
    suspicious_auth_window_seconds: int = 3600,
) -> list[RecordFindingRequest]:
    """Detect CloudTrail StopLogging correlated with prior suspicious authentication.

    Heuristic: if a ``StopLogging`` or ``DeleteTrail`` event is preceded by a
    suspicious-auth event (``ConsoleLogin`` from unusual source, or ``GetSessionToken``
    with ``mfa_authenticated=False``) within ``suspicious_auth_window_seconds``, the
    pair is flagged as a coordinated logging-tamper attempt.

    Parameters
    ----------
    events:
        CloudTrail-style events sorted by ``eventTime`` ascending.
    suspicious_auth_window_seconds:
        Time window (seconds) to look backwards from a tamper event for prior
        suspicious auth activity.

    Returns
    -------
    list[RecordFindingRequest]
    """
    import re
    from datetime import datetime, timedelta

    # Events that unconditionally disable / destroy logging.
    _ALWAYS_DISABLE_EVENTS = {"StopLogging", "DeleteTrail", "DeleteFlowLogs"}
    # UpdateTrail is only tampering when it actually disables logging (see below).
    _CONDITIONAL_TAMPER_EVENTS = {"UpdateTrail"}
    _SUSPICIOUS_AUTH_EVENTS = {"ConsoleLogin", "GetSessionToken", "AssumeRole"}

    def _parse_event_time(ev: dict[str, Any]) -> datetime | None:
        ts = ev.get("eventTime")
        if not ts:
            return None
        # Support both ISO-8601 with 'Z' and with timezone offset.
        ts = re.sub(r"Z$", "+00:00", str(ts))
        try:
            return datetime.fromisoformat(ts)
        except ValueError:
            return None

    def _is_logging_disable_update(ev: dict[str, Any]) -> bool:
        """Codex #207: only an UpdateTrail that *disables* logging is tampering.

        Mirrors the accompanying ``cloudtrail_stoplog.yml`` Sigma rule's
        ``selection_update_disable`` predicate
        (``requestParameters.enableLogFileValidation: 'false'``). Routine
        UpdateTrail changes — destination/bucket updates, *enabling* log-file
        validation, multi-region toggles — do not disable logging and must not
        fire. Both the AWS API field name and the falsy value are matched
        case-insensitively across str/bool shapes.
        """
        params = ev.get("requestParameters") or {}
        if not isinstance(params, dict):
            return False
        # Log-file validation explicitly turned off.
        validation = params.get("enableLogFileValidation")
        if validation is not None and str(validation).strip().lower() == "false":
            return True
        # CloudWatch Logs delivery / global-service-event capture disabled — both
        # blind portions of the audit trail.
        for key in ("includeGlobalServiceEvents", "isLogging", "isMultiRegionTrail"):
            value = params.get(key)
            if value is not None and str(value).strip().lower() == "false":
                return True
        return False

    def _is_suspicious_auth(ev: dict[str, Any]) -> bool:
        """Codex #207: apply the documented unusual-source / no-MFA criteria.

        A ConsoleLogin / AssumeRole / GetSessionToken only corroborates a
        logging-tamper event when it shows genuinely suspicious authentication:
        MFA was not used, or the call originated from an unusual source. Without
        this gate any unrelated login in the lookback window wrongly escalated
        the finding to CRITICAL.
        """
        name = ev.get("eventName", "")
        if name not in _SUSPICIOUS_AUTH_EVENTS:
            return False

        additional = ev.get("additionalEventData") or {}
        if not isinstance(additional, dict):
            additional = {}

        # MFA signal: present on ConsoleLogin and STS calls. Treat an explicit
        # "false"/"no" as suspicious; an explicit "true"/"yes" is corroborating-
        # clean. AWS uses ``mfaAuthenticated`` (STS) and ``MFAUsed`` (ConsoleLogin).
        mfa = additional.get("mfaAuthenticated")
        if mfa is None:
            mfa = additional.get("MFAUsed")
        if mfa is None:
            mfa = (ev.get("requestParameters") or {}).get("mfaAuthenticated")
        mfa_str = str(mfa).strip().lower() if mfa is not None else None
        if mfa_str in ("false", "no"):
            return True
        if mfa_str in ("true", "yes"):
            return False

        # Unusual-source signal — an explicit flag set by the fixture/connector
        # shim, or a non-AWS-service source IP marked unusual.
        if str(additional.get("unusualSource", "")).strip().lower() == "true":
            return True
        if str(ev.get("unusualSource", "")).strip().lower() == "true":
            return True

        # No MFA evidence and no unusual-source signal — not corroborating.
        return False

    # Separate events by category.
    suspicious_auths: list[tuple[datetime, dict[str, Any]]] = []
    tamper_events: list[tuple[datetime, dict[str, Any]]] = []

    for ev in events:
        ts = _parse_event_time(ev)
        if ts is None:
            continue
        name = ev.get("eventName", "")
        if name in _ALWAYS_DISABLE_EVENTS or (
            name in _CONDITIONAL_TAMPER_EVENTS and _is_logging_disable_update(ev)
        ):
            tamper_events.append((ts, ev))
        elif _is_suspicious_auth(ev):
            suspicious_auths.append((ts, ev))

    window = timedelta(seconds=suspicious_auth_window_seconds)
    findings: list[RecordFindingRequest] = []

    for tamper_ts, tamper_ev in tamper_events:
        actor_arn = (tamper_ev.get("userIdentity") or {}).get("arn", "unknown")
        trail_arn = str(
            (tamper_ev.get("requestParameters") or {}).get("trailARN")
            or (tamper_ev.get("requestParameters") or {}).get("name")
            or "unknown"
        )
        event_name = tamper_ev.get("eventName", "")

        # Collect any suspicious auths that preceded this tamper within the window.
        correlated_auths: list[dict[str, Any]] = [
            auth_ev
            for auth_ts, auth_ev in suspicious_auths
            if tamper_ts - window <= auth_ts < tamper_ts
        ]

        if not correlated_auths:
            # Still flag standalone StopLogging/DeleteTrail, but with lower confidence.
            findings.append(
                RecordFindingRequest(
                    source=HuntSource.CLOUD,
                    domain=HuntDomain.CLOUD,
                    title=f"CloudTrail logging tamper: {event_name} by {actor_arn}",
                    description=(
                        f"CloudTrail control event {event_name!r} detected on trail "
                        f"{trail_arn!r}. No correlated suspicious authentication found "
                        "in the lookback window, but logging tamper is always high priority."
                    ),
                    severity=Severity.HIGH,
                    confidence=0.75,
                    technique_ids=[_T_CLOUDTRAIL_TAMPER],
                    entities=[HuntEntity(kind="cloud_identity", value=actor_arn)],
                    observables=[HuntObservable(type="cloudtrail_trail_arn", value=trail_arn)],
                    evidence={
                        "detection": "cloudtrail_tamper",
                        "event_name": event_name,
                        "event_time": tamper_ev.get("eventTime"),
                        "trail_arn": trail_arn,
                        "correlated_suspicious_auths": [],
                    },
                )
            )
        else:
            prior_actors = list(
                {a.get("userIdentity", {}).get("arn", "?") for a in correlated_auths}
            )
            findings.append(
                RecordFindingRequest(
                    source=HuntSource.CLOUD,
                    domain=HuntDomain.CLOUD,
                    title=(
                        f"CloudTrail tamper + prior suspicious auth: {event_name} "
                        f"(correlated with {len(correlated_auths)} auth event(s))"
                    ),
                    description=(
                        f"CloudTrail {event_name!r} on {trail_arn!r} detected, "
                        f"correlated with {len(correlated_auths)} suspicious authentication "
                        f"event(s) in the preceding {suspicious_auth_window_seconds}s "
                        f"from: {', '.join(prior_actors)}. "
                        "This pattern suggests an attacker is disabling logging to cover tracks."
                    ),
                    severity=Severity.CRITICAL,
                    confidence=0.93,
                    technique_ids=[_T_CLOUDTRAIL_TAMPER, _T_STS_CHAINING],
                    entities=[
                        HuntEntity(kind="cloud_identity", value=actor_arn),
                        *[
                            HuntEntity(kind="prior_auth_actor", value=a)
                            for a in prior_actors
                            if a != "?"
                        ],
                    ],
                    observables=[
                        HuntObservable(type="cloudtrail_trail_arn", value=trail_arn),
                    ],
                    evidence={
                        "detection": "cloudtrail_tamper",
                        "event_name": event_name,
                        "event_time": tamper_ev.get("eventTime"),
                        "trail_arn": trail_arn,
                        "correlated_suspicious_auths": [
                            {
                                "eventName": a.get("eventName"),
                                "eventTime": a.get("eventTime"),
                                "actorArn": (a.get("userIdentity") or {}).get("arn"),
                            }
                            for a in correlated_auths
                        ],
                    },
                )
            )

    return findings


# ---------------------------------------------------------------------------
# D6 — Shadow agentic workload discovery
# ---------------------------------------------------------------------------


def detect_shadow_workloads(
    workloads: list[AgenticWorkload],
) -> list[RecordFindingRequest]:
    """Emit one finding per shadow agentic workload in the inventory.

    A *shadow* workload is one where ``classify_workload()`` returns True
    (untagged or UNMANAGED kind).  Findings are distinctly marked with
    ``"shadow_workload": True`` in evidence so the downstream triage agent can
    route them to a governance workflow.

    The governance workflow itself is deferred (out of scope for this slice).

    Parameters
    ----------
    workloads:
        All :class:`~btagent_shared.types.cloud_hunt.AgenticWorkload` records
        from a fixture or connector inventory.

    Returns
    -------
    list[RecordFindingRequest]
        One finding per shadow workload.
    """
    findings: list[RecordFindingRequest] = []

    for wl in workloads:
        if not classify_workload(wl):
            continue  # managed and tagged — not shadow

        risk = score_workload_risk(wl)
        sev = (
            Severity.CRITICAL if risk >= 0.8 else Severity.HIGH if risk >= 0.5 else Severity.MEDIUM
        )

        findings.append(
            RecordFindingRequest(
                source=HuntSource.CLOUD,
                domain=HuntDomain.CLOUD,
                title=(
                    f"Shadow agentic workload: {wl.display_name or wl.resource_id} "
                    f"({wl.kind} / {wl.provider})"
                ),
                description=(
                    f"Agentic workload {wl.resource_id!r} (kind={wl.kind}, "
                    f"provider={wl.provider}) is not governance-tagged "
                    f"{'and is of unmanaged kind ' if wl.kind == AgenticWorkloadKind.UNMANAGED else ''}"
                    f"(risk_score={risk:.2f}). "
                    "Shadow AI agents may exfiltrate data, bypass access controls, or "
                    "consume cloud budget without oversight. "
                    "Route to governance workflow (deferred) for remediation."
                ),
                severity=sev,
                confidence=0.90,
                technique_ids=[_T_SHADOW_WORKLOAD],
                entities=[
                    HuntEntity(kind="agentic_workload", value=wl.resource_id),
                    HuntEntity(kind="cloud_identity", value=wl.identity_ref),
                ],
                observables=[
                    HuntObservable(type="cloud_resource_id", value=wl.resource_id),
                ],
                evidence={
                    "detection": "shadow_workload",
                    "shadow_workload": True,  # routing marker for governance workflow
                    "kind": wl.kind.value,
                    "provider": wl.provider.value,
                    "governance_tagged": wl.governance_tagged,
                    "is_shadow": wl.is_shadow,
                    "has_overprivileged_identity": wl.has_overprivileged_identity,
                    "internet_reachable": wl.internet_reachable,
                    "risk_score": risk,
                    "identity_ref": wl.identity_ref,
                    # governance_workflow_deferred: see PR description / live-wiring TODO
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# D7 — Overprivileged agentic identity
# ---------------------------------------------------------------------------


def detect_overprivileged_workload_identity(
    workloads: list[AgenticWorkload],
    identities: list[CloudIdentity],
) -> list[RecordFindingRequest]:
    """Flag agentic workloads whose linked identity has overly broad permissions.

    Combines the ``AgenticWorkload.has_overprivileged_identity`` flag (set by
    the fixture or connector shim) with optional cross-reference to the
    :class:`CloudIdentity` record.

    Parameters
    ----------
    workloads:
        All AgenticWorkload records in scope.
    identities:
        All CloudIdentity records in scope.

    Returns
    -------
    list[RecordFindingRequest]
    """
    identity_map = {i.arn_or_id: i for i in identities}
    findings: list[RecordFindingRequest] = []

    for wl in workloads:
        if not wl.has_overprivileged_identity:
            continue
        linked_identity = identity_map.get(wl.identity_ref)
        identity_display = (
            linked_identity.display_name or wl.identity_ref if linked_identity else wl.identity_ref
        )

        findings.append(
            RecordFindingRequest(
                source=HuntSource.CLOUD,
                domain=HuntDomain.CLOUD,
                title=(
                    f"Overprivileged agentic identity: {wl.display_name or wl.resource_id} "
                    f"runs as {identity_display}"
                ),
                description=(
                    f"Agentic workload {wl.resource_id!r} runs as {wl.identity_ref!r}, "
                    "which has broad or wildcard IAM permissions. "
                    "Principle of least privilege requires agentic workloads to run "
                    "with scoped, purpose-built identities. "
                    "A compromised agent with admin-level credentials could exfiltrate "
                    "data across the entire account."
                ),
                severity=Severity.HIGH,
                confidence=0.88,
                technique_ids=[_T_OVERPRIVILEGED, _T_SHADOW_WORKLOAD],
                entities=[
                    HuntEntity(kind="agentic_workload", value=wl.resource_id),
                    HuntEntity(kind="cloud_identity", value=wl.identity_ref),
                ],
                observables=[
                    HuntObservable(type="cloud_resource_id", value=wl.resource_id),
                    HuntObservable(type="iam_identity_ref", value=wl.identity_ref),
                ],
                evidence={
                    "detection": "overprivileged_workload_identity",
                    "workload_id": wl.resource_id,
                    "identity_ref": wl.identity_ref,
                    "provider": wl.provider.value,
                    "kind": wl.kind.value,
                    "has_overprivileged_identity": True,
                },
            )
        )

    return findings


# ---------------------------------------------------------------------------
# Convenience: run all detections over a combined fixture bundle
# ---------------------------------------------------------------------------


def run_all_detections(
    *,
    identities: list[CloudIdentity] | None = None,
    workloads: list[AgenticWorkload] | None = None,
    cloudtrail_events: list[dict[str, Any]] | None = None,
    resource_events: list[dict[str, Any]] | None = None,
    high_value_targets: set[str] | None = None,
    trusted_account_ids: set[str] | None = None,
) -> list[RecordFindingRequest]:
    """Run all connector-independent detections over a fixture bundle.

    Convenience wrapper for the golden test runner and future engine node.
    Each detection is silently skipped if its required inputs are absent.

    Returns
    -------
    list[RecordFindingRequest]
        All findings from all detections, unsorted.  Deduplication is handled
        by the downstream triage clustering logic (#119).
    """
    findings: list[RecordFindingRequest] = []

    _identities = identities or []
    _workloads = workloads or []
    _ct_events = cloudtrail_events or []
    _res_events = resource_events or []

    if _identities:
        findings.extend(detect_sts_chaining(_identities, high_value_targets=high_value_targets))
        findings.extend(
            detect_cross_account_trust_abuse(_identities, trusted_account_ids=trusted_account_ids)
        )

    if _ct_events:
        findings.extend(detect_iam_persistence(_ct_events))
        findings.extend(detect_cloudtrail_tamper(_ct_events))

    if _res_events:
        findings.extend(
            detect_snapshot_external_share(_res_events, trusted_account_ids=trusted_account_ids)
        )

    if _workloads:
        findings.extend(detect_shadow_workloads(_workloads))
        findings.extend(detect_overprivileged_workload_identity(_workloads, _identities))

    logger.info("Cloud hunt detections complete: %d findings", len(findings))
    return findings
