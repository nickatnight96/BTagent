"""Code-based detector: shadow-MCP correlation (agentic hunt pack #121, Phase C).

Correlates two host-telemetry streams to surface a **shadow MCP server** — an
unsanctioned Model-Context-Protocol server process reaching out to an endpoint
outside the approved allowlist:

  1. **process-cmdline** records — processes whose name / command line identify
     an MCP server or agent runtime (``mcp-server``, ``mcp_runtime``,
     ``@modelcontextprotocol/...``, ``mcp-proxy``, ``--mcp``, ``agent-runtime``).
  2. **DNS-resolution** records — outbound name lookups the host performed.

The join is *code-side* (control-plane), the defensive complement to the
network-side Sigma rule ``mcp_server_egress_to_unknown_endpoint.yml``: when an
MCP-server process on a host resolved a hostname that is **not** in the
sanctioned MCP-endpoint allowlist, the pair is emitted as a shadow-MCP finding.
Where the Sigma rule fires on the wire (needing an EDR network+process feed
already joined), this detector performs the correlation itself over the two raw
streams and carries the same governance routing marker
(``evidence["shadow_workload"] = True``) the shadow-agent detectors use, so
cloud-, agentic-, and host-discovered shadow MCP servers converge in one queue.

Pure-logic and dependency-free (Pydantic only) — no DB, no network, no EDR SDK.

Live-wiring TODO (deferred, #100):
  Replace the fixture-supplied ``dns_events`` + ``process_events`` with a live
  pull from an EDR process+DNS telemetry MCP connector (CrowdStrike / Defender /
  SentinelOne process-tree + DNS-request events), normalised to
  :class:`DnsResolutionEvent` + :class:`ProcessCmdlineEvent`. The correlation
  logic itself requires no changes.
"""

from __future__ import annotations

import re
from collections import defaultdict

from btagent_shared.types.enums import Severity
from btagent_shared.types.hunt import HuntDomain, HuntSource
from btagent_shared.types.hunt_finding import (
    HuntEntity,
    HuntObservable,
    RecordFindingRequest,
)
from pydantic import BaseModel, ConfigDict, Field

# MITRE technique ids for the correlated signal.
_T_APP_LAYER_C2 = "T1071.001"  # Application Layer Protocol: Web Protocols (C2 channel)
_T_EXFIL_WEB = "T1567"  # Exfiltration Over Web Service
_T_SHADOW_WORKLOAD = "T1580"  # Cloud Infrastructure Discovery / shadow-IT proxy

# Default sanctioned MCP-endpoint suffixes — kept in lock-step with the Sigma
# rule ``mcp_server_egress_to_unknown_endpoint.yml`` filter. Tune per env.
_DEFAULT_SANCTIONED_SUFFIXES: tuple[str, ...] = (
    ".internal",
    ".svc.cluster.local",
    "mcp.internal.company.com",
    "localhost",
)

# Signatures that identify a process as an MCP server / agent runtime. Matched
# case-insensitively against ``"<process_name> <cmdline>"``. Defensive-facing:
# these are process-identity markers, not attack tooling.
_MCP_PROCESS_RE = re.compile(
    r"(?:"
    r"mcp[-_](?:server|runtime|proxy|gateway)"  # mcp-server / mcp_runtime / mcp-proxy / mcp-gateway
    r"|@modelcontextprotocol\b"  # npm-published MCP servers
    r"|\bmodelcontextprotocol\b"
    r"|agent[-_]runtime"
    r"|\b--mcp\b"  # a generic runtime launched in MCP mode
    r"|\bmcp[-_]server[.\w]*"  # mcp-server.py / mcp_server.js …
    r")",
    re.IGNORECASE,
)


class ProcessCmdlineEvent(BaseModel):
    """One observed process with its command line (from an EDR process feed)."""

    model_config = ConfigDict(extra="forbid")

    host: str = Field(..., min_length=1, max_length=512)
    pid: int | None = Field(default=None, ge=0)
    process_name: str = Field(default="", max_length=512)
    cmdline: str = Field(default="", max_length=8192)


class DnsResolutionEvent(BaseModel):
    """One observed outbound DNS resolution (from an EDR DNS-request feed)."""

    model_config = ConfigDict(extra="forbid")

    host: str = Field(..., min_length=1, max_length=512)
    pid: int | None = Field(default=None, ge=0)
    query_name: str = Field(..., min_length=1, max_length=1024)
    resolved_ips: list[str] = Field(default_factory=list)
    process_name: str = Field(default="", max_length=512)


def _looks_like_mcp_process(proc: ProcessCmdlineEvent) -> bool:
    """True when the process name / cmdline identifies an MCP server or runtime."""
    return bool(_MCP_PROCESS_RE.search(f"{proc.process_name} {proc.cmdline}"))


def _is_sanctioned(query_name: str, suffixes: tuple[str, ...]) -> bool:
    """True when a resolved hostname is on the sanctioned MCP-endpoint allowlist."""
    qn = query_name.strip().rstrip(".").lower()
    return any(qn == s.lower() or qn.endswith(s.lower()) for s in suffixes)


def run(
    dns_events: list[DnsResolutionEvent],
    process_events: list[ProcessCmdlineEvent],
    *,
    sanctioned_endpoint_suffixes: list[str] | None = None,
) -> list[RecordFindingRequest]:
    """Correlate MCP-server processes with DNS resolutions to unknown endpoints.

    Parameters
    ----------
    dns_events:
        Outbound DNS-resolution telemetry for the scoped hosts.
    process_events:
        Process + command-line telemetry for the scoped hosts.
    sanctioned_endpoint_suffixes:
        Allowlist of trusted MCP-endpoint host suffixes. Resolutions matching an
        entry are ignored. Defaults to :data:`_DEFAULT_SANCTIONED_SUFFIXES`.

    Returns
    -------
    list[RecordFindingRequest]
        One finding per ``(host, pid, query_name)`` correlation where an
        MCP-server process resolved a non-sanctioned endpoint. Each carries
        ``evidence["shadow_workload"] = True`` for governance-workflow routing.
    """
    suffixes = tuple(sanctioned_endpoint_suffixes or _DEFAULT_SANCTIONED_SUFFIXES)

    # Index MCP-server processes by host (correlation key).
    mcp_procs_by_host: dict[str, list[ProcessCmdlineEvent]] = defaultdict(list)
    for proc in process_events:
        if _looks_like_mcp_process(proc):
            mcp_procs_by_host[proc.host].append(proc)

    findings: list[RecordFindingRequest] = []
    seen: set[tuple[str, int | None, str]] = set()

    for dns in dns_events:
        procs = mcp_procs_by_host.get(dns.host)
        if not procs:
            continue
        # When both sides carry a pid, require it to match a same-pid MCP process
        # (best-effort attribution); otherwise correlate at host granularity.
        if dns.pid is not None:
            matched = [p for p in procs if p.pid is None or p.pid == dns.pid]
            if not matched:
                continue
        else:
            matched = procs
        if _is_sanctioned(dns.query_name, suffixes):
            continue

        key = (dns.host, dns.pid, dns.query_name.strip().rstrip(".").lower())
        if key in seen:
            continue
        seen.add(key)

        proc = matched[0]
        proc_label = proc.process_name or proc.cmdline[:80] or "<unknown>"
        observables: list[HuntObservable] = [
            HuntObservable(type="domain", value=dns.query_name),
        ]
        observables.extend(HuntObservable(type="ip", value=ip) for ip in dns.resolved_ips[:8])
        findings.append(
            RecordFindingRequest(
                source=HuntSource.AGENTIC,
                domain=HuntDomain.AGENTIC,
                title=(
                    f"Shadow MCP egress: {proc_label} on {dns.host} resolved "
                    f"unsanctioned endpoint {dns.query_name}"
                ),
                description=(
                    f"An MCP-server / agent-runtime process ({proc_label!r}, "
                    f"pid={proc.pid}) on host {dns.host!r} resolved {dns.query_name!r} "
                    "which is not in the sanctioned MCP-endpoint allowlist. A "
                    "compromised or unsanctioned (shadow) MCP server can exfiltrate "
                    "context, leak credentials, or proxy attacker C2. Correlated "
                    "code-side from process-cmdline + DNS telemetry — the "
                    "defensive complement to the mcp_server_egress Sigma rule."
                ),
                severity=Severity.HIGH,
                confidence=0.8,
                technique_ids=[_T_APP_LAYER_C2, _T_EXFIL_WEB, _T_SHADOW_WORKLOAD],
                entities=[
                    HuntEntity(kind="host", value=dns.host),
                    HuntEntity(kind="process", value=proc_label),
                ],
                observables=observables,
                evidence={
                    "detection": "shadow_mcp_correlation",
                    # Same governance routing marker the shadow-agent detectors set.
                    "shadow_workload": True,
                    "host": dns.host,
                    "pid": dns.pid,
                    "process_name": proc.process_name,
                    "process_cmdline": proc.cmdline[:512],
                    "query_name": dns.query_name,
                    "resolved_ips": dns.resolved_ips[:8],
                    "sanctioned_endpoint_suffixes": list(suffixes),
                },
            )
        )

    return findings
