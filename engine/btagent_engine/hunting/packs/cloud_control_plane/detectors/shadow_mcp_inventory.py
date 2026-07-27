"""Code-based detector: shadow-MCP discovery via Cloud Run inventory + DNS (#117 task B).

The **cloud** complement to the #121 host-side shadow-MCP correlation
(``agentic_misuse/detectors/shadow_mcp_correlation.py``, which joins process
cmdline + DNS-resolution telemetry). Where that keys on an MCP *process* on a
host, this keys on a Cloud Run **service inventory** record correlated with the
tenant's DNS records: an MCP-server Cloud Run service fronted by a hostname
outside the sanctioned MCP-endpoint allowlist is emitted as a shadow MCP server.

The correlation logic itself lives in
:func:`btagent_shared.hunt.cloud.detect_shadow_mcp_servers`; this module is the
pack-side entrypoint the runner / golden tests invoke.

Live-wiring TODO (deferred, #100):
  Replace the fixture-supplied ``cloud_run_services`` + ``dns_records`` with a
  live pull from a Cloud Run ``services.list`` connector (normalised to
  :class:`~btagent_shared.types.cloud_hunt.AgenticWorkload`) and a Cloud DNS /
  resolver-log connector (normalised to
  :class:`~btagent_shared.hunt.cloud.DnsRecord`). The correlation needs no change.
"""

from __future__ import annotations

from btagent_shared.hunt.cloud import DnsRecord, detect_shadow_mcp_servers
from btagent_shared.types.cloud_hunt import AgenticWorkload
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(
    cloud_run_services: list[AgenticWorkload],
    dns_records: list[DnsRecord],
    *,
    sanctioned_endpoint_suffixes: list[str] | None = None,
) -> list[RecordFindingRequest]:
    """Run the shadow-MCP Cloud Run + DNS correlation detector.

    Parameters
    ----------
    cloud_run_services:
        Cloud Run (and Cloud-Run-like) service inventory for the scoped project.
    dns_records:
        Zone / resolver DNS records for the tenant footprint.
    sanctioned_endpoint_suffixes:
        Allowlist of trusted MCP-endpoint host suffixes; defaults applied by the
        shared detector when omitted.

    Returns
    -------
    list[RecordFindingRequest]
        One finding per ``(service, unsanctioned-fronting-domain)`` correlation.
        Each carries ``evidence["shadow_workload"] = True`` for governance routing.
    """
    return detect_shadow_mcp_servers(
        cloud_run_services,
        dns_records,
        sanctioned_endpoint_suffixes=sanctioned_endpoint_suffixes,
    )
