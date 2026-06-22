"""Code-based detector: shadow agent / shadow MCP inventory (agentic hunt pack #121).

Reuses :func:`btagent_shared.hunt.cloud.classify_workload` from the #117 cloud
control-plane pack so the same governance routing marker
(``evidence["shadow_workload"] = True``) appears on both cloud-side and
agentic-side shadow findings — the single shared-surface point with #117 the
issue text mandates.

Live-wiring TODO (deferred):
  Replace ``workloads`` + ``identities`` parameters with inventory from:
  - AWS: Bedrock AgentCore ``list-agents`` + Lambda/ECS tag scan
  - GCP: Vertex AI Agent Engine ``agents.list`` + Cloud Run MCP service scan
  - Azure: Azure AI Foundry agent list + Container Apps tag scan
  Normalise to :class:`AgenticWorkload` (#117 type) + :class:`AgentIdentity`
  (#121 type) before calling :func:`run`.
"""

from __future__ import annotations

from btagent_shared.hunt.agentic import detect_shadow_agents
from btagent_shared.types.agentic_hunt import AgentIdentity
from btagent_shared.types.cloud_hunt import AgenticWorkload
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(
    workloads: list[AgenticWorkload],
    *,
    identities: list[AgentIdentity] | None = None,
) -> list[RecordFindingRequest]:
    """Run the shadow-agent / shadow-MCP discovery detector.

    Parameters
    ----------
    workloads:
        All :class:`AgenticWorkload` records (#117 type) for the scoped accounts.
    identities:
        Optional :class:`AgentIdentity` registrations (#121 type).  An identity
        may exist without a matching workload (e.g. on-prem agents) and vice
        versa; both sweeps run independently.

    Returns
    -------
    list[RecordFindingRequest]
        Findings carrying ``evidence["shadow_workload"] = True`` (same marker
        the #117 cloud detector uses) for governance-workflow routing.
    """
    return detect_shadow_agents(workloads, identities=identities)
