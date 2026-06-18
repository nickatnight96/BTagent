"""Code-based detector: shadow agentic-workload discovery (cloud hunt pack #117).

Classifies AI agent workloads (Bedrock AgentCore, Vertex Agent Engine, Cloud Run
MCP, GKE inference, and unmanaged compute with LLM SDK calls) as *managed* vs.
*shadow*.  Shadow workloads are emitted into the #119 triage queue with a
routing marker so the downstream triage agent can hand them off to a governance
workflow.

The governance workflow itself is out of scope for this slice (deferred).

Live-wiring TODO (#100):
  Replace ``workloads`` parameter with inventory from:
  - AWS: Bedrock AgentCore ``list-agents`` + Lambda/ECS tag scan for unmanaged agents
  - GCP: Vertex AI Agent Engine ``agents.list`` + Cloud Run service tag scan
  - Azure: Azure AI Foundry agent list + Container Apps tag scan
  Connector output should be normalised to :class:`AgenticWorkload` before calling
  :func:`run`.
"""

from __future__ import annotations

from btagent_shared.hunt.cloud import detect_shadow_workloads
from btagent_shared.types.cloud_hunt import AgenticWorkload
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(workloads: list[AgenticWorkload]) -> list[RecordFindingRequest]:
    """Run the shadow-workload discovery detector.

    Parameters
    ----------
    workloads:
        All agentic workload inventory records for the scoped accounts/projects.

    Returns
    -------
    list[RecordFindingRequest]
        One finding per shadow workload (governance-untagged or UNMANAGED kind).
        Each finding carries ``evidence["shadow_workload"] = True`` as a routing
        marker for the governance workflow.
    """
    return detect_shadow_workloads(workloads)
