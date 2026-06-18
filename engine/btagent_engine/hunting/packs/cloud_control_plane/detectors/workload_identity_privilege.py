"""Code-based detector: overprivileged agentic workload identity (cloud hunt pack #117).

Cross-references each agentic workload's linked IAM identity against the
CloudIdentity inventory to flag identities with broad or wildcard permissions.
Principle of least privilege requires agentic workloads to run with scoped,
purpose-built identities.

Live-wiring TODO (#100):
  The ``has_overprivileged_identity`` flag on :class:`AgenticWorkload` should be
  populated by the IAM Access Analyzer connector or by evaluating the identity's
  policy against a least-privilege scoring function.  Until then, the fixture
  sets this flag manually.
"""

from __future__ import annotations

from btagent_shared.hunt.cloud import detect_overprivileged_workload_identity
from btagent_shared.types.cloud_hunt import AgenticWorkload, CloudIdentity
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(
    workloads: list[AgenticWorkload],
    identities: list[CloudIdentity],
) -> list[RecordFindingRequest]:
    """Run the overprivileged-identity detector.

    Parameters
    ----------
    workloads:
        Agentic workload inventory for the scoped accounts.
    identities:
        IAM identity inventory for cross-reference.

    Returns
    -------
    list[RecordFindingRequest]
        One finding per workload whose linked identity has overprivileged
        permissions (``has_overprivileged_identity=True``).
    """
    return detect_overprivileged_workload_identity(workloads, identities)
