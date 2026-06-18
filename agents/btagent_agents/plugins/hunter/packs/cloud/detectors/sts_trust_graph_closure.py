"""Code-based detector: STS trust-graph transitive closure (cloud hunt pack #117).

This module is the *pack entry point* for the trust-graph-based STS chaining
detector.  The actual logic lives in :mod:`btagent_shared.hunt.cloud` so it is
dependency-free and unit-testable.

The pack runner calls :func:`run` with inventory data (from a fixture or future
CloudTrail/IAM connector) and receives a list of
:class:`~btagent_shared.types.hunt_finding.RecordFindingRequest` objects.

Live-wiring TODO (#100):
  Replace ``identities`` parameter with a call to the IAM connector MCP server
  to fetch the live role inventory for the scoped accounts.  The graph-closure
  logic itself requires no changes.
"""

from __future__ import annotations

from btagent_shared.hunt.cloud import detect_sts_chaining
from btagent_shared.types.cloud_hunt import CloudIdentity
from btagent_shared.types.hunt_finding import RecordFindingRequest


def run(
    identities: list[CloudIdentity],
    *,
    high_value_targets: set[str] | None = None,
    min_hops: int = 2,
) -> list[RecordFindingRequest]:
    """Run the STS trust-graph closure detector.

    Parameters
    ----------
    identities:
        IAM role/user inventory for the scoped accounts.  Loaded from a fixture
        (tests) or future IAM connector output (production).
    high_value_targets:
        Optional set of ARNs to treat as high-value.  Defaults to heuristic
        (admin/root/billing in name).
    min_hops:
        Minimum chain depth to report (default 2 = at least one intermediate hop).

    Returns
    -------
    list[RecordFindingRequest]
        One finding per discovered transitive attack path.
    """
    return detect_sts_chaining(
        identities,
        high_value_targets=high_value_targets,
        min_hops=min_hops,
    )
