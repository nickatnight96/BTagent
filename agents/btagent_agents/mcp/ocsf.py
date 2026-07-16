"""OCSF claim validation for MCP router results (#100 Layer 2).

The engine's ``OCSFNormalizerMiddleware`` enforces the declared-vs-actual
OCSF contract on integration-node outputs; this module is the same
enforcement for ``mcp_router_tool`` results, sharing the engine's exact
claim-extraction shapes and skip semantics:

* Claims are duck-typed from the result envelope — top-level
  ``ocsf_event_class: str``, top-level ``ocsf_emits: list[str]``, and
  per-event ``events[*].class`` (identity-connector event dumps carry no
  ``class`` key, so vendor-shaped mocks sail through untagged).
* A capability that declares ``ocsf_emits=[]`` emits raw / vendor-shaped
  data by contract — claims on such results are not validated.
* A result carrying **no** OCSF tags passes untouched: most connectors
  aren't OCSF-retrofitted yet, and validating absent claims would be
  warning spam (engine parity).
* A claimed class the manifest does **not** declare is a contract
  violation — almost always a connector bug — and is refused loudly with
  an ``ocsf_violation`` envelope so declared/actual schemas can't drift.

The engine middleware also aggregates an emit summary into the node
context for coverage maps; the router has no per-run context, so summary
aggregation stays engine-side.
"""

from __future__ import annotations

from typing import Any

from btagent_agents.mcp.manifests import MANIFESTS


def extract_ocsf_claims(payload: Any) -> list[str]:
    """Pull every OCSF-class string a result envelope exposes.

    Same three shapes the engine normalizer accepts; de-duplicated,
    order-preserving, raw strings (the validator compares by value).
    """
    if not isinstance(payload, dict):
        return []

    seen: list[str] = []

    top_class = payload.get("ocsf_event_class")
    if isinstance(top_class, str):
        seen.append(top_class)

    top_emits = payload.get("ocsf_emits")
    if isinstance(top_emits, list):
        seen.extend(c for c in top_emits if isinstance(c, str))

    events = payload.get("events")
    if isinstance(events, list):
        for ev in events:
            if isinstance(ev, dict):
                cls = ev.get("class")
                if isinstance(cls, str):
                    seen.append(cls)

    return list(dict.fromkeys(seen))


def validate_ocsf_claims(tool_name: str, result: Any) -> dict[str, Any] | None:
    """Validate a dispatched result's OCSF claims against the manifest.

    Returns ``None`` when the result honours its capability's contract
    (including the skip cases above); returns an ``ocsf_violation`` error
    envelope when the result claims a class the manifest doesn't declare.
    """
    claims = extract_ocsf_claims(result)
    if not claims:
        return None

    capability = None
    server_id = None
    for sid, manifest in MANIFESTS.items():
        capability = manifest.capability(tool_name)
        if capability is not None:
            server_id = sid
            break
    if capability is None or not capability.ocsf_emits:
        # Undeclared tools never reach dispatch (the policy gate fails
        # closed first); an empty ocsf_emits means raw/vendor data by
        # contract — nothing to validate either way.
        return None

    declared = {c.value for c in capability.ocsf_emits}
    undeclared = [c for c in claims if c not in declared]
    if not undeclared:
        return None

    return {
        "status": "ocsf_violation",
        "tool_name": tool_name,
        "server_id": server_id,
        "message": (
            f"Result of '{tool_name}' claims OCSF classes {undeclared} that its "
            f"manifest does not declare (declared: {sorted(declared)}). This is "
            "a connector contract bug — fix the manifest or the output tagging."
        ),
        "undeclared_seen": undeclared,
        "declared": sorted(declared),
    }
