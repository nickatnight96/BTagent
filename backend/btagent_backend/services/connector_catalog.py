"""Connector catalog — read model over the platform's connector manifests (#100).

Layer 3 of the connector strategy declares a :class:`ConnectorManifest` on
every connector; this service is the backend read model that surfaces those
manifests to the ``GET /connectors`` API (and, through it, the frontend
Settings → Integrations view).

The catalog unions **two** manifest registries, both declarative and
secret-free (they name credential *types*, never material):

* the engine ``NodeRegistry`` — every INTEGRATION-category node carries a
  ``manifest`` (the CTI-enrichment sources + the Phase-1 SIEM/EDR nodes); and
* the agents-side MCP server registry
  (:data:`btagent_agents.mcp.manifests.MANIFESTS`) — the SIEM / EDR / identity
  / email / cloud / ticketing MCP connectors the agent actually dispatches to.

The engine set and the MCP set overlap on a few names (splunk, sentinel,
elastic, crowdstrike). **The engine manifest wins on a name clash** — it is
the "installed node" truth the rest of the backend already reasons over — so
the union is purely additive over the pre-existing engine-only catalog.

Both registries are enumerated once and memoised; the imports (which register
the engine nodes / carry the MCP manifests) are done lazily inside the builder
so the module stays cheap to import. If the agents package can't be imported
(a deployment without the agent runtime), the catalog degrades gracefully to
engine-only rather than failing the whole endpoint.
"""

from __future__ import annotations

import logging

from btagent_shared.types.connector import ConnectorManifest

logger = logging.getLogger("btagent.services.connector_catalog")

_CATALOG: dict[str, ConnectorManifest] | None = None


def _build_catalog() -> dict[str, ConnectorManifest]:
    catalog: dict[str, ConnectorManifest] = {}

    # 1) Engine INTEGRATION nodes — importing the package registers them.
    import btagent_engine.integrations  # noqa: F401
    from btagent_engine.node import NodeCategory, NodeRegistry

    for cls in NodeRegistry.all().values():
        if cls.meta.category != NodeCategory.INTEGRATION:
            continue
        manifest = getattr(cls, "manifest", None)
        if isinstance(manifest, ConnectorManifest):
            # One manifest per connector name (multiple nodes of the same
            # connector share it); first wins, they're identical objects.
            catalog.setdefault(manifest.name, manifest)

    # 2) Agents-side MCP connectors — additive; engine wins on name clashes.
    try:
        from btagent_agents.mcp.manifests import MANIFESTS as MCP_MANIFESTS
    except ImportError as exc:  # pragma: no cover - agent runtime absent
        logger.warning("connector catalog: MCP manifests unavailable (%s); engine-only", exc)
    else:
        for manifest in MCP_MANIFESTS.values():
            if isinstance(manifest, ConnectorManifest):
                catalog.setdefault(manifest.name, manifest)

    return catalog


def get_catalog(*, refresh: bool = False) -> dict[str, ConnectorManifest]:
    """Return the connector-name → manifest map (memoised)."""
    global _CATALOG
    if _CATALOG is None or refresh:
        _CATALOG = _build_catalog()
    return _CATALOG


def list_manifests() -> list[ConnectorManifest]:
    """All connector manifests, sorted by connector name."""
    return [m for _name, m in sorted(get_catalog().items())]


def get_manifest(name: str) -> ConnectorManifest | None:
    """One connector's manifest by name (None when not installed)."""
    return get_catalog().get(name)
