"""Connector catalog — read model over the engine's connector manifests (#100).

Layer 3 of the connector strategy declares a :class:`ConnectorManifest` on
every integration node; this service is the backend read model that surfaces
those manifests to the ``GET /connectors`` API (and, through it, the
frontend Settings → Integrations view).

Source of truth is the engine ``NodeRegistry``: every INTEGRATION-category
node carries a ``manifest`` (pinned by the engine's coverage test), so the
catalog is exactly the set of installed connectors — no second registry to
drift. Manifests are declarative and secret-free (they name credential
*types*, never material), so the whole catalog is safe to serve read-only.

The registry is enumerated once and memoised; import of
``btagent_engine.integrations`` (needed to register the nodes) is done
lazily inside the builder so the module stays cheap to import.
"""

from __future__ import annotations

from btagent_shared.types.connector import ConnectorManifest

_CATALOG: dict[str, ConnectorManifest] | None = None


def _build_catalog() -> dict[str, ConnectorManifest]:
    # Importing the integrations package registers every integration node.
    import btagent_engine.integrations  # noqa: F401
    from btagent_engine.node import NodeCategory, NodeRegistry

    catalog: dict[str, ConnectorManifest] = {}
    for cls in NodeRegistry.all().values():
        if cls.meta.category != NodeCategory.INTEGRATION:
            continue
        manifest = getattr(cls, "manifest", None)
        if isinstance(manifest, ConnectorManifest):
            # One manifest per connector name (multiple nodes of the same
            # connector share it); first wins, they're identical objects.
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
