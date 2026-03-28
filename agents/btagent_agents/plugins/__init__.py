"""BTagent plugin registry — discovery, loading, and instantiation."""

from __future__ import annotations

import importlib
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from btagent_agents.plugins.base import DefensivePlugin

logger = logging.getLogger(__name__)

# Map of plugin name → fully-qualified module path containing the plugin class.
PLUGIN_MODULES: dict[str, str] = {
    "triage": "btagent_agents.plugins.triage",
    "query": "btagent_agents.plugins.query",
    "enrichment": "btagent_agents.plugins.enrichment",
    "knowledge": "btagent_agents.plugins.knowledge",
    "coordination": "btagent_agents.plugins.coordination",
    "report": "btagent_agents.plugins.report",
    "mitigation": "btagent_agents.plugins.mitigation",
}

# In-process cache of already-loaded plugin instances.
_loaded_plugins: dict[str, DefensivePlugin] = {}


def load_plugin(name: str) -> DefensivePlugin | None:
    """Load and instantiate a plugin by its registered name.

    Returns ``None`` if the plugin cannot be found or fails to import.
    Already-loaded plugins are returned from cache.
    """
    if name in _loaded_plugins:
        return _loaded_plugins[name]

    module_path = PLUGIN_MODULES.get(name)
    if module_path is None:
        logger.warning("Unknown plugin requested: %s", name)
        return None

    try:
        module = importlib.import_module(module_path)
    except ImportError:
        logger.exception("Failed to import plugin module: %s", module_path)
        return None

    # Each plugin sub-package must expose a ``plugin`` attribute that is an
    # instance (or callable returning an instance) of DefensivePlugin.
    plugin_factory = getattr(module, "plugin", None)
    if plugin_factory is None:
        logger.error(
            "Module %s does not expose a 'plugin' attribute", module_path
        )
        return None

    # Support both pre-instantiated singletons and factory callables.
    if callable(plugin_factory) and not isinstance(plugin_factory, type):
        plugin_instance = plugin_factory()
    elif isinstance(plugin_factory, type):
        plugin_instance = plugin_factory()
    else:
        plugin_instance = plugin_factory

    _loaded_plugins[name] = plugin_instance
    logger.info("Loaded plugin: %s v%s", plugin_instance.name, plugin_instance.version)
    return plugin_instance


def list_plugins() -> list[str]:
    """Return the names of all registered plugins."""
    return sorted(PLUGIN_MODULES.keys())


def get_all_plugins() -> dict[str, DefensivePlugin]:
    """Load and return all registered plugins.

    Plugins that fail to load are silently skipped (errors are logged).
    """
    result: dict[str, DefensivePlugin] = {}
    for name in list_plugins():
        plugin = load_plugin(name)
        if plugin is not None:
            result[name] = plugin
    return result


__all__ = [
    "PLUGIN_MODULES",
    "get_all_plugins",
    "list_plugins",
    "load_plugin",
]
