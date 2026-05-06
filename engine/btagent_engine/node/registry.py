"""Process-local registry of Node classes by stable id.

The registry is the discovery surface the canvas UI reads to populate
its palette and the workflow compiler reads to resolve a node id from
a workflow file. Registration is explicit (``NodeRegistry.register``)
so test-only nodes don't pollute the production surface.

Lookup is by ``meta.id`` -- *not* by class name -- because class names
can drift but ids are part of the workflow file format.
"""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType

from btagent_engine.node.base import Node


class NodeAlreadyRegisteredError(ValueError):
    """Two Node classes claimed the same ``meta.id``."""


class NodeRegistry:
    """Process-local map of node id -> Node class."""

    _registry: dict[str, type[Node]] = {}

    @classmethod
    def register(cls, node_class: type[Node]) -> type[Node]:
        """Register *node_class* under its ``meta.id``. Returns the class
        unchanged so this can be used as a decorator.

        Raises ``NodeAlreadyRegisteredError`` if the id is taken; collisions
        almost always mean a typo or a copy-paste bug, so we fail loud.
        """
        node_id = node_class.meta.id
        existing = cls._registry.get(node_id)
        if existing is not None and existing is not node_class:
            raise NodeAlreadyRegisteredError(
                f"Node id {node_id!r} already registered as {existing.__qualname__}; "
                f"cannot also register {node_class.__qualname__}"
            )
        cls._registry[node_id] = node_class
        return node_class

    @classmethod
    def unregister(cls, node_id: str) -> None:
        """Remove a registration. Mostly useful in test teardown."""
        cls._registry.pop(node_id, None)

    @classmethod
    def get(cls, node_id: str) -> type[Node] | None:
        """Resolve a node id to its class, or ``None`` if not registered."""
        return cls._registry.get(node_id)

    @classmethod
    def all(cls) -> Mapping[str, type[Node]]:
        """Read-only view of the full registry."""
        return MappingProxyType(cls._registry)

    @classmethod
    def clear(cls) -> None:
        """Wipe the registry. Test-only -- never call from production code."""
        cls._registry.clear()
