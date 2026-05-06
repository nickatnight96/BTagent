"""BTagent workflow engine.

Public API:

* ``Node`` -- the ABC every workflow node subclasses.
* ``NodeContext`` -- per-run state passed to ``Node.run``.
* ``NodeMeta`` / ``NodeCategory`` -- design-time node metadata.
* ``NodeRegistry`` -- discovery surface for the canvas / compiler.
* ``Middleware`` / ``Runner`` -- composition of cross-cutting concerns
  (TLP egress gate, evidence chain, HITL, cost budget) around node
  execution.

Engine has zero runtime dependency on ``btagent_agents`` or
``btagent_backend`` -- the ``btagent-shared`` types are the only sibling
package import. This makes the engine standalone-shippable / embeddable
in other security tools per the redesign plan.
"""

from btagent_engine.middleware import Middleware, Runner
from btagent_engine.node import (
    Node,
    NodeAlreadyRegisteredError,
    NodeCategory,
    NodeContext,
    NodeMeta,
    NodeRegistry,
)

__all__ = [
    "Middleware",
    "Node",
    "NodeAlreadyRegisteredError",
    "NodeCategory",
    "NodeContext",
    "NodeMeta",
    "NodeRegistry",
    "Runner",
]
