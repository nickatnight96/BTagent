"""Out-of-tree community node loading (#101).

Community packages ship Node classes without touching this repo: they declare
entry points in the ``btagent.nodes`` group, each pointing at a
:class:`~btagent_engine.node.base.Node` subclass::

    # pyproject.toml of a community package
    [project.entry-points."btagent.nodes"]
    acme_lookup = "acme_btagent_nodes.lookup:AcmeLookupNode"

Installing the package makes the entry point discoverable;
:func:`load_external_nodes` registers the class on the shared
:class:`~btagent_engine.node.registry.NodeRegistry`, from which the canvas
palette, the connector catalog, and the workflow executor all resolve nodes —
no engine change required. See ``docs/COMMUNITY_NODES.md`` for the packaging
walk-through.

Security posture — the two properties everything else here serves:

* **Nothing loads without an explicit allowlist.** Loading an entry point
  executes third-party code, so mere installation must not be enough (a
  transitive dependency could otherwise inject nodes). The operator names
  each trusted distribution in ``BTAGENT_EXTERNAL_NODE_PACKAGES``
  (comma-separated, PEP 503-normalised match); the default is empty and
  nothing is loaded. There is deliberately no "load everything" wildcard.
* **One broken package cannot take the engine down.** Every entry point is
  loaded and validated independently; failures (import errors, non-Node
  objects, id collisions with builtin nodes) are collected into the returned
  report and logged loudly, and the remaining entries still load. A silent
  drop is the failure mode this report exists to prevent.
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from importlib import metadata

from btagent_engine.node.base import Node
from btagent_engine.node.registry import NodeRegistry

logger = logging.getLogger("btagent.node.external")

#: Entry-point group community packages declare their nodes under.
EXTERNAL_NODES_GROUP = "btagent.nodes"

#: Env var carrying the comma-separated distribution allowlist.
ALLOWLIST_ENV = "BTAGENT_EXTERNAL_NODE_PACKAGES"


def _normalise(dist_name: str) -> str:
    """PEP 503 name normalisation, so ``My_Pkg`` matches ``my-pkg``."""
    return re.sub(r"[-_.]+", "-", dist_name).lower()


@dataclass
class ExternalNodeReport:
    """What :func:`load_external_nodes` did, for logging and tests."""

    #: node id -> distribution name, for every node registered this call.
    loaded: dict[str, str] = field(default_factory=dict)
    #: Distributions that declared entry points but are not allowlisted.
    skipped_distributions: list[str] = field(default_factory=list)
    #: ``"dist:entry_point"`` -> error string, one per failed entry point.
    failures: dict[str, str] = field(default_factory=dict)


def _entry_point_dist_name(ep: metadata.EntryPoint) -> str:
    """Best-effort distribution name for an entry point ('' when unknown)."""
    dist = getattr(ep, "dist", None)
    name = getattr(dist, "name", None)
    return name or ""


def load_external_nodes(allowlist: str | None = None) -> ExternalNodeReport:
    """Register allowlisted community nodes; return a report of the outcome.

    ``allowlist`` defaults to :data:`ALLOWLIST_ENV`; empty/unset means the
    feature is off and nothing is imported. Safe to call more than once —
    re-registering the same class is a no-op in the registry.
    """
    raw = allowlist if allowlist is not None else os.getenv(ALLOWLIST_ENV, "")
    allowed = {_normalise(part.strip()) for part in raw.split(",") if part.strip()}
    report = ExternalNodeReport()
    if not allowed:
        return report

    for ep in metadata.entry_points(group=EXTERNAL_NODES_GROUP):
        dist_name = _entry_point_dist_name(ep)
        if _normalise(dist_name) not in allowed:
            if dist_name and dist_name not in report.skipped_distributions:
                report.skipped_distributions.append(dist_name)
            continue

        key = f"{dist_name}:{ep.name}"
        try:
            obj = ep.load()
            if not (isinstance(obj, type) and issubclass(obj, Node) and obj is not Node):
                raise TypeError(f"entry point must resolve to a Node subclass, got {obj!r}")
            NodeRegistry.register(obj)
            report.loaded[obj.meta.id] = dist_name
        except Exception as exc:  # noqa: BLE001 - fail-soft per entry, by design
            report.failures[key] = f"{type(exc).__name__}: {exc}"
            logger.warning(
                "external node entry point %s failed to load: %s", key, exc, exc_info=True
            )

    if report.loaded:
        logger.info(
            "registered %d external node(s): %s",
            len(report.loaded),
            ", ".join(sorted(report.loaded)),
        )
    if report.failures:
        logger.warning(
            "%d external node entry point(s) FAILED to load: %s",
            len(report.failures),
            ", ".join(sorted(report.failures)),
        )
    return report


__all__ = [
    "ALLOWLIST_ENV",
    "EXTERNAL_NODES_GROUP",
    "ExternalNodeReport",
    "load_external_nodes",
]
