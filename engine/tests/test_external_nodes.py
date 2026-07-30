"""Tests for the out-of-tree node loader (#101, ``node/external.py``).

The two security properties are the point, so they get the sharpest tests:
nothing loads without an explicit allowlist (installation alone must never be
enough), and one broken community package cannot prevent the others from
loading (fail-soft with a loud report, never a crash and never a silent drop).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest
from pydantic import BaseModel

from btagent_engine.node import external
from btagent_engine.node.base import Node, NodeCategory, NodeContext, NodeMeta
from btagent_engine.node.registry import NodeRegistry

# --------------------------------------------------------------------------- #
# Fakes
# --------------------------------------------------------------------------- #


class _In(BaseModel):
    pass


class _Out(BaseModel):
    pass


def _make_node(node_id: str) -> type[Node]:
    class _ExternalNode(Node[_In, _Out]):
        meta = NodeMeta(
            id=node_id,
            name=f"External {node_id}",
            version="1.0.0",
            category=NodeCategory.DATA,
        )
        input_schema = _In
        output_schema = _Out

        async def run(self, input: _In, ctx: NodeContext) -> _Out:  # noqa: ARG002
            return _Out()

    return _ExternalNode


@dataclass
class _FakeDist:
    name: str


@dataclass
class _FakeEntryPoint:
    """Shape-compatible stand-in for ``importlib.metadata.EntryPoint``."""

    name: str
    dist: _FakeDist
    obj: Any = None
    error: Exception | None = None

    def load(self) -> Any:
        if self.error is not None:
            raise self.error
        return self.obj


@pytest.fixture()
def entry_points(monkeypatch):
    """Install a fake entry-point set; return the list to populate."""
    eps: list[_FakeEntryPoint] = []

    def fake_entry_points(*, group: str):
        assert group == external.EXTERNAL_NODES_GROUP
        return list(eps)

    monkeypatch.setattr(external.metadata, "entry_points", fake_entry_points)
    return eps


@pytest.fixture(autouse=True)
def _clean_registry():
    """Unregister anything a test loads so the shared registry stays pristine."""
    before = set(NodeRegistry.all())
    yield
    for node_id in set(NodeRegistry.all()) - before:
        NodeRegistry.unregister(node_id)


# --------------------------------------------------------------------------- #
# The gate
# --------------------------------------------------------------------------- #


def test_disabled_by_default_loads_nothing(entry_points, monkeypatch):
    """Installation alone is not consent: with no allowlist the loader must
    not even call ``load()`` on a discovered entry point."""
    monkeypatch.delenv(external.ALLOWLIST_ENV, raising=False)
    boom = _FakeEntryPoint(
        name="n", dist=_FakeDist("acme-nodes"), error=AssertionError("must not load")
    )
    entry_points.append(boom)

    report = external.load_external_nodes()

    assert report.loaded == {}
    assert report.failures == {}
    assert report.skipped_distributions == []


def test_non_allowlisted_distribution_is_skipped_not_loaded(entry_points):
    entry_points.append(
        _FakeEntryPoint(
            name="n", dist=_FakeDist("evil-transitive-dep"), error=AssertionError("must not load")
        )
    )

    report = external.load_external_nodes(allowlist="acme-nodes")

    assert report.loaded == {}
    assert report.skipped_distributions == ["evil-transitive-dep"]
    assert report.failures == {}


def test_allowlisted_distribution_registers_its_node(entry_points):
    cls = _make_node("external.acme.lookup")
    entry_points.append(_FakeEntryPoint(name="lookup", dist=_FakeDist("acme-nodes"), obj=cls))

    report = external.load_external_nodes(allowlist="acme-nodes")

    assert report.loaded == {"external.acme.lookup": "acme-nodes"}
    assert NodeRegistry.get("external.acme.lookup") is cls


def test_allowlist_match_is_pep503_normalised(entry_points):
    cls = _make_node("external.acme.norm")
    entry_points.append(_FakeEntryPoint(name="n", dist=_FakeDist("Acme_Nodes"), obj=cls))

    report = external.load_external_nodes(allowlist=" acme.nodes ")

    assert report.loaded == {"external.acme.norm": "Acme_Nodes"}


def test_allowlist_env_var_is_the_default_source(entry_points, monkeypatch):
    cls = _make_node("external.acme.env")
    entry_points.append(_FakeEntryPoint(name="n", dist=_FakeDist("acme-nodes"), obj=cls))
    monkeypatch.setenv(external.ALLOWLIST_ENV, "acme-nodes")

    report = external.load_external_nodes()

    assert "external.acme.env" in report.loaded


# --------------------------------------------------------------------------- #
# Fail-soft containment
# --------------------------------------------------------------------------- #


def test_one_broken_entry_point_does_not_stop_the_others(entry_points):
    good = _make_node("external.acme.good")
    entry_points.append(
        _FakeEntryPoint(
            name="broken", dist=_FakeDist("acme-nodes"), error=ImportError("missing dep")
        )
    )
    entry_points.append(_FakeEntryPoint(name="good", dist=_FakeDist("acme-nodes"), obj=good))

    report = external.load_external_nodes(allowlist="acme-nodes")

    assert "external.acme.good" in report.loaded
    assert report.failures == {"acme-nodes:broken": "ImportError: missing dep"}


def test_non_node_object_is_a_recorded_failure(entry_points):
    entry_points.append(
        _FakeEntryPoint(name="notanode", dist=_FakeDist("acme-nodes"), obj=object())
    )

    report = external.load_external_nodes(allowlist="acme-nodes")

    assert report.loaded == {}
    assert list(report.failures) == ["acme-nodes:notanode"]
    assert "Node subclass" in report.failures["acme-nodes:notanode"]


def test_id_collision_with_existing_node_is_refused_and_recorded(entry_points):
    original = _make_node("external.acme.taken")
    NodeRegistry.register(original)
    impostor = _make_node("external.acme.taken")
    entry_points.append(
        _FakeEntryPoint(name="impostor", dist=_FakeDist("acme-nodes"), obj=impostor)
    )

    report = external.load_external_nodes(allowlist="acme-nodes")

    # The registration that was there first survives; the collision is loud.
    assert NodeRegistry.get("external.acme.taken") is original
    assert report.loaded == {}
    assert "NodeAlreadyRegisteredError" in report.failures["acme-nodes:impostor"]


def test_reload_of_the_same_class_is_idempotent(entry_points):
    cls = _make_node("external.acme.again")
    entry_points.append(_FakeEntryPoint(name="n", dist=_FakeDist("acme-nodes"), obj=cls))

    first = external.load_external_nodes(allowlist="acme-nodes")
    second = external.load_external_nodes(allowlist="acme-nodes")

    assert first.loaded == second.loaded == {"external.acme.again": "acme-nodes"}
    assert second.failures == {}
