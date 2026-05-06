"""Tests for the orchestrator workflow templates (Sprint 3C).

Verifies that the four seeded YAML templates compile, that the loader
caches identity-stable :class:`Workflow` instances, and that every
``action`` step resolves to a Node id that's actually registered in the
engine's :class:`NodeRegistry`. The decision/parallel/join/end synthetic
node ids are *not* checked against the registry -- the engine
deliberately doesn't ship them as registered Nodes; the runner handles
them structurally.
"""

from __future__ import annotations

import sys
from pathlib import Path

# The agents package isn't currently a runtime dep of btagent_engine;
# inject the engine source root onto sys.path so the templates can
# import cleanly when the test is run from the agents/ directory.
_AGENTS_DIR = Path(__file__).resolve().parent.parent
_REPO_ROOT = _AGENTS_DIR.parent
_ENGINE_DIR = _REPO_ROOT / "engine"
for _candidate in (_ENGINE_DIR, _AGENTS_DIR.parent / "shared"):
    _path = str(_candidate)
    if _candidate.is_dir() and _path not in sys.path:
        sys.path.insert(0, _path)

# Importing btagent_engine.integrations triggers @NodeRegistry.register
# decorators on every shipped integration Node, populating the registry
# the templates reference. The submodule import is what matters; we
# don't use the names directly.
import btagent_engine.integrations  # noqa: F401, E402
import pytest  # noqa: E402
from btagent_engine.compiler import Workflow  # noqa: E402
from btagent_engine.node import NodeRegistry  # noqa: E402

from btagent_agents.orchestrator.templates import (  # noqa: E402
    UnknownTemplateError,
    _clear_cache,
    available_templates,
    load_template,
)

# Compiler-synthetic node ids the runner handles structurally; they
# don't appear in NodeRegistry by design.
_SYNTHETIC_NODE_IDS = frozenset(
    {
        "decision.branch",
        "decision.parallel",
        "decision.hitl_gate",
        "compiler.join",
        "compiler.end",
    }
)

_ALL_TEMPLATES = ("triage", "query", "enrichment", "knowledge")


@pytest.fixture(autouse=True)
def _reset_cache():
    """Each test gets a fresh template cache."""
    _clear_cache()
    yield
    _clear_cache()


# --------------------------------------------------------------------------- #
# Compile smoke tests -- one per template
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", _ALL_TEMPLATES)
def test_template_compiles(name: str) -> None:
    workflow = load_template(name)  # type: ignore[arg-type]
    assert isinstance(workflow, Workflow)
    assert workflow.name
    assert workflow.nodes, f"Template {name!r} compiled with zero nodes"


# --------------------------------------------------------------------------- #
# Cache behaviour
# --------------------------------------------------------------------------- #


def test_load_template_caches_workflow_instance() -> None:
    first = load_template("triage")
    second = load_template("triage")
    assert first is second, "load_template must cache compiled Workflows by name"


def test_load_template_unknown_name_raises_clear_error() -> None:
    with pytest.raises(UnknownTemplateError) as exc:
        load_template("does_not_exist")  # type: ignore[arg-type]
    # Sanity check that the error message names the bad input -- a bare
    # KeyError on the cache dict wouldn't.
    assert "does_not_exist" in str(exc.value)


def test_available_templates_matches_seed() -> None:
    assert available_templates() == tuple(sorted(_ALL_TEMPLATES))


# --------------------------------------------------------------------------- #
# Per-template structural assertions
# --------------------------------------------------------------------------- #


def test_triage_template_has_manual_trigger_and_decision() -> None:
    workflow = load_template("triage")
    assert workflow.trigger.get("type") == "manual"
    # At least one decision step (severity branch).
    decision_nodes = [n for n in workflow.nodes if n.node_id == "decision.branch"]
    assert decision_nodes, "Triage template missing a DecisionNode (severity branch)"
    # The decision must have both a true and a false out-edge.
    branch_labels = {
        e.label for e in workflow.edges if e.source == decision_nodes[0].step_id
    }
    assert {"true", "false"}.issubset(branch_labels)


def test_query_template_parallel_fork_has_four_siem_branches() -> None:
    workflow = load_template("query")
    parallel_nodes = [n for n in workflow.nodes if n.node_id == "decision.parallel"]
    assert parallel_nodes, "Query template missing a ParallelNode fan-out"
    fork = parallel_nodes[0]
    # branches live on the WorkflowNode config.
    branches = fork.config.get("branches", [])
    assert len(branches) == 4, f"Query fan-out has {len(branches)} branches (want 4)"

    # Resolve each branch's first step to its WorkflowNode and assert
    # the node_id matches one of the four expected SIEM/EDR Nodes.
    expected_ids = {
        "integration.splunk.search",
        "integration.crowdstrike.list_detections",
        "integration.sentinel.kql_query",
        "integration.elastic.search",
    }
    branch_node_ids: set[str] = set()
    for branch in branches:
        first_step = branch[0]
        wn = workflow.step(first_step)
        assert wn is not None, f"Query branch step {first_step!r} not found"
        branch_node_ids.add(wn.node_id)
    assert branch_node_ids == expected_ids


def test_enrichment_template_parallel_fork_has_five_cti_branches() -> None:
    workflow = load_template("enrichment")
    parallel_nodes = [n for n in workflow.nodes if n.node_id == "decision.parallel"]
    assert parallel_nodes, "Enrichment template missing a ParallelNode fan-out"
    fork = parallel_nodes[0]
    branches = fork.config.get("branches", [])
    assert len(branches) == 5, (
        f"Enrichment fan-out has {len(branches)} branches (want 5)"
    )
    expected_ids = {
        "integration.virustotal.ip_lookup",
        "integration.shodan.host_lookup",
        "integration.abuseipdb.check",
        "integration.greynoise.lookup_ip",
        "integration.misp.search_attribute",
    }
    branch_node_ids = {
        workflow.step(b[0]).node_id  # type: ignore[union-attr]
        for b in branches
    }
    assert branch_node_ids == expected_ids


def test_knowledge_template_has_llm_call_step() -> None:
    workflow = load_template("knowledge")
    llm_steps = [n for n in workflow.nodes if n.node_id == "reasoning.llm.call"]
    assert llm_steps, "Knowledge template must contain at least one LLMCallNode step"


# --------------------------------------------------------------------------- #
# Registry coverage -- every action step must reference a registered Node
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("name", _ALL_TEMPLATES)
def test_template_action_nodes_are_registered(name: str) -> None:
    workflow = load_template(name)  # type: ignore[arg-type]
    unregistered: list[tuple[str, str]] = []
    for node in workflow.nodes:
        if node.node_id in _SYNTHETIC_NODE_IDS:
            continue
        if NodeRegistry.get(node.node_id) is None:
            unregistered.append((node.step_id, node.node_id))
    assert not unregistered, (
        f"Template {name!r} references unregistered Node ids: {unregistered}"
    )
