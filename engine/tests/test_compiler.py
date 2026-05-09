"""Compiler-level tests: YAML -> Workflow shape, validation, safety caps."""

from __future__ import annotations

from pathlib import Path

import pytest

from btagent_engine.compiler import (
    MAX_PARALLEL_BRANCHES,
    PlaybookCompileError,
    Workflow,
    compile_playbook,
)
from btagent_engine.compiler.steps import DecisionNode, HITLGateNode, ParallelNode

# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

_LINEAR_YAML = """
name: Linear Playbook
trigger:
  type: manual
steps:
  - id: a
    type: action
    tool_name: integration.test.echo
    next_step: b
  - id: b
    type: action
    tool_name: integration.test.tag
    next_step: c
  - id: c
    type: end
    name: Done
"""

_DECISION_YAML = """
name: Decision Playbook
trigger:
  type: manual
steps:
  - id: gate
    type: decision
    condition: "score > 0.7"
    true_branch: take_action
    false_branch: log_only
  - id: take_action
    type: action
    tool_name: integration.test.escalate
    next_step: done
  - id: log_only
    type: action
    tool_name: integration.test.log
    next_step: done
  - id: done
    type: end
"""

_PARALLEL_YAML = """
name: Parallel Playbook
trigger:
  type: manual
steps:
  - id: fan_out
    type: parallel_fork
    branches:
      - [enrich_ip, score_ip]
      - [enrich_domain]
    next_step: merge
  - id: enrich_ip
    type: action
    tool_name: integration.test.enrich_ip
  - id: score_ip
    type: action
    tool_name: integration.test.score_ip
  - id: enrich_domain
    type: action
    tool_name: integration.test.enrich_domain
  - id: merge
    type: end
"""

_HITL_YAML = """
name: HITL Playbook
trigger:
  type: manual
steps:
  - id: gate
    type: hitl_gate
    prompt: "Approve containment?"
    required_role: incident_commander
    next_step: contain
  - id: contain
    type: action
    tool_name: integration.test.contain
"""

_CYCLE_YAML = """
name: Cyclic
trigger:
  type: manual
steps:
  - id: a
    type: action
    tool_name: integration.test.echo
    next_step: b
  - id: b
    type: action
    tool_name: integration.test.echo
    next_step: a
"""


# --------------------------------------------------------------------------- #
# Tests
# --------------------------------------------------------------------------- #


def test_compile_linear_playbook_returns_workflow():
    wf = compile_playbook(_LINEAR_YAML)
    assert isinstance(wf, Workflow)
    assert wf.name == "Linear Playbook"
    assert {n.step_id for n in wf.nodes} == {"a", "b", "c"}
    # Linear edges
    labels = {(e.source, e.target, e.label) for e in wf.edges}
    assert ("a", "b", "next") in labels
    assert ("b", "c", "next") in labels


def test_compile_action_step_uses_tool_name_as_node_id():
    wf = compile_playbook(_LINEAR_YAML)
    step_a = wf.step("a")
    assert step_a is not None
    assert step_a.node_id == "integration.test.echo"


def test_compile_decision_step_emits_branch_edges_with_decision_node_id():
    wf = compile_playbook(_DECISION_YAML)
    gate = wf.step("gate")
    assert gate is not None
    assert gate.node_id == DecisionNode.meta.id == "decision.branch"
    out = {e.label: e.target for e in wf.out_edges("gate")}
    assert out["true"] == "take_action"
    assert out["false"] == "log_only"


def test_compile_parallel_step_emits_branch_edges_and_join():
    wf = compile_playbook(_PARALLEL_YAML)
    fan = wf.step("fan_out")
    assert fan is not None
    assert fan.node_id == ParallelNode.meta.id == "decision.parallel"
    out = wf.out_edges("fan_out")
    labels = {e.label for e in out}
    # Two branches → branch.0 + branch.1, plus a join edge to `merge`.
    assert "branch.0" in labels
    assert "branch.1" in labels
    assert "join" in labels
    # Within-branch sequencing emitted as `next` edges.
    enrich_out = wf.out_edges("enrich_ip")
    assert any(e.target == "score_ip" and e.label == "next" for e in enrich_out)


def test_compile_hitl_gate_step_is_decision_category_node():
    wf = compile_playbook(_HITL_YAML)
    gate = wf.step("gate")
    assert gate is not None
    assert gate.node_id == HITLGateNode.meta.id == "decision.hitl_gate"
    # The Node class has the right category for the HITL middleware to gate on.
    assert HITLGateNode.meta.category.value == "decision"
    # And the YAML config flows through to the WorkflowNode.
    assert gate.config["prompt"] == "Approve containment?"
    assert gate.config["required_role"] == "incident_commander"


def test_compile_rejects_cycles():
    with pytest.raises(PlaybookCompileError, match="Cycle detected"):
        compile_playbook(_CYCLE_YAML)


def test_compile_rejects_unknown_top_level_keys():
    bad = """
name: x
trigger: {type: manual}
steps: []
oops: 1
"""
    with pytest.raises(PlaybookCompileError, match="Unknown top-level"):
        compile_playbook(bad)


def test_compile_rejects_unknown_step_keys():
    bad = """
name: x
trigger: {type: manual}
steps:
  - id: s
    type: action
    tool: integration.test.echo  # typo: should be tool_name
"""
    with pytest.raises(PlaybookCompileError, match="unknown keys"):
        compile_playbook(bad)


def test_compile_rejects_unknown_step_type():
    bad = """
name: x
trigger: {type: manual}
steps:
  - id: s
    type: jiggery_pokery
"""
    with pytest.raises(PlaybookCompileError, match="unknown type"):
        compile_playbook(bad)


def test_compile_enforces_step_count_cap():
    # 501 steps -> over the cap of 500
    steps = "\n".join(
        f"  - {{id: s{i}, type: action, tool_name: integration.test.echo}}" for i in range(501)
    )
    yaml_str = f"""
name: TooMany
trigger: {{type: manual}}
steps:
{steps}
"""
    with pytest.raises(PlaybookCompileError, match="max 500"):
        compile_playbook(yaml_str)


def test_compile_enforces_parallel_branch_cap():
    branches = ", ".join(f"[s{i}]" for i in range(MAX_PARALLEL_BRANCHES + 1))
    yaml_str = f"""
name: TooParallel
trigger: {{type: manual}}
steps:
  - id: fan
    type: parallel_fork
    branches: [{branches}]
"""
    with pytest.raises(PlaybookCompileError, match=f"max {MAX_PARALLEL_BRANCHES}"):
        compile_playbook(yaml_str)


def test_compile_rejects_oversize_yaml():
    huge = "name: x\ntrigger: {type: manual}\nsteps: []\ndescription: " + ("A" * (1024 * 1024 + 1))
    with pytest.raises(PlaybookCompileError, match="exceeds"):
        compile_playbook(huge)


def test_compile_rejects_duplicate_step_ids():
    bad = """
name: dup
trigger: {type: manual}
steps:
  - {id: s, type: action, tool_name: integration.test.echo}
  - {id: s, type: action, tool_name: integration.test.echo}
"""
    with pytest.raises(PlaybookCompileError, match="Duplicate"):
        compile_playbook(bad)


def test_compile_action_step_without_tool_name_uses_unresolved_sentinel():
    """Legacy templates omit tool_name on stub action steps; the compiler
    tolerates this and flags the node id as ``action.unresolved`` so the
    runner fails at execute time (not compile time)."""
    yaml_str = """
name: stub
trigger: {type: manual}
steps:
  - {id: s, type: action}
"""
    wf = compile_playbook(yaml_str)
    step = wf.step("s")
    assert step is not None
    assert step.node_id == "action.unresolved"


# --------------------------------------------------------------------------- #
# Smoke test: every shipped library/template compiles without error.
# --------------------------------------------------------------------------- #


def _find_library_yamls() -> list[Path]:
    """Locate any playbook YAML the repo ships, without importing agents code."""
    candidates: list[Path] = []
    repo_root = Path(__file__).resolve().parents[2]
    for sub in (
        "agents/btagent_agents/playbook/library",
        "agents/btagent_agents/playbook/templates",
    ):
        d = repo_root / sub
        if d.is_dir():
            for p in sorted(d.glob("*.yaml")):
                # Skip the schema doc (not a real playbook).
                if p.name.startswith("_"):
                    continue
                candidates.append(p)
    return candidates


@pytest.mark.parametrize("yaml_path", _find_library_yamls(), ids=lambda p: p.name)
def test_compile_shipped_playbook_smoke(yaml_path: Path) -> None:
    wf = compile_playbook(yaml_path.read_text())
    assert wf.name
    assert len(wf.nodes) > 0
