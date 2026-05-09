"""Playbook YAML -> Node-graph compiler.

Turns a YAML playbook spec into a :class:`Workflow` -- a directed graph of
Node ids the runner can walk. The four playbook step kinds (action,
decision, parallel, hitl_gate) all become Nodes; ``action`` wraps an
already-registered Node by id while the other three are first-class Node
classes shipped in :mod:`btagent_engine.compiler.steps`.

The compiler intentionally does **not** resolve every ``tool_name`` against
the :class:`NodeRegistry` at compile time -- registry membership is a
runtime concern (tests register/unregister freely, Phase 2 plugins arrive
asynchronously). Resolution happens when the runner walks the graph.
What the compiler *does* enforce is structural: shape, key-allowlists,
size caps, and DAG-ness.
"""

from btagent_engine.compiler.compiler import (
    MAX_BRANCH_DEPTH,
    MAX_PARALLEL_BRANCHES,
    MAX_PLAYBOOK_BYTES,
    MAX_STEPS,
    CompiledStep,
    PlaybookCompileError,
    compile_playbook,
)
from btagent_engine.compiler.steps import (
    DecisionNode,
    DecisionNodeInput,
    DecisionNodeOutput,
    HITLGateNode,
    HITLGateNodeInput,
    HITLGateNodeOutput,
    ParallelNode,
    ParallelNodeInput,
    ParallelNodeOutput,
)
from btagent_engine.compiler.workflow import Workflow, WorkflowEdge, WorkflowNode

__all__ = [
    "MAX_BRANCH_DEPTH",
    "MAX_PARALLEL_BRANCHES",
    "MAX_PLAYBOOK_BYTES",
    "MAX_STEPS",
    "CompiledStep",
    "DecisionNode",
    "DecisionNodeInput",
    "DecisionNodeOutput",
    "HITLGateNode",
    "HITLGateNodeInput",
    "HITLGateNodeOutput",
    "ParallelNode",
    "ParallelNodeInput",
    "ParallelNodeOutput",
    "PlaybookCompileError",
    "Workflow",
    "WorkflowEdge",
    "WorkflowNode",
    "compile_playbook",
]
