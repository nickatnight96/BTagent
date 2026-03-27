"""Playbook execution state schema for LangGraph subgraph."""

from __future__ import annotations

from typing import Any, TypedDict


class StepResultEntry(TypedDict, total=False):
    """Result of a single playbook step execution."""

    step_id: str
    status: str
    output: dict[str, Any]
    error: str | None
    started_at: str
    completed_at: str


class PlaybookExecutionState(TypedDict, total=False):
    """Root state for the playbook executor LangGraph subgraph.

    Every node reads and returns a partial dict of this shape.  LangGraph merges
    the returned keys into the running state.

    Fields
    ------
    execution_id : str
        Prefixed ULID (``pbe_...``) for this execution run.
    playbook_id : str
        ID of the playbook definition being executed.
    investigation_id : str
        Optional investigation ID this execution is associated with.
    current_step_id : str
        ID of the step currently being executed.
    status : str
        Overall execution status (pending / running / paused_hitl /
        completed / failed / cancelled).
    trigger_data : dict
        Runtime trigger payload (alert data, webhook payload, etc.).
    step_results : list[StepResultEntry]
        Accumulated results from each completed step.
    context : dict
        Shared context accessible by all steps (enrichment results,
        intermediate outputs, etc.).
    error : str | None
        Last error message, or None if healthy.
    hitl_pending : bool
        True if execution is blocked on a human-in-the-loop gate.
    hitl_prompt : str
        The HITL gate prompt displayed to the analyst.
    hitl_response : dict
        Response from the analyst (approved / rejected + notes).
    """

    execution_id: str
    playbook_id: str
    investigation_id: str
    current_step_id: str
    status: str
    trigger_data: dict[str, Any]
    step_results: list[StepResultEntry]
    context: dict[str, Any]
    error: str | None
    hitl_pending: bool
    hitl_prompt: str
    hitl_response: dict[str, Any]
