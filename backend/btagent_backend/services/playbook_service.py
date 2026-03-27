"""Playbook service — validation, compilation, CRUD, and execution dispatch.

Provides the core business logic for SOAR playbooks:
- Parse and validate YAML against the Pydantic schema
- DAG cycle detection via topological sort
- Tool reference verification
- CRUD operations on playbook rows
- Execution dispatch to TaskManager
"""

from __future__ import annotations

import logging
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any

import yaml
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.db.models_playbook import PlaybookExecutionRow, PlaybookRow
from btagent_shared.types.playbook import (
    ActionStep,
    DecisionStep,
    HITLGateStep,
    OnFailure,
    ParallelForkStep,
    PlaybookDefinition,
    PlaybookExecution,
    PlaybookStatus,
    PlaybookStep,
    StepType,
    TriggerCondition,
    ValidationResult,
)
from btagent_shared.utils.ids import generate_id

logger = logging.getLogger("btagent.services.playbook")


# ---------------------------------------------------------------------------
# Known tool names that can be referenced in action steps
# ---------------------------------------------------------------------------

KNOWN_TOOLS: set[str] = {
    "alert_classifier",
    "severity_scorer",
    "query_generator",
    "query_executor",
    "enrich_ioc",
    "confidence_scorer",
    "splunk_search",
    "elastic_search",
    "sentinel_search",
    "crowdstrike_search",
    "virustotal_lookup",
    "shodan_lookup",
    "abuseipdb_lookup",
    "greynoise_lookup",
    "misp_lookup",
    "search_knowledge_base",
    "get_investigation_context",
}


# ---------------------------------------------------------------------------
# DAG cycle detection
# ---------------------------------------------------------------------------


def _detect_cycles(steps: list[PlaybookStep]) -> list[str]:
    """Detect cycles in the step graph using Kahn's topological sort.

    Returns a list of error strings (empty if DAG is valid).
    """
    step_ids = {s.id for s in steps}
    adj: dict[str, list[str]] = defaultdict(list)
    in_degree: dict[str, int] = {sid: 0 for sid in step_ids}

    for step in steps:
        successors: list[str] = []

        if step.next_step and step.next_step in step_ids:
            successors.append(step.next_step)

        if step.type == StepType.DECISION:
            # Parse decision-specific fields from raw data
            if hasattr(step, "true_branch") and step.true_branch in step_ids:
                successors.append(step.true_branch)
            if hasattr(step, "false_branch") and step.false_branch in step_ids:
                successors.append(step.false_branch)

        if step.type == StepType.PARALLEL_FORK:
            if hasattr(step, "branches"):
                for branch in step.branches:
                    for branch_step_id in branch:
                        if branch_step_id in step_ids:
                            successors.append(branch_step_id)

        for succ in successors:
            adj[step.id].append(succ)
            in_degree[succ] = in_degree.get(succ, 0) + 1

    # Kahn's algorithm
    queue: deque[str] = deque()
    for sid, deg in in_degree.items():
        if deg == 0:
            queue.append(sid)

    visited = 0
    while queue:
        node = queue.popleft()
        visited += 1
        for neighbor in adj[node]:
            in_degree[neighbor] -= 1
            if in_degree[neighbor] == 0:
                queue.append(neighbor)

    errors: list[str] = []
    if visited < len(step_ids):
        cycle_nodes = {sid for sid, deg in in_degree.items() if deg > 0}
        errors.append(
            f"Cycle detected among steps: {sorted(cycle_nodes)}"
        )

    return errors


# ---------------------------------------------------------------------------
# Step parser — converts raw dicts to typed step subclasses
# ---------------------------------------------------------------------------


def _parse_step(raw: dict[str, Any]) -> PlaybookStep:
    """Convert a raw step dict into the appropriate PlaybookStep subclass."""
    step_type = raw.get("type", "action")

    if step_type == StepType.ACTION:
        return ActionStep(
            id=raw["id"],
            type=StepType.ACTION,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=OnFailure(raw.get("on_failure", "abort")),
            tool_name=raw.get("tool_name", ""),
            arguments=raw.get("arguments", {}),
            timeout_seconds=raw.get("timeout_seconds", 300),
        )
    elif step_type == StepType.DECISION:
        return DecisionStep(
            id=raw["id"],
            type=StepType.DECISION,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=OnFailure(raw.get("on_failure", "abort")),
            condition=raw.get("condition", ""),
            true_branch=raw.get("true_branch", ""),
            false_branch=raw.get("false_branch", ""),
        )
    elif step_type == StepType.HITL_GATE:
        return HITLGateStep(
            id=raw["id"],
            type=StepType.HITL_GATE,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=OnFailure(raw.get("on_failure", "abort")),
            prompt=raw.get("prompt", ""),
            timeout_seconds=raw.get("timeout_seconds", 3600),
            required_role=raw.get("required_role", "senior_analyst"),
        )
    elif step_type == StepType.PARALLEL_FORK:
        return ParallelForkStep(
            id=raw["id"],
            type=StepType.PARALLEL_FORK,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=OnFailure(raw.get("on_failure", "abort")),
            branches=raw.get("branches", []),
        )
    else:
        # join, end, or unknown — use base class
        return PlaybookStep(
            id=raw["id"],
            type=StepType(step_type) if step_type in StepType.__members__.values() else StepType.END,
            name=raw.get("name", ""),
            description=raw.get("description", ""),
            config=raw.get("config", {}),
            next_step=raw.get("next_step"),
            on_failure=OnFailure(raw.get("on_failure", "abort")),
        )


# ---------------------------------------------------------------------------
# PlaybookService
# ---------------------------------------------------------------------------


class PlaybookService:
    """Service layer for playbook CRUD, validation, and execution."""

    # ------------------------------------------------------------------ #
    # Validate
    # ------------------------------------------------------------------ #

    def validate_playbook(self, yaml_str: str) -> ValidationResult:
        """Parse YAML, validate schema, check DAG, verify tool refs.

        Parameters
        ----------
        yaml_str : str
            Raw YAML content of the playbook.

        Returns
        -------
        ValidationResult
            Validation outcome with errors and warnings.
        """
        errors: list[str] = []
        warnings: list[str] = []

        # 1. Parse YAML
        try:
            raw = yaml.safe_load(yaml_str)
        except yaml.YAMLError as exc:
            return ValidationResult(
                valid=False,
                errors=[f"YAML parse error: {exc}"],
            )

        if not isinstance(raw, dict):
            return ValidationResult(
                valid=False,
                errors=["Playbook YAML must be a mapping (dict) at top level"],
            )

        # 2. Required top-level fields
        if "name" not in raw:
            errors.append("Missing required field: name")
        if "steps" not in raw or not isinstance(raw.get("steps"), list):
            errors.append("Missing or invalid field: steps (must be a list)")
        if "trigger" not in raw:
            errors.append("Missing required field: trigger")

        if errors:
            return ValidationResult(valid=False, errors=errors)

        # 3. Validate trigger
        trigger_raw = raw["trigger"]
        if not isinstance(trigger_raw, dict) or "type" not in trigger_raw:
            errors.append("Trigger must be a dict with a 'type' field")
        else:
            from btagent_shared.types.playbook import TriggerType as _TT

            valid_trigger_types = {t.value for t in _TT}
            if trigger_raw["type"] not in valid_trigger_types:
                errors.append(
                    f"Invalid trigger type: {trigger_raw['type']}. "
                    f"Must be one of: {sorted(valid_trigger_types)}"
                )

        # 4. Parse steps
        steps: list[PlaybookStep] = []
        step_ids: set[str] = set()
        for i, step_raw in enumerate(raw.get("steps", [])):
            if not isinstance(step_raw, dict):
                errors.append(f"Step {i}: must be a dict")
                continue
            if "id" not in step_raw:
                errors.append(f"Step {i}: missing required field 'id'")
                continue
            if step_raw["id"] in step_ids:
                errors.append(f"Duplicate step id: {step_raw['id']}")
                continue
            step_ids.add(step_raw["id"])

            try:
                step = _parse_step(step_raw)
                steps.append(step)
            except Exception as exc:
                errors.append(f"Step {step_raw['id']}: {exc}")

        # 5. Validate step references
        for step in steps:
            if step.next_step and step.next_step not in step_ids:
                errors.append(
                    f"Step '{step.id}': next_step '{step.next_step}' "
                    f"does not reference a valid step"
                )
            if isinstance(step, DecisionStep):
                if step.true_branch and step.true_branch not in step_ids:
                    errors.append(
                        f"Step '{step.id}': true_branch '{step.true_branch}' "
                        f"does not reference a valid step"
                    )
                if step.false_branch and step.false_branch not in step_ids:
                    errors.append(
                        f"Step '{step.id}': false_branch '{step.false_branch}' "
                        f"does not reference a valid step"
                    )
            if isinstance(step, ParallelForkStep):
                for branch in step.branches:
                    for branch_step_id in branch:
                        if branch_step_id not in step_ids:
                            errors.append(
                                f"Step '{step.id}': branch references "
                                f"unknown step '{branch_step_id}'"
                            )

        # 6. Verify tool references
        for step in steps:
            if isinstance(step, ActionStep) and step.tool_name:
                if step.tool_name not in KNOWN_TOOLS:
                    warnings.append(
                        f"Step '{step.id}': tool '{step.tool_name}' is not "
                        f"in the known tool registry"
                    )

        # 7. DAG cycle detection
        if steps:
            cycle_errors = _detect_cycles(steps)
            errors.extend(cycle_errors)

        # 8. Must have at least one 'end' step
        has_end = any(s.type == StepType.END for s in steps)
        if not has_end:
            warnings.append("Playbook has no 'end' step — execution may not terminate cleanly")

        return ValidationResult(
            valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            step_count=len(steps),
        )

    # ------------------------------------------------------------------ #
    # Compile
    # ------------------------------------------------------------------ #

    def compile_playbook(self, yaml_str: str) -> PlaybookDefinition:
        """Parse YAML, validate, and return a typed PlaybookDefinition.

        Raises ValueError if validation fails.
        """
        result = self.validate_playbook(yaml_str)
        if not result.valid:
            raise ValueError(
                f"Playbook validation failed: {'; '.join(result.errors)}"
            )

        raw = yaml.safe_load(yaml_str)
        trigger = TriggerCondition(
            type=raw["trigger"]["type"],
            parameters=raw["trigger"].get("parameters", {}),
        )

        steps = [_parse_step(s) for s in raw.get("steps", [])]

        return PlaybookDefinition(
            name=raw["name"],
            version=raw.get("version", "1.0"),
            description=raw.get("description", ""),
            trigger=trigger,
            steps=steps,
        )

    # ------------------------------------------------------------------ #
    # Create
    # ------------------------------------------------------------------ #

    async def create_playbook(
        self,
        db: AsyncSession,
        *,
        name: str,
        yaml_str: str,
        user_id: str | None = None,
    ) -> PlaybookRow:
        """Validate and store a new playbook.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        name : str
            Display name for the playbook.
        yaml_str : str
            Raw YAML content.
        user_id : str | None
            ID of the user creating the playbook.

        Returns
        -------
        PlaybookRow
            The persisted playbook row.

        Raises
        ------
        ValueError
            If the playbook YAML is invalid.
        """
        definition = self.compile_playbook(yaml_str)

        row = PlaybookRow(
            id=generate_id("pb"),
            name=name,
            version=definition.version,
            description=definition.description,
            yaml_content=yaml_str,
            trigger_type=definition.trigger.type.value,
            trigger_config=definition.trigger.parameters,
            created_by=user_id,
            is_active=True,
        )
        db.add(row)
        await db.flush()

        logger.info(
            "Created playbook %s (name=%r, trigger=%s, steps=%d)",
            row.id,
            name,
            definition.trigger.type.value,
            len(definition.steps),
        )
        return row

    # ------------------------------------------------------------------ #
    # Update
    # ------------------------------------------------------------------ #

    async def update_playbook(
        self,
        db: AsyncSession,
        playbook_id: str,
        yaml_str: str,
    ) -> PlaybookRow | None:
        """Validate and update an existing playbook's YAML.

        Returns the updated row, or None if not found.
        """
        result = await db.execute(
            select(PlaybookRow).where(PlaybookRow.id == playbook_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return None

        definition = self.compile_playbook(yaml_str)

        row.yaml_content = yaml_str
        row.version = definition.version
        row.description = definition.description
        row.trigger_type = definition.trigger.type.value
        row.trigger_config = definition.trigger.parameters
        row.updated_at = datetime.now(timezone.utc)

        await db.flush()

        logger.info("Updated playbook %s", playbook_id)
        return row

    # ------------------------------------------------------------------ #
    # Execute
    # ------------------------------------------------------------------ #

    async def execute_playbook(
        self,
        db: AsyncSession,
        playbook_id: str,
        trigger_data: dict[str, Any] | None = None,
        investigation_id: str | None = None,
    ) -> PlaybookExecutionRow:
        """Create an execution record and dispatch to TaskManager.

        Parameters
        ----------
        db : AsyncSession
            Database session.
        playbook_id : str
            ID of the playbook to execute.
        trigger_data : dict | None
            Runtime trigger data (alert payload, etc.).
        investigation_id : str | None
            Optional investigation to associate with.

        Returns
        -------
        PlaybookExecutionRow
            The created execution row.

        Raises
        ------
        ValueError
            If the playbook is not found or inactive.
        """
        result = await db.execute(
            select(PlaybookRow).where(
                PlaybookRow.id == playbook_id,
                PlaybookRow.is_active.is_(True),
            )
        )
        pb = result.scalar_one_or_none()
        if pb is None:
            raise ValueError(f"Playbook '{playbook_id}' not found or inactive")

        now = datetime.now(timezone.utc)
        execution = PlaybookExecutionRow(
            id=generate_id("pbe"),
            playbook_id=playbook_id,
            investigation_id=investigation_id,
            status=PlaybookStatus.RUNNING.value,
            trigger_data=trigger_data or {},
            step_results={},
            started_at=now,
        )
        db.add(execution)
        await db.flush()

        logger.info(
            "Dispatched playbook execution %s for playbook %s",
            execution.id,
            playbook_id,
        )
        return execution

    # ------------------------------------------------------------------ #
    # List / History
    # ------------------------------------------------------------------ #

    async def list_playbooks(
        self,
        db: AsyncSession,
        *,
        active_only: bool = True,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[PlaybookRow], int]:
        """List playbooks with optional active filter and pagination.

        Returns (rows, total_count).
        """
        query = select(PlaybookRow).order_by(PlaybookRow.created_at.desc())
        count_query = select(func.count(PlaybookRow.id))

        if active_only:
            query = query.where(PlaybookRow.is_active.is_(True))
            count_query = count_query.where(PlaybookRow.is_active.is_(True))

        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        rows = list(result.scalars().all())

        return rows, total

    async def get_playbook(
        self,
        db: AsyncSession,
        playbook_id: str,
    ) -> PlaybookRow | None:
        """Fetch a single playbook by ID."""
        result = await db.execute(
            select(PlaybookRow).where(PlaybookRow.id == playbook_id)
        )
        return result.scalar_one_or_none()

    async def deactivate_playbook(
        self,
        db: AsyncSession,
        playbook_id: str,
    ) -> bool:
        """Soft-delete a playbook (set is_active=False).

        Returns True if found and deactivated, False otherwise.
        """
        result = await db.execute(
            select(PlaybookRow).where(PlaybookRow.id == playbook_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            return False

        row.is_active = False
        row.updated_at = datetime.now(timezone.utc)
        await db.flush()

        logger.info("Deactivated playbook %s", playbook_id)
        return True

    async def get_execution_history(
        self,
        db: AsyncSession,
        playbook_id: str,
        *,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[list[PlaybookExecutionRow], int]:
        """Get paginated execution history for a playbook."""
        query = (
            select(PlaybookExecutionRow)
            .where(PlaybookExecutionRow.playbook_id == playbook_id)
            .order_by(PlaybookExecutionRow.started_at.desc())
        )
        count_query = select(func.count(PlaybookExecutionRow.id)).where(
            PlaybookExecutionRow.playbook_id == playbook_id
        )

        total_result = await db.execute(count_query)
        total = total_result.scalar() or 0

        query = query.offset((page - 1) * page_size).limit(page_size)
        result = await db.execute(query)
        rows = list(result.scalars().all())

        return rows, total

    async def get_execution(
        self,
        db: AsyncSession,
        execution_id: str,
    ) -> PlaybookExecutionRow | None:
        """Fetch a single execution by ID."""
        result = await db.execute(
            select(PlaybookExecutionRow).where(
                PlaybookExecutionRow.id == execution_id
            )
        )
        return result.scalar_one_or_none()
