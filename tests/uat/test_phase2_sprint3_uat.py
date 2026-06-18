"""Phase 2 Sprint 3 UAT — SOAR Playbook System.

Run with: pytest tests/uat/test_phase2_sprint3_uat.py -v

Tests cover:
- Playbook Pydantic schema (shared types)
- Playbook ORM models (DB layer)
- Playbook service (validate, compile, CRUD, DAG cycle detection)
- Playbook API router (endpoints, request/response schemas)
- Pre-built YAML templates validate
- PlaybookExecutor (LangGraph subgraph)
- Step handlers (action, decision, hitl_gate, parallel)
- RBAC permissions for playbook operations
- Event types for playbook lifecycle
- Knowledge frontend types
"""

import asyncio
from pathlib import Path

import pytest
import yaml


# ── UAT-PLAYBOOK-TYPES: Shared Pydantic model validation ─────


class TestPlaybookTypes:
    """Validate shared playbook Pydantic models."""

    def test_playbook_definition_model(self):
        """PlaybookDefinition can be constructed and has required fields."""
        from btagent_shared.types.playbook import (
            PlaybookDefinition,
            TriggerCondition,
        )

        definition = PlaybookDefinition(
            name="Test Playbook",
            version="1.0",
            description="A test playbook",
            trigger=TriggerCondition(type="manual", parameters={}),
            steps=[],
        )
        assert definition.name == "Test Playbook"
        assert definition.version == "1.0"
        assert definition.trigger.type == "manual"

    def test_action_step_model(self):
        """ActionStep has tool_name and arguments fields."""
        from btagent_shared.types.playbook import ActionStep, StepType

        step = ActionStep(
            id="test_action",
            type=StepType.ACTION,
            name="Test Action",
            tool_name="alert_classifier",
            arguments={"source": "email"},
        )
        assert step.tool_name == "alert_classifier"
        assert step.arguments == {"source": "email"}
        assert step.timeout_seconds == 300

    def test_decision_step_model(self):
        """DecisionStep has condition, true_branch, false_branch."""
        from btagent_shared.types.playbook import DecisionStep, StepType

        step = DecisionStep(
            id="test_decision",
            type=StepType.DECISION,
            name="Test Decision",
            condition="enrichment.max_confidence > 0.7",
            true_branch="block",
            false_branch="log",
        )
        assert step.condition == "enrichment.max_confidence > 0.7"
        assert step.true_branch == "block"
        assert step.false_branch == "log"

    def test_hitl_gate_step_model(self):
        """HITLGateStep has prompt, timeout, and required_role."""
        from btagent_shared.types.playbook import HITLGateStep, StepType

        step = HITLGateStep(
            id="test_hitl",
            type=StepType.HITL_GATE,
            name="Test HITL Gate",
            prompt="Approve this action?",
            timeout_seconds=1800,
            required_role="senior_analyst",
        )
        assert step.prompt == "Approve this action?"
        assert step.timeout_seconds == 1800
        assert step.required_role == "senior_analyst"

    def test_parallel_fork_step_model(self):
        """ParallelForkStep has branches field."""
        from btagent_shared.types.playbook import ParallelForkStep, StepType

        step = ParallelForkStep(
            id="test_parallel",
            type=StepType.PARALLEL_FORK,
            name="Test Parallel",
            branches=[["step_a", "step_b"], ["step_c"]],
        )
        assert len(step.branches) == 2
        assert step.branches[0] == ["step_a", "step_b"]

    def test_trigger_condition_model(self):
        """TriggerCondition validates trigger types."""
        from btagent_shared.types.playbook import TriggerCondition, TriggerType

        trigger = TriggerCondition(
            type=TriggerType.ALERT_SEVERITY,
            parameters={"min_severity": "medium"},
        )
        assert trigger.type == "alert_severity"
        assert trigger.parameters["min_severity"] == "medium"

    def test_playbook_execution_model(self):
        """PlaybookExecution tracks execution state."""
        from btagent_shared.types.playbook import (
            PlaybookExecution,
            PlaybookStatus,
        )

        execution = PlaybookExecution(
            id="pbe_test",
            playbook_id="pb_test",
            status=PlaybookStatus.RUNNING,
        )
        assert execution.status == "running"
        assert execution.step_results == []
        assert execution.error is None

    def test_validation_result_model(self):
        """ValidationResult has valid, errors, warnings, step_count."""
        from btagent_shared.types.playbook import ValidationResult

        result = ValidationResult(
            valid=True,
            errors=[],
            warnings=["No end step"],
            step_count=5,
        )
        assert result.valid is True
        assert result.step_count == 5
        assert len(result.warnings) == 1

    def test_step_type_enum(self):
        """StepType enum has all expected values."""
        from btagent_shared.types.playbook import StepType

        expected = {"action", "decision", "hitl_gate", "parallel_fork", "join", "end"}
        actual = {e.value for e in StepType}
        assert expected == actual

    def test_on_failure_enum(self):
        """OnFailure enum has skip, abort, retry."""
        from btagent_shared.types.playbook import OnFailure

        expected = {"skip", "abort", "retry"}
        actual = {e.value for e in OnFailure}
        assert expected == actual


# ── UAT-PLAYBOOK-DB: ORM model validation ────────────────────


class TestPlaybookDB:
    """Validate playbook ORM models."""

    def test_playbook_row_importable(self):
        """PlaybookRow can be imported."""
        from btagent_backend.db.models_playbook import PlaybookRow

        assert PlaybookRow is not None
        assert PlaybookRow.__tablename__ == "playbooks"

    def test_execution_row_importable(self):
        """PlaybookExecutionRow can be imported."""
        from btagent_backend.db.models_playbook import PlaybookExecutionRow

        assert PlaybookExecutionRow is not None
        assert PlaybookExecutionRow.__tablename__ == "playbook_executions"

    def test_playbook_row_has_required_columns(self):
        """PlaybookRow has all required columns."""
        from btagent_backend.db.models_playbook import PlaybookRow

        columns = {c.name for c in PlaybookRow.__table__.columns}
        required = {
            "id",
            "name",
            "version",
            "description",
            "yaml_content",
            "trigger_type",
            "trigger_config",
            "created_by",
            "created_at",
            "updated_at",
            "is_active",
        }
        assert required.issubset(columns), f"Missing columns: {required - columns}"

    def test_execution_row_has_required_columns(self):
        """PlaybookExecutionRow has all required columns."""
        from btagent_backend.db.models_playbook import PlaybookExecutionRow

        columns = {c.name for c in PlaybookExecutionRow.__table__.columns}
        required = {
            "id",
            "playbook_id",
            "investigation_id",
            "status",
            "trigger_data",
            "step_results",
            "started_at",
            "completed_at",
            "error",
        }
        assert required.issubset(columns), f"Missing columns: {required - columns}"

    def test_migration_file_exists(self):
        """Migration 0005_playbooks.py exists."""
        migration_path = (
            Path(__file__).resolve().parents[2]
            / "backend"
            / "migrations"
            / "versions"
            / "0005_playbooks.py"
        )
        assert migration_path.exists(), f"Migration not found at {migration_path}"


# ── UAT-PLAYBOOK-SERVICE: Service layer validation ───────────


class TestPlaybookService:
    """Validate PlaybookService methods."""

    def test_service_importable(self):
        """PlaybookService can be imported."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        assert svc is not None

    def test_validate_valid_playbook(self):
        """Valid YAML passes validation."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        yaml_str = """
name: Test Playbook
version: "1.0"
description: A test
trigger:
  type: manual
  parameters: {}
steps:
  - id: step1
    type: action
    name: Do something
    tool_name: alert_classifier
    next_step: end
  - id: end
    type: end
    name: Done
"""
        result = svc.validate_playbook(yaml_str)
        assert result.valid is True
        assert result.step_count == 2
        assert len(result.errors) == 0

    def test_validate_invalid_yaml(self):
        """Invalid YAML produces errors."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        result = svc.validate_playbook(":::invalid yaml:::")
        assert result.valid is False
        assert len(result.errors) > 0
        assert len(result.errors[0]) > 0  # Error message present

    def test_validate_missing_name(self):
        """Missing 'name' field produces error."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        result = svc.validate_playbook("""
trigger:
  type: manual
steps:
  - id: end
    type: end
    name: Done
""")
        assert result.valid is False
        assert any("name" in e for e in result.errors)

    def test_validate_duplicate_step_ids(self):
        """Duplicate step IDs produce error."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        result = svc.validate_playbook("""
name: Test
trigger:
  type: manual
steps:
  - id: step1
    type: action
    name: First
    tool_name: alert_classifier
  - id: step1
    type: end
    name: Duplicate
""")
        assert result.valid is False
        assert any("Duplicate" in e or "duplicate" in e.lower() for e in result.errors)

    def test_validate_invalid_step_reference(self):
        """Invalid next_step reference produces error."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        result = svc.validate_playbook("""
name: Test
trigger:
  type: manual
steps:
  - id: step1
    type: action
    name: First
    tool_name: alert_classifier
    next_step: nonexistent_step
  - id: end
    type: end
    name: Done
""")
        assert result.valid is False
        assert any("nonexistent_step" in e for e in result.errors)

    def test_compile_playbook(self):
        """compile_playbook returns a PlaybookDefinition."""
        from btagent_backend.services.playbook_service import PlaybookService
        from btagent_shared.types.playbook import PlaybookDefinition

        svc = PlaybookService()
        definition = svc.compile_playbook("""
name: Compiled Test
version: "2.0"
trigger:
  type: alert_severity
  parameters:
    min_severity: high
steps:
  - id: classify
    type: action
    name: Classify
    tool_name: alert_classifier
    next_step: end
  - id: end
    type: end
    name: Done
""")
        assert isinstance(definition, PlaybookDefinition)
        assert definition.name == "Compiled Test"
        assert definition.version == "2.0"
        assert len(definition.steps) == 2

    def test_compile_invalid_raises_valueerror(self):
        """compile_playbook raises ValueError for invalid YAML."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        with pytest.raises(ValueError):
            svc.compile_playbook("not: valid: playbook:")

    def test_dag_cycle_detection(self):
        """Cycle detection catches a simple cycle."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        result = svc.validate_playbook("""
name: Cyclic
trigger:
  type: manual
steps:
  - id: a
    type: action
    name: A
    tool_name: alert_classifier
    next_step: b
  - id: b
    type: action
    name: B
    tool_name: alert_classifier
    next_step: a
""")
        assert result.valid is False
        assert any("Cycle" in e or "cycle" in e.lower() for e in result.errors)

    def test_known_tools_set_exists(self):
        """KNOWN_TOOLS set contains expected tools."""
        from btagent_backend.services.playbook_service import KNOWN_TOOLS

        assert "alert_classifier" in KNOWN_TOOLS
        assert "enrich_ioc" in KNOWN_TOOLS
        assert "splunk_search" in KNOWN_TOOLS
        assert "query_generator" in KNOWN_TOOLS


# ── UAT-PLAYBOOK-API: API router validation ──────────────────


class TestPlaybookAPI:
    """Validate playbook API router and endpoints."""

    def test_router_importable(self):
        """Playbook router can be imported."""
        from btagent_backend.api.v1.playbooks import router

        assert router is not None
        assert router.prefix == "/playbooks"

    def test_router_mounted_in_v1(self):
        """Playbook router is mounted in the v1 API router."""
        from fastapi import FastAPI

        from btagent_backend.api.v1.router import api_v1_router

        # FastAPI >=0.137 keeps sub-router routes inside _IncludedRouter
        # entries instead of flattening them into ``.routes``; resolve the
        # full path set via the OpenAPI schema, which walks every endpoint
        # regardless of the internal route representation.
        app = FastAPI()
        app.include_router(api_v1_router)
        route_paths = list(app.openapi()["paths"].keys())
        playbook_paths = [p for p in route_paths if "playbook" in p]
        assert len(playbook_paths) > 0, "No playbook routes found in api_v1_router"

    def test_list_endpoint_exists(self):
        """GET /playbooks endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/playbooks", ("GET",)) in routes

    def test_create_endpoint_exists(self):
        """POST /playbooks endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/playbooks", ("POST",)) in routes

    def test_detail_endpoint_exists(self):
        """GET /playbooks/{playbook_id} endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        route_paths = [r.path for r in router.routes]
        assert "/playbooks/{playbook_id}" in route_paths

    def test_update_endpoint_exists(self):
        """PUT /playbooks/{playbook_id} endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/playbooks/{playbook_id}", ("PUT",)) in routes

    def test_delete_endpoint_exists(self):
        """DELETE /playbooks/{playbook_id} endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        routes = {
            (r.path, tuple(r.methods)) for r in router.routes if hasattr(r, "methods")
        }
        assert ("/playbooks/{playbook_id}", ("DELETE",)) in routes

    def test_validate_endpoint_exists(self):
        """POST /playbooks/{playbook_id}/validate endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        route_paths = [r.path for r in router.routes]
        assert "/playbooks/{playbook_id}/validate" in route_paths

    def test_execute_endpoint_exists(self):
        """POST /playbooks/{playbook_id}/execute endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        route_paths = [r.path for r in router.routes]
        assert "/playbooks/{playbook_id}/execute" in route_paths

    def test_executions_endpoint_exists(self):
        """GET /playbooks/{playbook_id}/executions endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        route_paths = [r.path for r in router.routes]
        assert "/playbooks/{playbook_id}/executions" in route_paths

    def test_execution_detail_endpoint_exists(self):
        """GET /playbooks/executions/{execution_id} endpoint is defined."""
        from btagent_backend.api.v1.playbooks import router

        route_paths = [r.path for r in router.routes]
        assert "/playbooks/executions/{execution_id}" in route_paths


# ── UAT-TEMPLATES: Pre-built template validation ─────────────


class TestPlaybookTemplates:
    """Validate pre-built playbook YAML templates."""

    def _template_dir(self) -> Path:
        return (
            Path(__file__).resolve().parents[2]
            / "agents"
            / "btagent_agents"
            / "playbook"
            / "templates"
        )

    def test_phishing_template_exists(self):
        """phishing_response.yaml template exists."""
        path = self._template_dir() / "phishing_response.yaml"
        assert path.exists(), f"Template not found: {path}"

    def test_ransomware_template_exists(self):
        """ransomware_containment.yaml template exists."""
        path = self._template_dir() / "ransomware_containment.yaml"
        assert path.exists(), f"Template not found: {path}"

    def test_credential_template_exists(self):
        """credential_compromise.yaml template exists."""
        path = self._template_dir() / "credential_compromise.yaml"
        assert path.exists(), f"Template not found: {path}"

    def test_schema_exists(self):
        """_schema.yaml JSON Schema file exists."""
        path = self._template_dir() / "_schema.yaml"
        assert path.exists(), f"Schema not found: {path}"

    def test_phishing_validates(self):
        """Phishing response template validates successfully."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        path = self._template_dir() / "phishing_response.yaml"
        yaml_str = path.read_text()
        result = svc.validate_playbook(yaml_str)
        assert result.valid is True, f"Validation errors: {result.errors}"
        assert result.step_count >= 5

    def test_ransomware_validates(self):
        """Ransomware containment template validates successfully."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        path = self._template_dir() / "ransomware_containment.yaml"
        yaml_str = path.read_text()
        result = svc.validate_playbook(yaml_str)
        assert result.valid is True, f"Validation errors: {result.errors}"
        assert result.step_count >= 8

    def test_credential_validates(self):
        """Credential compromise template validates successfully."""
        from btagent_backend.services.playbook_service import PlaybookService

        svc = PlaybookService()
        path = self._template_dir() / "credential_compromise.yaml"
        yaml_str = path.read_text()
        result = svc.validate_playbook(yaml_str)
        assert result.valid is True, f"Validation errors: {result.errors}"
        assert result.step_count >= 8

    def test_all_templates_parse_as_yaml(self):
        """All .yaml templates (excluding _schema) parse as valid YAML."""
        template_dir = self._template_dir()
        for path in template_dir.glob("*.yaml"):
            if path.name.startswith("_"):
                continue
            data = yaml.safe_load(path.read_text())
            assert isinstance(data, dict), f"{path.name} did not parse as dict"
            assert "name" in data, f"{path.name} missing 'name' field"
            assert "steps" in data, f"{path.name} missing 'steps' field"


# ── UAT-EXECUTOR: PlaybookExecutor validation ────────────────


class TestPlaybookExecutor:
    """Validate the PlaybookExecutor compiles and runs."""

    def test_executor_importable(self):
        """PlaybookExecutor can be imported."""
        from btagent_agents.playbook.executor import PlaybookExecutor

        assert PlaybookExecutor is not None

    def test_compiler_importable(self):
        """PlaybookCompiler can be imported."""
        from btagent_agents.playbook.compiler import PlaybookCompiler

        assert PlaybookCompiler is not None

    def test_state_has_required_fields(self):
        """PlaybookExecutionState TypedDict has required fields."""
        from btagent_agents.playbook.state import PlaybookExecutionState

        annotations = PlaybookExecutionState.__annotations__
        required = {
            "execution_id",
            "playbook_id",
            "current_step_id",
            "status",
            "step_results",
            "context",
        }
        for field in required:
            assert field in annotations, (
                f"Missing field '{field}' in PlaybookExecutionState"
            )

    def test_compiler_compiles_valid_yaml(self):
        """PlaybookCompiler.compile parses valid YAML into definition."""
        from btagent_agents.playbook.compiler import PlaybookCompiler
        from btagent_shared.types.playbook import PlaybookDefinition

        compiler = PlaybookCompiler()
        definition = compiler.compile("""
name: Test
trigger:
  type: manual
steps:
  - id: step1
    type: action
    name: First
    tool_name: alert_classifier
    next_step: end
  - id: end
    type: end
    name: Done
""")
        assert isinstance(definition, PlaybookDefinition)
        assert len(definition.steps) == 2

    def test_compiler_rejects_cycles(self):
        """PlaybookCompiler raises ValueError on DAG cycle."""
        from btagent_agents.playbook.compiler import PlaybookCompiler

        compiler = PlaybookCompiler()
        with pytest.raises(ValueError, match="[Cc]ycle"):
            compiler.compile("""
name: Cyclic
trigger:
  type: manual
steps:
  - id: a
    type: action
    name: A
    tool_name: alert_classifier
    next_step: b
  - id: b
    type: action
    name: B
    tool_name: alert_classifier
    next_step: a
""")


# ── UAT-STEPS: Step handler validation ───────────────────────


class TestStepHandlers:
    """Validate individual step handler functions."""

    def test_action_step_handler(self):
        """Action step handler returns completed result."""
        from btagent_agents.playbook.steps.action import execute_action_step
        from btagent_shared.types.playbook import ActionStep, StepType

        step = ActionStep(
            id="test",
            type=StepType.ACTION,
            name="Test",
            tool_name="alert_classifier",
            arguments={"source": "email"},
        )
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(execute_action_step(step, {}, mock=True))
        finally:
            loop.close()

        assert result["status"] == "completed"
        assert result["output"]["tool_name"] == "alert_classifier"

    def test_decision_step_evaluates_condition(self):
        """Decision condition evaluator works correctly."""
        from btagent_agents.playbook.steps.decision import evaluate_condition

        ctx = {"enrichment": {"max_confidence": 0.9}}
        assert evaluate_condition("enrichment.max_confidence > 0.7", ctx) is True
        assert evaluate_condition("enrichment.max_confidence < 0.5", ctx) is False
        assert evaluate_condition("enrichment.max_confidence == 0.9", ctx) is True

    def test_decision_step_missing_key(self):
        """Decision evaluator returns False for missing key."""
        from btagent_agents.playbook.steps.decision import evaluate_condition

        assert evaluate_condition("nonexistent.key > 0", {}) is False

    def test_decision_step_string_comparison(self):
        """Decision evaluator handles string comparisons."""
        from btagent_agents.playbook.steps.decision import evaluate_condition

        ctx = {"alert": {"severity": "critical"}}
        assert evaluate_condition("alert.severity == critical", ctx) is True
        assert evaluate_condition("alert.severity != low", ctx) is True

    def test_hitl_gate_mock_auto_approves(self):
        """HITL gate in mock mode auto-approves."""
        from btagent_agents.playbook.steps.hitl_gate import execute_hitl_gate_step
        from btagent_shared.types.playbook import HITLGateStep, StepType

        step = HITLGateStep(
            id="test",
            type=StepType.HITL_GATE,
            name="Test",
            prompt="Approve?",
            required_role="senior_analyst",
        )
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(
                execute_hitl_gate_step(step, {}, mock=True)
            )
        finally:
            loop.close()

        assert result["status"] == "completed"
        assert result["output"]["approved"] is True

    def test_parallel_fork_mock(self):
        """Parallel fork in mock mode completes all branches."""
        from btagent_agents.playbook.steps.parallel import (
            execute_parallel_fork_step,
        )
        from btagent_shared.types.playbook import ParallelForkStep, StepType

        step = ParallelForkStep(
            id="test",
            type=StepType.PARALLEL_FORK,
            name="Test",
            branches=[["a", "b"], ["c"]],
        )
        loop = asyncio.new_event_loop()
        try:
            result = loop.run_until_complete(execute_parallel_fork_step(step, {}))
        finally:
            loop.close()

        assert result["status"] == "completed"
        assert len(result["output"]["results"]) == 2


# ── UAT-RBAC: Permission verification ────────────────────────


class TestPlaybookRBAC:
    """Validate RBAC permissions for playbook operations."""

    def test_playbook_view_analyst(self):
        """Analyst can view playbooks."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "playbook:view") is True

    def test_playbook_create_senior(self):
        """Senior analyst can create playbooks."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("senior_analyst", "playbook:create") is True

    def test_playbook_create_analyst_denied(self):
        """Regular analyst cannot create playbooks."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "playbook:create") is False

    def test_playbook_execute_senior(self):
        """Senior analyst can execute playbooks."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("senior_analyst", "playbook:execute") is True

    def test_playbook_delete_senior(self):
        """Senior analyst can soft-delete playbooks.

        Symmetric with ``playbook:create`` / ``playbook:edit`` /
        ``playbook:execute`` — SOAR authors own the full lifecycle.
        The DELETE endpoint is soft-delete (``active=false``); admin
        is still the gate for hard removal via the DB.
        """
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("senior_analyst", "playbook:delete") is True
        # Admin still inherits the permission via role hierarchy.
        assert has_permission("admin", "playbook:delete") is True

    def test_playbook_delete_analyst_denied(self):
        """Plain analyst cannot delete playbooks (no soft-delete either)."""
        from btagent_backend.auth.rbac import has_permission

        assert has_permission("analyst", "playbook:delete") is False

    def test_playbook_execute_containment_commander(self):
        """Incident commander can execute containment playbooks."""
        from btagent_backend.auth.rbac import has_permission

        assert (
            has_permission("incident_commander", "playbook:execute_containment") is True
        )

    def test_all_playbook_permissions_in_registry(self):
        """All playbook permissions are in the PERMISSIONS dict."""
        from btagent_backend.auth.rbac import PERMISSIONS

        expected = {
            "playbook:view",
            "playbook:create",
            "playbook:edit",
            "playbook:delete",
            "playbook:execute",
            "playbook:execute_containment",
        }
        for perm in expected:
            assert perm in PERMISSIONS, f"Missing permission: {perm}"


# ── UAT-EVENTS: Playbook event types ─────────────────────────


class TestPlaybookEvents:
    """Validate playbook-related event types are defined."""

    def test_playbook_started_event(self):
        """PLAYBOOK_STARTED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "PLAYBOOK_STARTED")
        assert EventType.PLAYBOOK_STARTED == "playbook_started"

    def test_playbook_step_complete_event(self):
        """PLAYBOOK_STEP_COMPLETE event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "PLAYBOOK_STEP_COMPLETE")
        assert EventType.PLAYBOOK_STEP_COMPLETE == "playbook_step_complete"

    def test_playbook_complete_event(self):
        """PLAYBOOK_COMPLETE event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "PLAYBOOK_COMPLETE")
        assert EventType.PLAYBOOK_COMPLETE == "playbook_complete"

    def test_playbook_failed_event(self):
        """PLAYBOOK_FAILED event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "PLAYBOOK_FAILED")
        assert EventType.PLAYBOOK_FAILED == "playbook_failed"

    def test_playbook_hitl_gate_event(self):
        """PLAYBOOK_HITL_GATE event type exists."""
        from btagent_shared.types.events import EventType

        assert hasattr(EventType, "PLAYBOOK_HITL_GATE")
        assert EventType.PLAYBOOK_HITL_GATE == "playbook_hitl_gate"


# ── UAT-KNOWLEDGE-FRONTEND: Frontend type validation ─────────


class TestKnowledgeFrontend:
    """Validate knowledge frontend TypeScript types exist."""

    def test_knowledge_types_file_exists(self):
        """knowledge.ts types file exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "types"
            / "knowledge.ts"
        )
        assert path.exists(), f"Types file not found: {path}"

    def test_knowledge_api_file_exists(self):
        """knowledge.ts API file exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "api"
            / "knowledge.ts"
        )
        assert path.exists(), f"API file not found: {path}"

    def test_knowledge_store_file_exists(self):
        """knowledgeStore.ts exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "stores"
            / "knowledgeStore.ts"
        )
        assert path.exists(), f"Store file not found: {path}"

    def test_knowledge_search_component_exists(self):
        """KnowledgeSearch.tsx component exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "components"
            / "knowledge"
            / "KnowledgeSearch.tsx"
        )
        assert path.exists(), f"Component not found: {path}"

    def test_knowledge_document_list_component_exists(self):
        """KnowledgeDocumentList.tsx component exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "components"
            / "knowledge"
            / "KnowledgeDocumentList.tsx"
        )
        assert path.exists(), f"Component not found: {path}"

    def test_knowledge_ingest_modal_component_exists(self):
        """KnowledgeIngestModal.tsx component exists."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "components"
            / "knowledge"
            / "KnowledgeIngestModal.tsx"
        )
        assert path.exists(), f"Component not found: {path}"

    def test_knowledge_route_in_router(self):
        """Router includes /knowledge route."""
        path = Path(__file__).resolve().parents[2] / "frontend" / "src" / "router.tsx"
        content = path.read_text()
        assert "knowledge" in content.lower(), "Knowledge route not found in router"

    def test_knowledge_in_sidebar(self):
        """Sidebar includes Knowledge Base nav item."""
        path = (
            Path(__file__).resolve().parents[2]
            / "frontend"
            / "src"
            / "components"
            / "layout"
            / "Sidebar.tsx"
        )
        content = path.read_text()
        assert "Knowledge Base" in content, "Knowledge Base not in sidebar"
