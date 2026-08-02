"""Org autonomy overrides on the LangGraph agent path (#418 follow-up).

``PUT /config/autonomy`` already governed workflow runs; these tests cover
the other live consumer — the investigation agent's HITL hook. The resolver
reads the investigation's org, merges the org's overrides over the shared
defaults, and degrades to defaults (never raises) when anything goes wrong,
because a config lookup must not abort a running investigation.
"""

from datetime import UTC, datetime

import pytest
from btagent_shared.types.config import AutonomyLevel, IntegrationAutonomy
from btagent_shared.types.enums import InvestigationStatus, Severity
from btagent_shared.utils.ids import generate_id

from btagent_backend.db.models import (
    DEFAULT_ORG_ID,
    InvestigationRow,
    OrganizationRow,
    OrgAutonomyRow,
)
from btagent_backend.services.task_manager import TaskManager


@pytest.fixture
def manager() -> TaskManager:
    # URLs are only used for the Redis/command plumbing these tests never
    # touch; the resolver is exercised with an injected session so it reads
    # the same in-memory DB the fixtures write to.
    return TaskManager(redis_url="redis://localhost:6379", database_url="sqlite+aiosqlite://")


async def _seed_investigation(db_session, org_id: str = DEFAULT_ORG_ID) -> str:
    inv = InvestigationRow(
        id=generate_id("inv"),
        org_id=org_id,
        title="Autonomy resolver test",
        description="",
        status=InvestigationStatus.INVESTIGATING.value,
        severity=Severity.HIGH.value,
        tlp_level="green",
        created_at=datetime.now(UTC),
        updated_at=datetime.now(UTC),
    )
    db_session.add(inv)
    await db_session.commit()
    return inv.id


async def test_resolver_returns_defaults_without_overrides(manager, db_session):
    inv_id = await _seed_investigation(db_session)

    autonomy = await manager._resolve_integration_autonomy(inv_id, session=db_session)

    assert autonomy.siem_query == AutonomyLevel.L3_AUTONOMOUS
    assert autonomy.host_isolation == AutonomyLevel.L0_MANUAL


async def test_resolver_applies_org_overrides(manager, db_session):
    # A DEDICATED org: the resolver reads through its own session, so the
    # override has to be committed — and committing it against the default
    # org would leak a tightened autonomy policy into every later test in
    # the session (it did, until this was scoped).
    org_id = "org_autonomy_agent_path"
    db_session.add(OrganizationRow(id=org_id, name="Autonomy Agent-Path Org"))
    await db_session.commit()
    inv_id = await _seed_investigation(db_session, org_id=org_id)
    db_session.add(
        OrgAutonomyRow(
            org_id=org_id,
            overrides={"siem_query": "L1"},
            updated_by="usr_test",
        )
    )
    await db_session.commit()

    autonomy = await manager._resolve_integration_autonomy(inv_id, session=db_session)

    # The org's tightened level reaches the agent path...
    assert autonomy.siem_query == AutonomyLevel.L1_ASSISTED
    # ...while untouched categories keep the shared defaults.
    assert autonomy.edr_query == AutonomyLevel.L3_AUTONOMOUS


async def test_resolver_degrades_to_defaults_for_unknown_investigation(manager, db_session):
    """A missing investigation must not raise — the agent still runs."""
    autonomy = await manager._resolve_integration_autonomy("inv_does_not_exist", session=db_session)

    assert autonomy == IntegrationAutonomy()


async def test_resolver_degrades_to_defaults_when_the_lookup_errors(manager):
    """Any DB failure falls back to defaults rather than aborting the run."""

    class _ExplodingSession:
        async def execute(self, *_args, **_kwargs):
            raise RuntimeError("database is on fire")

    autonomy = await manager._resolve_integration_autonomy(
        "inv_whatever", session=_ExplodingSession()
    )

    assert autonomy == IntegrationAutonomy()


async def test_build_hooks_passes_autonomy_to_the_hitl_hook(manager, monkeypatch):
    """The resolved policy actually lands on HITLHook, not just the resolver."""
    from btagent_backend.services.task_manager import _load_agents

    # ``_build_hooks`` uses names the module binds lazily on first agent use.
    if not _load_agents():
        pytest.skip("agents package unavailable — TaskManager is in stub mode")

    from btagent_agents.hooks.hitl_hook import HITLHook

    captured: dict = {}
    original_init = HITLHook.__init__

    def _capture(self, *args, **kwargs):
        captured.update(kwargs)
        original_init(self, *args, **kwargs)

    monkeypatch.setattr(HITLHook, "__init__", _capture)

    tightened = IntegrationAutonomy(siem_query=AutonomyLevel.L0_MANUAL)

    class _Emitter:  # RedisEmitter stand-in; hooks only store the reference.
        pass

    manager._build_hooks(_Emitter(), "inv_hook_test", object(), tightened)

    assert captured["integration_autonomy"] is tightened


# --------------------------------------------------------------------------- #
# A5: the graph's step budget must reach LangGraph as ``recursion_limit``.
# --------------------------------------------------------------------------- #


def test_graph_invoke_config_passes_step_budget_as_recursion_limit():
    """The compiled graph's ``max_steps`` governs the run — not LangGraph's
    silent default of 25 (the budget used to be computed and discarded)."""
    from btagent_backend.services.task_manager import _graph_invoke_config

    class _Graph:
        max_steps = 80

    config = _graph_invoke_config(_Graph(), callbacks=[], investigation_id="inv_x")
    assert config["recursion_limit"] == 80
    assert config["configurable"]["thread_id"] == "inv_x"


def test_graph_invoke_config_omits_limit_when_budget_absent_or_invalid():
    from btagent_backend.services.task_manager import _graph_invoke_config

    class _Bare:
        pass

    class _Zero:
        max_steps = 0

    assert "recursion_limit" not in _graph_invoke_config(
        _Bare(), callbacks=[], investigation_id="i"
    )
    assert "recursion_limit" not in _graph_invoke_config(
        _Zero(), callbacks=[], investigation_id="i"
    )
