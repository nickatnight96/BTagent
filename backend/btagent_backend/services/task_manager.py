"""TaskManager -- spawns and manages LangGraph investigation tasks as asyncio.Tasks.

The TaskManager is the bridge between the FastAPI backend and the LangGraph agent
engine.  It creates compiled graphs, wraps them in ``asyncio.Task`` instances, and
provides lifecycle operations (start / pause / resume / stop / auto-resume /
shutdown).  Events flow from the agent hooks through ``RedisEmitter`` into the
WebSocket hub for browser delivery.

Redis command channel pattern: ``btagent:commands:{investigation_id}``
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from btagent_backend.config import get_settings
from btagent_backend.db.engine import async_session_factory
from btagent_backend.db.models import InvestigationRow
from btagent_shared.types.enums import InvestigationStatus
from btagent_shared.types.events import EventType

logger = logging.getLogger("btagent.task_manager")

# ---------------------------------------------------------------------------
# Lazy imports for the agents package -- may fail if not installed or if
# LangGraph dependencies are missing.
# ---------------------------------------------------------------------------

_AGENTS_AVAILABLE = False
_agents_import_error: str | None = None

try:
    from btagent_agents.events.emitter import RedisEmitter
    from btagent_agents.hooks.base import HookRegistry
    from btagent_agents.hooks.event_emitter_hook import EventEmitterHook
    from btagent_agents.hooks.prompt_budget_hook import PromptBudgetHook
    from btagent_agents.hooks.hitl_hook import HITLHook
    from btagent_agents.hooks.evidence_chain_hook import EvidenceChainHook
    from btagent_agents.hooks.scope_enforcement_hook import ScopeEnforcementHook
    from btagent_agents.hooks.classification_hook import ClassificationHook
    from btagent_agents.llm.cost_calculator import CostAccumulator
    from btagent_agents.orchestrator.graph import create_investigation_graph
    from btagent_agents.orchestrator.state import InvestigationState
    from btagent_shared.types.config import AgentConfig, AutonomyLevel, TLP

    _AGENTS_AVAILABLE = True
except ImportError as exc:
    _agents_import_error = str(exc)
    logger.warning(
        "agents package not available -- TaskManager will operate in stub mode: %s",
        _agents_import_error,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

COMMAND_CHANNEL_PREFIX = "btagent:commands"

# Statuses that indicate an investigation was actively running before a restart.
_ACTIVE_STATUSES = (
    InvestigationStatus.INVESTIGATING.value,
    InvestigationStatus.TRIAGING.value,
)


def _command_channel(investigation_id: str) -> str:
    return f"{COMMAND_CHANNEL_PREFIX}:{investigation_id}"


# ---------------------------------------------------------------------------
# TaskManager
# ---------------------------------------------------------------------------


class TaskManager:
    """Manages running LangGraph investigation tasks as ``asyncio.Task`` instances.

    Parameters
    ----------
    redis_url : str
        Redis connection URL for event emission and command channels.
    database_url : str
        Async SQLAlchemy database URL (used only for status updates that
        happen inside the task runner, separate from the request session).
    """

    def __init__(self, redis_url: str, database_url: str) -> None:
        self._tasks: dict[str, asyncio.Task[None]] = {}
        self._redis_url = redis_url
        self._database_url = database_url
        self._total_started: int = 0
        self._started_at = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start_investigation(
        self,
        investigation_id: str,
        config: dict[str, Any],
    ) -> None:
        """Create a LangGraph graph and spawn it as an ``asyncio.Task``.

        Parameters
        ----------
        investigation_id : str
            Prefixed ULID of the investigation row.
        config : dict
            Configuration dict that will be used to build an ``AgentConfig``
            and the initial ``InvestigationState``.
        """
        if not _AGENTS_AVAILABLE:
            logger.error(
                "Cannot start investigation %s -- agents package not available: %s",
                investigation_id,
                _agents_import_error,
            )
            await self._set_investigation_status(
                investigation_id,
                InvestigationStatus.FAILED.value,
                error=f"agents package not available: {_agents_import_error}",
            )
            return

        if investigation_id in self._tasks:
            logger.warning(
                "Investigation %s already has a running task -- skipping",
                investigation_id,
            )
            return

        try:
            agent_config = self._build_agent_config(investigation_id, config)
            graph = create_investigation_graph(config)
            initial_state = self._build_initial_state(investigation_id, agent_config, config)
        except Exception:
            logger.exception(
                "Failed to build graph / state for investigation %s", investigation_id
            )
            await self._set_investigation_status(
                investigation_id,
                InvestigationStatus.FAILED.value,
                error="Failed to build investigation graph",
            )
            return

        task = asyncio.create_task(
            self._run_graph(investigation_id, graph, initial_state, agent_config),
            name=f"investigation-{investigation_id}",
        )
        self._tasks[investigation_id] = task
        self._total_started += 1

        logger.info(
            "Started investigation %s (running=%d, total=%d)",
            investigation_id,
            len(self._tasks),
            self._total_started,
        )

    async def send_message(
        self,
        investigation_id: str,
        message: str,
        user_id: str,
    ) -> None:
        """Forward a chat message to a running investigation via Redis.

        The message is published to ``btagent:commands:{investigation_id}`` so
        that the graph runner (or a future command-listener loop) can pick it up.
        """
        channel = _command_channel(investigation_id)
        payload = {
            "type": "chat",
            "message": message,
            "user_id": user_id,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        redis: Redis | None = None
        try:
            redis = Redis.from_url(self._redis_url, decode_responses=True)
            await redis.publish(channel, json.dumps(payload))
            logger.info(
                "Published chat message to %s for investigation %s",
                channel,
                investigation_id,
            )
        except Exception:
            logger.exception(
                "Failed to publish chat message for investigation %s",
                investigation_id,
            )
            raise
        finally:
            if redis is not None:
                await redis.aclose()

    async def pause_investigation(self, investigation_id: str) -> None:
        """Cancel the ``asyncio.Task`` for a running investigation.

        LangGraph checkpoints automatically when the task is cancelled, so the
        investigation can be resumed later from the last checkpoint.
        """
        task = self._tasks.pop(investigation_id, None)
        if task is None:
            logger.warning(
                "pause_investigation: no running task for %s", investigation_id
            )
            return

        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

        await self._set_investigation_status(
            investigation_id, InvestigationStatus.PAUSED.value
        )
        await self._emit_lifecycle_event(
            investigation_id, EventType.INVESTIGATION_PAUSED
        )
        logger.info("Paused investigation %s", investigation_id)

    async def resume_investigation(self, investigation_id: str) -> None:
        """Resume an investigation from its LangGraph checkpoint."""
        if not _AGENTS_AVAILABLE:
            logger.error(
                "Cannot resume investigation %s -- agents package not available",
                investigation_id,
            )
            return

        if investigation_id in self._tasks:
            logger.warning(
                "Investigation %s already running -- skipping resume",
                investigation_id,
            )
            return

        # Load the investigation config from the DB to rebuild the graph.
        inv_config = await self._load_investigation_config(investigation_id)
        if inv_config is None:
            logger.error(
                "Cannot resume investigation %s -- not found in DB",
                investigation_id,
            )
            return

        try:
            agent_config = self._build_agent_config(investigation_id, inv_config)
            graph = create_investigation_graph(inv_config)
            initial_state = self._build_initial_state(
                investigation_id, agent_config, inv_config
            )
        except Exception:
            logger.exception(
                "Failed to rebuild graph for investigation %s resume",
                investigation_id,
            )
            await self._set_investigation_status(
                investigation_id,
                InvestigationStatus.FAILED.value,
                error="Failed to rebuild graph for resume",
            )
            return

        task = asyncio.create_task(
            self._run_graph(investigation_id, graph, initial_state, agent_config),
            name=f"investigation-{investigation_id}",
        )
        self._tasks[investigation_id] = task
        self._total_started += 1

        await self._set_investigation_status(
            investigation_id, InvestigationStatus.INVESTIGATING.value
        )
        await self._emit_lifecycle_event(
            investigation_id, EventType.INVESTIGATION_RESUMED
        )
        logger.info("Resumed investigation %s", investigation_id)

    async def stop_investigation(self, investigation_id: str) -> None:
        """Cancel the task and mark the investigation as cancelled."""
        task = self._tasks.pop(investigation_id, None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        await self._set_investigation_status(
            investigation_id,
            InvestigationStatus.CANCELLED.value,
            close=True,
        )
        await self._emit_lifecycle_event(
            investigation_id, EventType.INVESTIGATION_FAILED, reason="cancelled"
        )
        logger.info("Stopped investigation %s", investigation_id)

    async def auto_resume(self) -> int:
        """Resume all investigations that were active before the last shutdown.

        Called during application startup.  Queries the DB for investigations with
        status ``investigating`` or ``triaging`` and resumes each from its
        checkpoint.

        Returns the count of investigations resumed.
        """
        if not _AGENTS_AVAILABLE:
            logger.warning(
                "auto_resume skipped -- agents package not available: %s",
                _agents_import_error,
            )
            return 0

        count = 0
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(InvestigationRow).where(
                        InvestigationRow.status.in_(_ACTIVE_STATUSES)
                    )
                )
                rows = result.scalars().all()

            for row in rows:
                try:
                    config = dict(row.config) if row.config else {}
                    config.setdefault("severity", row.severity)
                    config.setdefault("tlp_level", row.tlp_level)
                    config.setdefault("template", row.template)
                    await self.resume_investigation(row.id)
                    count += 1
                except Exception:
                    logger.exception(
                        "Failed to auto-resume investigation %s", row.id
                    )
        except Exception:
            logger.exception("auto_resume: DB query failed")

        logger.info("auto_resume: resumed %d investigation(s)", count)
        return count

    async def shutdown(self) -> None:
        """Graceful shutdown: cancel all running tasks.

        LangGraph graphs checkpoint automatically on cancellation, so state is
        preserved for the next startup.
        """
        if not self._tasks:
            logger.info("shutdown: no running tasks")
            return

        logger.info("shutdown: cancelling %d running task(s)", len(self._tasks))

        for investigation_id, task in list(self._tasks.items()):
            task.cancel()

        # Wait for all tasks to finish cancellation.
        results = await asyncio.gather(
            *self._tasks.values(), return_exceptions=True
        )

        for investigation_id, result in zip(list(self._tasks.keys()), results):
            if isinstance(result, Exception) and not isinstance(
                result, asyncio.CancelledError
            ):
                logger.error(
                    "shutdown: task for %s raised %s: %s",
                    investigation_id,
                    type(result).__name__,
                    result,
                )

        self._tasks.clear()
        logger.info("shutdown: all tasks cancelled")

    def get_status(self) -> dict[str, Any]:
        """Return running task count and IDs for health/diagnostics."""
        return {
            "running": len(self._tasks),
            "total_started": self._total_started,
            "running_ids": sorted(self._tasks.keys()),
            "agents_available": _AGENTS_AVAILABLE,
            "agents_import_error": _agents_import_error,
            "uptime_seconds": round(time.monotonic() - self._started_at, 1),
        }

    # ------------------------------------------------------------------
    # Internal: graph execution
    # ------------------------------------------------------------------

    async def _run_graph(
        self,
        investigation_id: str,
        graph: Any,
        initial_state: dict[str, Any],
        agent_config: Any,
    ) -> None:
        """Execute the LangGraph graph, publish events, and handle errors.

        This method runs inside an ``asyncio.Task`` for the lifetime of the
        investigation.
        """
        emitter: RedisEmitter | None = None
        try:
            # 1. Create RedisEmitter for this investigation.
            emitter = RedisEmitter(investigation_id, self._redis_url)
            await emitter.connect()

            # 2. Build hook registry with all applicable hooks.
            registry = self._build_hooks(emitter, investigation_id, agent_config)
            callbacks = registry.get_all_callbacks()

            # 3. Emit INVESTIGATION_INIT event.
            await emitter.emit(
                EventType.INVESTIGATION_INIT,
                investigation_id=investigation_id,
                hooks_registered=registry.registered_hooks,
                hooks_failed=registry.failed,
            )

            # 4. Update DB status to investigating.
            await self._set_investigation_status(
                investigation_id, InvestigationStatus.INVESTIGATING.value
            )

            # 5. Invoke the graph.
            graph_config: dict[str, Any] = {
                "callbacks": callbacks,
                "configurable": {
                    "thread_id": investigation_id,
                },
            }

            logger.info(
                "Invoking graph for investigation %s with %d callbacks",
                investigation_id,
                len(callbacks),
            )

            # Use ainvoke for async execution.
            final_state = await graph.ainvoke(initial_state, config=graph_config)

            # 6. Investigation completed successfully.
            final_status = final_state.get("status", InvestigationStatus.CLOSED.value)
            if isinstance(final_status, InvestigationStatus):
                final_status = final_status.value

            await self._set_investigation_status(
                investigation_id, final_status, close=True
            )
            await emitter.emit(
                EventType.INVESTIGATION_COMPLETE,
                investigation_id=investigation_id,
                final_status=final_status,
            )
            logger.info(
                "Investigation %s completed with status %s",
                investigation_id,
                final_status,
            )

            # 7. Auto-index investigation into knowledge base.
            await self._on_investigation_complete(investigation_id)

        except asyncio.CancelledError:
            # Task was cancelled (pause / stop / shutdown).  LangGraph
            # checkpoints automatically, so nothing to do here.
            logger.info(
                "Investigation %s task cancelled (checkpoint preserved)",
                investigation_id,
            )
            raise

        except Exception as exc:
            # Unexpected error -- mark investigation as failed.
            error_msg = f"{type(exc).__name__}: {exc}"
            logger.exception(
                "Investigation %s failed: %s", investigation_id, error_msg
            )
            await self._set_investigation_status(
                investigation_id,
                InvestigationStatus.FAILED.value,
                error=error_msg,
            )
            if emitter is not None:
                try:
                    await emitter.emit(
                        EventType.INVESTIGATION_FAILED,
                        investigation_id=investigation_id,
                        error=error_msg,
                        error_type=type(exc).__name__,
                    )
                except Exception:
                    logger.exception(
                        "Failed to emit INVESTIGATION_FAILED for %s",
                        investigation_id,
                    )
        finally:
            # Clean up the emitter and remove the task reference.
            if emitter is not None:
                try:
                    await emitter.close()
                except Exception:
                    pass
            self._tasks.pop(investigation_id, None)

    # ------------------------------------------------------------------
    # Internal: knowledge auto-indexing on completion
    # ------------------------------------------------------------------

    async def _on_investigation_complete(self, investigation_id: str) -> None:
        """Index investigation findings and enrichment data into the
        knowledge base when an investigation completes.

        This enables future investigations to benefit from prior findings
        via the RAG knowledge retrieval pipeline.  Failures are logged but
        never propagated -- indexing is best-effort.
        """
        try:
            from btagent_backend.services.knowledge_service import KnowledgeService
            from btagent_backend.services.embedding_service import (
                MockEmbeddingService,
            )

            async with async_session_factory() as session:
                # Use MockEmbeddingService for auto-indexing to avoid
                # requiring external API keys during background tasks.
                knowledge_svc = KnowledgeService(
                    embedding_service=MockEmbeddingService()
                )

                # Index investigation report
                inv_doc = await knowledge_svc.auto_index_investigation(
                    session, investigation_id
                )
                if inv_doc:
                    logger.info(
                        "Auto-indexed investigation %s as knowledge doc %s",
                        investigation_id,
                        inv_doc.id,
                    )

                # Index enrichment results
                enrich_doc = await knowledge_svc.auto_index_enrichment(
                    session, investigation_id
                )
                if enrich_doc:
                    logger.info(
                        "Auto-indexed enrichment for %s as knowledge doc %s",
                        investigation_id,
                        enrich_doc.id,
                    )

                await session.commit()
        except ImportError:
            logger.debug(
                "Knowledge service not available for auto-indexing "
                "investigation %s",
                investigation_id,
            )
        except Exception:
            logger.exception(
                "Failed to auto-index investigation %s into knowledge base",
                investigation_id,
            )

    # ------------------------------------------------------------------
    # Internal: hook construction
    # ------------------------------------------------------------------

    def _build_hooks(
        self,
        emitter: RedisEmitter,  # type: ignore[name-defined]
        investigation_id: str,
        agent_config: Any,
    ) -> HookRegistry:  # type: ignore[name-defined]
        """Construct the hook registry for an investigation."""
        registry = HookRegistry()

        # Event emitter -- always register, critical.
        registry.register(
            EventEmitterHook(emitter, investigation_id),
            critical=True,
        )

        # Prompt budget tracking.
        accumulator = CostAccumulator()
        max_tokens = getattr(agent_config, "max_tokens", 80_000)
        max_cost = getattr(agent_config, "max_cost_usd", 5.0)
        registry.register(
            PromptBudgetHook(
                emitter=emitter,
                accumulator=accumulator,
                max_tokens=max_tokens,
                max_cost_usd=max_cost,
            ),
            critical=True,
        )

        # Human-in-the-loop.
        autonomy = getattr(agent_config, "autonomy_level", AutonomyLevel.L2_SUPERVISED)
        if isinstance(autonomy, str):
            autonomy = AutonomyLevel(autonomy)
        registry.register(
            HITLHook(
                emitter=emitter,
                investigation_id=investigation_id,
                agent_autonomy=autonomy,
            ),
        )

        # Evidence chain.
        registry.register(
            EvidenceChainHook(emitter, investigation_id),
        )

        # TLP classification enforcement.
        tlp = getattr(agent_config, "tlp_level", TLP.GREEN)
        if isinstance(tlp, str):
            tlp = TLP(tlp)
        provider = getattr(agent_config, "model_provider", "anthropic")
        registry.register(
            ClassificationHook(
                emitter=emitter,
                tlp_level=tlp,
                provider=provider,
                investigation_id=investigation_id,
            ),
            critical=True,
        )

        # Scope enforcement is registered only when scope config is present.
        scope_config = getattr(agent_config, "org_profile", {})
        if scope_config.get("allowed_domains") or scope_config.get("allowed_cidrs"):
            from btagent_agents.hooks.scope_enforcement_hook import InvestigationScope

            scope = InvestigationScope(
                allowed_domains=scope_config.get("allowed_domains", []),
                allowed_ips=scope_config.get("allowed_ips", []),
                allowed_cidrs=scope_config.get("allowed_cidrs", []),
                allowed_hostnames=scope_config.get("allowed_hostnames", []),
                allowed_systems=scope_config.get("allowed_systems", []),
                blocked_domains=scope_config.get("blocked_domains", []),
                blocked_ips=scope_config.get("blocked_ips", []),
            )
            registry.register(
                ScopeEnforcementHook(emitter, scope, investigation_id),
                critical=True,
            )

        return registry

    # ------------------------------------------------------------------
    # Internal: state / config builders
    # ------------------------------------------------------------------

    @staticmethod
    def _build_agent_config(
        investigation_id: str,
        config: dict[str, Any],
    ) -> AgentConfig:  # type: ignore[name-defined]
        """Build an ``AgentConfig`` from the raw configuration dict."""
        settings = get_settings()
        return AgentConfig(
            investigation_id=investigation_id,
            model_provider=config.get("model_provider", settings.default_model_provider),
            model_id=config.get("model_id", settings.default_model_id),
            tlp_level=config.get("tlp_level", "green"),
            autonomy_level=config.get("autonomy_level", "L2"),
            max_tokens=config.get("max_tokens", 80_000),
            max_cost_usd=config.get("max_cost_usd", 5.0),
            template=config.get("template"),
            org_profile=config.get("org_profile", {}),
            mock_connectors=config.get("mock_connectors", settings.mock_connectors),
        )

    @staticmethod
    def _build_initial_state(
        investigation_id: str,
        agent_config: Any,
        config: dict[str, Any],
    ) -> dict[str, Any]:
        """Build the initial ``InvestigationState`` dict for graph invocation."""
        return {
            "investigation_id": investigation_id,
            "messages": [],
            "task_type": config.get("task_type", "triage"),
            "severity": config.get("severity", "medium"),
            "tlp_level": getattr(agent_config, "tlp_level", "green"),
            "autonomy_level": getattr(agent_config, "autonomy_level", "L2"),
            "iocs": [],
            "timeline": [],
            "containment_actions": [],
            "evidence": [],
            "current_agent": "",
            "status": InvestigationStatus.TRIAGING.value,
            "error": None,
            "org_profile": getattr(agent_config, "org_profile", {}),
            "template_config": config.get("template_config", {}),
            "token_usage": {},
            "cost_usd": 0.0,
            "knowledge_context": "",
        }

    # ------------------------------------------------------------------
    # Internal: DB helpers
    # ------------------------------------------------------------------

    async def _set_investigation_status(
        self,
        investigation_id: str,
        status: str,
        *,
        error: str | None = None,
        close: bool = False,
    ) -> None:
        """Update the investigation status in the database.

        Uses its own session (not the request-scoped one) since this runs
        inside a background task.
        """
        try:
            async with async_session_factory() as session:
                values: dict[str, Any] = {
                    "status": status,
                    "updated_at": datetime.now(timezone.utc),
                }
                if close:
                    values["closed_at"] = datetime.now(timezone.utc)
                if error:
                    # Store the error in the config JSONB column for inspection.
                    result = await session.execute(
                        select(InvestigationRow.config).where(
                            InvestigationRow.id == investigation_id
                        )
                    )
                    existing_config = result.scalar_one_or_none() or {}
                    existing_config["last_error"] = error
                    values["config"] = existing_config

                stmt = (
                    update(InvestigationRow)
                    .where(InvestigationRow.id == investigation_id)
                    .values(**values)
                )
                await session.execute(stmt)
                await session.commit()
        except Exception:
            logger.exception(
                "Failed to update status for investigation %s to %s",
                investigation_id,
                status,
            )

    async def _load_investigation_config(
        self,
        investigation_id: str,
    ) -> dict[str, Any] | None:
        """Load investigation config from the DB for resume."""
        try:
            async with async_session_factory() as session:
                result = await session.execute(
                    select(InvestigationRow).where(
                        InvestigationRow.id == investigation_id
                    )
                )
                row = result.scalar_one_or_none()
                if row is None:
                    return None
                config = dict(row.config) if row.config else {}
                config.setdefault("severity", row.severity)
                config.setdefault("tlp_level", row.tlp_level)
                config.setdefault("template", row.template)
                return config
        except Exception:
            logger.exception(
                "Failed to load config for investigation %s", investigation_id
            )
            return None

    async def _emit_lifecycle_event(
        self,
        investigation_id: str,
        event_type: EventType,
        **data: Any,
    ) -> None:
        """Emit a one-off lifecycle event via a short-lived RedisEmitter."""
        if not _AGENTS_AVAILABLE:
            return

        emitter: RedisEmitter | None = None
        try:
            emitter = RedisEmitter(investigation_id, self._redis_url)
            await emitter.connect()
            await emitter.emit(event_type, investigation_id=investigation_id, **data)
        except Exception:
            logger.exception(
                "Failed to emit %s event for investigation %s",
                event_type.value,
                investigation_id,
            )
        finally:
            if emitter is not None:
                try:
                    await emitter.close()
                except Exception:
                    pass
