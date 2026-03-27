"""Hook provider base class and registry for LangGraph callback injection."""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod

from langchain_core.callbacks import BaseCallbackHandler

logger = logging.getLogger("btagent.hooks")


class HookProvider(ABC):
    """Base class for all BTagent hooks.

    Each hook provides one or more LangChain callback handlers that get injected
    into the LangGraph agent's execution loop. Hooks are the primary extension
    point for cross-cutting concerns (event emission, budget tracking, HITL,
    evidence chain, scope enforcement, classification).
    """

    @abstractmethod
    def get_callbacks(self) -> list[BaseCallbackHandler]:
        """Return LangChain callback handlers for this hook."""
        ...

    @property
    def name(self) -> str:
        """Human-readable hook name for diagnostics."""
        return self.__class__.__name__


class HookRegistry:
    """Collects hooks and returns a merged callback list for LangGraph invocation.

    Usage::

        registry = HookRegistry()
        registry.register(EventEmitterHook(emitter, inv_id))
        registry.register(PromptBudgetHook(emitter, config))
        callbacks = registry.get_all_callbacks()
        # Pass `callbacks` to LangGraph's `config={"callbacks": callbacks}`
    """

    def __init__(self) -> None:
        self._hooks: list[HookProvider] = []
        self._failed: dict[str, str] = {}

    def register(self, hook: HookProvider, *, critical: bool = False) -> None:
        """Register a hook provider.

        Args:
            hook: The hook provider instance.
            critical: If True, raise immediately when the hook's get_callbacks()
                fails. If False, log the error and skip the hook.
        """
        try:
            # Validate that the hook can produce callbacks before accepting it.
            hook.get_callbacks()
            self._hooks.append(hook)
            logger.info("Registered hook: %s", hook.name)
        except Exception as exc:
            msg = f"Hook {hook.name} failed to initialize: {exc}"
            self._failed[hook.name] = msg
            if critical:
                raise RuntimeError(msg) from exc
            logger.warning(msg)

    def get_all_callbacks(self) -> list[BaseCallbackHandler]:
        """Return a flat list of all callback handlers from registered hooks.

        Hooks that raise during get_callbacks() are silently skipped and recorded
        in the `failed` property for diagnostics.
        """
        callbacks: list[BaseCallbackHandler] = []
        for hook in self._hooks:
            try:
                callbacks.extend(hook.get_callbacks())
            except Exception as exc:
                msg = f"Hook {hook.name} failed during get_callbacks(): {exc}"
                self._failed[hook.name] = msg
                logger.warning(msg)
        return callbacks

    @property
    def failed(self) -> dict[str, str]:
        """Map of hook name to failure reason for hooks that could not load."""
        return dict(self._failed)

    @property
    def registered_hooks(self) -> list[str]:
        """Names of successfully registered hooks."""
        return [h.name for h in self._hooks]

    def __len__(self) -> int:
        return len(self._hooks)
