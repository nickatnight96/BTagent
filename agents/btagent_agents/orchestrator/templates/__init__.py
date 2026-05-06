"""Workflow templates that mirror the hardcoded orchestrator subgraphs.

Sprint 3C lifted the four investigation phases (Triage, Query, Enrichment,
Knowledge) out of :mod:`btagent_agents.orchestrator.nodes` and into YAML
files compiled by :mod:`btagent_engine.compiler`. The orchestrator itself
is rewired in Sprint 3D; this module's job is just to ship the templates
and a small loader that hands them to whoever asks for one already
compiled.

Usage::

    from btagent_agents.orchestrator.templates import load_template

    triage_workflow = load_template("triage")  # -> Workflow

The first call for a given name reads the YAML from disk and compiles it
through :func:`btagent_engine.compiler.compile_playbook`. Subsequent
calls return the cached :class:`btagent_engine.compiler.Workflow`
instance -- compiled workflows are immutable so caching is safe.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final, Literal

from btagent_engine.compiler import Workflow, compile_playbook

TemplateName = Literal["triage", "query", "enrichment", "knowledge"]

_TEMPLATE_DIR: Final[Path] = Path(__file__).resolve().parent
_KNOWN_TEMPLATES: Final[frozenset[str]] = frozenset(
    {"triage", "query", "enrichment", "knowledge"}
)

# Process-local cache. Compiled workflows are frozen Pydantic models, so
# sharing a single instance across callers is safe.
_CACHE: dict[str, Workflow] = {}


class UnknownTemplateError(ValueError):
    """Raised when ``load_template`` is given a name with no matching YAML.

    Distinct from ``KeyError`` so callers can tell "I asked for a real
    template but it failed to compile" from "I typo'd the name".
    """


def available_templates() -> tuple[str, ...]:
    """Return the sorted tuple of valid template names."""
    return tuple(sorted(_KNOWN_TEMPLATES))


def load_template(name: TemplateName) -> Workflow:
    """Compile and cache the named workflow template.

    Cache key is the template name. The first call reads + compiles the
    YAML from disk; subsequent calls return the cached
    :class:`Workflow`. Raises :class:`UnknownTemplateError` for any name
    not in :data:`_KNOWN_TEMPLATES` -- a bare ``KeyError`` would leak
    cache-implementation details to callers.
    """
    if name not in _KNOWN_TEMPLATES:
        raise UnknownTemplateError(
            f"Unknown workflow template {name!r}. "
            f"Valid names: {available_templates()}"
        )

    cached = _CACHE.get(name)
    if cached is not None:
        return cached

    yaml_path = _TEMPLATE_DIR / f"{name}.yaml"
    if not yaml_path.is_file():
        # The known-name set and the on-disk YAML files should always
        # agree; this branch only fires if a template file is deleted
        # without updating ``_KNOWN_TEMPLATES``.
        raise UnknownTemplateError(
            f"Template {name!r} is registered but its YAML file is missing: {yaml_path}"
        )

    yaml_text = yaml_path.read_text(encoding="utf-8")
    workflow = compile_playbook(yaml_text)
    _CACHE[name] = workflow
    return workflow


def _clear_cache() -> None:
    """Test-only: forget every cached template. Never call from prod."""
    _CACHE.clear()


__all__ = [
    "TemplateName",
    "UnknownTemplateError",
    "Workflow",
    "available_templates",
    "load_template",
]
