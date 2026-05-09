"""Investigation templates — predefined workflows for common incident types."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).resolve().parent
_template_cache: dict[str, dict[str, Any]] = {}


def _discover_templates() -> dict[str, Path]:
    """Scan the templates directory for YAML template files."""
    templates: dict[str, Path] = {}
    for path in sorted(_TEMPLATES_DIR.glob("*.yaml")):
        templates[path.stem] = path
    return templates


def load_template(name: str) -> dict[str, Any] | None:
    """Load an investigation template by name.

    Returns the parsed YAML as a dictionary, or ``None`` if not found.
    Results are cached after first load.
    """
    if name in _template_cache:
        return _template_cache[name]

    available = _discover_templates()
    path = available.get(name)
    if path is None:
        logger.warning("Investigation template not found: %s", name)
        return None

    try:
        with path.open() as f:
            data: dict[str, Any] = yaml.safe_load(f)
    except Exception:
        logger.exception("Failed to load template: %s", path)
        return None

    _template_cache[name] = data
    return data


def list_templates() -> list[str]:
    """Return the names of all available investigation templates."""
    return sorted(_discover_templates().keys())


def get_template_summaries() -> list[dict[str, str]]:
    """Return name + description for each available template."""
    summaries: list[dict[str, str]] = []
    for name in list_templates():
        data = load_template(name)
        if data is not None:
            summaries.append(
                {
                    "name": data.get("name", name),
                    "description": data.get("description", ""),
                    "severity": data.get("severity", "unknown"),
                }
            )
    return summaries


__all__ = [
    "get_template_summaries",
    "list_templates",
    "load_template",
]
