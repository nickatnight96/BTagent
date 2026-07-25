"""Shift-handover narrative composer (EPIC-5 UC-5.1, #108).

Turns the structured :func:`~btagent_backend.services.handover_service.
build_handover_summary` dict into a multi-line plain-text brief the incoming
shift can read top-to-bottom: what's new, what moved, what's still open, and
what to watch first. Deterministic template composition — a pure function
over the summary, no DB and no LLM. An LLM-polished prose variant remains
the documented follow-up on #108; this brief is the substrate (and the
fallback) for it.
"""

from __future__ import annotations

from typing import Any

# Canonical severity ordering for rollup lines.
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")

# The brief stays a brief: cap per-section case bullets.
_MAX_BULLETS = 5


def _severity_line(buckets: dict[str, int]) -> str:
    """Render `{severity: count}` as "2 critical, 1 high" in canonical order."""
    parts = [f"{buckets[s]} {s}" for s in _SEVERITY_ORDER if buckets.get(s)]
    # Unknown severity labels still surface rather than silently dropping.
    parts += [f"{c} {s}" for s, c in buckets.items() if s not in _SEVERITY_ORDER and c]
    return ", ".join(parts)


def _case_bullet(item: dict[str, Any]) -> str:
    return f"  - [{item['severity']}] {item['title']} ({item['status']})"


def compose_handover_narrative(summary: dict[str, Any]) -> str:
    """Compose the multi-line handover brief from a summary dict.

    Pure function: consumes exactly what ``build_handover_summary`` returns.
    A quiet window collapses to a single reassuring line.
    """
    investigations: list[dict[str, Any]] = list(summary["investigations"])
    open_by_severity: dict[str, int] = summary["open_by_severity"]
    findings_by_severity: dict[str, int] = summary["findings_by_severity"]
    untriaged: int = summary["findings_untriaged"]
    window_hours: int = summary["window_hours"]

    new_cases = [i for i in investigations if i["is_new"]]
    updated_cases = [i for i in investigations if not i["is_new"]]
    findings_total = sum(findings_by_severity.values())
    open_total = sum(open_by_severity.values())

    if not investigations and findings_total == 0 and open_total == 0:
        return (
            f"Quiet shift: no case activity or hunt findings in the last "
            f"{window_hours}h, and the open backlog is empty."
        )

    lines: list[str] = [f"Shift brief — last {window_hours}h:"]

    if new_cases:
        lines.append(f"New cases ({len(new_cases)}):")
        lines.extend(_case_bullet(i) for i in new_cases[:_MAX_BULLETS])
        if len(new_cases) > _MAX_BULLETS:
            lines.append(f"  … and {len(new_cases) - _MAX_BULLETS} more")

    if updated_cases:
        lines.append(f"Updated cases ({len(updated_cases)}):")
        lines.extend(_case_bullet(i) for i in updated_cases[:_MAX_BULLETS])
        if len(updated_cases) > _MAX_BULLETS:
            lines.append(f"  … and {len(updated_cases) - _MAX_BULLETS} more")

    if findings_total:
        lines.append(
            f"Hunt findings: {findings_total} landed "
            f"({_severity_line(findings_by_severity)}); {untriaged} untriaged."
        )

    if open_total:
        lines.append(f"Open backlog: {open_total} case(s) — {_severity_line(open_by_severity)}.")

    # Watch-items: the incoming shift's first moves, most urgent first.
    watch: list[str] = []
    if untriaged:
        watch.append(f"triage the {untriaged} untriaged finding(s)")
    crit_open = open_by_severity.get("critical", 0)
    high_open = open_by_severity.get("high", 0)
    if crit_open:
        watch.append(f"{crit_open} critical case(s) still open")
    if high_open:
        watch.append(f"{high_open} high-severity case(s) still open")
    if watch:
        lines.append("Watch first: " + "; ".join(watch) + ".")

    return "\n".join(lines)
