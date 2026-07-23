"""Export a stored HuntPlan as Markdown or a report-sections dict (#99 Phase B).

The runbook is a team-coordination artifact — analysts paste it into
tickets, wikis, and IR reports. ``plan_to_markdown`` is the canonical
text rendering; ``plan_to_report_sections`` reshapes the same content
into the ``{sections: {...}}`` dict :func:`report_pdf.render_report_pdf`
consumes, so the PDF path reuses the existing renderer (TLP stamping,
egress gate) instead of growing a second one.

Pure functions, no DB, no engine imports — unit-testable in isolation.
"""

from __future__ import annotations

from typing import Any

from btagent_shared.types.hunt import HuntPlan, TTPRunbookEntry


def _entry_markdown(entry: TTPRunbookEntry) -> str:
    lines: list[str] = [f"## {entry.ttp_id} — {entry.ttp_name}", ""]
    if entry.rationale:
        lines += [f"**Why this TTP:** {entry.rationale}", ""]
    if entry.behavioral_description:
        lines += [f"**What to look for:** {entry.behavioral_description}", ""]

    if entry.queries:
        lines.append("### Queries")
        for backend, query in entry.queries.items():
            lines += [f"**{backend}**", "```", query.query, "```"]
            if query.notes:
                lines.append(f"_{query.notes}_")
        lines.append("")

    noise = entry.expected_noise
    if noise.expected_hits_per_day is not None:
        window = (
            f" over a {noise.sample_window_days}-day sample"
            if noise.sample_window_days is not None
            else ""
        )
        lines += [f"**Expected noise:** ~{noise.expected_hits_per_day} hits/day{window}", ""]

    if entry.pivot_questions:
        lines.append("### Pivot questions on hit")
        lines += [f"1. {q}" for q in entry.pivot_questions]
        lines.append("")

    if entry.evidence_checklist:
        lines.append("### Evidence to collect")
        lines += [f"- [ ] {item}" for item in entry.evidence_checklist]
        lines.append("")

    lines += [f"**Status:** {entry.state.value}", ""]
    return "\n".join(lines)


def plan_to_markdown(plan: HuntPlan) -> str:
    """Render the full runbook as a single Markdown document."""
    summary = plan.executive_summary
    target = ", ".join(plan.input.adversaries + plan.input.ttps) or plan.id

    lines: list[str] = [
        f"# Hunt Plan: {target}",
        "",
        f"- **Plan id:** {plan.id}",
        f"- **State:** {plan.state.value}",
        f"- **Generated:** {plan.created_at.isoformat()}",
        f"- **Hypotheses:** {len(plan.hypotheses)} · **Runbook entries:** {len(plan.ttp_entries)}",
        "",
        "## Executive summary",
        "",
    ]
    if summary.adversary_profile:
        lines += [summary.adversary_profile, ""]
    if summary.scope_description:
        lines += [f"**Scope:** {summary.scope_description}", ""]
    if summary.success_criteria:
        lines += [f"**Success criteria:** {summary.success_criteria}", ""]
    if summary.estimated_effort_hours is not None:
        lines += [f"**Estimated effort:** ~{summary.estimated_effort_hours}h", ""]

    if plan.hypotheses:
        lines.append("## Hypotheses (priority order)")
        lines += [
            f"{i}. **{h.ttp_id} — {h.ttp_name}** (priority {h.priority:.2f}): {h.rationale}"
            for i, h in enumerate(plan.hypotheses, start=1)
        ]
        lines.append("")

    lines += [_entry_markdown(e) for e in plan.ttp_entries]

    if plan.correlation_rules:
        lines.append("## Cross-TTP correlation rules")
        lines += [f"- {r.trigger} → {r.action}" for r in plan.correlation_rules]
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def plan_to_report_sections(plan: HuntPlan) -> dict[str, Any]:
    """Reshape the runbook into the dict ``render_report_pdf`` consumes."""
    summary = plan.executive_summary
    target = ", ".join(plan.input.adversaries + plan.input.ttps) or plan.id

    exec_lines = []
    if summary.adversary_profile:
        exec_lines.append(summary.adversary_profile)
    if summary.success_criteria:
        exec_lines.append(f"Success criteria: {summary.success_criteria}")
    exec_lines.append(
        f"{len(plan.hypotheses)} hypotheses, {len(plan.ttp_entries)} runbook entries."
    )

    sections: dict[str, str] = {"Executive summary": "\n\n".join(exec_lines)}
    if plan.hypotheses:
        sections["Hypotheses"] = "\n".join(
            f"{i}. {h.ttp_id} — {h.ttp_name} (priority {h.priority:.2f}): {h.rationale}"
            for i, h in enumerate(plan.hypotheses, start=1)
        )
    for entry in plan.ttp_entries:
        sections[f"{entry.ttp_id} — {entry.ttp_name}"] = _entry_markdown(entry)

    return {
        "template_title": f"Hunt Plan: {target}",
        "investigation_id": plan.id,
        "generated_at": plan.created_at.isoformat(),
        "sections": sections,
    }
