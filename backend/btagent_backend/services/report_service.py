"""Report service — business logic for report generation, summarization, and remediation.

Orchestrates calls to the coordination, report, and mitigation plugins to
provide a unified service layer for the reports API.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - import only for type hints
    from sqlalchemy.ext.asyncio import AsyncSession

    from btagent_backend.db.models import ReportDistributionRow

logger = logging.getLogger("btagent.services.report")


# --------------------------------------------------------------------------- #
# Regulatory-notification clock (EPIC-6 UC-6.2 part C)
# --------------------------------------------------------------------------- #
#
# Statutory initial-notification windows that start ticking at incident
# detection/determination. Each entry is (human label, kind, amount) where
# ``kind`` is "business_days" or "hours". These are the mandated *initial*
# reporting deadlines, not the full-report deadlines.
_REGULATORY_REGIMES: dict[str, tuple[str, str, int]] = {
    "sec": ("SEC Form 8-K Item 1.05 (material cybersecurity incident)", "business_days", 4),
    "nis2": ("EU NIS2 Article 23 early warning", "hours", 24),
    "dora": ("EU DORA major ICT-related incident initial notification", "hours", 72),
}


def _add_business_days(start: datetime, days: int) -> datetime:
    """Return ``start`` advanced by ``days`` business days (Mon–Fri)."""
    current = start
    remaining = days
    while remaining > 0:
        current = current + timedelta(days=1)
        if current.weekday() < 5:  # 0–4 == Mon–Fri
            remaining -= 1
    return current


def _compute_regulatory_deadlines(detected_at: datetime) -> dict[str, dict[str, Any]]:
    """Compute per-regime regulatory notification deadlines from a detection time.

    Returns a mapping keyed by regime (``sec`` / ``nis2`` / ``dora``) with the
    human label, the window, and the absolute ISO-8601 deadline. Purely
    derived — the clock start is ``detected_at``.
    """
    deadlines: dict[str, dict[str, Any]] = {}
    for regime, (label, kind, amount) in _REGULATORY_REGIMES.items():
        if kind == "business_days":
            deadline = _add_business_days(detected_at, amount)
            window = f"{amount} business days"
        else:
            deadline = detected_at + timedelta(hours=amount)
            window = f"{amount} hours"
        deadlines[regime] = {
            "label": label,
            "window": window,
            "deadline": deadline.isoformat(),
        }
    return deadlines


def _render_regulatory_deadline_section(
    detected_at: datetime, deadlines: dict[str, dict[str, Any]]
) -> str:
    """Render the ``regulatory_deadline`` report section from computed deadlines."""
    lines = [
        "## Regulatory Notification Deadlines\n",
        f"Clock start (incident detection/determination): {detected_at.isoformat()}\n",
        "The following statutory *initial* notification deadlines apply. Confirm "
        "applicability with legal/compliance before relying on any single window.\n",
    ]
    for regime in ("sec", "nis2", "dora"):
        info = deadlines[regime]
        lines.append(
            f"- **{regime.upper()}** — {info['label']}: within {info['window']} "
            f"(by {info['deadline']})"
        )
    return "\n".join(lines)


class ReportService:
    """Business logic for report generation, summarization, and remediation.

    Methods are designed to be called from the FastAPI route handlers and
    delegate to the appropriate plugin tools.
    """

    async def generate_report(
        self,
        investigation_id: str,
        template: str = "incident_report",
        *,
        detected_at: datetime | None = None,
    ) -> dict[str, Any]:
        """Generate a full report from investigation data.

        Parameters
        ----------
        investigation_id : str
            The investigation to generate a report for.
        template : str
            Template name (incident_report, ioc_report, executive_briefing,
            regulatory_notification, cisa_incident, external_advisory).
        detected_at : datetime | None
            Incident detection/determination time used as the start of the
            regulatory-notification clock for the ``regulatory_notification``
            template. Defaults to "now" when not supplied.

        Returns
        -------
        dict
            Report sections and metadata. For the ``regulatory_notification``
            template the result also carries a ``regulatory_deadlines`` block
            (SEC 4 business days / NIS2 24h / DORA 72h) and a populated
            ``regulatory_deadline`` section.
        """
        from btagent_agents.plugins.report.tools.report_generator import (
            generate_report as report_tool,
        )

        logger.info(
            "Generating report for investigation %s with template %s",
            investigation_id,
            template,
        )

        result = report_tool.invoke(
            {
                "investigation_id": investigation_id,
                "template": template,
            }
        )

        if result.get("status") == "failed":
            logger.warning(
                "Report generation failed for %s: %s",
                investigation_id,
                result.get("error"),
            )
        else:
            logger.info(
                "Report generated for %s: %d sections",
                investigation_id,
                result.get("section_count", 0),
            )
            if template == "regulatory_notification":
                self._attach_regulatory_clock(result, detected_at)

        return result

    @staticmethod
    def _attach_regulatory_clock(result: dict[str, Any], detected_at: datetime | None) -> None:
        """Stamp the regulatory-notification clock onto a generated report.

        Adds a structured ``regulatory_deadlines`` block and fills the
        ``regulatory_deadline`` section content (the template declares the
        section; the deadlines are auto-computed here rather than authored by
        the analyst).
        """
        clock_start = detected_at or datetime.now(UTC)
        deadlines = _compute_regulatory_deadlines(clock_start)
        result["regulatory_deadlines"] = {
            "detected_at": clock_start.isoformat(),
            "regimes": deadlines,
        }
        sections = result.get("sections")
        if isinstance(sections, dict) and "regulatory_deadline" in sections:
            sections["regulatory_deadline"] = _render_regulatory_deadline_section(
                clock_start, deadlines
            )

    async def export_report_pdf(
        self,
        investigation_id: str,
        *,
        template: str = "incident_report",
        tlp_level: str = "green",
        severity: str = "medium",
        org_id: str | None = None,
    ) -> bytes:
        """Generate a report and render it to PDF bytes.

        Generates the report via the report plugin, then renders it with
        reportlab, stamping the investigation's severity and TLP marking.

        Parameters
        ----------
        investigation_id : str
            The investigation to export.
        template : str
            Report template name.
        tlp_level : str
            The investigation's TLP classification. Passed to the central
            egress gate (``assert_tlp_allows_egress``) inside the renderer so
            TLP:RED is refused identically to every other egress path.
        severity : str
            The investigation's severity, stamped on the report cover.
        org_id : str | None
            Org identifier carried on any TLP violation event.

        Returns
        -------
        bytes
            The rendered PDF (starts with ``%PDF``).

        Raises
        ------
        ValueError
            If report generation fails (e.g. unknown investigation/template).
        btagent_shared.security.TLPViolation
            If the report's TLP context is TLP:RED. Defense-in-depth backstop;
            the API layer is expected to 403 first.
        """
        from btagent_backend.services.report_pdf import render_report_pdf

        report = await self.generate_report(
            investigation_id=investigation_id,
            template=template,
        )

        if report.get("status") == "failed":
            raise ValueError(report.get("error", "Report generation failed"))

        return render_report_pdf(
            report,
            tlp_level=tlp_level,
            severity=severity,
            org_id=org_id,
        )

    async def list_templates(self) -> dict[str, Any]:
        """List available report templates.

        Returns
        -------
        dict
            Available templates with descriptions.
        """
        from btagent_agents.plugins.report.tools.report_generator import (
            list_templates as templates_tool,
        )

        return templates_tool.invoke({})

    async def summarize_investigations(
        self,
        investigation_ids: list[str],
        format: str = "generic",
    ) -> dict[str, Any]:
        """Summarize one or more investigations for agency submission.

        Parameters
        ----------
        investigation_ids : list[str]
            Investigation IDs to summarize.
        format : str
            Agency format (cisa, fbi_ic3, isac, generic).

        Returns
        -------
        dict
            Summarized and formatted report.
        """
        from btagent_agents.plugins.coordination.tools.summarizer import (
            format_agency_report,
            summarize_investigation,
            summarize_multiple,
        )

        logger.info(
            "Summarizing %d investigation(s) in '%s' format",
            len(investigation_ids),
            format,
        )

        # Summarize
        if len(investigation_ids) == 1:
            summary = summarize_investigation.invoke(
                {
                    "investigation_id": investigation_ids[0],
                }
            )
        else:
            ids_str = ",".join(investigation_ids)
            summary = summarize_multiple.invoke(
                {
                    "investigation_ids": ids_str,
                }
            )

        if summary.get("status") == "failed":
            return summary

        # Format for agency
        formatted = format_agency_report.invoke(
            {
                "summary_json": json.dumps(summary),
                "format": format,
            }
        )

        return {
            "summary": summary,
            "formatted_report": formatted,
            "status": formatted.get("status", "failed"),
        }

    async def generate_remediation(
        self,
        investigation_id: str,
        audience: str = "technical",
    ) -> dict[str, Any]:
        """Generate audience-specific remediation guidance.

        Parameters
        ----------
        investigation_id : str
            The investigation to generate remediation for.
        audience : str
            Target audience (executive, technical, compliance).

        Returns
        -------
        dict
            Remediation checklist and guidance.
        """
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_remediation as remediation_tool,
        )

        logger.info(
            "Generating %s remediation for investigation %s",
            audience,
            investigation_id,
        )

        return remediation_tool.invoke(
            {
                "investigation_id": investigation_id,
                "audience": audience,
            }
        )

    async def generate_detection_content(
        self,
        investigation_id: str,
        platform: str = "splunk",
    ) -> dict[str, Any]:
        """Generate SIEM detection rules.

        Parameters
        ----------
        investigation_id : str
            The investigation to generate detection rules for.
        platform : str
            Target SIEM platform (splunk, elastic, sentinel).

        Returns
        -------
        dict
            Detection rules for the specified platform.
        """
        from btagent_agents.plugins.mitigation.tools.remediation_generator import (
            generate_detection_content as detection_tool,
        )

        logger.info(
            "Generating %s detection content for investigation %s",
            platform,
            investigation_id,
        )

        return detection_tool.invoke(
            {
                "investigation_id": investigation_id,
                "platform": platform,
            }
        )

    # ----------------------------------------------------------------------- #
    # Distribution tracking (EPIC-6 UC-6.2 part A)
    # ----------------------------------------------------------------------- #

    async def record_distribution(
        self,
        db: AsyncSession,
        *,
        org_id: str,
        report_id: str,
        audience: str,
        recipient: str,
        tlp_applied: str = "amber",
        approver_id: str | None = None,
        sent_at: datetime | None = None,
    ) -> ReportDistributionRow:
        """Record a single report distribution and persist it to the audit ledger.

        Writes one org-scoped ``report_distributions`` row capturing who
        received a generated report, when, under which TLP marking, and who
        approved the release. Returns the persisted row.

        Parameters
        ----------
        db : AsyncSession
            Active DB session (the caller owns commit/rollback).
        org_id : str
            Owning tenant — the row is only ever visible to this org.
        report_id : str
            Free-form report reference (reports are generated on the fly).
        audience : str
            Distribution audience (e.g. ``cisa_liaison``, ``leadership``).
        recipient : str
            The concrete recipient (mailbox, channel, contact).
        tlp_applied : str
            TLP marking stamped on the delivered artifact.
        approver_id : str | None
            Identifier of whoever signed off on the release (HITL gate).
        sent_at : datetime | None
            Delivery time; defaults to "now".
        """
        from btagent_shared.utils.ids import generate_id

        from btagent_backend.db.models import ReportDistributionRow

        row = ReportDistributionRow(
            id=generate_id("rdist"),
            org_id=org_id,
            report_id=report_id,
            audience=audience,
            recipient=recipient,
            tlp_applied=tlp_applied,
            approver_id=approver_id,
            sent_at=sent_at or datetime.now(UTC),
        )
        db.add(row)
        await db.commit()
        await db.refresh(row)
        logger.info(
            "Recorded report distribution %s (report=%s audience=%s org=%s)",
            row.id,
            report_id,
            audience,
            org_id,
        )
        return row

    async def list_distributions(
        self,
        db: AsyncSession,
        *,
        org_id: str,
        report_id: str | None = None,
    ) -> list[ReportDistributionRow]:
        """Return an org's report distributions, newest first (read-only audit).

        Strictly org-scoped: only rows belonging to ``org_id`` are returned, so
        one tenant can never read another's distribution ledger. When
        ``report_id`` is supplied, the result is narrowed to that report.
        """
        from sqlalchemy import select

        from btagent_backend.db.models import ReportDistributionRow

        stmt = select(ReportDistributionRow).where(ReportDistributionRow.org_id == org_id)
        if report_id is not None:
            stmt = stmt.where(ReportDistributionRow.report_id == report_id)
        stmt = stmt.order_by(ReportDistributionRow.sent_at.desc())

        rows = (await db.execute(stmt)).scalars().all()
        return list(rows)
