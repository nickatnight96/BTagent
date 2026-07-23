"""Report service — business logic for report generation, summarization, and remediation.

Orchestrates calls to the coordination, report, and mitigation plugins to
provide a unified service layer for the reports API.
"""

from __future__ import annotations

import json
import logging
from typing import Any

logger = logging.getLogger("btagent.services.report")


class ReportService:
    """Business logic for report generation, summarization, and remediation.

    Methods are designed to be called from the FastAPI route handlers and
    delegate to the appropriate plugin tools.
    """

    async def generate_report(
        self,
        investigation_id: str,
        template: str = "incident_report",
    ) -> dict[str, Any]:
        """Generate a full report from investigation data.

        Parameters
        ----------
        investigation_id : str
            The investigation to generate a report for.
        template : str
            Template name (incident_report, ioc_report, executive_briefing,
            regulatory_notification, cisa_incident).

        Returns
        -------
        dict
            Report sections and metadata.
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

        return result

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
