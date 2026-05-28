"""PDF rendering for investigation reports (#145).

Renders the structured report dict produced by the report plugin
(:func:`btagent_agents.plugins.report.tools.report_generator.generate_report`)
into a PDF document, preserving section structure and stamping the
investigation's severity and TLP / classification markings on the cover and
every page.

Library choice — **reportlab**: it ships pure-Python wheels with no system
dependencies (unlike weasyprint/wkhtmltopdf, which need cairo / pango / a
wkhtmltopdf binary that CI runners don't carry).

TLP enforcement is *not* invented here. The renderer calls the same central
egress gate every other non-LLM egress path uses
(:func:`btagent_shared.security.assert_tlp_allows_egress`) with the
``"report_export"`` egress kind, so a TLP:RED report is refused exactly the
way a TLP:RED STIX export or knowledge-ingest is. The API layer 403s before
reaching this function; the gate below is the defense-in-depth backstop.
"""

from __future__ import annotations

import io
from typing import Any

from btagent_shared.security import assert_tlp_allows_egress

# TLP marking colours (hex) for the cover/footer banner, matching the
# canonical FIRST TLP palette used across the platform UI.
_TLP_COLORS: dict[str, str] = {
    "white": "#FFFFFF",
    "clear": "#FFFFFF",
    "green": "#33FF00",
    "amber": "#FFC000",
    "amber_strict": "#FFC000",
    "red": "#FF0033",
}

# Background colours so the marking stays legible on its banner.
_TLP_BG_COLORS: dict[str, str] = {
    "white": "#000000",
    "clear": "#000000",
    "green": "#000000",
    "amber": "#000000",
    "amber_strict": "#000000",
    "red": "#000000",
}


def _tlp_banner_text(tlp_level: str) -> str:
    """Render the canonical ``TLP:LEVEL`` marking string."""
    return f"TLP:{tlp_level.replace('_', ':').upper()}"


def render_report_pdf(
    report: dict[str, Any],
    *,
    tlp_level: str = "green",
    severity: str = "medium",
    org_id: str | None = None,
) -> bytes:
    """Render a generated report dict to PDF bytes.

    Parameters
    ----------
    report:
        The dict returned by the report generator — expects ``sections``
        (mapping of section name -> markdown-ish text), plus optional
        ``template_title``, ``investigation_id``, and ``generated_at``.
    tlp_level:
        The investigation's TLP classification. Stamped on the document and
        fed to the central egress gate.
    severity:
        The investigation's severity, stamped on the cover.
    org_id:
        Optional org identifier carried on any emitted
        ``tlp.violation_attempt`` event so the alerter can route by tenant.

    Returns
    -------
    bytes
        The rendered PDF (starts with the ``%PDF`` magic).

    Raises
    ------
    btagent_shared.security.TLPViolation
        If the report's TLP context is TLP:RED (or any section is tagged
        TLP:RED). Mirrors the STIX-export backstop — the API layer is
        expected to 403 first.
    """
    # Defense in depth: the API route 403s on tlp_level == "red" before we get
    # here. This gate is the backstop for any internal caller that bypasses the
    # route — it refuses TLP:RED egress the same way every other channel does.
    assert_tlp_allows_egress(
        report,
        "report_export",
        classification_ctx=tlp_level,
        org_id=org_id,
    )

    # Imported lazily so the heavy reportlab import cost is only paid when a
    # PDF is actually requested (keeps app startup / test collection light).
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_CENTER
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        HRFlowable,
        Paragraph,
        SimpleDocTemplate,
        Spacer,
    )

    banner = _tlp_banner_text(tlp_level)
    fg = _TLP_COLORS.get(tlp_level.lower(), "#000000")
    bg = _TLP_BG_COLORS.get(tlp_level.lower(), "#FFFFFF")

    buffer = io.BytesIO()

    def _stamp_marking(canvas: Any, doc: Any) -> None:
        """Draw the TLP marking banner at the top and bottom of every page."""
        canvas.saveState()
        width, height = letter
        canvas.setFont("Helvetica-Bold", 9)
        # Top-of-page marking.
        canvas.setFillColor(colors.HexColor(bg))
        canvas.rect(0, height - 0.32 * inch, width, 0.32 * inch, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor(fg))
        canvas.drawCentredString(width / 2.0, height - 0.24 * inch, banner)
        # Bottom-of-page marking.
        canvas.setFillColor(colors.HexColor(bg))
        canvas.rect(0, 0, width, 0.32 * inch, stroke=0, fill=1)
        canvas.setFillColor(colors.HexColor(fg))
        canvas.drawCentredString(width / 2.0, 0.12 * inch, banner)
        canvas.restoreState()

    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        topMargin=0.7 * inch,
        bottomMargin=0.7 * inch,
        leftMargin=0.8 * inch,
        rightMargin=0.8 * inch,
        title=str(report.get("template_title", "Investigation Report")),
        # Leave the content stream uncompressed so the TLP marking is
        # text-extractable (searchable / auditable) in the output rather than
        # buried in a Flate stream.
        pageCompression=0,
    )

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "ReportTitle",
        parent=styles["Title"],
        fontSize=20,
        spaceAfter=12,
    )
    banner_style = ParagraphStyle(
        "TLPBanner",
        parent=styles["Normal"],
        alignment=TA_CENTER,
        fontSize=12,
        textColor=colors.HexColor(fg),
        backColor=colors.HexColor(bg),
        spaceBefore=6,
        spaceAfter=12,
    )
    meta_style = ParagraphStyle(
        "Meta",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.grey,
    )
    heading_style = ParagraphStyle(
        "SectionHeading",
        parent=styles["Heading2"],
        fontSize=13,
        spaceBefore=14,
        spaceAfter=6,
    )
    body_style = ParagraphStyle(
        "Body",
        parent=styles["Normal"],
        fontSize=10,
        leading=14,
        spaceAfter=4,
    )

    def _esc(text: str) -> str:
        """Escape the XML-significant chars reportlab Paragraph parses."""
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    flow: list[Any] = []

    # --- Cover block: title + markings -------------------------------------
    title = str(report.get("template_title", "Investigation Report"))
    flow.append(Paragraph(_esc(title), title_style))
    flow.append(Paragraph(banner, banner_style))
    flow.append(
        Paragraph(
            f"<b>Severity:</b> {_esc(str(severity).upper())} &nbsp;&nbsp; "
            f"<b>Classification:</b> {banner}",
            meta_style,
        )
    )
    inv_id = report.get("investigation_id")
    if inv_id:
        flow.append(Paragraph(f"<b>Investigation:</b> {_esc(str(inv_id))}", meta_style))
    generated_at = report.get("generated_at")
    if generated_at:
        flow.append(Paragraph(f"<b>Generated:</b> {_esc(str(generated_at))}", meta_style))
    flow.append(Spacer(1, 8))
    flow.append(HRFlowable(width="100%", thickness=1, color=colors.grey))

    # --- Sections (preserve structure + order) -----------------------------
    sections: dict[str, Any] = report.get("sections", {}) or {}
    for name, content in sections.items():
        pretty = name.replace("_", " ").title()
        flow.append(Paragraph(_esc(pretty), heading_style))
        text = content if isinstance(content, str) else str(content)
        # Each non-empty line becomes a paragraph so structure survives; bare
        # markdown markers are stripped for legibility (not full markdown).
        for raw_line in text.splitlines():
            line = raw_line.rstrip()
            if not line.strip():
                flow.append(Spacer(1, 4))
                continue
            cleaned = line.lstrip("#").lstrip("-").strip()
            if not cleaned:
                continue
            flow.append(Paragraph(_esc(cleaned), body_style))

    doc.build(flow, onFirstPage=_stamp_marking, onLaterPages=_stamp_marking)
    return buffer.getvalue()
