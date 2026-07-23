"""Unit tests for the report generator (EPIC-6 UC-6.1 slice 1).

Covers the new CISA US-CERT incident-notification template and the
field-completeness gate that reports unfilled required fields ("gaps") back to
the analyst before sign-off:

- ``list_templates`` surfaces the ``cisa_incident`` template with its sections.
- ``generate_report`` produces every CISA-form section from the mock case.
- The ``completeness`` block scores only ``required`` sections, flags the
  analyst-supplied points-of-contact section as a gap, and leaves optional
  sections (e.g. incident-report appendices) out of the denominator.
- Placeholder sections (no registered generator) also count as gaps.
- Unknown templates / investigations still fail cleanly.
"""

from __future__ import annotations

from btagent_agents.plugins.report.tools.report_generator import (
    _ANALYST_INPUT_MARKER,
    generate_report,
    list_templates,
)

_INV = "inv_mock_001"


def test_cisa_template_listed_with_sections() -> None:
    result = list_templates.invoke({})
    assert result["status"] == "success"
    by_name = {t["name"]: t for t in result["templates"]}
    assert "cisa_incident" in by_name, "CISA template must be discoverable"
    cisa = by_name["cisa_incident"]
    assert "CISA" in cisa["title"]
    # Federal-form required fields are present.
    for section in (
        "reporting_details",
        "incident_description",
        "impact_assessment",
        "points_of_contact",
    ):
        assert section in cisa["sections"]


def test_cisa_report_generates_all_sections() -> None:
    result = generate_report.invoke({"investigation_id": _INV, "template": "cisa_incident"})
    assert result["status"] == "success"
    sections = result["sections"]
    # Every section the template declares is emitted, none left as a raw stub.
    for name in (
        "reporting_details",
        "incident_description",
        "impact_assessment",
        "findings",
        "iocs",
        "timeline",
        "containment",
        "points_of_contact",
    ):
        assert name in sections
        assert sections[name].strip()
    # Data-backed sections pulled real values from the mock case.
    assert "T1566.002" in sections["findings"]
    assert "malicious-domain.com" in sections["iocs"]


def test_cisa_completeness_flags_points_of_contact_gap() -> None:
    result = generate_report.invoke({"investigation_id": _INV, "template": "cisa_incident"})
    completeness = result["completeness"]

    # 8 required sections; reporting_details and points_of_contact carry the
    # analyst-input marker → 2 gaps, 6 populated.
    assert completeness["required_total"] == 8
    gap_sections = {g["section"] for g in completeness["gaps"]}
    assert "points_of_contact" in gap_sections
    assert "reporting_details" in gap_sections
    assert completeness["required_populated"] == completeness["required_total"] - len(
        completeness["gaps"]
    )
    # Percentage is consistent with the counts.
    expected_pct = round(100 * completeness["required_populated"] / completeness["required_total"])
    assert completeness["completeness_pct"] == expected_pct
    # Analyst-input gaps are labelled distinctly from missing-data gaps.
    poc_gap = next(g for g in completeness["gaps"] if g["section"] == "points_of_contact")
    assert poc_gap["reason"] == "analyst input required"
    assert _ANALYST_INPUT_MARKER in result["sections"]["points_of_contact"]


def test_full_incident_report_is_complete() -> None:
    """incident_report has generators for every required section → no gaps."""
    result = generate_report.invoke({"investigation_id": _INV, "template": "incident_report"})
    completeness = result["completeness"]
    assert completeness["gaps"] == []
    assert completeness["completeness_pct"] == 100
    # Optional 'appendices' section is present but excluded from the denominator.
    assert "appendices" in result["sections"]
    assert completeness["required_total"] < len(result["sections"])


def test_unknown_template_and_investigation_fail_cleanly() -> None:
    bad_tmpl = generate_report.invoke({"investigation_id": _INV, "template": "does_not_exist"})
    assert bad_tmpl["status"] == "failed"

    bad_inv = generate_report.invoke({"investigation_id": "inv_nope", "template": "cisa_incident"})
    assert bad_inv["status"] == "failed"
