import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listReportTemplates = vi.fn();
const generateReport = vi.fn();
const exportReportPdf = vi.fn();
const listInvestigations = vi.fn();

const summarizeInvestigations = vi.fn();
const generateRemediation = vi.fn();

vi.mock("@/api/reports", () => ({
  listReportTemplates: (...a: unknown[]) => listReportTemplates(...a),
  generateReport: (...a: unknown[]) => generateReport(...a),
  exportReportPdf: (...a: unknown[]) => exportReportPdf(...a),
  summarizeInvestigations: (...a: unknown[]) => summarizeInvestigations(...a),
  generateRemediation: (...a: unknown[]) => generateRemediation(...a),
}));

vi.mock("@/api/investigations", () => ({
  listInvestigations: (...a: unknown[]) => listInvestigations(...a),
}));

import { ReportsPage } from "@/components/reports/ReportsPage";

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

const TEMPLATES = {
  templates: [
    {
      name: "cisa_incident",
      title: "CISA US-CERT Incident Notification",
      description: "Federal incident-notification form",
      sections: ["reporting_details", "points_of_contact"],
    },
    {
      name: "external_advisory",
      title: "External Threat Advisory",
      description: "Partner-facing advisory",
      sections: ["threat_overview", "iocs"],
    },
  ],
  count: 2,
  status: "success",
};

const REPORT = {
  investigation_id: "inv_mock_001",
  template: "cisa_incident",
  template_title: "CISA US-CERT Incident Notification",
  generated_at: "2026-07-23 18:00 UTC",
  sections: {
    reporting_details: "## Reporting and Impacted Organization\n[ANALYST INPUT REQUIRED]",
    points_of_contact: "## Points of Contact\n[ANALYST INPUT REQUIRED]",
  },
  section_count: 2,
  completeness: {
    required_total: 2,
    required_populated: 0,
    completeness_pct: 0,
    gaps: [
      { section: "reporting_details", title: "Reporting and Impacted Organization", reason: "analyst input required" },
      { section: "points_of_contact", title: "Points of Contact", reason: "analyst input required" },
    ],
  },
  status: "success",
};

const INVESTIGATIONS = {
  items: [
    {
      id: "inv_mock_001",
      title: "Phishing Campaign Targeting Finance Department",
      severity: "high",
      status: "contained",
      description: "",
      created_at: "2026-07-01T00:00:00Z",
      updated_at: "2026-07-01T00:00:00Z",
    },
    {
      id: "inv_mock_002",
      title: "Suspicious OAuth Grant",
      severity: "medium",
      status: "active",
      description: "",
      created_at: "2026-07-02T00:00:00Z",
      updated_at: "2026-07-02T00:00:00Z",
    },
  ],
  total: 2,
  page: 1,
  page_size: 50,
};

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listReportTemplates.mockResolvedValue(TEMPLATES);
    generateReport.mockResolvedValue(REPORT);
    listInvestigations.mockResolvedValue(INVESTIGATIONS);
  });

  it("loads templates into the picker and shows the empty state", async () => {
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalledTimes(1));
    expect(screen.getByText(/Pick an investigation and a template/i)).toBeTruthy();
    const select = screen.getByTestId("reports-template-select") as HTMLSelectElement;
    expect(select.value).toBe("cisa_incident");
  });

  it("generates a report and renders completeness, gaps and sections", async () => {
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_001" },
    });

    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-generate"));
    });

    await waitFor(() => expect(generateReport).toHaveBeenCalledWith("inv_mock_001", "cisa_incident"));
    // Completeness percentage surfaces.
    expect(await screen.findByTestId("reports-completeness-pct")).toHaveProperty(
      "textContent",
      "0%",
    );
    // Both gaps are listed.
    expect(screen.getByTestId("reports-gap-points_of_contact")).toBeTruthy();
    expect(screen.getByTestId("reports-gap-reporting_details")).toBeTruthy();
    // Sections render.
    expect(screen.getByTestId("reports-section-reporting_details")).toBeTruthy();
  });

  it("does not generate until an investigation ID is entered", async () => {
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());
    const btn = screen.getByTestId("reports-generate") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(generateReport).not.toHaveBeenCalled();
  });

  it("summarizes an investigation into an agency draft", async () => {
    summarizeInvestigations.mockResolvedValue({
      summary: {},
      formatted_report: {
        format: "fbi_ic3",
        sections: {
          header: "FBI IC3 COMPLAINT DRAFT",
          incident_details: "INCIDENT DETAILS\n\nPhishing campaign …",
        },
        generated_at: "2026-07-24 00:00 UTC",
        status: "success",
      },
      status: "success",
    });
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    // Disabled until an investigation ID is present.
    const btn = screen.getByTestId("reports-summarize") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_001" },
    });
    fireEvent.change(screen.getByTestId("reports-agency-format"), {
      target: { value: "fbi_ic3" },
    });
    await act(async () => {
      fireEvent.click(btn);
    });

    await waitFor(() =>
      expect(summarizeInvestigations).toHaveBeenCalledWith(["inv_mock_001"], "fbi_ic3"),
    );
    const sections = await screen.findByTestId("reports-agency-sections");
    expect(sections.textContent).toContain("FBI IC3 COMPLAINT DRAFT");
    expect(screen.getByTestId("reports-agency-section-incident_details")).toBeTruthy();
  });

  it("surfaces a summarization failure in the error banner", async () => {
    summarizeInvestigations.mockRejectedValue(new Error("boom"));
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_nope" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-summarize"));
    });

    const err = await screen.findByTestId("reports-error");
    expect(err.textContent).toContain("summarization failed");
  });

  it("generates an audience-tuned remediation checklist", async () => {
    generateRemediation.mockResolvedValue({
      audience: "executive",
      title: "Executive Remediation Summary — Phishing Campaign",
      severity: "high",
      business_impact: "A high-severity incident was identified affecting 3 accounts.",
      actions: [
        {
          priority: "immediate",
          action: "Approve credential reset for all affected accounts",
          estimated_effort: "1-2 hours",
          business_owner: "IT Security",
        },
        {
          priority: "short_term",
          action: "Schedule phishing-awareness refresher",
        },
      ],
      investigation_id: "inv_mock_001",
      generated_at: "2026-07-24T02:00:00Z",
      status: "success",
    });
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    // Disabled until an investigation ID is present.
    const btn = screen.getByTestId("reports-remediate") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_001" },
    });
    fireEvent.change(screen.getByTestId("reports-remediation-audience"), {
      target: { value: "executive" },
    });
    await act(async () => {
      fireEvent.click(btn);
    });

    await waitFor(() =>
      expect(generateRemediation).toHaveBeenCalledWith("inv_mock_001", "executive"),
    );
    const result = await screen.findByTestId("reports-remediation-result");
    expect(result.textContent).toContain("Executive Remediation Summary");
    expect(result.textContent).toContain("business owner: IT Security");
    // Both checklist rows render with their priorities.
    expect(screen.getByTestId("reports-remediation-action-0").textContent).toContain(
      "immediate",
    );
    expect(screen.getByTestId("reports-remediation-action-1").textContent).toContain(
      "short term",
    );
  });

  it("surfaces a remediation failure in the error banner", async () => {
    generateRemediation.mockRejectedValue(new Error("boom"));
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_nope" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-remediate"));
    });

    const err = await screen.findByTestId("reports-error");
    expect(err.textContent).toContain("Remediation generation failed");
  });

  it("suggests real investigations and shows a hint on match", async () => {
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listInvestigations).toHaveBeenCalledWith({ page_size: 50 }));

    // Datalist carries one option per fetched investigation.
    const datalist = await screen.findByTestId("reports-investigation-options");
    expect(datalist.querySelectorAll("option")).toHaveLength(2);

    // No hint until the typed ID matches a real case.
    expect(screen.queryByTestId("reports-investigation-hint")).toBeNull();
    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_002" },
    });
    const hint = await screen.findByTestId("reports-investigation-hint");
    expect(hint.textContent).toContain("Suspicious OAuth Grant");
    expect(hint.textContent).toContain("medium");
  });

  it("keeps free-text generation working when the case list fails to load", async () => {
    listInvestigations.mockRejectedValue(new Error("boom"));
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_001" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-generate"));
    });

    await waitFor(() =>
      expect(generateReport).toHaveBeenCalledWith("inv_mock_001", "cisa_incident"),
    );
    // The picker failure never surfaces as a page error.
    expect(screen.queryByTestId("reports-error")).toBeNull();
  });

  it("exports the generated report as a PDF", async () => {
    exportReportPdf.mockResolvedValue(new Blob(["%PDF"], { type: "application/pdf" }));
    const createSpy = vi.fn(() => "blob:report");
    const revokeSpy = vi.fn();
    vi.stubGlobal("URL", { ...URL, createObjectURL: createSpy, revokeObjectURL: revokeSpy });
    try {
      renderPage(<ReportsPage />);
      await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());
      // No export button before a report exists.
      expect(screen.queryByTestId("reports-export-pdf")).toBeNull();

      fireEvent.change(screen.getByTestId("reports-investigation-input"), {
        target: { value: "inv_mock_001" },
      });
      await act(async () => {
        fireEvent.click(screen.getByTestId("reports-generate"));
      });

      await act(async () => {
        fireEvent.click(await screen.findByTestId("reports-export-pdf"));
      });

      await waitFor(() =>
        expect(exportReportPdf).toHaveBeenCalledWith("inv_mock_001", "cisa_incident"),
      );
      await waitFor(() => expect(createSpy).toHaveBeenCalled());
      expect(revokeSpy).toHaveBeenCalledWith("blob:report");
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("surfaces a TLP block on export as a distinct error", async () => {
    exportReportPdf.mockRejectedValue(
      new Error("Export blocked by TLP policy (classified investigation)"),
    );
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_mock_001" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-generate"));
    });
    await act(async () => {
      fireEvent.click(await screen.findByTestId("reports-export-pdf"));
    });

    const err = await screen.findByTestId("reports-error");
    expect(err.textContent).toContain("TLP policy");
  });

  it("surfaces an error when generation fails", async () => {
    generateReport.mockRejectedValue(new Error("boom"));
    renderPage(<ReportsPage />);
    await waitFor(() => expect(listReportTemplates).toHaveBeenCalled());

    fireEvent.change(screen.getByTestId("reports-investigation-input"), {
      target: { value: "inv_bad" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("reports-generate"));
    });

    await waitFor(() => expect(screen.getByTestId("reports-error")).toBeTruthy());
  });
});
