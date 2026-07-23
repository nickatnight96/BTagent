import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement } from "react";

const listReportTemplates = vi.fn();
const generateReport = vi.fn();
const exportReportPdf = vi.fn();

vi.mock("@/api/reports", () => ({
  listReportTemplates: (...a: unknown[]) => listReportTemplates(...a),
  generateReport: (...a: unknown[]) => generateReport(...a),
  exportReportPdf: (...a: unknown[]) => exportReportPdf(...a),
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

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listReportTemplates.mockResolvedValue(TEMPLATES);
    generateReport.mockResolvedValue(REPORT);
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
