/**
 * STIX bundle import (#113).
 *
 * `POST /cti/propose-detections` is the front of the detection-engineering
 * funnel — every proposal on the review page originates from it — and it had
 * no consumer. Review, validate, compose-PR and PR-outcome were all reachable;
 * the step that *creates* the work was curl-only.
 *
 * The cases that carry weight are about not letting a partial import read as a
 * complete one, and about passing the server's two contentful refusals (TLP:RED
 * and malformed STIX) through to the analyst instead of flattening them.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const proposeDetections = vi.fn();
const proposeDetectionsFromReport = vi.fn();

vi.mock("@/api/detection", () => ({
  proposeDetections: (...a: unknown[]) => proposeDetections(...a),
  proposeDetectionsFromReport: (...a: unknown[]) => proposeDetectionsFromReport(...a),
}));

import { ImportBundlePanel } from "@/components/detection/ImportBundlePanel";
import { ApiError } from "@/api/client";

const BUNDLE = '{"type":"bundle","objects":[]}';

function result(over: Record<string, unknown> = {}) {
  return {
    proposals: [{ id: "p1" }],
    skipped: [],
    persisted: { created: 1, updated: 0, unchanged: 0 },
    ...over,
  };
}

describe("ImportBundlePanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    proposeDetections.mockResolvedValue(result());
    proposeDetectionsFromReport.mockResolvedValue(result());
  });

  function paste(text: string) {
    fireEvent.change(screen.getByTestId("import-bundle-input"), {
      target: { value: text },
    });
  }

  it("sends the parsed bundle and the chosen TLP", async () => {
    const onImported = vi.fn();
    render(<ImportBundlePanel onImported={onImported} />);
    paste(BUNDLE);
    fireEvent.change(screen.getByTestId("import-bundle-tlp"), {
      target: { value: "amber" },
    });
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    await waitFor(() =>
      expect(proposeDetections).toHaveBeenCalledWith(
        { type: "bundle", objects: [] },
        "amber",
      ),
    );
    // The review queue below is stale the moment an import lands.
    await waitFor(() => expect(onImported).toHaveBeenCalled());
  });

  it("reports how many rows were left alone because they were already decided", async () => {
    // Re-importing must not look like it overwrote analyst decisions.
    proposeDetections.mockResolvedValue(
      result({ persisted: { created: 2, updated: 3, unchanged: 4 } }),
    );
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    expect((await screen.findByTestId("import-bundle-persisted")).textContent).toContain(
      "4 left as decided",
    );
  });

  it("shows the indicators that could not be converted", async () => {
    // These are the actionable output of an import: CTI the pipeline can't act
    // on. Hiding them would make a partial run look complete.
    proposeDetections.mockResolvedValue(
      result({
        skipped: [
          { stix_id: "indicator--9", pattern: "[foo:bar='x']", reason: "unsupported pattern" },
        ],
      }),
    );
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    const skipped = await screen.findByTestId("import-bundle-skipped");
    expect(skipped.textContent).toContain("indicator--9");
    expect(skipped.textContent).toContain("unsupported pattern");
  });

  it("distinguishes an empty bundle from a successful conversion", async () => {
    proposeDetections.mockResolvedValue(
      result({ proposals: [], skipped: [], persisted: { created: 0, updated: 0, unchanged: 0 } }),
    );
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    expect((await screen.findByTestId("import-bundle-empty")).textContent).toContain(
      "no indicators to convert",
    );
  });

  it("surfaces a TLP:RED refusal verbatim", async () => {
    // The server's reason tells the analyst what to change; "import failed"
    // does not.
    proposeDetections.mockRejectedValue(
      new ApiError(403, "Forbidden", {
        detail: "TLP:RED bundles cannot be converted to shareable detections.",
      }),
    );
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    expect((await screen.findByTestId("import-bundle-error")).textContent).toContain(
      "TLP:RED bundles cannot be converted",
    );
  });

  it("surfaces a malformed-STIX rejection verbatim", async () => {
    proposeDetections.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail: "Not a valid STIX 2.1 bundle: missing 'objects'.",
      }),
    );
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    expect((await screen.findByTestId("import-bundle-error")).textContent).toContain(
      "missing 'objects'",
    );
  });

  it("rejects non-JSON before calling the server", async () => {
    render(<ImportBundlePanel />);
    paste("not json at all");
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    expect((await screen.findByTestId("import-bundle-error")).textContent).toContain(
      "valid JSON",
    );
    expect(proposeDetections).not.toHaveBeenCalled();
  });

  it("requires input before calling the server", async () => {
    render(<ImportBundlePanel />);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));
    expect(await screen.findByTestId("import-bundle-error")).toBeTruthy();
    expect(proposeDetections).not.toHaveBeenCalled();
  });

  it("clears a previous result when a later import fails", async () => {
    // A stale success sitting above a failure would misreport the last run.
    render(<ImportBundlePanel />);
    paste(BUNDLE);
    fireEvent.click(screen.getByTestId("import-bundle-submit"));
    await screen.findByTestId("import-bundle-result");

    proposeDetections.mockRejectedValue(new Error("boom"));
    fireEvent.click(screen.getByTestId("import-bundle-submit"));
    await screen.findByTestId("import-bundle-error");
    expect(screen.queryByTestId("import-bundle-result")).toBeNull();
  });
});

describe("ImportBundlePanel report mode (#113 back half)", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    proposeDetectionsFromReport.mockResolvedValue({
      proposals: [{ id: "p1" }, { id: "p2" }],
      skipped: [],
      persisted: { created: 2, updated: 0, unchanged: 0 },
    });
  });

  function paste(text: string) {
    fireEvent.change(screen.getByTestId("import-bundle-input"), {
      target: { value: text },
    });
  }

  it("sends raw prose (no JSON parsing) with the report name and TLP", async () => {
    render(<ImportBundlePanel />);
    fireEvent.click(screen.getByTestId("import-mode-report"));
    paste("dropper beaconing to hxxps://c2[.]example[.]com");
    fireEvent.change(screen.getByTestId("import-report-name"), {
      target: { value: "Frostline advisory" },
    });
    fireEvent.click(screen.getByTestId("import-bundle-submit"));

    await waitFor(() => expect(proposeDetectionsFromReport).toHaveBeenCalled());
    expect(proposeDetectionsFromReport).toHaveBeenCalledWith(
      "dropper beaconing to hxxps://c2[.]example[.]com",
      "Frostline advisory",
      "green",
    );
    // Prose must never be run through the JSON path.
    expect(proposeDetections).not.toHaveBeenCalled();
    expect(await screen.findByTestId("import-bundle-result")).toBeInTheDocument();
  });

  it("does not reject prose as invalid JSON", async () => {
    render(<ImportBundlePanel />);
    fireEvent.click(screen.getByTestId("import-mode-report"));
    paste("plain prose, definitely not JSON");
    fireEvent.click(screen.getByTestId("import-bundle-submit"));
    await waitFor(() => expect(proposeDetectionsFromReport).toHaveBeenCalled());
    expect(screen.queryByTestId("import-bundle-error")).not.toBeInTheDocument();
  });

  it("surfaces the server's no-IOCs-found 422 verbatim", async () => {
    proposeDetectionsFromReport.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail: "No supported IOCs (IP / domain / URL / file hash / email) were found in the report text.",
      }),
    );
    render(<ImportBundlePanel />);
    fireEvent.click(screen.getByTestId("import-mode-report"));
    paste("calm quarter, nothing observed");
    fireEvent.click(screen.getByTestId("import-bundle-submit"));
    expect(await screen.findByTestId("import-bundle-error")).toHaveTextContent(
      /No supported IOCs/,
    );
  });
});
