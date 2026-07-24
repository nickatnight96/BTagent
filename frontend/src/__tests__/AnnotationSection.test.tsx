import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";

const annotateIOC = vi.fn();

vi.mock("@/api/iocs", () => ({
  annotateIOC: (...a: unknown[]) => annotateIOC(...a),
}));

import { AnnotationSection } from "@/components/iocs/AnnotationSection";
import type { IOC } from "@/types/ioc";

const IOC_FIXTURE: IOC = {
  id: "ioc_TEST1",
  type: "domain",
  value: "annotation-test.example.com",
  source: "unit-test",
  confidence: 0.8,
  first_seen: "2026-07-01T00:00:00Z",
  tags: ["phishing"],
  pinned: false,
  analyst_note: "seed note",
  disposition: "under_review",
};

describe("AnnotationSection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    annotateIOC.mockImplementation((_id: string, patch: Record<string, unknown>) =>
      Promise.resolve({ ...IOC_FIXTURE, ...patch }),
    );
  });

  it("seeds controls from the IOC", () => {
    render(<AnnotationSection ioc={IOC_FIXTURE} />);
    expect(
      (screen.getByTestId("ioc-annotations-tags") as HTMLInputElement).value,
    ).toBe("phishing");
    expect(
      (screen.getByTestId("ioc-annotations-note") as HTMLTextAreaElement).value,
    ).toBe("seed note");
    expect(
      (screen.getByTestId("ioc-annotations-disposition") as HTMLSelectElement).value,
    ).toBe("under_review");
    expect(screen.getByTestId("ioc-annotations-pin").textContent).toContain("Pin");
  });

  it("saves the full patch and reports the update", async () => {
    const onAnnotated = vi.fn();
    render(<AnnotationSection ioc={IOC_FIXTURE} onAnnotated={onAnnotated} />);

    fireEvent.click(screen.getByTestId("ioc-annotations-pin"));
    fireEvent.change(screen.getByTestId("ioc-annotations-tags"), {
      target: { value: "phishing, c2 , " },
    });
    fireEvent.change(screen.getByTestId("ioc-annotations-disposition"), {
      target: { value: "confirmed_malicious" },
    });
    fireEvent.change(screen.getByTestId("ioc-annotations-note"), {
      target: { value: "resolves to C2 block" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("ioc-annotations-save"));
    });

    await waitFor(() =>
      expect(annotateIOC).toHaveBeenCalledWith("ioc_TEST1", {
        pinned: true,
        tags: ["phishing", "c2"],
        analyst_note: "resolves to C2 block",
        disposition: "confirmed_malicious",
      }),
    );
    expect(await screen.findByTestId("ioc-annotations-saved")).toBeTruthy();
    expect(onAnnotated).toHaveBeenCalledWith(
      expect.objectContaining({ pinned: true, disposition: "confirmed_malicious" }),
    );
  });

  it("surfaces a save failure", async () => {
    annotateIOC.mockRejectedValue(new Error("boom"));
    render(<AnnotationSection ioc={IOC_FIXTURE} />);

    await act(async () => {
      fireEvent.click(screen.getByTestId("ioc-annotations-save"));
    });

    expect(await screen.findByTestId("ioc-annotations-error")).toBeTruthy();
    expect(screen.queryByTestId("ioc-annotations-saved")).toBeNull();
  });
});
