import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor, act, fireEvent } from "@testing-library/react";

const generateDetectionContent = vi.fn();

vi.mock("@/api/reports", () => ({
  generateDetectionContent: (...a: unknown[]) => generateDetectionContent(...a),
}));

import { IocRulesPanel } from "@/components/detection/IocRulesPanel";

const CONTENT = {
  investigation_id: "inv_mock_001",
  platform: "sentinel",
  rules: [
    {
      name: "IOC - Malicious IP Communication",
      description: "Detect communication with known malicious IPs",
      language: "kql",
      rule: 'CommonSecurityLog\n| where DestinationIP in ("198.51.100.23")',
    },
    {
      name: "IOC - Malicious Domain Resolution",
      description: "Detect DNS queries for known malicious domains",
      language: "kql",
      rule: 'DnsEvents\n| where Name in ("malicious-domain.com")',
    },
  ],
  rule_count: 2,
  generated_at: "2026-07-24T04:00:00Z",
  status: "success",
};

describe("IocRulesPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    generateDetectionContent.mockResolvedValue(CONTENT);
  });

  it("is disabled until an investigation ID is entered", () => {
    render(<IocRulesPanel />);
    const btn = screen.getByTestId("ioc-rules-generate") as HTMLButtonElement;
    expect(btn.disabled).toBe(true);
    expect(generateDetectionContent).not.toHaveBeenCalled();
  });

  it("generates and renders platform rules", async () => {
    render(<IocRulesPanel />);

    fireEvent.change(screen.getByTestId("ioc-rules-investigation-input"), {
      target: { value: "inv_mock_001" },
    });
    fireEvent.change(screen.getByTestId("ioc-rules-platform"), {
      target: { value: "sentinel" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("ioc-rules-generate"));
    });

    await waitFor(() =>
      expect(generateDetectionContent).toHaveBeenCalledWith("inv_mock_001", "sentinel"),
    );
    const result = await screen.findByTestId("ioc-rules-result");
    expect(result.textContent).toContain("2 rules for sentinel");
    expect(screen.getByTestId("ioc-rule-0").textContent).toContain(
      "IOC - Malicious IP Communication",
    );
    expect(screen.getByTestId("ioc-rule-1").textContent).toContain("DnsEvents");
    // Language badge renders per rule.
    expect(screen.getByTestId("ioc-rule-0").textContent).toContain("kql");
  });

  it("surfaces a generation failure in the panel error", async () => {
    generateDetectionContent.mockRejectedValue(new Error("boom"));
    render(<IocRulesPanel />);

    fireEvent.change(screen.getByTestId("ioc-rules-investigation-input"), {
      target: { value: "inv_nope" },
    });
    await act(async () => {
      fireEvent.click(screen.getByTestId("ioc-rules-generate"));
    });

    const err = await screen.findByTestId("ioc-rules-error");
    expect(err.textContent).toContain("Rule generation failed");
    expect(screen.queryByTestId("ioc-rules-result")).toBeNull();
  });
});
