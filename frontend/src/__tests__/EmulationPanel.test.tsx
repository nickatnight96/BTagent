/**
 * Adversary-emulation trigger (#118).
 *
 * `POST /validation/emulate` shipped with no consumer, so the emulation path
 * was unreachable outside curl. What these tests pin is mostly about the
 * *refusal* path, because that is the one that matters: a non-sandbox target
 * must come back as an audited outcome carrying a ledger id, not as a generic
 * "request failed" that throws the audit pointer away.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const runEmulation = vi.fn();
let mockRole = "incident_commander";

vi.mock("@/api/validation", async () => {
  // `emulationDenial` is real logic under test — only the network call is faked.
  const actual = await vi.importActual<typeof import("@/api/validation")>("@/api/validation");
  return {
    ...actual,
    runEmulation: (...a: unknown[]) => runEmulation(...a),
  };
});

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) => selector({ user: { role: mockRole } }),
}));

import { EmulationPanel } from "@/components/validation/EmulationPanel";
import { ApiError } from "@/api/client";

const VERDICT = {
  technique_id: "T1059",
  verdict: "silent_gap",
  emulator: "atomic_red_team",
  expected_severity: "high",
  observed_severity: null,
  latency_seconds: null,
  latency_sla_seconds: 300,
  detail: "No rule fired within the SLA.",
};

function deniedError(auditId = "aud_123") {
  return new ApiError(403, "Forbidden", {
    detail: {
      status: "denied",
      technique_id: "T1059",
      target_env: "production",
      reason: "target_env='production' is not an approved sandbox.",
      audit_id: auditId,
    },
  });
}

describe("EmulationPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "incident_commander";
  });

  it("hides itself below incident commander", () => {
    // validation:emulate sits at the containment:execute tier. The server
    // enforces it either way; this just avoids offering a control that can
    // only ever 403.
    mockRole = "senior_analyst";
    render(<EmulationPanel />);
    expect(screen.queryByTestId("emulation-panel")).toBeNull();
  });

  it("sends the technique, target and emulator, and renders the verdict", async () => {
    runEmulation.mockResolvedValue({ verdicts: [VERDICT] });
    const onComplete = vi.fn();
    render(<EmulationPanel onComplete={onComplete} />);

    fireEvent.change(screen.getByTestId("emulation-technique"), {
      target: { value: "t1059" },
    });
    fireEvent.change(screen.getByTestId("emulation-emulator"), {
      target: { value: "caldera" },
    });
    fireEvent.click(screen.getByTestId("emulation-run"));

    await waitFor(() =>
      expect(runEmulation).toHaveBeenCalledWith({
        // Upper-cased: ATT&CK ids are canonical uppercase, and an operator
        // typing "t1059" shouldn't get a different result.
        technique_id: "T1059",
        target_env: "sandbox",
        emulator: "caldera",
      }),
    );
    const row = await screen.findByTestId("emulation-verdict-T1059");
    expect(row.textContent).toContain("silent gap");
    expect(row.textContent).toContain("no firing observed");
    expect(onComplete).toHaveBeenCalled();
  });

  it("renders a refusal as an audited outcome, keeping the audit id", async () => {
    runEmulation.mockRejectedValue(deniedError("aud_denied_1"));
    render(<EmulationPanel />);

    fireEvent.change(screen.getByTestId("emulation-technique"), {
      target: { value: "T1059" },
    });
    fireEvent.change(screen.getByTestId("emulation-target-env"), {
      target: { value: "production" },
    });
    fireEvent.click(screen.getByTestId("emulation-run"));

    const denial = await screen.findByTestId("emulation-denied");
    expect(denial.textContent).toContain("no emulator ran");
    expect(denial.textContent).toContain("not an approved sandbox");
    expect(screen.getByTestId("emulation-denied-audit").textContent).toBe("aud_denied_1");
    // A denial is not a generic failure — the error line must stay clear.
    expect(screen.queryByTestId("emulation-error")).toBeNull();
  });

  it("offers non-sandbox targets rather than hiding the guardrail", () => {
    // Hardcoding `sandbox` client-side would conceal the control instead of
    // enforcing it — the server's allowlist is the enforcement. Letting the
    // operator pick production and see the audited refusal is the point.
    render(<EmulationPanel />);
    const select = screen.getByTestId("emulation-target-env") as HTMLSelectElement;
    const values = Array.from(select.options).map((o) => o.value);
    expect(values).toContain("sandbox");
    expect(values).toContain("production");
  });

  it("treats a plain RBAC 403 as an error, not a sandbox denial", async () => {
    // A bare 403 has a string detail and no ledger row behind it. Rendering
    // it in the denial box would claim an audit entry that doesn't exist.
    runEmulation.mockRejectedValue(new ApiError(403, "Forbidden", { detail: "Forbidden" }));
    render(<EmulationPanel />);

    fireEvent.change(screen.getByTestId("emulation-technique"), {
      target: { value: "T1059" },
    });
    fireEvent.click(screen.getByTestId("emulation-run"));

    expect(await screen.findByTestId("emulation-error")).toBeTruthy();
    expect(screen.queryByTestId("emulation-denied")).toBeNull();
  });

  it("requires a technique id before calling the endpoint", async () => {
    render(<EmulationPanel />);
    fireEvent.click(screen.getByTestId("emulation-run"));
    expect(await screen.findByTestId("emulation-error")).toBeTruthy();
    expect(runEmulation).not.toHaveBeenCalled();
  });

  it("clears a previous refusal when a new run succeeds", async () => {
    runEmulation.mockRejectedValueOnce(deniedError());
    render(<EmulationPanel />);
    fireEvent.change(screen.getByTestId("emulation-technique"), {
      target: { value: "T1059" },
    });
    fireEvent.click(screen.getByTestId("emulation-run"));
    await screen.findByTestId("emulation-denied");

    runEmulation.mockResolvedValueOnce({ verdicts: [VERDICT] });
    fireEvent.click(screen.getByTestId("emulation-run"));
    await screen.findByTestId("emulation-verdicts");
    // A stale refusal sitting above a fresh success would misreport what the
    // last run actually did.
    expect(screen.queryByTestId("emulation-denied")).toBeNull();
  });
});
