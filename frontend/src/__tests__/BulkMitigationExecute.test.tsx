/**
 * Bulk-block execution (UC-3.3).
 *
 * `POST /containment/execute/bulk-block` shipped in #463 with no consumer: the
 * page could plan and stage blocks, then told the operator "execution requires
 * incident-commander sign-off" — with no way for a commander to actually sign
 * off. Staging was a dead end.
 *
 * The cases that matter are the refusals. A safelisted IOC comes back as an
 * audited 403, and that has to render as *this IOC was not blocked* with its
 * ledger id — not as a failed request, and above all not silently absent from
 * a list that would otherwise read as "all done".
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";

const planBulkMitigation = vi.fn();
const executeBulkBlock = vi.fn();
let mockRole = "incident_commander";

vi.mock("@/api/mitigation", () => ({
  planBulkMitigation: (...a: unknown[]) => planBulkMitigation(...a),
}));

vi.mock("@/api/containment", async () => {
  // `executionDenial` is real logic under test — only the call is faked.
  const actual = await vi.importActual<typeof import("@/api/containment")>(
    "@/api/containment",
  );
  return { ...actual, executeBulkBlock: (...a: unknown[]) => executeBulkBlock(...a) };
});

// The page reads the role through a selector; the Header it renders calls the
// store bare and destructures. Support both shapes.
vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector?: (s: unknown) => unknown) => {
    const state = { user: { id: "usr_ic", role: mockRole }, logout: vi.fn() };
    return selector ? selector(state) : state;
  },
}));

vi.mock("@/stores/uiStore", () => ({
  useUIStore: (selector?: (s: unknown) => unknown) => {
    const state = { toggleSidebar: vi.fn(), sidebarOpen: true };
    return selector ? selector(state) : state;
  },
}));

import { BulkMitigationPage } from "@/components/mitigation/BulkMitigationPage";
import { ApiError } from "@/api/client";

function blockAction(id: string, value: string) {
  return {
    id,
    ioc_type: "ip",
    ioc_value: value,
    decision: "block",
    tool: "panorama",
    policy_object: "BLOCKLIST-EDL",
    policy_preview: `add ${value}`,
    description: `Block ${value}`,
    destructive: true,
    requires_approval: true,
    rollback: `remove ${value}`,
    reason: "malicious",
  };
}

const PLAN = {
  plan: {
    summary: "2 blocks",
    actions: [blockAction("act_1", "45.83.12.7"), blockAction("act_2", "8.8.8.8")],
    block_count: 2,
    skip_count: 0,
    tools: ["panorama"],
  },
  mock_mode: true,
};

function executed(auditId: string) {
  return {
    executed: true,
    outcome: "success",
    tool: "panorama",
    target: "45.83.12.7",
    audit_id: auditId,
    approver_id: "usr_ic",
    change_ref: "CHG0001",
    tool_response: {},
  };
}

function safelistDenial(auditId = "aud_safelisted") {
  return new ApiError(403, "Forbidden", {
    detail: {
      message: "IOC is on the org never-block safelist (collateral-outage guard).",
      outcome: "denied",
      target: "8.8.8.8",
      tool: "panorama",
      audit_id: auditId,
      approver_id: "usr_ic",
    },
  });
}

/** Plan → approve all → stage, leaving the page ready to execute. */
async function stageBlocks() {
  render(
    <MemoryRouter>
      <BulkMitigationPage />
    </MemoryRouter>,
  );
  fireEvent.change(screen.getByTestId("bulk-mitigation-input"), {
    target: { value: "45.83.12.7\n8.8.8.8" },
  });
  fireEvent.click(screen.getByTestId("bulk-mitigation-submit"));
  await screen.findByTestId("bulk-mitigation-stage");
  fireEvent.click(screen.getByText("Approve all"));
  await waitFor(() =>
    expect((screen.getByTestId("bulk-mitigation-stage") as HTMLButtonElement).disabled).toBe(
      false,
    ),
  );
  fireEvent.click(screen.getByTestId("bulk-mitigation-stage"));
  await screen.findByTestId("bulk-mitigation-staged");
}

describe("BulkMitigationPage execution", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "incident_commander";
    planBulkMitigation.mockResolvedValue(PLAN);
  });

  it("offers no execute button below incident commander", async () => {
    mockRole = "senior_analyst";
    await stageBlocks();
    expect(screen.queryByTestId("bulk-mitigation-execute")).toBeNull();
    expect(screen.getByTestId("bulk-mitigation-execute-denied")).toBeTruthy();
  });

  it("executes each staged block and shows its audit id", async () => {
    executeBulkBlock.mockResolvedValueOnce(executed("aud_1"));
    executeBulkBlock.mockResolvedValueOnce(executed("aud_2"));
    await stageBlocks();

    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    await screen.findByTestId("bulk-mitigation-outcomes");

    expect(executeBulkBlock).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("bulk-mitigation-audit-act_1").textContent).toBe("aud_1");
    expect(screen.getByTestId("bulk-mitigation-audit-act_2").textContent).toBe("aud_2");
  });

  it("renders a safelist refusal as an un-blocked IOC, not a failure", async () => {
    executeBulkBlock.mockResolvedValueOnce(executed("aud_1"));
    executeBulkBlock.mockRejectedValueOnce(safelistDenial("aud_refused"));
    await stageBlocks();

    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    const refused = await screen.findByTestId("bulk-mitigation-outcome-act_2");

    expect(refused.textContent).toContain("refused — not blocked");
    expect(refused.textContent).toContain("never-block safelist");
    // The ledger id is the operator's handle on the refusal.
    expect(screen.getByTestId("bulk-mitigation-audit-act_2").textContent).toBe("aud_refused");
  });

  it("keeps going after a refusal instead of abandoning later blocks", async () => {
    // A refusal on the first IOC must not silently drop the second: the
    // operator would believe both were handled.
    executeBulkBlock.mockRejectedValueOnce(safelistDenial());
    executeBulkBlock.mockResolvedValueOnce(executed("aud_2"));
    await stageBlocks();

    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    await screen.findByTestId("bulk-mitigation-outcomes");

    expect(executeBulkBlock).toHaveBeenCalledTimes(2);
    expect(screen.getByTestId("bulk-mitigation-outcome-act_1").textContent).toContain(
      "refused",
    );
    expect(screen.getByTestId("bulk-mitigation-audit-act_2").textContent).toBe("aud_2");
  });

  it("marks un-attempted blocks when a transport error breaks the run", async () => {
    // A network failure is not a refusal — there is no ledger row and no
    // decision. The remaining IOCs must not read as handled.
    executeBulkBlock.mockResolvedValueOnce(executed("aud_1"));
    executeBulkBlock.mockRejectedValueOnce(new Error("network down"));
    await stageBlocks();

    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    await screen.findByTestId("bulk-mitigation-outcomes");

    expect(screen.getByTestId("bulk-mitigation-outcome-act_2").textContent).toContain(
      "not attempted",
    );
  });

  it("sends the approval flag and the rollback the plan proposed", async () => {
    executeBulkBlock.mockResolvedValue(executed("aud_1"));
    await stageBlocks();
    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    await screen.findByTestId("bulk-mitigation-outcomes");

    // The client sends the whole action; the server re-checks approval and the
    // safelist regardless, so this only pins that nothing is dropped en route.
    expect(executeBulkBlock.mock.calls[0]?.[0]).toMatchObject({
      id: "act_1",
      ioc_value: "45.83.12.7",
      rollback: "remove 45.83.12.7",
    });
  });

  it("does not re-fire once a run has completed", async () => {
    executeBulkBlock.mockResolvedValue(executed("aud_1"));
    await stageBlocks();
    fireEvent.click(screen.getByTestId("bulk-mitigation-execute"));
    await screen.findByTestId("bulk-mitigation-outcomes");

    // Double-blocking the same IOCs would write duplicate ledger rows and
    // duplicate change records.
    expect((screen.getByTestId("bulk-mitigation-execute") as HTMLButtonElement).disabled).toBe(
      true,
    );
  });
});
