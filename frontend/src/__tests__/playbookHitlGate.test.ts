/**
 * The HITL-gate decision path in the playbook store (#588).
 *
 * The gate had no UI at all: releasing one meant hand-rolling an API call,
 * which is why the browser spec drove approval through `api.ctx.post` and why
 * a broken spec meant the control was never exercised from the app side.
 *
 * These cover the store action the new Approve/Reject buttons call — that it
 * targets the right endpoint, that it replaces the polled execution state with
 * the server's answer rather than guessing locally, and that a refusal
 * surfaces instead of being swallowed.
 */
import { describe, it, expect, vi, beforeEach } from "vitest";

import { usePlaybookStore } from "@/stores/playbookStore";
import { PlaybookStatus, StepExecutionStatus } from "@/types/playbook";

vi.mock("@/api/playbooks", async () => {
  const actual = await vi.importActual<typeof import("@/api/playbooks")>(
    "@/api/playbooks",
  );
  return { ...actual, resolveExecutionGate: vi.fn() };
});

const { resolveExecutionGate } = await import("@/api/playbooks");
const mockResolve = vi.mocked(resolveExecutionGate);

const PAUSED = {
  id: "pbe_1",
  playbook_id: "pb_1",
  status: PlaybookStatus.PAUSED_HITL,
  trigger_data: {},
  step_results: [
    {
      step_id: "gate",
      status: StepExecutionStatus.RUNNING,
      output: { awaiting_approval: true },
    },
  ],
} as never;

describe("playbookStore.resolveGate", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    usePlaybookStore.setState({ executionState: PAUSED, error: null });
  });

  it("sends the decision and adopts the server's execution state", async () => {
    const resumed = {
      ...(PAUSED as unknown as Record<string, unknown>),
      status: PlaybookStatus.RUNNING,
      step_results: [
        {
          step_id: "gate",
          status: StepExecutionStatus.COMPLETED,
          output: { approved: true, approver_id: "usr_1" },
        },
      ],
    };
    mockResolve.mockResolvedValue(resumed as never);

    await usePlaybookStore.getState().resolveGate("pbe_1", "approve", "looks ok");

    expect(mockResolve).toHaveBeenCalledWith("pbe_1", "approve", "looks ok");
    // The store must not optimistically invent the post-approval state: the
    // run can resume, complete, or pause again at a later gate, and only the
    // server knows which.
    expect(usePlaybookStore.getState().executionState).toEqual(resumed);
  });

  it("carries a rejection through as its own decision", async () => {
    const failed = {
      ...(PAUSED as unknown as Record<string, unknown>),
      status: PlaybookStatus.FAILED,
    };
    mockResolve.mockResolvedValue(failed as never);

    await usePlaybookStore.getState().resolveGate("pbe_1", "reject");

    expect(mockResolve).toHaveBeenCalledWith("pbe_1", "reject", "");
    expect(usePlaybookStore.getState().executionState).toEqual(failed);
  });

  it("surfaces a refusal instead of leaving the run looking released", async () => {
    mockResolve.mockRejectedValue(new Error("Forbidden"));

    await usePlaybookStore.getState().resolveGate("pbe_1", "approve");

    expect(usePlaybookStore.getState().error).toBe("Forbidden");
    // Still paused — a failed approval must not read as an approval.
    expect(usePlaybookStore.getState().executionState).toEqual(PAUSED);
  });
});
