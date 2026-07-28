/**
 * Pattern-plan run history (#120 follow-up, #473 ratchet).
 *
 * `GET /pattern/proposals/{id}/plan/runs` shipped with the plan_runs table
 * and never got a consumer, while its hunt-plan sibling was wired into the
 * Hunt Planner the same week. The gap it left is concrete: the plan JSON's
 * `last_run` blob only ever shows the latest execution, so re-running a hunt
 * silently overwrote the only visible evidence of the previous run — nothing
 * to compare "this week's re-hunt" against.
 *
 * The cases that carry weight: history is auxiliary and must never take the
 * plan panel down with it, and a single run earns no extra rows — the
 * last-run line already tells that story.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

const listProposalPlanRuns = vi.fn();

vi.mock("@/api/pattern", () => ({
  listProposalPlanRuns: (...a: unknown[]) => listProposalPlanRuns(...a),
}));

// The panel lives in the page module, which imports the WS refresh hook and
// the triage page's event list; neither participates in this panel.
vi.mock("@/hooks/useLiveEventRefresh", () => ({ useLiveEventRefresh: () => {} }));
vi.mock("@/components/hunt/HuntTriagePage", () => ({ HUNT_FINDING_EVENTS: [] }));

import { HuntPlanPanel } from "@/components/pattern/PatternInsightsPage";
import type { ProposalHuntPlan, ProposalPlanRun } from "@/types/pattern_hunt";

function makeRun(over: Partial<ProposalPlanRun> = {}): ProposalPlanRun {
  return {
    id: `plr_${Math.random().toString(36).slice(2, 8)}`,
    org_id: "org_default",
    plan_row_id: "hpl_1",
    proposal_id: "php_1",
    plan_id: "plan_1",
    run_id: "run_1",
    ttp_stats: {},
    hit_count: 3,
    error_count: 0,
    findings_created: 2,
    status: "completed",
    error: null,
    started_at: "2026-07-28T10:00:00Z",
    completed_at: "2026-07-28T10:05:00Z",
    ...over,
  };
}

const READY_PLAN: ProposalHuntPlan = {
  id: "hpl_1",
  org_id: "org_default",
  proposal_id: "php_1",
  status: "ready",
  plan: {
    id: "plan_1",
    state: "ready",
    hypotheses: [{ ttp_id: "T1059", ttp_name: "Command Interpreter", priority: 1 }],
    ttp_entries: [
      {
        ttp_id: "T1059",
        ttp_name: "Command Interpreter",
        queries: { splunk: { backend: "splunk", query: "index=main" } },
      },
    ],
    last_run: {
      run_id: "run_2",
      started_at: "2026-07-28T11:00:00Z",
      completed_at: "2026-07-28T11:04:00Z",
      findings_created: 1,
      error_count: 0,
      per_ttp: { T1059: { hits: 1, errors: [] } },
    },
  },
  error: "",
  created_at: "2026-07-28T09:00:00Z",
  updated_at: "2026-07-28T11:04:00Z",
};

function renderPanel(plan: ProposalHuntPlan = READY_PLAN) {
  return render(
    <HuntPlanPanel
      plan={plan}
      busy={false}
      canTriage={true}
      onRefresh={() => {}}
      onExecute={() => {}}
    />,
  );
}

describe("HuntPlanPanel run history", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listProposalPlanRuns.mockResolvedValue({ items: [], total: 0 });
  });

  it("asks for the proposal's run history", async () => {
    renderPanel();
    await waitFor(() =>
      expect(listProposalPlanRuns).toHaveBeenCalledWith("php_1", { page_size: 5 }),
    );
  });

  it("renders the history once there is more than one run to compare", async () => {
    const runs = [
      makeRun({ id: "plr_new", run_id: "run_2", findings_created: 1, hit_count: 1 }),
      makeRun({ id: "plr_old", run_id: "run_1", findings_created: 2, hit_count: 3 }),
    ];
    listProposalPlanRuns.mockResolvedValue({ items: runs, total: 2 });
    renderPanel();

    const history = await screen.findByTestId("pattern-plan-run-history");
    expect(history).toBeTruthy();
    // The older run is the whole point — last_run alone cannot show it.
    const old = screen.getByTestId("pattern-plan-run-plr_old");
    expect(old.textContent).toContain("2 findings");
    expect(old.textContent).toContain("3 hits");
  });

  it("shows nothing extra for a single run — last_run already tells it", async () => {
    listProposalPlanRuns.mockResolvedValue({ items: [makeRun()], total: 1 });
    renderPanel();
    await waitFor(() => expect(listProposalPlanRuns).toHaveBeenCalled());
    expect(screen.queryByTestId("pattern-plan-run-history")).toBeNull();
  });

  it("keeps the plan panel intact when the history fetch fails", async () => {
    // Auxiliary data: a 404 (plan row raced away) or a flaky fetch must not
    // cost the analyst the runbook view or the execute button.
    listProposalPlanRuns.mockRejectedValue(new Error("boom"));
    renderPanel();
    await waitFor(() => expect(listProposalPlanRuns).toHaveBeenCalled());
    expect(screen.getByTestId("pattern-plan-panel")).toBeTruthy();
    expect(screen.getByTestId("pattern-plan-execute")).toBeTruthy();
    expect(screen.queryByTestId("pattern-plan-run-history")).toBeNull();
  });

  it("surfaces a failed run's status and error count, not just successes", async () => {
    const runs = [
      makeRun({ id: "plr_bad", status: "failed", error_count: 4, findings_created: 0 }),
      makeRun({ id: "plr_ok" }),
    ];
    listProposalPlanRuns.mockResolvedValue({ items: runs, total: 2 });
    renderPanel();

    const bad = await screen.findByTestId("pattern-plan-run-plr_bad");
    expect(bad.textContent).toContain("failed");
    expect(bad.textContent).toContain("4 error(s)");
  });

  it("refetches when a new execution lands (last_run.run_id changes)", async () => {
    const { rerender } = renderPanel();
    await waitFor(() => expect(listProposalPlanRuns).toHaveBeenCalledTimes(1));

    const rerun: ProposalHuntPlan = {
      ...READY_PLAN,
      plan: {
        ...READY_PLAN.plan!,
        last_run: { ...READY_PLAN.plan!.last_run!, run_id: "run_3" },
      },
    };
    rerender(
      <HuntPlanPanel
        plan={rerun}
        busy={false}
        canTriage={true}
        onRefresh={() => {}}
        onExecute={() => {}}
      />,
    );
    await waitFor(() => expect(listProposalPlanRuns).toHaveBeenCalledTimes(2));
  });
});
