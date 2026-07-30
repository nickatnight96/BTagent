/**
 * Coverage Console page (#501).
 *
 * The page's job is to make the detection-engineering loop legible in one
 * screen, so the cases worth pinning are the ones where an honest rendering
 * differs from a reassuring one:
 *
 *  - a load failure must not render as an empty (i.e. healthy-looking) console;
 *  - "no coverage data at all" must not read like "nothing is stale";
 *  - a never-validated technique must not render as freshly validated;
 *  - the next-best-action order is the server's, not the component's;
 *  - every action deep-links to a real surface.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import type { ReactElement } from "react";

const getCoverageConsole = vi.fn();

vi.mock("@/api/coverage", () => ({
  getCoverageConsole: (...a: unknown[]) => getCoverageConsole(...a),
}));

import { CoverageConsolePage } from "@/components/coverage-console/CoverageConsolePage";

const FRESH = {
  technique_id: "T1059",
  name: "Command and Scripting Interpreter",
  tactic: "execution",
  last_validated: "2026-07-24T00:00:00Z",
  last_verdict: "validated",
  days_since_validated: 2,
  stale: false,
  has_detection: true,
  status: "fresh",
};

const STALE = {
  technique_id: "T1055",
  name: "Process Injection",
  tactic: "defense-evasion",
  last_validated: "2026-01-01T00:00:00Z",
  last_verdict: "validated",
  days_since_validated: 206,
  stale: true,
  has_detection: true,
  status: "stale",
};

const NEVER = {
  technique_id: "T1078",
  name: "Valid Accounts",
  tactic: "persistence",
  last_validated: null,
  last_verdict: null,
  days_since_validated: null,
  stale: true,
  has_detection: true,
  status: "never",
};

const SILENT = {
  technique_id: "T1003",
  name: "OS Credential Dumping",
  tactic: "credential-access",
  last_validated: "2026-07-20T00:00:00Z",
  last_verdict: "silent_gap",
  days_since_validated: 6,
  stale: false,
  has_detection: true,
  status: "silent_gap",
};

const BROKEN_RULE = {
  pack_id: "pack_1",
  pack_name: "Windows baseline",
  rule_id: "rule_dead",
  rule_title: "Suspicious LSASS access",
  state: "errored",
  runs_observed: 5,
  runs_hit: 0,
  hit_rate: 0,
  total_hits: 0,
  last_errors: 2,
  last_run_at: "2026-07-25T00:00:00Z",
};

/** The weaker, inferred kind: the rule may work, no backend could prove it. */
const GAP = {
  technique_id: "T1566",
  name: "Phishing",
  proposal_id: "p1",
  proposal_row_id: "dprop_1",
  title: "Detect phishing attachment",
  reason: "backends_errored",
  signal: "derived",
  missing_ocsf_classes: [],
  data_sources_required: [],
  unavailable_backends: ["splunk", "sentinel"],
  available_backends: [],
  attack_data_sources: ["Application Log"],
};

/** The strong kind: the persisted matcher says nothing emits what it needs. */
const OCSF_GAP = {
  technique_id: "T1114",
  name: "Email Collection",
  proposal_id: "p2",
  proposal_row_id: "dprop_2",
  title: "Detect mailbox export",
  reason: "ocsf_telemetry_gap",
  signal: "persisted",
  missing_ocsf_classes: ["email_activity"],
  data_sources_required: ["splunk"],
  unavailable_backends: [],
  available_backends: [],
  attack_data_sources: ["Application Log"],
};

const ACTIONS = [
  {
    id: "nba_silent_gap",
    kind: "author_detection",
    title: "1 technique(s) fired with no rule at all",
    detail: "A proven coverage hole.",
    priority: 1,
    count: 1,
    link: "/detection-proposals",
    technique_ids: ["T1003"],
    rule_ids: [],
  },
  {
    id: "nba_stale",
    kind: "revalidate_technique",
    title: "1 technique(s) are overdue for re-validation",
    detail: "Outside the staleness horizon.",
    priority: 3,
    count: 1,
    link: "/detection-validation",
    technique_ids: ["T1055"],
    rule_ids: [],
  },
];

function payload(over: Record<string, unknown> = {}) {
  const techniques = (over.techniques as unknown[]) ?? [FRESH, STALE, NEVER, SILENT];
  return {
    generated_at: "2026-07-26T12:00:00Z",
    stale_days: 90,
    summary: {
      total_techniques: techniques.length,
      with_detection: techniques.length,
      fresh: 1,
      stale: 1,
      never_validated: 1,
      silent_gap: 1,
      mitre_total_techniques: 600,
      mapped_techniques: 4,
      unmapped_techniques: 596,
      broken_rules: 1,
      telemetry_gaps: 2,
      ocsf_telemetry_gaps: 1,
      open_proposals: 2,
      proposals_awaiting_review: 1,
      prs_open: 1,
    },
    tactics: [
      { tactic: "execution", techniques: [FRESH], fresh: 1, stale: 0, never: 0, silent_gap: 0 },
      {
        tactic: "defense-evasion",
        techniques: [STALE],
        fresh: 0,
        stale: 1,
        never: 0,
        silent_gap: 0,
      },
      { tactic: "persistence", techniques: [NEVER], fresh: 0, stale: 0, never: 1, silent_gap: 0 },
      {
        tactic: "credential-access",
        techniques: [SILENT],
        fresh: 0,
        stale: 0,
        never: 0,
        silent_gap: 1,
      },
    ],
    techniques,
    broken_rules: [BROKEN_RULE],
    telemetry_gaps: [OCSF_GAP, GAP],
    verdict_counts: {
      validated: 3,
      wrong_severity: 1,
      late: 0,
      silent_gap: 1,
      errored: 0,
      total: 5,
    },
    next_best_actions: ACTIONS,
    ...over,
  };
}

function renderPage(ui: ReactElement) {
  return render(<MemoryRouter>{ui}</MemoryRouter>);
}

describe("CoverageConsolePage", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    getCoverageConsole.mockResolvedValue(payload());
  });

  it("renders the heatmap banded by the server's freshness status", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("coverage-heatmap");

    // The band is read off the payload, never recomputed — a technique the
    // server calls a silent gap must not render as merely "validated 6d ago".
    expect(screen.getByTestId("coverage-cell-T1059").dataset.status).toBe("fresh");
    expect(screen.getByTestId("coverage-cell-T1055").dataset.status).toBe("stale");
    expect(screen.getByTestId("coverage-cell-T1078").dataset.status).toBe("never");
    expect(screen.getByTestId("coverage-cell-T1003").dataset.status).toBe("silent_gap");
  });

  it("describes a never-validated technique as such, not as 'today'", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("coverage-heatmap");

    fireEvent.click(screen.getByTestId("coverage-cell-T1078"));
    // A null day-count must not fall through to a zero-days reading.
    expect(screen.getByTestId("coverage-selected-status").textContent).toContain(
      "never validated",
    );
    // And the selection deep-links out rather than firing anything itself.
    expect(
      screen.getByTestId("coverage-selected-validate").getAttribute("href"),
    ).toBe("/detection-validation");
  });

  it("filters the heatmap to one band without hiding that the band is empty", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("coverage-heatmap");

    fireEvent.click(screen.getByTestId("coverage-heatmap-band-silent_gap"));
    expect(screen.getByTestId("coverage-cell-T1003")).toBeTruthy();
    expect(screen.queryByTestId("coverage-cell-T1059")).toBeNull();

    // Toggling off restores the full matrix — the good news is not permanently
    // filtered away.
    fireEvent.click(screen.getByTestId("coverage-heatmap-band-silent_gap"));
    expect(screen.getByTestId("coverage-cell-T1059")).toBeTruthy();
  });

  it("keeps the server's action ordering and links each one to a real surface", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("next-best-actions-list");

    const items = screen.getAllByTestId(/^next-best-action-nba/);
    // Worst-first: the proven coverage hole leads, not the stale technique.
    expect(items[0]?.getAttribute("data-testid")).toBe("next-best-action-nba_silent_gap");
    expect(
      screen.getByTestId("next-best-action-link-nba_silent_gap").getAttribute("href"),
    ).toBe("/detection-proposals");
    expect(
      screen.getByTestId("next-best-action-link-nba_stale").getAttribute("href"),
    ).toBe("/detection-validation");
  });

  it("shows broken rules and telemetry gaps with their reason", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("broken-rules-table");

    // "errored" and "over-firing" need different fixes; the state must survive.
    expect(screen.getByTestId("broken-rule-state-rule_dead").textContent).toContain("errored");
    expect(screen.getByTestId("telemetry-gap-reason-T1566").textContent).toContain(
      "no backend could run it",
    );
  });

  it("names the OCSF classes behind a measured gap and keeps it distinct from an inferred one", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("telemetry-gaps-list");

    // The whole point of persisting the matcher output: the panel says WHICH
    // telemetry is missing, not just "something is unproven".
    expect(screen.getByTestId("telemetry-gap-missing-ocsf-T1114").textContent).toContain(
      "email_activity",
    );
    expect(screen.getByTestId("telemetry-gap-reason-T1114").textContent).toContain(
      "no connected telemetry",
    );

    // A measured gap must never be presented as the same claim as an inferred
    // one — that conflation is exactly the debt this panel carried.
    expect(screen.getByTestId("telemetry-gap-signal-T1114").textContent).toContain("measured");
    expect(screen.getByTestId("telemetry-gap-signal-T1566").textContent).toContain("inferred");
    expect(screen.getByTestId("telemetry-gap-T1114").dataset.signal).toBe("persisted");
    expect(screen.getByTestId("telemetry-gap-T1566").dataset.signal).toBe("derived");
    // An inferred row has no OCSF class list to show — it does not know any.
    expect(screen.queryByTestId("telemetry-gap-missing-ocsf-T1566")).toBeNull();

    // The "cannot fire" count is the server's, not a client re-tally.
    expect(screen.getByTestId("telemetry-gaps-measured-count").textContent).toContain(
      "1 cannot fire",
    );
  });

  it("distinguishes an empty programme from a healthy one", async () => {
    // Zero rows everywhere means the console has nothing to measure — the
    // opposite of "all clear", and it must not be rendered as all clear.
    getCoverageConsole.mockResolvedValue(
      payload({
        techniques: [],
        tactics: [],
        broken_rules: [],
        telemetry_gaps: [],
        next_best_actions: [],
      }),
    );
    renderPage(<CoverageConsolePage />);

    expect(await screen.findByTestId("coverage-heatmap-empty")).toBeTruthy();
    expect(screen.queryByTestId("coverage-heatmap")).toBeNull();
    expect(screen.getByTestId("next-best-actions-none")).toBeTruthy();
    expect(screen.getByTestId("broken-rules-none")).toBeTruthy();
  });

  it("surfaces a load failure instead of an empty console", async () => {
    getCoverageConsole.mockRejectedValue(new Error("boom"));
    renderPage(<CoverageConsolePage />);

    expect(await screen.findByTestId("coverage-console-error")).toBeTruthy();
    // An empty console would read as "nothing wrong" — the reassuring reading
    // of a failure, which is the wrong way for this page to fail.
    expect(screen.queryByTestId("coverage-heatmap-empty")).toBeNull();
    expect(screen.queryByTestId("coverage-summary")).toBeNull();
  });

  it("refetches with a new stale window and rejects out-of-range values", async () => {
    renderPage(<CoverageConsolePage />);
    await screen.findByTestId("coverage-heatmap");
    expect(getCoverageConsole).toHaveBeenCalledWith({ staleDays: 90 });

    // 0 is below the server's ge=1 bound — sending it would 422.
    fireEvent.change(screen.getByTestId("coverage-stale-days"), { target: { value: "0" } });
    fireEvent.click(screen.getByTestId("coverage-apply"));
    await waitFor(() => expect(getCoverageConsole).toHaveBeenCalledTimes(1));

    fireEvent.change(screen.getByTestId("coverage-stale-days"), { target: { value: "30" } });
    fireEvent.click(screen.getByTestId("coverage-apply"));
    await waitFor(() => expect(getCoverageConsole).toHaveBeenCalledWith({ staleDays: 30 }));
  });
});
