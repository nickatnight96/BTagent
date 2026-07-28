/**
 * Suggested hunt packs (#120/#112).
 *
 * I shipped the writer and then the read/decide API without ever giving
 * either a consumer, so suggestions piled up where nobody could see them and
 * decisions could only be made with curl. The reachability ratchet (#473)
 * named it; these tests pin the panel that closes it.
 *
 * The load-bearing cases are the ones about *not overstating what happened*:
 * a failed accept must not remove the row (the pack was not armed), and a
 * reviewer must be able to read the actual Sigma before arming anything.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const listPackSuggestions = vi.fn();
const decidePackSuggestion = vi.fn();
let mockRole = "senior_analyst";

vi.mock("@/api/hunts", () => ({
  listPackSuggestions: (...a: unknown[]) => listPackSuggestions(...a),
  decidePackSuggestion: (...a: unknown[]) => decidePackSuggestion(...a),
}));

vi.mock("@/stores/authStore", () => ({
  useAuthStore: (selector: (s: unknown) => unknown) => selector({ user: { role: mockRole } }),
}));

import { PackSuggestionsPanel } from "@/components/hunts/PackSuggestionsPanel";

const SUGGESTION = {
  id: "sug_1",
  proposal_id: "prop_1",
  plan_id: "plan_1",
  title: "Recurring OAuth consent abuse",
  technique_ids: ["T1528", "T1550.001"],
  rationale: "Fired in 4 closed investigations over 30 days.",
  state: "suggested" as const,
  hit_count: 4,
  created_at: "2026-07-01T00:00:00Z",
  updated_at: "2026-07-20T00:00:00Z",
  manifest: { name: "oauth_consent_abuse", rules: [{ id: "r1" }, { id: "r2" }] },
};

describe("PackSuggestionsPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockRole = "senior_analyst";
    listPackSuggestions.mockResolvedValue({ items: [SUGGESTION], total: 1 });
    decidePackSuggestion.mockResolvedValue({ ...SUGGESTION, state: "accepted" });
  });

  it("asks only for the pending queue", async () => {
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestions-list");
    // Already-decided suggestions aren't an inbox; fetching them would make
    // the panel grow forever.
    expect(listPackSuggestions).toHaveBeenCalledWith({ state: "suggested" });
  });

  it("shows the hit count and techniques that justify the suggestion", async () => {
    render(<PackSuggestionsPanel />);
    const row = await screen.findByTestId("pack-suggestion-sug_1");
    expect(screen.getByTestId("pack-suggestion-hits-sug_1").textContent).toBe("4 hits");
    expect(row.textContent).toContain("T1528");
    expect(row.textContent).toContain("Fired in 4 closed investigations");
  });

  it("lets a reviewer read the draft Sigma before arming it", async () => {
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestion-sug_1");
    // Accepting arms a scheduled pack against real telemetry — the manifest
    // has to be inspectable *before* the decision.
    expect(screen.getByTestId("pack-suggestion-toggle-sug_1").textContent).toContain("2 rules");
    expect(screen.queryByTestId("pack-suggestion-manifest-sug_1")).toBeNull();

    fireEvent.click(screen.getByTestId("pack-suggestion-toggle-sug_1"));
    expect(
      (await screen.findByTestId("pack-suggestion-manifest-sug_1")).textContent,
    ).toContain("oauth_consent_abuse");
  });

  it("accepts a suggestion and drops it from the queue", async () => {
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestion-sug_1");

    fireEvent.click(screen.getByTestId("pack-suggestion-accept-sug_1"));
    await waitFor(() =>
      expect(decidePackSuggestion).toHaveBeenCalledWith("sug_1", "accepted"),
    );
    await waitFor(() => expect(screen.queryByTestId("pack-suggestion-sug_1")).toBeNull());
  });

  it("dismisses a suggestion with the dismissed state", async () => {
    decidePackSuggestion.mockResolvedValue({ ...SUGGESTION, state: "dismissed" });
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestion-sug_1");

    fireEvent.click(screen.getByTestId("pack-suggestion-dismiss-sug_1"));
    await waitFor(() =>
      expect(decidePackSuggestion).toHaveBeenCalledWith("sug_1", "dismissed"),
    );
  });

  it("keeps the row when accepting fails — the pack was not armed", async () => {
    // Optimistically removing here would tell the reviewer a pack is running
    // when nothing was armed. That's the worst available outcome.
    decidePackSuggestion.mockRejectedValue(new Error("boom"));
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestion-sug_1");

    fireEvent.click(screen.getByTestId("pack-suggestion-accept-sug_1"));
    expect((await screen.findByTestId("pack-suggestions-error")).textContent).toContain(
      "not armed",
    );
    expect(screen.getByTestId("pack-suggestion-sug_1")).toBeTruthy();
  });

  it("shows analysts the queue but not the decide buttons", async () => {
    // hunt:promote is senior+. Seeing what awaits review is useful at any
    // level; the server enforces the write either way.
    mockRole = "analyst";
    render(<PackSuggestionsPanel />);
    await screen.findByTestId("pack-suggestion-sug_1");
    expect(screen.queryByTestId("pack-suggestion-accept-sug_1")).toBeNull();
    expect(screen.getByTestId("pack-suggestion-readonly-sug_1")).toBeTruthy();
  });

  it("says the queue is empty rather than rendering nothing", async () => {
    listPackSuggestions.mockResolvedValue({ items: [], total: 0 });
    render(<PackSuggestionsPanel />);
    expect(await screen.findByTestId("pack-suggestions-empty")).toBeTruthy();
  });

  it("hides itself if the fetch fails", async () => {
    // Advisory panel on someone else's page — it must not break the
    // installed-pack list below it.
    listPackSuggestions.mockRejectedValue(new Error("boom"));
    render(<PackSuggestionsPanel />);
    await waitFor(() => expect(listPackSuggestions).toHaveBeenCalled());
    expect(screen.queryByTestId("pack-suggestions-panel")).toBeNull();
  });
});
