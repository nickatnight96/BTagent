/**
 * Never-block safelist manager (#106). The safelist is what *stops*
 * containment, so this panel is the only place an operator can see or correct
 * the guard. What matters: it hides itself when the caller can't read the
 * safelist (403), removal takes two clicks because it re-enables containment,
 * server-side validation messages are surfaced verbatim rather than
 * re-implemented, and every entry insists on a reason.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { render, screen, fireEvent, waitFor } from "@testing-library/react";

const listSafelistEntries = vi.fn();
const addSafelistEntry = vi.fn();
const removeSafelistEntry = vi.fn();
const toastSuccess = vi.fn();
const toastError = vi.fn();

vi.mock("@/api/containment", () => ({
  listSafelistEntries: (...a: unknown[]) => listSafelistEntries(...a),
  addSafelistEntry: (...a: unknown[]) => addSafelistEntry(...a),
  removeSafelistEntry: (...a: unknown[]) => removeSafelistEntry(...a),
}));

vi.mock("sonner", () => ({
  toast: {
    success: (...a: unknown[]) => toastSuccess(...a),
    error: (...a: unknown[]) => toastError(...a),
  },
}));

import { SafelistPanel } from "@/components/settings/SafelistPanel";
import { ApiError } from "@/api/client";

const DNS_ENTRY = {
  id: "safe_dns",
  org_id: "org_default",
  entry_type: "ip" as const,
  value: "10.0.0.53",
  reason: "internal resolver",
  created_by: "usr_ic",
};

describe("SafelistPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    listSafelistEntries.mockResolvedValue([DNS_ENTRY]);
    removeSafelistEntry.mockResolvedValue(undefined);
  });

  it("hides itself when the caller may not read the safelist", async () => {
    // containment:execute is incident_commander+; everyone else gets a 403,
    // and an analyst should see no trace of the panel rather than an error.
    listSafelistEntries.mockRejectedValue(new ApiError(403, "Forbidden", null));
    render(<SafelistPanel />);
    await waitFor(() => expect(listSafelistEntries).toHaveBeenCalled());
    expect(screen.queryByTestId("safelist-panel")).toBeNull();
  });

  it("distinguishes an empty org list from the universal baseline", async () => {
    listSafelistEntries.mockResolvedValue([]);
    render(<SafelistPanel />);
    // "No entries" must not read as "nothing is protected" — the code-level
    // baseline still applies and the copy has to say so.
    expect((await screen.findByTestId("safelist-empty")).textContent).toContain(
      "universal baseline",
    );
  });

  it("removal takes an explicit confirmation, and cancelling leaves the guard up", async () => {
    render(<SafelistPanel />);
    fireEvent.click(await screen.findByTestId("safelist-remove-safe_dns"));
    expect(removeSafelistEntry).not.toHaveBeenCalled();

    fireEvent.click(screen.getByTestId("safelist-remove-cancel-safe_dns"));
    expect(removeSafelistEntry).not.toHaveBeenCalled();
    expect(screen.getByTestId("safelist-entry-safe_dns")).toBeTruthy();

    fireEvent.click(screen.getByTestId("safelist-remove-safe_dns"));
    fireEvent.click(screen.getByTestId("safelist-remove-confirm-safe_dns"));
    await waitFor(() => expect(removeSafelistEntry).toHaveBeenCalledWith("safe_dns"));
    await waitFor(() => expect(screen.queryByTestId("safelist-entry-safe_dns")).toBeNull());
    expect(toastSuccess).toHaveBeenCalledWith("10.0.0.53 can be contained again");
  });

  it("keeps the entry listed when removal fails", async () => {
    removeSafelistEntry.mockRejectedValue(new ApiError(404, "Not Found", null));
    render(<SafelistPanel />);
    fireEvent.click(await screen.findByTestId("safelist-remove-safe_dns"));
    fireEvent.click(screen.getByTestId("safelist-remove-confirm-safe_dns"));
    await waitFor(() => expect(toastError).toHaveBeenCalled());
    // The optimistic path must not drop a still-protected target from view.
    expect(screen.getByTestId("safelist-entry-safe_dns")).toBeTruthy();
  });

  it("adds an entry with its type and reason, and prepends it", async () => {
    addSafelistEntry.mockResolvedValue({
      id: "safe_new",
      org_id: "org_default",
      entry_type: "domain",
      value: "corp.example.com",
      reason: "primary SSO",
      created_by: "usr_ic",
    });
    render(<SafelistPanel />);
    await screen.findByTestId("safelist-list");

    fireEvent.change(screen.getByTestId("safelist-add-type"), {
      target: { value: "domain" },
    });
    fireEvent.change(screen.getByTestId("safelist-add-value"), {
      target: { value: "corp.example.com" },
    });
    fireEvent.change(screen.getByTestId("safelist-add-reason"), {
      target: { value: "primary SSO" },
    });
    fireEvent.click(screen.getByTestId("safelist-add-button"));

    await waitFor(() =>
      expect(addSafelistEntry).toHaveBeenCalledWith({
        entryType: "domain",
        value: "corp.example.com",
        reason: "primary SSO",
      }),
    );
    await screen.findByTestId("safelist-entry-safe_new");
    expect(screen.getByTestId("safelist-entry-safe_dns")).toBeTruthy();
    expect((screen.getByTestId("safelist-add-value") as HTMLInputElement).value).toBe("");
  });

  it("insists on a reason before sending anything", async () => {
    render(<SafelistPanel />);
    await screen.findByTestId("safelist-list");

    fireEvent.change(screen.getByTestId("safelist-add-value"), {
      target: { value: "198.51.100.10" },
    });
    fireEvent.click(screen.getByTestId("safelist-add-button"));

    expect((await screen.findByTestId("safelist-add-error")).textContent).toContain("reason");
    expect(addSafelistEntry).not.toHaveBeenCalled();
  });

  it("surfaces the server's validation message rather than guessing at one", async () => {
    // The rules for a valid IP/domain live in `normalize_entry` server-side.
    // The panel deliberately doesn't re-implement them, so the 422 detail is
    // the only thing the operator has to go on and must be shown verbatim.
    addSafelistEntry.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail: "'999.1.1.1' is not a valid IP address",
      }),
    );
    render(<SafelistPanel />);
    await screen.findByTestId("safelist-list");

    fireEvent.change(screen.getByTestId("safelist-add-value"), {
      target: { value: "999.1.1.1" },
    });
    fireEvent.change(screen.getByTestId("safelist-add-reason"), {
      target: { value: "typo" },
    });
    fireEvent.click(screen.getByTestId("safelist-add-button"));

    expect((await screen.findByTestId("safelist-add-error")).textContent).toBe(
      "'999.1.1.1' is not a valid IP address",
    );
  });
});
