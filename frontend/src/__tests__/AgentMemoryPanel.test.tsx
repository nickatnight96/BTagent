/**
 * Agent Memory panel (#482/#484 UI — clears the last #473 KNOWN_GAPS debt).
 *
 * The memory store's write side runs itself (close hooks) and its recall is
 * injected into every new investigation's prompt — but none of it was
 * visible, and a wrong remembered fact could only be corrected over curl.
 *
 * The cases that carry weight: the record form is the correction path
 * (upsert semantics surfaced in copy), it hides below senior_analyst, and an
 * empty store is an explicit statement about a young deployment, not a
 * blank.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import {
  render as rtlRender,
  screen,
  fireEvent,
  waitFor,
  type RenderOptions,
} from "@testing-library/react";
import { MemoryRouter } from "react-router";

// The panel renders router <Link>s for memory sources (F13), so every render
// needs a router context. Shadow `render` so call sites stay unchanged.
const render = (ui: React.ReactElement, options?: RenderOptions) =>
  rtlRender(ui, {
    wrapper: ({ children }) => <MemoryRouter>{children}</MemoryRouter>,
    ...options,
  });

const recallMemories = vi.fn();
const recordMemory = vi.fn();
const forgetMemory = vi.fn();

vi.mock("@/api/memory", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/api/memory")>()),
  recallMemories: (...a: unknown[]) => recallMemories(...a),
  recordMemory: (...a: unknown[]) => recordMemory(...a),
  forgetMemory: (...a: unknown[]) => forgetMemory(...a),
}));

import { AgentMemoryPanel } from "@/components/knowledge/AgentMemoryPanel";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";
import type { AgentMemory } from "@/api/memory";

function makeMemory(over: Partial<AgentMemory> = {}): AgentMemory {
  return {
    id: `mem_${Math.random().toString(36).slice(2, 8)}`,
    kind: "entity_note",
    subject: "web-prod-03",
    content: "Bastion host; SSH exposure is expected and safelisted.",
    source: "investigation:inv_1",
    confidence: 0.9,
    tlp_level: "green",
    created_at: "2026-07-20T10:00:00Z",
    updated_at: "2026-07-28T10:00:00Z",
    ...over,
  };
}

function setRole(role: UserRole | null) {
  useAuthStore.setState({
    user: role ? { id: "usr_1", username: "t", role } : null,
  });
}

describe("AgentMemoryPanel", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    recallMemories.mockResolvedValue({
      items: [makeMemory({ id: "mem_a" })],
      total: 1,
      mode: "recency",
    });
    recordMemory.mockResolvedValue(makeMemory());
    forgetMemory.mockResolvedValue(undefined);
    setRole(UserRole.SENIOR_ANALYST);
  });

  it("hides itself entirely when recall fails", async () => {
    recallMemories.mockRejectedValue(new Error("forbidden"));
    const { container } = render(<AgentMemoryPanel />);
    await waitFor(() => expect(recallMemories).toHaveBeenCalled());
    expect(screen.queryByTestId("agent-memory-panel")).toBeNull();
    expect(container.textContent).toBe("");
  });

  it("renders each memory with kind, subject, TLP and content", async () => {
    render(<AgentMemoryPanel />);
    const row = await screen.findByTestId("agent-memory-mem_a");
    expect(row.textContent).toContain("entity note");
    expect(row.textContent).toContain("web-prod-03");
    expect(row.textContent).toContain("TLP:green");
    expect(row.textContent).toContain("Bastion host");
    expect(row.textContent).toContain("90% confidence");
  });

  it("states an empty store explicitly — young deployment, not a blank", async () => {
    recallMemories.mockResolvedValue({ items: [], total: 0 });
    render(<AgentMemoryPanel />);
    expect((await screen.findByTestId("agent-memory-empty")).textContent).toContain(
      "recorded nothing",
    );
  });

  it("narrows recall by subject and kind through the server, not client-side", async () => {
    render(<AgentMemoryPanel />);
    await screen.findByTestId("agent-memory-list");

    fireEvent.change(screen.getByTestId("agent-memory-filter-kind"), {
      target: { value: "decision" },
    });
    await waitFor(() =>
      expect(recallMemories).toHaveBeenLastCalledWith({
        subject: undefined,
        kind: "decision",
        query: undefined,
        limit: 50,
      }),
    );
  });

  it("hides the record affordance from plain analysts", async () => {
    setRole(UserRole.ANALYST);
    render(<AgentMemoryPanel />);
    await screen.findByTestId("agent-memory-panel");
    expect(screen.queryByTestId("agent-memory-add")).toBeNull();
  });

  it("records a fact and reloads so the upserted row appears", async () => {
    render(<AgentMemoryPanel />);
    fireEvent.click(await screen.findByTestId("agent-memory-add"));
    fireEvent.change(screen.getByTestId("agent-memory-kind"), {
      target: { value: "learning" },
    });
    fireEvent.change(screen.getByTestId("agent-memory-subject"), {
      target: { value: "vendor Acme" },
    });
    fireEvent.change(screen.getByTestId("agent-memory-content"), {
      target: { value: "Acme maintenance windows are Tuesdays 02:00-04:00 UTC." },
    });
    fireEvent.click(screen.getByTestId("agent-memory-submit"));

    await waitFor(() =>
      expect(recordMemory).toHaveBeenCalledWith({
        kind: "learning",
        subject: "vendor Acme",
        content: "Acme maintenance windows are Tuesdays 02:00-04:00 UTC.",
      }),
    );
    // Reload rather than local splice: upsert may have replaced an existing
    // row, and the server owns dedup and ordering.
    await waitFor(() => expect(recallMemories.mock.calls.length).toBeGreaterThan(1));
  });

  it("requires subject and content before calling the server", async () => {
    render(<AgentMemoryPanel />);
    fireEvent.click(await screen.findByTestId("agent-memory-add"));
    fireEvent.click(screen.getByTestId("agent-memory-submit"));

    expect(await screen.findByTestId("agent-memory-error")).toBeTruthy();
    expect(recordMemory).not.toHaveBeenCalled();
  });

  it("surfaces the server's rejection verbatim", async () => {
    recordMemory.mockRejectedValue(
      new ApiError(422, "Unprocessable Entity", {
        detail: "Unknown memory kind 'vibe'; expected one of [...]",
      }),
    );
    render(<AgentMemoryPanel />);
    fireEvent.click(await screen.findByTestId("agent-memory-add"));
    fireEvent.change(screen.getByTestId("agent-memory-subject"), {
      target: { value: "x" },
    });
    fireEvent.change(screen.getByTestId("agent-memory-content"), {
      target: { value: "y" },
    });
    fireEvent.click(screen.getByTestId("agent-memory-submit"));

    expect((await screen.findByTestId("agent-memory-error")).textContent).toContain(
      "Unknown memory kind",
    );
  });

  // --- FORGET ------------------------------------------------------------ //
  //
  // The missing trust primitive: a wrong fact is recalled into every future
  // investigation, so it has to be removable — but removal reshapes future
  // recall just as decisively as writing one, hence the confirmation step.

  describe("forget", () => {
    it("never deletes on the first click — it asks first", async () => {
      render(<AgentMemoryPanel />);
      fireEvent.click(await screen.findByTestId("agent-memory-forget-mem_a"));

      expect(screen.getByTestId("agent-memory-forget-confirm-panel-mem_a")).toBeTruthy();
      expect(forgetMemory).not.toHaveBeenCalled();
    });

    it("forgets on confirm and reloads from the server", async () => {
      render(<AgentMemoryPanel />);
      fireEvent.click(await screen.findByTestId("agent-memory-forget-mem_a"));
      fireEvent.click(screen.getByTestId("agent-memory-forget-confirm-mem_a"));

      await waitFor(() => expect(forgetMemory).toHaveBeenCalledWith("mem_a"));
      // The server owns what is still live after a soft delete.
      await waitFor(() => expect(recallMemories.mock.calls.length).toBeGreaterThan(1));
    });

    it("keeps the fact when the analyst backs out", async () => {
      render(<AgentMemoryPanel />);
      fireEvent.click(await screen.findByTestId("agent-memory-forget-mem_a"));
      fireEvent.click(screen.getByTestId("agent-memory-forget-cancel-mem_a"));

      await waitFor(() =>
        expect(screen.queryByTestId("agent-memory-forget-confirm-panel-mem_a")).toBeNull(),
      );
      expect(forgetMemory).not.toHaveBeenCalled();
    });

    it("hides the forget affordance from plain analysts", async () => {
      setRole(UserRole.ANALYST);
      render(<AgentMemoryPanel />);
      await screen.findByTestId("agent-memory-mem_a");
      expect(screen.queryByTestId("agent-memory-forget-mem_a")).toBeNull();
    });

    it("surfaces a refused forget instead of pretending it worked", async () => {
      forgetMemory.mockRejectedValue(
        new ApiError(404, "Not Found", { detail: "Memory not found" }),
      );
      render(<AgentMemoryPanel />);
      fireEvent.click(await screen.findByTestId("agent-memory-forget-mem_a"));
      fireEvent.click(screen.getByTestId("agent-memory-forget-confirm-mem_a"));

      expect((await screen.findByTestId("agent-memory-forget-error")).textContent).toContain(
        "Memory not found",
      );
    });
  });

  // --- SEMANTIC SEARCH --------------------------------------------------- //

  describe("search", () => {
    it("sends the query to the server and reports the mode that answered", async () => {
      recallMemories.mockResolvedValue({
        items: [makeMemory({ id: "mem_a" })],
        total: 1,
        mode: "semantic",
      });
      render(<AgentMemoryPanel />);
      await screen.findByTestId("agent-memory-list");

      fireEvent.change(screen.getByTestId("agent-memory-search"), {
        target: { value: "lateral movement on finance hosts" },
      });
      fireEvent.submit(screen.getByTestId("agent-memory-search-form"));

      await waitFor(() =>
        expect(recallMemories).toHaveBeenLastCalledWith({
          subject: undefined,
          kind: undefined,
          query: "lateral movement on finance hosts",
          limit: 50,
        }),
      );
      await waitFor(() =>
        expect(screen.getByTestId("agent-memory-mode").textContent).toContain("semantic"),
      );
    });

    it("does not embed on every keystroke — only on submit", async () => {
      render(<AgentMemoryPanel />);
      await screen.findByTestId("agent-memory-list");
      const before = recallMemories.mock.calls.length;

      fireEvent.change(screen.getByTestId("agent-memory-search"), {
        target: { value: "beaconing" },
      });

      expect(recallMemories.mock.calls.length).toBe(before);
    });

    it("distinguishes 'nothing similar' from 'nothing recorded'", async () => {
      recallMemories.mockResolvedValue({ items: [], total: 0, mode: "semantic" });
      render(<AgentMemoryPanel />);
      fireEvent.change(await screen.findByTestId("agent-memory-search"), {
        target: { value: "kerberoasting" },
      });
      fireEvent.submit(screen.getByTestId("agent-memory-search-form"));

      await waitFor(() =>
        expect(screen.getByTestId("agent-memory-empty").textContent).toContain(
          "semantically close",
        ),
      );
    });
  });

  // --- PROVENANCE -------------------------------------------------------- //

  describe("provenance", () => {
    it("marks an auto-captured fact and links back to its investigation", async () => {
      recallMemories.mockResolvedValue({
        items: [makeMemory({ id: "mem_a", source: "inv_abc123" })],
        total: 1,
        mode: "recency",
      });
      render(<AgentMemoryPanel />);

      expect((await screen.findByTestId("agent-memory-origin-mem_a")).textContent).toContain(
        "auto-captured",
      );
      const link = screen.getByTestId("agent-memory-source-link-mem_a");
      expect(link.getAttribute("href")).toBe("/investigations/inv_abc123");
    });

    it("marks a hand-entered fact as analyst-entered and does not fake a link", async () => {
      recallMemories.mockResolvedValue({
        items: [makeMemory({ id: "mem_a", source: "analyst" })],
        total: 1,
        mode: "recency",
      });
      render(<AgentMemoryPanel />);

      expect((await screen.findByTestId("agent-memory-origin-mem_a")).textContent).toContain(
        "analyst-entered",
      );
      expect(screen.queryByTestId("agent-memory-source-link-mem_a")).toBeNull();
    });

    it("shows when the fact was last updated, not only that it exists", async () => {
      render(<AgentMemoryPanel />);
      expect((await screen.findByTestId("agent-memory-mem_a")).textContent).toContain("updated");
    });
  });
});
