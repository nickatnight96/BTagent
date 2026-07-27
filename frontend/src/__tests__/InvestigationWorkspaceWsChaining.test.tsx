/**
 * Regression test for GH #390 — InvestigationWorkspace must CHAIN the shared
 * WebSocket ``onEvent`` handler (save prev → call prev FIRST → restore prev on
 * cleanup) instead of clobbering it.
 *
 * The singleton WS client exposes a single ``onEvent`` slot. TlpViolationAlerts
 * is mounted once in the persistent Layout shell and registers the real-time
 * TLP:RED egress-violation alerter through the save-prev / call-prev / restore
 * contract. If the workspace bare-overwrites ``onEvent`` on mount and restores
 * a no-op on unmount, that alerter goes permanently dead for the session after
 * a user opens and then leaves any investigation. This test proves the alerter
 * survives a workspace mount+unmount cycle, and that its own investigation-id
 * guard never drops events destined for other subscribers.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";
import { EventType } from "@/types/events";
import type { AgentEvent } from "@/types/events";
import { UserRole } from "@/types/config";

// Shared fake WS singleton exposing the same public surface the workspace and
// the TLP alerter touch. ``isConnected`` is true so the effect never calls
// ``connect()`` (no jsdom WebSocket needed).
const fakeWs: {
  onEvent: (ev: AgentEvent) => void;
  onConnect: () => void;
  isConnected: boolean;
  connect: () => void;
} = {
  onEvent: () => {},
  onConnect: () => {},
  isConnected: true,
  connect: vi.fn(),
};

vi.mock("@/api/ws", () => ({
  getWSClient: () => fakeWs,
}));

// Observe the alerter's toast.
const toastError = vi.fn();
vi.mock("sonner", () => ({
  toast: { error: (...args: unknown[]) => toastError(...args) },
}));

// Keep the on-mount investigation fetch unresolved so the workspace stays in
// its lightweight loading state (no AgentChat / EventStream mounted).
vi.mock("@/api/investigations", () => ({
  getInvestigation: vi.fn(() => new Promise<never>(() => {})),
  listInvestigations: vi.fn(() => new Promise<never>(() => {})),
  pauseInvestigation: vi.fn(),
  resumeInvestigation: vi.fn(),
  stopInvestigation: vi.fn(),
}));

// Header drags in NotificationBell / ThemeToggle which are irrelevant here.
vi.mock("@/components/layout/Header", () => ({
  Header: ({ title }: { title: string }) => <div>{title}</div>,
}));

import { useTlpViolationAlerts } from "@/components/governance/TlpViolationAlerts";
import { InvestigationWorkspace } from "@/components/workspace/InvestigationWorkspace";
import { useAuthStore } from "@/stores/authStore";
import { useInvestigationStore } from "@/stores/investigationStore";

/** Headless host that registers the TLP alerter, like the Layout shell does. */
function TlpHost(): null {
  useTlpViolationAlerts();
  return null;
}

function violationEvent(): AgentEvent {
  return {
    id: "evt_1",
    type: EventType.TLP_VIOLATION_ATTEMPT,
    // Deliberately a DIFFERENT investigation than the mounted workspace, to
    // prove the workspace's ``investigation_id`` guard is local and never
    // drops events bound for other subscribers.
    investigation_id: "inv_other",
    timestamp: "2026-07-24T00:00:00Z",
    data: { tlp: "red", egress_kind: "cloud_llm" },
  };
}

function renderWorkspace() {
  return render(
    <MemoryRouter initialEntries={["/investigations/inv_1"]}>
      <Routes>
        <Route
          path="/investigations/:id"
          element={<InvestigationWorkspace />}
        />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  fakeWs.onEvent = () => {};
  fakeWs.isConnected = true;
  toastError.mockReset();
  // The workspace WS effect is gated on a hydrated user.
  useAuthStore.setState({
    user: { id: "usr_1", username: "amy", role: UserRole.ANALYST },
  });
  useInvestigationStore.setState({ currentInvestigation: null });
});

afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

describe("InvestigationWorkspace WS handler chaining (GH #390)", () => {
  it("keeps the TLP alerter alive after the workspace mounts and unmounts", () => {
    // 1. The persistent shell registers the TLP alerter FIRST.
    render(<TlpHost />);

    // 2. A user opens an investigation, then leaves it (mount + unmount).
    const { unmount } = renderWorkspace();
    unmount();

    // 3. A TLP:RED egress-violation event arrives after they left.
    act(() => {
      fakeWs.onEvent(violationEvent());
    });

    // The alerter must STILL fire: the workspace restored the chain rather
    // than clobbering it with a no-op on cleanup.
    expect(toastError).toHaveBeenCalledTimes(1);
  });

  it("forwards events to prior subscribers while mounted, even for another investigation", () => {
    render(<TlpHost />);
    renderWorkspace();

    // Event bound for a DIFFERENT investigation must still reach the alerter:
    // the workspace calls prev() unconditionally before applying its own
    // investigation_id guard.
    act(() => {
      fakeWs.onEvent(violationEvent());
    });

    expect(toastError).toHaveBeenCalledTimes(1);
  });
});
