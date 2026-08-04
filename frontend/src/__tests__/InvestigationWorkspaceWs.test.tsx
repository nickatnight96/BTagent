/**
 * InvestigationWorkspace ↔ WebSocket wiring.
 *
 * Supersedes InvestigationWorkspaceWsChaining.test.tsx, which pinned the old
 * save-prev / call-prev / restore-prev "chaining" contract on a single mutable
 * `onEvent` slot. That contract is only correct when consumer lifetimes are
 * strictly LIFO, and a non-LIFO teardown silently unhooked a live consumer —
 * the GH #390 bug class. The client now exposes a registration list, so this
 * file pins the stronger invariants:
 *
 *  1. the workspace coexists with other subscribers (TlpViolationAlerts, which
 *     the persistent Layout shell mounts) in either mount order, and its
 *     unmount deregisters only its own handler;
 *  2. its `investigation_id` guard gates only its own logic;
 *  3. it SUBSCRIBES the connection to the investigation's channel on mount and
 *     unsubscribes on unmount — without which the hub delivers no agent events
 *     to this browser at all (RedisEmitter publishes only to
 *     `btagent:events:{investigation_id}`);
 *  4. it does NOT open the socket — the Layout shell owns that lifecycle.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { render, cleanup, act } from "@testing-library/react";
import { MemoryRouter, Routes, Route } from "react-router";
import { EventType } from "@/types/events";
import type { AgentEvent } from "@/types/events";
import { UserRole } from "@/types/config";

type Handler = (ev: AgentEvent) => void;

const listeners = new Set<Handler>();
const subscribedChannels: string[] = [];
const unsubscribedChannels: string[] = [];
const connectSpy = vi.fn();

type DisconnectHandler = (code: number, reason: string) => void;
const disconnectListeners = new Set<DisconnectHandler>();

const fakeWs = {
  onEvent(handler: Handler): () => void {
    listeners.add(handler);
    return () => {
      listeners.delete(handler);
    };
  },
  onDisconnect(handler: DisconnectHandler): () => void {
    disconnectListeners.add(handler);
    return () => {
      disconnectListeners.delete(handler);
    };
  },
  subscribeToInvestigation(id: string): () => void {
    subscribedChannels.push(id);
    return () => {
      unsubscribedChannels.push(id);
    };
  },
  isConnected: true,
  isTerminallyClosed: false,
  connect: connectSpy,
};

function emit(ev: AgentEvent): void {
  for (const fn of [...listeners]) fn(ev);
}

/** Drive a server-side close, the way `ws.ts` notifies its listeners. */
function emitClose(code: number, reason = ""): void {
  for (const fn of [...disconnectListeners]) fn(code, reason);
}

vi.mock("@/api/ws", () => ({
  getWSClient: () => fakeWs,
  // Mirrors the real export. Kept as the actual value rather than a stub so a
  // change to which codes are terminal is reflected here without editing.
  TERMINAL_CLOSE_CODES: new Set([4404, 1008]),
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
import { useAgentStore } from "@/stores/agentStore";
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
    // prove the workspace's `investigation_id` guard is local and never
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
  listeners.clear();
  disconnectListeners.clear();
  subscribedChannels.length = 0;
  unsubscribedChannels.length = 0;
  connectSpy.mockReset();
  fakeWs.isConnected = true;
  fakeWs.isTerminallyClosed = false;
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

describe("InvestigationWorkspace WS subscriber registration", () => {
  it("keeps the TLP alerter alive after the workspace mounts and unmounts", () => {
    // 1. The persistent shell registers the TLP alerter FIRST.
    render(<TlpHost />);

    // 2. A user opens an investigation, then leaves it (mount + unmount).
    const { unmount } = renderWorkspace();
    unmount();

    // 3. A TLP:RED egress-violation event arrives after they left.
    act(() => {
      emit(violationEvent());
    });

    expect(toastError).toHaveBeenCalledTimes(1);
  });

  it("keeps a LATER subscriber alive too (non-LIFO teardown)", () => {
    // Reverse order: the workspace registers first, the alerter after. Under
    // the old save/restore contract the workspace's unmount would roll the
    // single handler slot back to a snapshot taken before the alerter existed,
    // killing it for the rest of the session.
    const { unmount } = renderWorkspace();
    render(<TlpHost />);

    unmount();

    act(() => {
      emit(violationEvent());
    });

    expect(toastError).toHaveBeenCalledTimes(1);
  });

  it("forwards events to other subscribers while mounted, even for another investigation", () => {
    render(<TlpHost />);
    renderWorkspace();

    act(() => {
      emit(violationEvent());
    });

    expect(toastError).toHaveBeenCalledTimes(1);
  });

  it("subscribes to the investigation channel on mount and unsubscribes on unmount", () => {
    const { unmount } = renderWorkspace();
    expect(subscribedChannels).toEqual(["inv_1"]);

    unmount();
    expect(unsubscribedChannels).toEqual(["inv_1"]);
  });

  it("does not open the socket itself — the Layout shell owns that", () => {
    fakeWs.isConnected = false;
    renderWorkspace();
    expect(connectSpy).not.toHaveBeenCalled();
    // ...but it still subscribes, so the subscription is replayed once the
    // session-scoped socket comes up.
    expect(subscribedChannels).toEqual(["inv_1"]);
  });
});

// --------------------------------------------------------------------------- //
// Live event contract — the payloads the agents-side hooks actually emit
// --------------------------------------------------------------------------- //

function agentEvent(
  type: EventType,
  data: Record<string, unknown>,
  id = "evt_stream_1",
): AgentEvent {
  return {
    id,
    type,
    investigation_id: "inv_1",
    timestamp: "2026-07-31T00:00:00Z",
    data,
  };
}

describe("InvestigationWorkspace applies the emitted event contract", () => {
  beforeEach(() => {
    useAgentStore.setState({
      messages: [],
      pendingCheckpoints: [],
      isStreaming: false,
      streamingContent: "",
      investigationId: "inv_1",
    });
  });

  it("streams output_chunk data.text and finalizes on output data.text", () => {
    renderWorkspace();

    // event_emitter_hook.on_llm_new_token → { text, index }.
    act(() => {
      emit(agentEvent(EventType.OUTPUT_CHUNK, { text: "Two ", index: 1 }));
      emit(agentEvent(EventType.OUTPUT_CHUNK, { text: "IPs.", index: 2 }));
    });
    expect(useAgentStore.getState().streamingContent).toBe("Two IPs.");

    // event_emitter_hook.on_llm_end → { text, run_id }.
    act(() => {
      emit(
        agentEvent(EventType.OUTPUT, { text: "Two IPs.", run_id: "r1" }, "evt_final"),
      );
    });

    const state = useAgentStore.getState();
    expect(state.streamingContent).toBe("");
    expect(state.messages).toHaveLength(1);
    expect(state.messages[0]).toMatchObject({
      id: "evt_final",
      role: "assistant",
      content: "Two IPs.",
    });
  });

  it("adds a pending checkpoint from a hitl_checkpoint event", () => {
    renderWorkspace();

    // hitl_hook → { checkpoint_id, tool_name, tool_input, message, ... }.
    act(() => {
      emit(
        agentEvent(EventType.HITL_CHECKPOINT, {
          checkpoint_id: "cp_1",
          tool_name: "cs_isolate_host",
          tool_input: '{"host": "web-01"}',
          message: "Tool 'cs_isolate_host' requires human approval before execution.",
        }),
      );
    });

    const checkpoints = useAgentStore.getState().pendingCheckpoints;
    expect(checkpoints).toHaveLength(1);
    expect(checkpoints[0]).toMatchObject({
      id: "cp_1",
      investigation_id: "inv_1",
      prompt: "Tool 'cs_isolate_host' requires human approval before execution.",
    });
  });

  it("ignores streaming events for other investigations", () => {
    renderWorkspace();

    act(() => {
      emit({
        ...agentEvent(EventType.OUTPUT_CHUNK, { text: "leak", index: 1 }),
        investigation_id: "inv_other",
      });
    });

    expect(useAgentStore.getState().streamingContent).toBe("");
  });
});

/**
 * A refusal is visible, not silent.
 *
 * `ws/access.py` closes an unauthorized subscribe with 4404 (1008 as the
 * transport fallback), and the client stops retrying on those — correct, but
 * on its own it means the page simply stops updating, which looks exactly
 * like a network blip. `isTerminallyClosed` shipped with no consumer; this is
 * the consumer, and these tests are what stop it from silently regressing to
 * one again.
 */
describe("InvestigationWorkspace — refused event stream", () => {
  it.each([
    [4404, "not found"],
    [1008, "policy violation"],
  ])("shows the banner after a %i close", (code, reason) => {
    const { queryByTestId } = renderWorkspace();
    expect(queryByTestId("workspace-stream-refused")).toBeNull();

    act(() => {
      emitClose(code, reason);
    });

    const banner = queryByTestId("workspace-stream-refused");
    expect(banner).not.toBeNull();
    expect(banner?.getAttribute("role")).toBe("alert");
    expect(banner?.textContent).toMatch(/no longer have access/i);
  });

  it.each([
    [1006, "abnormal"],
    [1011, "server error"],
    [1000, "server hung up"],
  ])("stays quiet after a retryable %i close", (code, reason) => {
    // These reconnect on their own; a scary banner during a blip is worse
    // than no banner, because it teaches analysts to ignore it.
    const { queryByTestId } = renderWorkspace();

    act(() => {
      emitClose(code, reason);
    });

    expect(queryByTestId("workspace-stream-refused")).toBeNull();
  });

  it("shows the banner on mount when the client was already refused", () => {
    // Navigating into a case on a client that is already latched — the
    // listener alone would never fire, because the close already happened.
    fakeWs.isTerminallyClosed = true;

    const { queryByTestId } = renderWorkspace();

    expect(queryByTestId("workspace-stream-refused")).not.toBeNull();
  });

  it("deregisters its disconnect handler on unmount", () => {
    const { unmount } = renderWorkspace();
    expect(disconnectListeners.size).toBe(1);

    unmount();

    expect(disconnectListeners.size).toBe(0);
  });
});
