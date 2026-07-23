/**
 * Unit tests for the real-time TLP-violation alerter (EPIC-7 UC-7.2).
 *
 * The global WS client is mocked with a mutable ``onEvent`` slot (the same
 * surface the real client exposes), and ``sonner``'s ``toast`` is stubbed so we
 * can assert the error toast fires with the humanised block message.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { EventType } from "@/types/events";
import type { AgentEvent } from "@/types/events";

const fakeWs: { onEvent: (ev: AgentEvent) => void } = {
  onEvent: () => {},
};

vi.mock("@/api/ws", () => ({
  getWSClient: () => fakeWs,
}));

const toastError = vi.fn();
vi.mock("sonner", () => ({
  toast: { error: (...args: unknown[]) => toastError(...args) },
}));

import { useTlpViolationAlerts } from "@/components/governance/TlpViolationAlerts";

function violationEvent(data: Record<string, unknown>): AgentEvent {
  return {
    id: "evt_1",
    type: EventType.TLP_VIOLATION_ATTEMPT,
    investigation_id: "inv_1",
    timestamp: "2026-07-23T00:00:00Z",
    data,
  };
}

beforeEach(() => {
  fakeWs.onEvent = () => {};
  toastError.mockReset();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("useTlpViolationAlerts", () => {
  it("fires an error toast on a TLP violation event", () => {
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      fakeWs.onEvent(
        violationEvent({
          tlp: "red",
          egress_kind: "cloud_llm",
          reason: "TLP:RED never leaves the tenant",
        }),
      );
    });

    expect(toastError).toHaveBeenCalledTimes(1);
    expect(toastError).toHaveBeenCalledWith(
      "Blocked TLP:RED egress via cloud_llm",
      expect.objectContaining({
        description: "TLP:RED never leaves the tenant",
      }),
    );
  });

  it("degrades gracefully when the payload is sparse", () => {
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      fakeWs.onEvent(violationEvent({}));
    });

    expect(toastError).toHaveBeenCalledWith(
      "Blocked TLP:CLASSIFIED egress via egress",
      expect.objectContaining({ description: undefined }),
    );
  });

  it("ignores non-violation events", () => {
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      fakeWs.onEvent({
        ...violationEvent({}),
        type: EventType.HUNT_FINDING_CREATED,
      });
    });

    expect(toastError).not.toHaveBeenCalled();
  });

  it("chains the previous onEvent so other consumers keep working", () => {
    const previous = vi.fn();
    fakeWs.onEvent = previous;
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      fakeWs.onEvent(violationEvent({ tlp: "red" }));
    });

    expect(previous).toHaveBeenCalledTimes(1);
  });

  it("restores the previous onEvent on unmount", () => {
    const previous = vi.fn();
    fakeWs.onEvent = previous;
    const { unmount } = renderHook(() => useTlpViolationAlerts());
    expect(fakeWs.onEvent).not.toBe(previous);
    unmount();
    expect(fakeWs.onEvent).toBe(previous);
  });
});
