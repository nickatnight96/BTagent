/**
 * Unit tests for the real-time TLP-violation alerter (EPIC-7 UC-7.2).
 *
 * The global WS client is mocked with the SAME registration-list surface the
 * real client exposes: `onEvent(handler)` registers and returns an unsubscribe
 * handle. `sonner`'s `toast` is stubbed so we can assert the error toast fires
 * with the humanised block message.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { EventType } from "@/types/events";
import type { AgentEvent } from "@/types/events";

type Handler = (ev: AgentEvent) => void;

const listeners = new Set<Handler>();
const fakeWs = {
  onEvent(handler: Handler): () => void {
    listeners.add(handler);
    return () => {
      listeners.delete(handler);
    };
  },
};
function emit(ev: AgentEvent): void {
  for (const fn of [...listeners]) fn(ev);
}

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
  listeners.clear();
  toastError.mockReset();
});

afterEach(() => {
  vi.clearAllMocks();
});

describe("useTlpViolationAlerts", () => {
  it("fires an error toast on a TLP violation event", () => {
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      emit(
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
      emit(violationEvent({}));
    });

    expect(toastError).toHaveBeenCalledWith(
      "Blocked TLP:CLASSIFIED egress via egress",
      expect.objectContaining({ description: undefined }),
    );
  });

  it("ignores non-violation events", () => {
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      emit({
        ...violationEvent({}),
        type: EventType.HUNT_FINDING_CREATED,
      });
    });

    expect(toastError).not.toHaveBeenCalled();
  });

  it("coexists with other subscribers instead of replacing them", () => {
    const other = vi.fn();
    fakeWs.onEvent(other);
    renderHook(() => useTlpViolationAlerts());

    act(() => {
      emit(violationEvent({ tlp: "red" }));
    });

    expect(other).toHaveBeenCalledTimes(1);
    expect(toastError).toHaveBeenCalledTimes(1);
  });

  it("deregisters only its own handler on unmount", () => {
    const other = vi.fn();
    fakeWs.onEvent(other);
    const { unmount } = renderHook(() => useTlpViolationAlerts());
    expect(listeners.size).toBe(2);

    unmount();

    expect(listeners.size).toBe(1);
    act(() => {
      emit(violationEvent({ tlp: "red" }));
    });
    expect(other).toHaveBeenCalledTimes(1);
    expect(toastError).not.toHaveBeenCalled();
  });
});
