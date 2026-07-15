/**
 * Unit tests for the shared live-refresh hook (WS upgrade for the hunt pages).
 *
 * The global WS client is mocked with a mutable ``onEvent`` slot (the same
 * surface the real client exposes); fake timers drive the debounce and the
 * polling safety net.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { EventType } from "@/types/events";

const fakeWs: { onEvent: (ev: { type: EventType }) => void } = {
  onEvent: () => {},
};
let wsAvailable = true;

vi.mock("@/api/ws", () => ({
  getWSClient: () => {
    if (!wsAvailable) throw new Error("ws unavailable");
    return fakeWs;
  },
}));

import { useLiveEventRefresh } from "@/hooks/useLiveEventRefresh";

const HUNT_EVENTS = [
  EventType.HUNT_FINDING_CREATED,
  EventType.HUNT_FINDING_UPDATED,
] as const;

beforeEach(() => {
  vi.useFakeTimers();
  wsAvailable = true;
  fakeWs.onEvent = () => {};
});

afterEach(() => {
  vi.useRealTimers();
  vi.clearAllMocks();
});

describe("useLiveEventRefresh", () => {
  it("refetches (debounced) when a matching event arrives", () => {
    const refetch = vi.fn();
    renderHook(() => useLiveEventRefresh(refetch, HUNT_EVENTS));

    act(() => {
      fakeWs.onEvent({ type: EventType.HUNT_FINDING_CREATED });
      fakeWs.onEvent({ type: EventType.HUNT_FINDING_UPDATED });
      fakeWs.onEvent({ type: EventType.HUNT_FINDING_CREATED });
    });
    expect(refetch).not.toHaveBeenCalled();

    act(() => {
      vi.advanceTimersByTime(1_100);
    });
    // A burst of three events collapses into one refetch.
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("ignores non-matching events", () => {
    const refetch = vi.fn();
    renderHook(() => useLiveEventRefresh(refetch, HUNT_EVENTS));

    act(() => {
      fakeWs.onEvent({ type: EventType.HUNT_FINDING_PROMOTED });
      vi.advanceTimersByTime(2_000);
    });
    expect(refetch).not.toHaveBeenCalled();
  });

  it("chains the previous onEvent so other consumers keep working", () => {
    const previous = vi.fn();
    fakeWs.onEvent = previous;
    const refetch = vi.fn();
    renderHook(() => useLiveEventRefresh(refetch, HUNT_EVENTS));

    act(() => {
      fakeWs.onEvent({ type: EventType.HUNT_FINDING_CREATED });
    });
    expect(previous).toHaveBeenCalledTimes(1);
  });

  it("restores the previous onEvent on unmount", () => {
    const previous = vi.fn();
    fakeWs.onEvent = previous;
    const { unmount } = renderHook(() => useLiveEventRefresh(vi.fn(), HUNT_EVENTS));
    expect(fakeWs.onEvent).not.toBe(previous);
    unmount();
    expect(fakeWs.onEvent).toBe(previous);
  });

  it("keeps the polling safety net", () => {
    const refetch = vi.fn();
    renderHook(() =>
      useLiveEventRefresh(refetch, HUNT_EVENTS, { pollIntervalMs: 5_000 }),
    );

    act(() => {
      vi.advanceTimersByTime(5_000 + 1_100); // poll tick + debounce
    });
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("falls back to polling when the WS client is unavailable", () => {
    wsAvailable = false;
    const refetch = vi.fn();
    renderHook(() =>
      useLiveEventRefresh(refetch, HUNT_EVENTS, { pollIntervalMs: 5_000 }),
    );

    act(() => {
      vi.advanceTimersByTime(5_000 + 1_100);
    });
    expect(refetch).toHaveBeenCalledTimes(1);
  });
});
