/**
 * Unit tests for the shared live-refresh hook (WS upgrade for the hunt pages).
 *
 * The global WS client is mocked with the SAME registration-list surface the
 * real client exposes: `onEvent(handler)` registers and returns an unsubscribe
 * handle. (It used to be a single mutable `onEvent` slot with a save/restore
 * dance — see the non-LIFO test below for why that had to go.) Fake timers
 * drive the debounce and the polling safety net.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";
import { EventType } from "@/types/events";

type Handler = (ev: { type: EventType }) => void;

const listeners = new Set<Handler>();
const fakeWs = {
  onEvent(handler: Handler): () => void {
    listeners.add(handler);
    return () => {
      listeners.delete(handler);
    };
  },
};
function emit(ev: { type: EventType }): void {
  for (const fn of [...listeners]) fn(ev);
}
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
  // `hunt_finding_triaged` is the real backend event; the frontend enum used
  // to spell it `hunt_finding_updated`, which nothing emitted.
  EventType.HUNT_FINDING_TRIAGED,
] as const;

beforeEach(() => {
  vi.useFakeTimers();
  wsAvailable = true;
  listeners.clear();
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
      emit({ type: EventType.HUNT_FINDING_CREATED });
      emit({ type: EventType.HUNT_FINDING_TRIAGED });
      emit({ type: EventType.HUNT_FINDING_CREATED });
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
      emit({ type: EventType.HUNT_FINDING_PROMOTED });
      vi.advanceTimersByTime(2_000);
    });
    expect(refetch).not.toHaveBeenCalled();
  });

  it("coexists with other subscribers instead of replacing them", () => {
    const other = vi.fn();
    fakeWs.onEvent(other);
    const refetch = vi.fn();
    renderHook(() => useLiveEventRefresh(refetch, HUNT_EVENTS));

    act(() => {
      emit({ type: EventType.HUNT_FINDING_CREATED });
      vi.advanceTimersByTime(1_100);
    });
    expect(other).toHaveBeenCalledTimes(1);
    expect(refetch).toHaveBeenCalledTimes(1);
  });

  it("deregisters only its own handler on unmount", () => {
    const other = vi.fn();
    fakeWs.onEvent(other);
    const { unmount } = renderHook(() =>
      useLiveEventRefresh(vi.fn(), HUNT_EVENTS),
    );
    expect(listeners.size).toBe(2);

    unmount();

    expect(listeners.size).toBe(1);
    act(() => {
      emit({ type: EventType.HUNT_FINDING_CREATED });
    });
    expect(other).toHaveBeenCalledTimes(1);
  });

  it("survives NON-LIFO subscriber teardown (the GH #390 bug class)", () => {
    // Register the hook FIRST, then a later subscriber, then tear the hook
    // down while the later one is still live. Under the old save-prev /
    // restore-prev contract this rolled `onEvent` back to a handler captured
    // before the later subscriber existed, silently unhooking it for the rest
    // of the session. With a registration list, ordering is irrelevant.
    const refetch = vi.fn();
    const { unmount } = renderHook(() =>
      useLiveEventRefresh(refetch, HUNT_EVENTS),
    );
    const later = vi.fn();
    fakeWs.onEvent(later);

    unmount();

    act(() => {
      emit({ type: EventType.HUNT_FINDING_CREATED });
      vi.advanceTimersByTime(1_100);
    });
    expect(later).toHaveBeenCalledTimes(1);
    expect(refetch).not.toHaveBeenCalled();
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
