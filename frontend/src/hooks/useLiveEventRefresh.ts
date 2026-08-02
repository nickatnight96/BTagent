/**
 * Live-refresh hook over the global WebSocket client (#116/#120 Phase C
 * follow-up — replaces bare 30 s polling on the hunt pages).
 *
 * Extracted from HuntTriagePage's proven inline effect so all hunt surfaces
 * share one implementation:
 *
 * - Registers a handler on the global WS client (via the client's
 *   multi-subscriber registration list, so any number of consumers can be
 *   live at once) and schedules a refetch when any of the given event types
 *   arrives.
 * - Debounces refetches (1 s) so an event burst becomes one API call.
 * - Refreshes on tab visibility change (catching up after an absence).
 * - Keeps a polling safety net regardless of WS connectivity; when the WS
 *   client is unavailable (tests, SSR) it degrades to polling only.
 *
 * The `refetch` callback must be referentially stable (`useCallback`) or the
 * subscription will churn on every render.
 */

import { useCallback, useEffect, useRef } from "react";
import { getWSClient } from "@/api/ws";
import type { EventType } from "@/types/events";

const DEBOUNCE_MS = 1_000;
const DEFAULT_POLL_INTERVAL_MS = 30_000;

export function useLiveEventRefresh(
  refetch: () => void,
  eventTypes: readonly EventType[],
  { pollIntervalMs = DEFAULT_POLL_INTERVAL_MS }: { pollIntervalMs?: number } = {},
): void {
  const refetchTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const scheduleRefetch = useCallback(() => {
    if (refetchTimerRef.current) return;
    refetchTimerRef.current = setTimeout(() => {
      refetchTimerRef.current = null;
      refetch();
    }, DEBOUNCE_MS);
  }, [refetch]);

  // Stable membership check without re-subscribing when the caller passes a
  // fresh array literal each render.
  const typesRef = useRef<ReadonlySet<EventType>>(new Set(eventTypes));
  // Updated in an effect, not during render (react-hooks/refs): the
  // subscription handler reads the ref at event time, so an after-commit
  // update is exactly as fresh, without the render-phase write.
  useEffect(() => {
    typesRef.current = new Set(eventTypes);
  });

  useEffect(() => {
    let pollTimer: ReturnType<typeof setInterval> | null = null;

    const clearAll = () => {
      if (pollTimer) clearInterval(pollTimer);
      if (refetchTimerRef.current) {
        clearTimeout(refetchTimerRef.current);
        refetchTimerRef.current = null;
      }
    };

    try {
      const ws = getWSClient();
      // Registration list, not a save/restore of a single shared slot: our
      // cleanup deregisters exactly our own handler and cannot unhook another
      // live consumer regardless of mount/unmount ordering (GH #390).
      const unsubscribe = ws.onEvent((ev) => {
        if (typesRef.current.has(ev.type)) {
          scheduleRefetch();
        }
      });

      const handleVisibility = () => scheduleRefetch();
      window.addEventListener("visibilitychange", handleVisibility);

      pollTimer = setInterval(() => {
        if (document.visibilityState === "visible") {
          scheduleRefetch();
        }
      }, pollIntervalMs);

      return () => {
        unsubscribe();
        window.removeEventListener("visibilitychange", handleVisibility);
        clearAll();
      };
    } catch {
      // WS unavailable (SSR, test env, etc.) — polling only.
      pollTimer = setInterval(() => scheduleRefetch(), pollIntervalMs);
      return clearAll;
    }
  }, [scheduleRefetch, pollIntervalMs]);
}
