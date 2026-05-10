import { create } from "zustand";
import type { AgentEvent } from "@/types/events";

interface EventState {
  // Events per investigation, keyed by investigation ID
  events: Map<string, AgentEvent[]>;
  // Seen event IDs per investigation for deduplication
  seenIds: Map<string, Set<string>>;
  // Pending events for batched flushing
  _pendingEvents: Map<string, AgentEvent[]>;
  _flushTimer: ReturnType<typeof setTimeout> | null;

  pushEvent: (event: AgentEvent) => void;
  getEvents: (investigationId: string) => AgentEvent[];
  clearEvents: (investigationId: string) => void;
  clearAll: () => void;
}

const FLUSH_INTERVAL_MS = 50;

// Stable empty-array sentinel for ``getEvents`` fallbacks. Returning a fresh
// ``[]`` literal each call breaks Zustand's referential equality — the
// selector's snapshot value differs on every store-state read, React detects
// "getSnapshot should be cached to avoid an infinite loop" (error #185), and
// the workspace tab where ``EventStream`` mounts crashes. Returning this
// frozen sentinel keeps the reference stable across calls before any events
// arrive for an investigation.
const EMPTY_EVENTS: readonly AgentEvent[] = Object.freeze([]);

export const useEventStore = create<EventState>((set, get) => ({
  events: new Map(),
  seenIds: new Map(),
  _pendingEvents: new Map(),
  _flushTimer: null,

  pushEvent: (event: AgentEvent) => {
    const state = get();
    const { investigation_id: invId, id: eventId } = event;

    // Check for duplicate
    const seenSet = state.seenIds.get(invId);
    if (seenSet?.has(eventId)) return;

    // Mark as seen
    const newSeenIds = new Map(state.seenIds);
    const seen = newSeenIds.get(invId) ?? new Set<string>();
    seen.add(eventId);
    newSeenIds.set(invId, seen);

    // Add to pending buffer
    const newPending = new Map(state._pendingEvents);
    const pending = newPending.get(invId) ?? [];
    pending.push(event);
    newPending.set(invId, pending);

    // Schedule flush if not already scheduled
    let timer = state._flushTimer;
    if (!timer) {
      timer = setTimeout(() => {
        const current = get();
        const pendingMap = current._pendingEvents;

        if (pendingMap.size === 0) {
          set({ _flushTimer: null });
          return;
        }

        const newEvents = new Map(current.events);
        for (const [id, pendingList] of pendingMap) {
          const existing = newEvents.get(id) ?? [];
          newEvents.set(id, [...existing, ...pendingList]);
        }

        set({
          events: newEvents,
          _pendingEvents: new Map(),
          _flushTimer: null,
        });
      }, FLUSH_INTERVAL_MS);
    }

    set({ seenIds: newSeenIds, _pendingEvents: newPending, _flushTimer: timer });
  },

  getEvents: (investigationId: string) => {
    return get().events.get(investigationId) ?? (EMPTY_EVENTS as AgentEvent[]);
  },

  clearEvents: (investigationId: string) => {
    set((state) => {
      const newEvents = new Map(state.events);
      const newSeenIds = new Map(state.seenIds);
      newEvents.delete(investigationId);
      newSeenIds.delete(investigationId);
      return { events: newEvents, seenIds: newSeenIds };
    });
  },

  clearAll: () => {
    const state = get();
    if (state._flushTimer) clearTimeout(state._flushTimer);
    set({
      events: new Map(),
      seenIds: new Map(),
      _pendingEvents: new Map(),
      _flushTimer: null,
    });
  },
}));
