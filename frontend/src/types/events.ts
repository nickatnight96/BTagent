/**
 * WebSocket event types — the browser side of the wire contract.
 *
 * `EventType` / `EventEnvelope` / `ClientMessageType` / `ServerMessageType` are
 * NOT declared here: they are re-exported from `events.generated.ts`, which
 * mirrors `shared/btagent_shared/types/events.py` and
 * `backend/btagent_backend/ws/protocol.py` and is regenerated from the live
 * Python types (see backend/tests/test_ws_contract.py). Adding a hand-written
 * member here is exactly how the two sides drifted apart before — the frontend
 * enum grew `hitl_requested` / `message_complete` / `status_changed` /
 * `timeline_entry` / `hunt_finding_updated`, none of which any Python enum
 * member has ever emitted, and every handler for them was dead code.
 *
 * `AgentEvent` below is the app-facing view. It stays deliberately close to the
 * wire shape — `envelopeToEvent` is now an identity-ish narrowing, not a
 * renaming — so a future field addition can't silently decode to `undefined`.
 */

export {
  EventType,
  ClientMessageType,
  ServerMessageType,
} from "./events.generated";
export type { EventEnvelope, ClientMessage } from "./events.generated";

import type { EventType as EventTypeT, EventEnvelope } from "./events.generated";

/** An event as consumed by stores/components. */
export interface AgentEvent {
  id: string;
  type: EventTypeT;
  investigation_id: string;
  timestamp: string;
  data: Record<string, unknown>;
  parent_id?: string | null;
  trace_id?: string | null;
}

/**
 * Narrow a raw wire envelope to an `AgentEvent`.
 *
 * The wire keys are the unaliased Python attribute names — `id`, `type`,
 * `data`. This function previously read `event_id` / `event_type` / `payload`,
 * which do not exist on the wire, so EVERY field decoded to `undefined`.
 */
export function envelopeToEvent(envelope: EventEnvelope): AgentEvent {
  return {
    id: envelope.id,
    type: envelope.type,
    investigation_id: envelope.investigation_id,
    timestamp: envelope.timestamp,
    data: envelope.data ?? {},
    parent_id: envelope.parent_id ?? null,
    trace_id: envelope.trace_id ?? null,
  };
}

/**
 * True when a decoded frame is a real `EventEnvelope` rather than a
 * protocol-level `ServerMessage` (`{type, data}`).
 *
 * Needed because `EventType.NOTIFICATION` and `ServerMessageType.NOTIFICATION`
 * share the literal `"notification"`: only the envelope carries `id` and
 * `investigation_id`.
 */
export function isEventEnvelope(value: unknown): value is EventEnvelope {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return typeof v.id === "string" && typeof v.investigation_id === "string";
}
