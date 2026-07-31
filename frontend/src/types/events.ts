export enum EventType {
  // Agent lifecycle
  AGENT_STARTED = "agent_started",
  AGENT_COMPLETED = "agent_completed",
  AGENT_ERROR = "agent_error",

  // Tool events
  TOOL_START = "tool_start",
  TOOL_END = "tool_end",
  TOOL_ERROR = "tool_error",

  // Investigation events
  IOC_DISCOVERED = "ioc_discovered",
  TIMELINE_ENTRY = "timeline_entry",
  CONTAINMENT_PROPOSED = "containment_proposed",
  CONTAINMENT_EXECUTED = "containment_executed",

  // Chat / streaming. Wire names come from the agents-side emitter
  // (shared/btagent_shared/types/events.py): OUTPUT_CHUNK carries
  // ``data.text`` per token, OUTPUT is the finalized answer from
  // ``on_llm_end`` — there is no "message_complete" on the wire (that name
  // was never emitted by anything; streaming finalization was dead until
  // this was aligned).
  OUTPUT_CHUNK = "output_chunk",
  OUTPUT = "output",

  // Cost / token accounting (prompt-budget hook).
  TOKEN_USAGE = "token_usage",

  // HITL. The checkpoint event's wire name is "hitl_checkpoint"
  // (EventType.HITL_CHECKPOINT in shared) — "hitl_requested" was a
  // frontend-only name no emitter ever used.
  HITL_CHECKPOINT = "hitl_checkpoint",
  HITL_RESPONSE = "hitl_response",
  HITL_TIMEOUT = "hitl_timeout",

  // Status changes
  STATUS_CHANGED = "status_changed",
  COST_UPDATE = "cost_update",

  // System
  HEARTBEAT = "heartbeat",
  ERROR = "error",

  // Hunt triage (Phase 6 #119)
  HUNT_FINDING_CREATED = "hunt_finding_created",
  HUNT_FINDING_UPDATED = "hunt_finding_updated",
  HUNT_FINDING_SUPPRESSED = "hunt_finding_suppressed",
  HUNT_FINDING_PROMOTED = "hunt_finding_promoted",

  // Behavioral Hunter (#114) — a baseline deviation was detected. Payload is
  // entity/score metadata only; the page refetches through the RBAC-scoped API.
  BEHAVIORAL_OUTLIER_DETECTED = "behavioral_outlier_detected",

  // Governance / classification (EPIC-7 UC-7.2) — real-time egress-block alert
  TLP_VIOLATION_ATTEMPT = "tlp.violation_attempt",
}

export interface AgentEvent {
  id: string;
  type: EventType;
  investigation_id: string;
  timestamp: string;
  data: Record<string, unknown>;
}

export interface EventEnvelope {
  event_id: string;
  event_type: EventType;
  investigation_id: string;
  timestamp: string;
  payload: Record<string, unknown>;
}

export function envelopeToEvent(envelope: EventEnvelope): AgentEvent {
  return {
    id: envelope.event_id,
    type: envelope.event_type,
    investigation_id: envelope.investigation_id,
    timestamp: envelope.timestamp,
    data: envelope.payload,
  };
}
