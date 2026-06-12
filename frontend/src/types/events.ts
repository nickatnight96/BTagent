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

  // Chat / streaming
  OUTPUT_CHUNK = "output_chunk",
  MESSAGE_COMPLETE = "message_complete",

  // HITL
  HITL_REQUESTED = "hitl_requested",
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
