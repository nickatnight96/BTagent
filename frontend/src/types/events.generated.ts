/**
 * GENERATED FILE — do not hand-edit.
 *
 * Mirrors the Python wire contract:
 *   - `EventType`     <- shared/btagent_shared/types/events.py :: EventType
 *   - `EventEnvelope` <- shared/btagent_shared/types/events.py :: EventEnvelope
 *                        (exactly `EventEnvelope.model_dump_json()` — the hub
 *                        forwards that JSON verbatim, with NO aliasing)
 *   - `ClientMessageType` / `ClientMessage`
 *                     <- backend/btagent_backend/ws/protocol.py
 *
 * Drift is a test failure, in BOTH directions:
 *   - backend/tests/test_ws_contract.py re-derives the contract from the live
 *     Python types and diffs it against ws-contract.fixture.json;
 *   - frontend/src/__tests__/wsContract.test.ts diffs THIS file against that
 *     same fixture and round-trips a real `model_dump_json()` payload through
 *     the real WebSocketClient.
 *
 * To change the protocol: edit the Python types, then regenerate with
 *   BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py
 * and commit the regenerated fixture + this file together.
 */


export enum EventType {
  INVESTIGATION_INIT = "investigation_init",
  INVESTIGATION_COMPLETE = "investigation_complete",
  INVESTIGATION_FAILED = "investigation_failed",
  INVESTIGATION_PAUSED = "investigation_paused",
  INVESTIGATION_RESUMED = "investigation_resumed",
  THINKING = "thinking",
  OUTPUT = "output",
  OUTPUT_CHUNK = "output_chunk",
  OUTPUT_COMPLETE = "output_complete",
  STEP_HEADER = "step_header",
  AGENT_STATUS = "agent_status",
  TOOL_START = "tool_start",
  TOOL_END = "tool_end",
  TOOL_PROGRESS = "tool_progress",
  HITL_CHECKPOINT = "hitl_checkpoint",
  HITL_RESPONSE = "hitl_response",
  HITL_TIMEOUT = "hitl_timeout",
  IOC_DISCOVERED = "ioc_discovered",
  IOC_ENRICHED = "ioc_enriched",
  IOC_CROSS_MATCH = "ioc_cross_match",
  IOC_ENRICHMENT_STARTED = "ioc_enrichment_started",
  IOC_ENRICHMENT_COMPLETE = "ioc_enrichment_complete",
  ALERT_CLASSIFIED = "alert_classified",
  CONTAINMENT_PROPOSED = "containment_proposed",
  CONTAINMENT_APPROVED = "containment_approved",
  CONTAINMENT_EXECUTED = "containment_executed",
  EVIDENCE_COLLECTED = "evidence_collected",
  TIMELINE_UPDATED = "timeline_updated",
  QUERY_GENERATED = "query_generated",
  QUERY_RESULTS = "query_results",
  THREAT_ASSESSMENT_UPDATE = "threat_assessment_update",
  KNOWLEDGE_INDEXED = "knowledge_indexed",
  KNOWLEDGE_QUERIED = "knowledge_queried",
  TLP_VIOLATION_ATTEMPT = "tlp.violation_attempt",
  REPORT_GENERATION_STARTED = "report_generation_started",
  REPORT_GENERATION_COMPLETE = "report_generation_complete",
  REMEDIATION_GENERATED = "remediation_generated",
  PLAYBOOK_STARTED = "playbook_started",
  PLAYBOOK_STEP_COMPLETE = "playbook_step_complete",
  PLAYBOOK_COMPLETE = "playbook_complete",
  PLAYBOOK_FAILED = "playbook_failed",
  PLAYBOOK_HITL_GATE = "playbook_hitl_gate",
  HUNT_STARTED = "hunt_started",
  HUNT_RULE_FIRED = "hunt_rule_fired",
  HUNT_FINDING_CREATED = "hunt_finding_created",
  HUNT_FINDING_TRIAGED = "hunt_finding_triaged",
  HUNT_FINDING_SUPPRESSED = "hunt_finding_suppressed",
  HUNT_FINDING_PROMOTED = "hunt_finding_promoted",
  BEHAVIORAL_OUTLIER_DETECTED = "behavioral_outlier_detected",
  METRICS_UPDATE = "metrics_update",
  COST_UPDATE = "cost_update",
  TOKEN_USAGE = "token_usage",
  ERROR = "error",
  TERMINATION_REASON = "termination_reason",
  SERVER_SHUTDOWN = "server_shutdown",
  NOTIFICATION = "notification",
}

export enum ClientMessageType {
  SUBSCRIBE = "subscribe",
  UNSUBSCRIBE = "unsubscribe",
  CHAT = "chat",
  HITL_RESPONSE = "hitl_response",
  PING = "ping",
}

export enum ServerMessageType {
  ERROR = "error",
  SUBSCRIBED = "subscribed",
  UNSUBSCRIBED = "unsubscribed",
  PONG = "pong",
  NOTIFICATION = "notification",
}

/**
 * The exact JSON the hub puts on the wire — `EventEnvelope.model_dump_json()`.
 * Field names are the Python attribute names (no aliases): `id`, `type`,
 * `data` — NOT `event_id` / `event_type` / `payload`.
 */
export interface EventEnvelope {
  type: EventType;
  id: string;
  investigation_id: string;
  parent_id: string | null;
  trace_id: string | null;
  timestamp: string;
  data: Record<string, unknown>;
}

/**
 * Browser -> server frame. Pydantic IGNORES unknown top-level keys, so every
 * payload field MUST be nested under `data` or it is silently dropped.
 */
export interface ClientMessage {
  type: ClientMessageType;
  investigation_id?: string | null;
  data?: Record<string, unknown>;
}
