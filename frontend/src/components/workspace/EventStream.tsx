import { useEffect, useRef } from "react";
import {
  Play,
  AlertCircle,
  Search,
  Shield,
  Clock,
  Zap,
  CheckCircle,
  XCircle,
  Eye,
  Box,
} from "lucide-react";
import { clsx } from "clsx";
import { useEventStore } from "@/stores/eventStore";
import { EventType, type AgentEvent } from "@/types/events";

interface EventStreamProps {
  investigationId: string;
}

// Event types and payload keys below mirror the generated wire contract
// (src/types/events.generated.ts). The previous set — agent_started /
// agent_completed / agent_error / tool_error / timeline_entry /
// hitl_requested / status_changed / heartbeat — did not exist on the Python
// side at all, so every one of these branches was unreachable.
function getEventIcon(type: EventType): React.ReactNode {
  switch (type) {
    case EventType.INVESTIGATION_INIT:
      return <Play className="w-3.5 h-3.5 text-green-400" />;
    case EventType.INVESTIGATION_COMPLETE:
      return <CheckCircle className="w-3.5 h-3.5 text-blue-400" />;
    case EventType.INVESTIGATION_FAILED:
    case EventType.ERROR:
      return <XCircle className="w-3.5 h-3.5 text-red-400" />;
    case EventType.THINKING:
      return <Search className="w-3.5 h-3.5 text-slate-400" />;
    case EventType.TOOL_START:
      return <Zap className="w-3.5 h-3.5 text-amber-400" />;
    case EventType.TOOL_END:
      return <CheckCircle className="w-3.5 h-3.5 text-green-400" />;
    case EventType.TOOL_PROGRESS:
      return <AlertCircle className="w-3.5 h-3.5 text-amber-400" />;
    case EventType.IOC_DISCOVERED:
      return <Eye className="w-3.5 h-3.5 text-purple-400" />;
    case EventType.TIMELINE_UPDATED:
      return <Clock className="w-3.5 h-3.5 text-blue-400" />;
    case EventType.CONTAINMENT_PROPOSED:
      return <Shield className="w-3.5 h-3.5 text-amber-400" />;
    case EventType.CONTAINMENT_EXECUTED:
      return <Shield className="w-3.5 h-3.5 text-green-400" />;
    case EventType.HITL_CHECKPOINT:
      return <AlertCircle className="w-3.5 h-3.5 text-purple-400" />;
    case EventType.AGENT_STATUS:
      return <Box className="w-3.5 h-3.5 text-blue-400" />;
    default:
      return <Search className="w-3.5 h-3.5 text-slate-400" />;
  }
}

function getEventLabel(event: AgentEvent): string {
  const data = event.data;
  switch (event.type) {
    case EventType.INVESTIGATION_INIT:
      return "Agent started investigation";
    case EventType.INVESTIGATION_COMPLETE:
      return `Agent completed investigation${data.final_status ? ` (${data.final_status as string})` : ""}`;
    case EventType.INVESTIGATION_FAILED:
      return `Investigation failed: ${(data.reason as string) ?? (data.error as string) ?? "unknown"}`;
    case EventType.ERROR:
      // The engine adapter tags errors with `source` ("llm" / "tool" / node
      // category) rather than emitting a distinct per-source event type.
      return `${(data.source as string) ?? "Agent"} error: ${(data.error as string) ?? "unknown"}`;
    case EventType.THINKING:
      return `Reasoning${data.model ? ` (${data.model as string})` : ""}`;
    case EventType.TOOL_START:
      return `Running tool: ${(data.tool_name as string) ?? "unknown"}`;
    case EventType.TOOL_END:
      return `Tool completed: ${(data.tool_name as string) ?? "unknown"}${data.duration_ms ? ` (${data.duration_ms as number}ms)` : ""}`;
    case EventType.IOC_DISCOVERED:
      return `IOC found: ${(data.type as string) ?? ""} - ${(data.value as string) ?? ""}`;
    case EventType.TIMELINE_UPDATED:
      return (data.description as string) ?? "Timeline entry added";
    case EventType.CONTAINMENT_PROPOSED:
      return `Containment proposed: ${(data.action_type as string) ?? ""} on ${(data.target as string) ?? ""}`;
    case EventType.CONTAINMENT_EXECUTED:
      return `Containment executed: ${(data.action_type as string) ?? ""}`;
    case EventType.HITL_CHECKPOINT:
      // HITLHook's payload key is `message` (the tool name lives in
      // `tool_name`); there is no `prompt`.
      return `Approval required: ${(data.message as string) ?? (data.tool_name as string) ?? ""}`;
    case EventType.AGENT_STATUS:
      return `Status: ${(data.status as string) ?? ""}`;
    case EventType.COST_UPDATE:
      // PromptBudgetHook emits `total_cost_usd` / `call_cost_usd`.
      return `Cost: $${((data.total_cost_usd as number) ?? (data.call_cost_usd as number) ?? 0).toFixed(4)}`;
    default:
      return event.type;
  }
}

function formatTimestamp(ts: string): string {
  const date = new Date(ts);
  return date.toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function EventRow({ event }: { event: AgentEvent }) {
  const isError =
    event.type === EventType.INVESTIGATION_FAILED ||
    event.type === EventType.ERROR;

  const isHITL = event.type === EventType.HITL_CHECKPOINT;

  return (
    <div
      className={clsx(
        "flex items-start gap-2.5 px-3 py-2 text-xs animate-slide-in",
        isError && "bg-red-500/5",
        isHITL && "bg-purple-500/5",
      )}
      data-testid={`event-stream-item-${event.id}`}
      data-event-type={event.type}
    >
      <span className="text-slate-600 font-mono shrink-0 pt-0.5">
        {formatTimestamp(event.timestamp)}
      </span>
      <span className="shrink-0 pt-0.5" aria-hidden="true">
        {getEventIcon(event.type)}
      </span>
      <span
        className={clsx(
          "text-slate-300 leading-relaxed break-all",
          isError && "text-red-400",
          isHITL && "text-purple-300 font-medium",
        )}
      >
        {getEventLabel(event)}
      </span>
    </div>
  );
}

export function EventStream({ investigationId }: EventStreamProps) {
  const events = useEventStore((state) => state.getEvents(investigationId));
  const scrollRef = useRef<HTMLDivElement>(null);

  // Auto-scroll to bottom on new events
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [events]);

  return (
    <div className="flex flex-col h-full" data-testid="event-stream">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-700/50 shrink-0">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          Event Stream
        </span>
        <span
          className="text-[10px] text-slate-500 font-mono"
          data-testid="event-stream-count"
        >
          {events.length} events
        </span>
      </div>

      {/* Events list */}
      <div
        ref={scrollRef}
        className="flex-1 overflow-y-auto divide-y divide-slate-800/50"
        data-testid="event-stream-list"
      >
        {events.length === 0 ? (
          <div
            className="flex items-center justify-center h-full text-slate-500 text-xs"
            data-testid="event-stream-empty"
          >
            Waiting for events...
          </div>
        ) : (
          events
            // OUTPUT_CHUNK is per-token streaming noise; it renders in the
            // chat pane, not the event log. (There is no `heartbeat` EVENT to
            // filter — the keepalive is a protocol-level ping/pong frame that
            // the WS client never surfaces as an event.)
            .filter((e) => e.type !== EventType.OUTPUT_CHUNK)
            .map((event) => <EventRow key={event.id} event={event} />)
        )}
      </div>
    </div>
  );
}
