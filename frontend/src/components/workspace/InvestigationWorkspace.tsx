import { useEffect, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Pause,
  Play,
  Square,
  Clock,
  Eye,
  FileText,
  Radio,
} from "lucide-react";
import { clsx } from "clsx";
import { useInvestigationStore } from "@/stores/investigationStore";
import { useUIStore } from "@/stores/uiStore";
import { useEventStore } from "@/stores/eventStore";
import { useAgentStore } from "@/stores/agentStore";
import { useAuthStore } from "@/stores/authStore";
import { InvestigationStatus } from "@/types/config";
import {
  pauseInvestigation,
  resumeInvestigation,
  stopInvestigation,
} from "@/api/investigations";
import type { ContainmentAction, TimelineEntry, IOC } from "@/types/investigation";
import { getWSClient } from "@/api/ws";
import { EventType } from "@/types/events";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ui/Button";
import { SeverityBadge, StatusBadge } from "@/components/ui/Badge";
import { CostBadge } from "./CostBadge";
import { AgentChat } from "./AgentChat";
import { EventStream } from "./EventStream";

type WorkspaceTab = "timeline" | "iocs" | "evidence" | "events";

const tabs: { id: WorkspaceTab; label: string; icon: React.ReactNode }[] = [
  { id: "timeline", label: "Timeline", icon: <Clock className="w-4 h-4" /> },
  { id: "iocs", label: "IOCs", icon: <Eye className="w-4 h-4" /> },
  { id: "evidence", label: "Evidence", icon: <FileText className="w-4 h-4" /> },
  { id: "events", label: "Events", icon: <Radio className="w-4 h-4" /> },
];

export function InvestigationWorkspace() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const { currentInvestigation, fetchInvestigation, updateStatus, updateCost } =
    useInvestigationStore();
  const { activePanel, setActivePanel } = useUIStore();
  const { appendStreamChunk, finalizeStreamMessage, addCheckpoint } =
    useAgentStore();
  // Phase C2: tokens are httpOnly cookies. We gate WS connection on the
  // presence of a hydrated user (the proxy for "session valid"); the
  // browser attaches the auth cookie on the upgrade handshake automatically.
  const user = useAuthStore((state) => state.user);

  // Fetch investigation (only when ID changes, not on store reference change)
  useEffect(() => {
    if (id) {
      void useInvestigationStore.getState().fetchInvestigation(id);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // Connect WebSocket for real-time events
  useEffect(() => {
    if (!id || !user) return;

    const wsClient = getWSClient();
    const eventStore = useEventStore.getState();

    wsClient.onEvent = (event) => {
      if (event.investigation_id !== id) return;

      // Push to event store
      eventStore.pushEvent(event);

      // Handle specific event types
      switch (event.type) {
        case EventType.OUTPUT_CHUNK:
          appendStreamChunk((event.data.chunk as string) ?? "");
          break;

        case EventType.MESSAGE_COMPLETE:
          finalizeStreamMessage(
            (event.data.message_id as string) ?? event.id,
            (event.data.content as string) ?? "",
          );
          break;

        case EventType.STATUS_CHANGED:
          updateStatus(
            id,
            (event.data.new_status as InvestigationStatus) ??
              InvestigationStatus.RUNNING,
          );
          break;

        case EventType.COST_UPDATE:
          updateCost(
            id,
            (event.data.cost_usd as number) ?? 0,
            (event.data.token_count as number) ?? 0,
          );
          break;

        case EventType.HITL_REQUESTED:
          addCheckpoint({
            id: (event.data.checkpoint_id as string) ?? event.id,
            investigation_id: id,
            action: event.data.action as ContainmentAction,
            prompt: (event.data.prompt as string) ?? "Approval required",
            timestamp: event.timestamp,
            timeout_seconds: (event.data.timeout_seconds as number) ?? 300,
          });
          break;
      }
    };

    wsClient.onConnect = () => {
      console.log("[WS] Connected for investigation:", id);
    };

    if (!wsClient.isConnected) {
      // Cookies authenticate the upgrade — no token argument needed.
      wsClient.connect();
    }

    return () => {
      wsClient.onEvent = () => {};
    };
  }, [
    id,
    user,
    appendStreamChunk,
    finalizeStreamMessage,
    updateStatus,
    updateCost,
    addCheckpoint,
  ]);

  const handlePause = useCallback(async () => {
    if (!id) return;
    const updated = await pauseInvestigation(id);
    updateStatus(id, updated.status);
  }, [id, updateStatus]);

  const handleResume = useCallback(async () => {
    if (!id) return;
    const updated = await resumeInvestigation(id);
    updateStatus(id, updated.status);
  }, [id, updateStatus]);

  const handleStop = useCallback(async () => {
    if (!id) return;
    const updated = await stopInvestigation(id);
    updateStatus(id, updated.status);
  }, [id, updateStatus]);

  if (!currentInvestigation) {
    return (
      <>
        <Header title="Investigation" />
        <div
          className="flex-1 flex items-center justify-center text-slate-500"
          data-testid="investigation-workspace-loading"
        >
          <div
            className="animate-spin w-8 h-8 border-2 border-slate-600 border-t-blue-500 rounded-full"
            aria-label="Loading investigation"
          />
        </div>
      </>
    );
  }

  const inv = currentInvestigation;
  const isRunning = inv.status === InvestigationStatus.RUNNING;
  const isPaused = inv.status === InvestigationStatus.PAUSED;
  const canControl =
    inv.status === InvestigationStatus.RUNNING ||
    inv.status === InvestigationStatus.PAUSED ||
    inv.status === InvestigationStatus.AWAITING_HITL;

  // Current active right-panel tab
  const rightTab =
    activePanel === "chat" ? "events" : (activePanel as WorkspaceTab);

  return (
    <div data-testid="investigation-workspace">
      {/* Workspace header */}
      <div className="flex items-center justify-between px-6 py-3 bg-slate-900/80 backdrop-blur-sm border-b border-slate-700/50 shrink-0">
        <div className="flex items-center gap-4 min-w-0">
          <button
            onClick={() => navigate("/")}
            className="text-slate-400 hover:text-slate-200 transition-colors shrink-0"
            aria-label="Back to investigations"
            data-testid="investigation-workspace-back-button"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>

          <div className="min-w-0">
            <h1
              className="text-base font-semibold text-slate-100 truncate"
              data-testid="investigation-workspace-title"
            >
              {inv.title}
            </h1>
            <div className="flex items-center gap-2 mt-1">
              <SeverityBadge severity={inv.severity} />
              <StatusBadge status={inv.status} />
              <CostBadge costUsd={inv.cost_usd ?? 0} tokenCount={inv.token_count ?? 0} />
            </div>
          </div>
        </div>

        {/* Control buttons */}
        {canControl && (
          <div className="flex items-center gap-2 shrink-0">
            {isRunning && (
              <Button
                variant="secondary"
                size="sm"
                onClick={handlePause}
                aria-label="Pause investigation"
                data-testid="investigation-workspace-pause-button"
              >
                <Pause className="w-4 h-4" aria-hidden="true" />
                <span className="hidden sm:inline">Pause</span>
              </Button>
            )}
            {isPaused && (
              <Button
                variant="secondary"
                size="sm"
                onClick={handleResume}
                aria-label="Resume investigation"
                data-testid="investigation-workspace-resume-button"
              >
                <Play className="w-4 h-4" aria-hidden="true" />
                <span className="hidden sm:inline">Resume</span>
              </Button>
            )}
            <Button
              variant="danger"
              size="sm"
              onClick={handleStop}
              aria-label="Stop investigation"
              data-testid="investigation-workspace-stop-button"
            >
              <Square className="w-4 h-4" aria-hidden="true" />
              <span className="hidden sm:inline">Stop</span>
            </Button>
          </div>
        )}
      </div>

      {/* Split layout */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Left panel: Agent Chat */}
        <div className="flex-1 min-w-0 border-r border-slate-700/50">
          <AgentChat investigationId={inv.id} />
        </div>

        {/* Right panel: Tabbed content */}
        <div className="w-[400px] lg:w-[480px] hidden md:flex flex-col bg-slate-950 shrink-0">
          {/* Tabs */}
          <div
            className="flex border-b border-slate-700/50 shrink-0"
            role="tablist"
            aria-label="Investigation panels"
            data-testid="investigation-workspace-tabs"
          >
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActivePanel(tab.id)}
                role="tab"
                aria-selected={rightTab === tab.id}
                data-testid={`investigation-workspace-tab-${tab.id}`}
                className={clsx(
                  "flex items-center gap-1.5 px-4 py-2.5 text-xs font-medium border-b-2 transition-colors",
                  rightTab === tab.id
                    ? "text-blue-400 border-blue-400"
                    : "text-slate-400 border-transparent hover:text-slate-200 hover:border-slate-600",
                )}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </div>

          {/* Tab content */}
          <div className="flex-1 overflow-hidden">
            {rightTab === "timeline" && (
              <TimelinePanel timeline={inv.timeline ?? []} />
            )}
            {rightTab === "iocs" && <IOCsPanel iocs={inv.iocs ?? []} />}
            {rightTab === "evidence" && <EvidencePanel />}
            {rightTab === "events" && <EventStream investigationId={inv.id} />}
          </div>
        </div>
      </div>
    </div>
  );
}

// -- Timeline Panel --

function TimelinePanel({ timeline }: { timeline: TimelineEntry[] }) {
  if (timeline.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        No timeline entries yet
      </div>
    );
  }

  return (
    <div className="overflow-y-auto h-full p-4 space-y-3">
      {timeline.map((entry) => (
        <div
          key={entry.id}
          className="relative pl-6 before:absolute before:left-2 before:top-2 before:w-1.5 before:h-1.5 before:rounded-full before:bg-slate-500 border-l border-slate-700/50 ml-2"
        >
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[10px] font-mono text-slate-500">
              {new Date(entry.timestamp).toLocaleString()}
            </span>
            <SeverityBadge severity={entry.severity} />
          </div>
          <p className="text-sm text-slate-300">{entry.description}</p>
          <span className="text-[10px] text-slate-500">
            Source: {entry.source}
          </span>
        </div>
      ))}
    </div>
  );
}

// -- IOCs Panel --

function IOCsPanel({ iocs }: { iocs: IOC[] }) {
  if (iocs.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-slate-500 text-sm">
        No IOCs discovered yet
      </div>
    );
  }

  return (
    <div className="overflow-y-auto h-full p-4 space-y-2">
      {iocs.map((ioc) => (
        <div
          key={ioc.id}
          className="bg-slate-900 border border-slate-700/40 rounded-md p-3"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] uppercase font-bold tracking-wider text-slate-400 bg-slate-800 px-1.5 py-0.5 rounded">
              {ioc.type}
            </span>
            <span
              className={clsx(
                "text-[10px] font-medium",
                ioc.confidence >= 0.8
                  ? "text-green-400"
                  : ioc.confidence >= 0.5
                    ? "text-amber-400"
                    : "text-slate-400",
              )}
            >
              {Math.round(ioc.confidence * 100)}% confidence
            </span>
          </div>
          <p className="font-mono text-sm text-slate-200 break-all">
            {ioc.value}
          </p>
          {ioc.context && (
            <p className="text-xs text-slate-500 mt-1">{ioc.context}</p>
          )}
          {(ioc.tags ?? []).length > 0 && (
            <div className="flex flex-wrap gap-1 mt-2">
              {(ioc.tags ?? []).map((tag) => (
                <span
                  key={tag}
                  className="px-1.5 py-0.5 text-[10px] rounded bg-slate-800 text-slate-400"
                >
                  {tag}
                </span>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

// -- Evidence Panel (placeholder for file/artifact display) --

function EvidencePanel() {
  return (
    <div className="flex flex-col items-center justify-center h-full text-slate-500 text-sm p-6">
      <FileText className="w-10 h-10 text-slate-600 mb-3" />
      <p className="font-medium text-slate-400">Evidence Collection</p>
      <p className="text-xs mt-1 text-center">
        Collected files, screenshots, and artifacts will appear here as the
        investigation progresses
      </p>
    </div>
  );
}
