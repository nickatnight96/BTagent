import { useEffect, useMemo, useCallback, useState } from "react";
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useParams, useNavigate } from "react-router-dom";
import {
  ArrowLeft,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  Pause,
  SkipForward,
  AlertTriangle,
} from "lucide-react";
import { clsx } from "clsx";

import { usePlaybookStore } from "@/stores/playbookStore";
import { StepExecutionStatus, PlaybookStatus } from "@/types/playbook";
import type { StepResult } from "@/types/playbook";
import { TriggerNode } from "./nodes/TriggerNode";
import { ActionNode } from "./nodes/ActionNode";
import { DecisionNode } from "./nodes/DecisionNode";
import { HITLGateNode } from "./nodes/HITLGateNode";
import { ParallelForkNode } from "./nodes/ParallelForkNode";
import { EndNode } from "./nodes/EndNode";

const nodeTypes = {
  trigger: TriggerNode,
  action: ActionNode,
  decision: DecisionNode,
  hitlGate: HITLGateNode,
  parallelFork: ParallelForkNode,
  end: EndNode,
};

// ---------------------------------------------------------------------------
// Status styling
// ---------------------------------------------------------------------------

const STEP_STATUS_STYLES: Record<string, { border: string; shadow: string; label: string; icon: React.ReactNode }> = {
  [StepExecutionStatus.PENDING]: {
    border: "border-slate-700",
    shadow: "",
    label: "Pending",
    icon: <Clock className="w-3 h-3 text-slate-500" />,
  },
  [StepExecutionStatus.RUNNING]: {
    border: "border-blue-500",
    shadow: "shadow-blue-500/20 shadow-lg",
    label: "Running",
    icon: <Loader2 className="w-3 h-3 text-blue-400 animate-spin" />,
  },
  [StepExecutionStatus.COMPLETED]: {
    border: "border-green-500",
    shadow: "",
    label: "Completed",
    icon: <CheckCircle2 className="w-3 h-3 text-green-400" />,
  },
  [StepExecutionStatus.FAILED]: {
    border: "border-red-500",
    shadow: "shadow-red-500/20 shadow-lg",
    label: "Failed",
    icon: <XCircle className="w-3 h-3 text-red-400" />,
  },
  [StepExecutionStatus.SKIPPED]: {
    border: "border-slate-600",
    shadow: "",
    label: "Skipped",
    icon: <SkipForward className="w-3 h-3 text-slate-500" />,
  },
  [StepExecutionStatus.WAITING_HITL]: {
    border: "border-amber-500",
    shadow: "shadow-amber-500/20 shadow-lg",
    label: "Awaiting Approval",
    icon: <Pause className="w-3 h-3 text-amber-400 animate-pulse" />,
  },
};

const PLAYBOOK_STATUS_STYLES: Record<string, string> = {
  [PlaybookStatus.PENDING]: "text-slate-400 bg-slate-500/10 border-slate-500/20",
  [PlaybookStatus.RUNNING]: "text-blue-400 bg-blue-500/10 border-blue-500/20",
  [PlaybookStatus.PAUSED_HITL]: "text-amber-400 bg-amber-500/10 border-amber-500/20",
  [PlaybookStatus.COMPLETED]: "text-green-400 bg-green-500/10 border-green-500/20",
  [PlaybookStatus.FAILED]: "text-red-400 bg-red-500/10 border-red-500/20",
  [PlaybookStatus.CANCELLED]: "text-slate-400 bg-slate-500/10 border-slate-500/20",
};

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PlaybookExecutionView() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();

  const {
    executionState,
    currentPlaybook,
    loadPlaybook,
    executePlaybook,
    fetchExecution,
    builderNodes,
    builderEdges,
    isLoading,
  } = usePlaybookStore();

  const [selectedStepResult, setSelectedStepResult] = useState<StepResult | null>(null);

  // Load playbook data
  useEffect(() => {
    if (id) {
      loadPlaybook(id);
    }
  }, [id, loadPlaybook]);

  // Poll execution state
  useEffect(() => {
    if (!executionState?.id) return;
    if (
      executionState.status === PlaybookStatus.COMPLETED ||
      executionState.status === PlaybookStatus.FAILED ||
      executionState.status === PlaybookStatus.CANCELLED
    ) {
      return;
    }

    const interval = setInterval(() => {
      fetchExecution(executionState.id);
    }, 2000);

    return () => clearInterval(interval);
  }, [executionState?.id, executionState?.status, fetchExecution]);

  // Build a step result lookup
  const stepResultMap = useMemo(() => {
    const map = new Map<string, StepResult>();
    if (executionState?.step_results) {
      for (const sr of executionState.step_results) {
        map.set(sr.step_id, sr);
      }
    }
    return map;
  }, [executionState?.step_results]);

  // Enhance nodes with execution status styling
  const executionNodes: Node[] = useMemo(() => {
    return builderNodes.map((node) => {
      const stepResult = stepResultMap.get(node.id);
      const status = stepResult?.status ?? StepExecutionStatus.PENDING;
      const styles = STEP_STATUS_STYLES[status] ?? STEP_STATUS_STYLES[StepExecutionStatus.PENDING]!;

      const isPulsing =
        status === StepExecutionStatus.RUNNING ||
        status === StepExecutionStatus.WAITING_HITL;

      return {
        ...node,
        className: clsx(
          "transition-all duration-300",
          styles.shadow,
          isPulsing && "animate-pulse-slow",
        ),
        style: {
          ...node.style,
          borderColor:
            status === StepExecutionStatus.RUNNING
              ? "#3b82f6"
              : status === StepExecutionStatus.COMPLETED
                ? "#22c55e"
                : status === StepExecutionStatus.FAILED
                  ? "#ef4444"
                  : status === StepExecutionStatus.WAITING_HITL
                    ? "#f59e0b"
                    : status === StepExecutionStatus.SKIPPED
                      ? "#475569"
                      : undefined,
        },
      };
    });
  }, [builderNodes, stepResultMap]);

  // Enhance edges with animated styles during execution
  const executionEdges: Edge[] = useMemo(() => {
    return builderEdges.map((edge) => {
      const sourceResult = stepResultMap.get(edge.source);
      const isActive =
        sourceResult?.status === StepExecutionStatus.COMPLETED ||
        sourceResult?.status === StepExecutionStatus.RUNNING;

      return {
        ...edge,
        animated: isActive,
        style: {
          ...edge.style,
          stroke: isActive ? "#3b82f6" : "#64748b",
          strokeWidth: isActive ? 2.5 : 2,
        },
      };
    });
  }, [builderEdges, stepResultMap]);

  const handleStartExecution = useCallback(async () => {
    if (id) {
      await executePlaybook(id);
    }
  }, [id, executePlaybook]);

  const handleNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      const result = stepResultMap.get(node.id);
      setSelectedStepResult(result ?? null);
    },
    [stepResultMap],
  );

  // Node types memoized
  const memoNodeTypes = useMemo(() => nodeTypes, []);

  return (
    <div className="flex flex-col h-full">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-slate-700/50 bg-slate-900 shrink-0">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate("/playbooks")}
            className="flex items-center gap-1.5 px-2 py-1.5 text-sm text-slate-400 hover:text-slate-200 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back
          </button>
          <div className="w-px h-5 bg-slate-700" />
          <h2 className="text-sm font-semibold text-slate-200">
            {currentPlaybook?.name ?? "Playbook Execution"}
          </h2>
        </div>

        <div className="flex items-center gap-3">
          {executionState && (
            <span
              className={clsx(
                "inline-flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-full border",
                PLAYBOOK_STATUS_STYLES[executionState.status] ??
                  PLAYBOOK_STATUS_STYLES[PlaybookStatus.PENDING],
              )}
            >
              {executionState.status === PlaybookStatus.RUNNING && (
                <Loader2 className="w-3 h-3 animate-spin" />
              )}
              {executionState.status.replace(/_/g, " ").toUpperCase()}
            </span>
          )}
          {!executionState && (
            <button
              onClick={handleStartExecution}
              disabled={isLoading}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-green-600 rounded-md hover:bg-green-700 disabled:opacity-50 transition-colors"
            >
              Start Execution
            </button>
          )}
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-1 min-h-0">
        {/* Canvas */}
        <div className="flex-1 relative">
          <ReactFlow
            nodes={executionNodes}
            edges={executionEdges}
            nodeTypes={memoNodeTypes}
            onNodeClick={handleNodeClick}
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={true}
            fitView
            proOptions={{ hideAttribution: true }}
            className="bg-slate-950"
          >
            <Controls
              position="top-right"
              className="!bg-slate-800 !border-slate-700 !rounded-lg !shadow-lg [&>button]:!bg-slate-800 [&>button]:!border-slate-700 [&>button]:!text-slate-400 [&>button:hover]:!bg-slate-700 [&>button]:!fill-slate-400"
            />
            <MiniMap
              position="bottom-right"
              className="!bg-slate-900 !border-slate-700 !rounded-lg"
              nodeColor={(node) => {
                const result = stepResultMap.get(node.id);
                switch (result?.status) {
                  case StepExecutionStatus.RUNNING:
                    return "#3b82f6";
                  case StepExecutionStatus.COMPLETED:
                    return "#22c55e";
                  case StepExecutionStatus.FAILED:
                    return "#ef4444";
                  case StepExecutionStatus.WAITING_HITL:
                    return "#f59e0b";
                  case StepExecutionStatus.SKIPPED:
                    return "#475569";
                  default:
                    return "#334155";
                }
              }}
              maskColor="rgba(15, 23, 42, 0.7)"
            />
            <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
          </ReactFlow>
        </div>

        {/* Right: Step detail panel */}
        {selectedStepResult && (
          <div className="w-80 bg-slate-900 border-l border-slate-700/50 flex flex-col">
            <div className="px-4 py-3 border-b border-slate-700/50">
              <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
                Step Result
              </h3>
            </div>
            <div className="flex-1 overflow-y-auto p-4 space-y-4">
              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Step ID</label>
                <div className="text-sm text-slate-200 font-mono">
                  {selectedStepResult.step_id}
                </div>
              </div>

              <div>
                <label className="block text-xs font-medium text-slate-400 mb-1">Status</label>
                <div className="flex items-center gap-2">
                  {STEP_STATUS_STYLES[selectedStepResult.status]?.icon}
                  <span className="text-sm text-slate-200">
                    {STEP_STATUS_STYLES[selectedStepResult.status]?.label ?? selectedStepResult.status}
                  </span>
                </div>
              </div>

              {selectedStepResult.started_at && (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Started</label>
                  <div className="text-xs text-slate-300 font-mono">
                    {new Date(selectedStepResult.started_at).toLocaleString()}
                  </div>
                </div>
              )}

              {selectedStepResult.completed_at && (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Completed</label>
                  <div className="text-xs text-slate-300 font-mono">
                    {new Date(selectedStepResult.completed_at).toLocaleString()}
                  </div>
                </div>
              )}

              {selectedStepResult.error && (
                <div>
                  <label className="block text-xs font-medium text-red-400 mb-1">
                    <AlertTriangle className="w-3 h-3 inline mr-1" />
                    Error
                  </label>
                  <div className="text-xs text-red-300 bg-red-500/10 border border-red-500/20 rounded-md p-2 font-mono">
                    {selectedStepResult.error}
                  </div>
                </div>
              )}

              {Object.keys(selectedStepResult.output).length > 0 && (
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1">Output</label>
                  <pre className="text-xs text-slate-300 bg-slate-800 border border-slate-700 rounded-md p-2 font-mono overflow-auto max-h-60">
                    {JSON.stringify(selectedStepResult.output, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Execution timeline at bottom */}
      {executionState && executionState.step_results.length > 0 && (
        <div className="border-t border-slate-700/50 bg-slate-900 px-4 py-3 shrink-0">
          <div className="flex items-center gap-1.5 mb-2">
            <Clock className="w-3 h-3 text-slate-500" />
            <span className="text-xs font-medium text-slate-400">Execution Timeline</span>
          </div>
          <div className="flex items-center gap-1 overflow-x-auto pb-1">
            {executionState.step_results.map((sr, idx) => {
              const styles = STEP_STATUS_STYLES[sr.status] ?? STEP_STATUS_STYLES[StepExecutionStatus.PENDING]!;
              return (
                <div key={sr.step_id} className="flex items-center shrink-0">
                  <button
                    onClick={() => setSelectedStepResult(sr)}
                    className={clsx(
                      "flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium rounded-md border transition-colors",
                      selectedStepResult?.step_id === sr.step_id
                        ? "ring-1 ring-blue-400/50"
                        : "",
                      styles.border,
                      "bg-slate-800/50 text-slate-300 hover:bg-slate-800",
                    )}
                    title={sr.step_id}
                  >
                    {styles.icon}
                    <span className="max-w-[80px] truncate">{sr.step_id}</span>
                  </button>
                  {idx < executionState.step_results.length - 1 && (
                    <div className="w-4 h-px bg-slate-700 mx-0.5" />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
