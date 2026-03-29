import { useCallback, useRef, useMemo, useState, useEffect, type DragEvent } from "react";
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  addEdge,
  type Connection,
  type Node,
  type Edge,
  type OnConnect,
  type ReactFlowInstance,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useParams, useNavigate } from "react-router-dom";
import {
  Save,
  CheckCircle2,
  FileDown,
  FileUp,
  ArrowLeft,
  Monitor,
} from "lucide-react";

import { usePlaybookStore } from "@/stores/playbookStore";
import { TriggerType, OnFailure } from "@/types/playbook";
import type {
  TriggerNodeData,
  ActionNodeData,
  DecisionNodeData,
  HITLGateNodeData,
  ParallelForkNodeData,
  EndNodeData,
} from "@/types/playbook";
import { generateNodeId, nodesToYAML, yamlToNodes, autoLayout } from "@/utils/playbook-graph";

import { TriggerNode } from "./nodes/TriggerNode";
import { ActionNode } from "./nodes/ActionNode";
import { DecisionNode } from "./nodes/DecisionNode";
import { HITLGateNode } from "./nodes/HITLGateNode";
import { ParallelForkNode } from "./nodes/ParallelForkNode";
import { EndNode } from "./nodes/EndNode";
import { PlaybookNodePalette } from "./PlaybookNodePalette";
import { PlaybookConfigPanel } from "./PlaybookConfigPanel";
import { PlaybookYAMLEditor } from "./PlaybookYAMLEditor";

// ---------------------------------------------------------------------------
// Node type registry
// ---------------------------------------------------------------------------

const nodeTypes = {
  trigger: TriggerNode,
  action: ActionNode,
  decision: DecisionNode,
  hitlGate: HITLGateNode,
  parallelFork: ParallelForkNode,
  end: EndNode,
};

// ---------------------------------------------------------------------------
// Default data factories per node type
// ---------------------------------------------------------------------------

function defaultNodeData(type: string): Record<string, unknown> {
  switch (type) {
    case "trigger":
      return {
        label: "Trigger",
        triggerType: TriggerType.MANUAL,
        parameters: {},
      } satisfies TriggerNodeData;
    case "action":
      return {
        label: "Action",
        toolName: "",
        arguments: {},
        timeoutSeconds: 300,
        onFailure: OnFailure.ABORT,
      } satisfies ActionNodeData;
    case "decision":
      return {
        label: "Decision",
        condition: "",
      } satisfies DecisionNodeData;
    case "hitlGate":
      return {
        label: "Approval Gate",
        prompt: "",
        timeoutSeconds: 3600,
        requiredRole: "senior_analyst",
      } satisfies HITLGateNodeData;
    case "parallelFork":
      return {
        label: "Parallel Fork",
        branchCount: 2,
        branchLabels: ["Branch 1", "Branch 2"],
      } satisfies ParallelForkNodeData;
    case "end":
      return { label: "End" } satisfies EndNodeData;
    default:
      return { label: type };
  }
}

// ---------------------------------------------------------------------------
// Connection validation
// ---------------------------------------------------------------------------

function isValidConnection(connection: Connection, nodes: Node[]): boolean {
  const sourceNode = nodes.find((n) => n.id === connection.source);
  const targetNode = nodes.find((n) => n.id === connection.target);

  if (!sourceNode || !targetNode) return false;

  // End nodes cannot have outputs
  if (sourceNode.type === "end") return false;

  // Cannot connect to trigger (it has no input handle)
  if (targetNode.type === "trigger") return false;

  // Decision must use yes/no handles
  if (sourceNode.type === "decision") {
    if (connection.sourceHandle !== "yes" && connection.sourceHandle !== "no") {
      return false;
    }
  }

  // No self-connections
  if (connection.source === connection.target) return false;

  return true;
}

// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------

export function PlaybookBuilder() {
  const { id } = useParams<{ id?: string }>();
  const navigate = useNavigate();

  const {
    builderNodes: storeNodes,
    builderEdges: storeEdges,
    setBuilderNodes,
    setBuilderEdges,
    setSelectedNode,
    selectedNodeId,
    loadPlaybook,
    savePlaybook,
    currentPlaybook,
    isLoading,
    error,
    clearError,
  } = usePlaybookStore();

  const [nodes, setNodes, onNodesChange] = useNodesState(storeNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(storeEdges);
  const [showYaml, setShowYaml] = useState(false);
  const [validationMsg, setValidationMsg] = useState<string | null>(null);

  const reactFlowWrapper = useRef<HTMLDivElement>(null);
  const reactFlowInstance = useRef<ReactFlowInstance | null>(null);

  // Keep store in sync with local React Flow state
  useEffect(() => {
    setBuilderNodes(nodes);
  }, [nodes, setBuilderNodes]);

  useEffect(() => {
    setBuilderEdges(edges);
  }, [edges, setBuilderEdges]);

  // Load existing playbook
  useEffect(() => {
    if (id) {
      loadPlaybook(id);
    }
  }, [id, loadPlaybook]);

  // Hydrate builder from loaded playbook
  useEffect(() => {
    if (currentPlaybook && (currentPlaybook.steps ?? []).length > 0) {
      // Convert playbook steps to nodes/edges
      const triggerNode: Node = {
        id: "trigger-1",
        type: "trigger",
        position: { x: 0, y: 0 },
        data: {
          label: currentPlaybook.name,
          triggerType: currentPlaybook.trigger?.type ?? TriggerType.MANUAL,
          parameters: currentPlaybook.trigger?.parameters ?? {},
        } satisfies TriggerNodeData,
      };

      const stepNodes: Node[] = (currentPlaybook.steps ?? []).map((step, index) => {
        const nodeType = step.type === "hitl_gate" ? "hitlGate" : step.type === "parallel_fork" ? "parallelFork" : step.type;
        return {
          id: step.id,
          type: nodeType,
          position: { x: 0, y: (index + 1) * 150 },
          data: {
            label: step.name,
            ...step.config,
            ...(step as Record<string, unknown>),
          },
        };
      });

      const allNodes = [triggerNode, ...stepNodes];
      const computedEdges: Edge[] = [];

      // Connect trigger to first step
      if (stepNodes.length > 0 && stepNodes[0]) {
        computedEdges.push({
          id: `e-trigger-1-${stepNodes[0].id}`,
          source: "trigger-1",
          target: stepNodes[0].id,
          type: "smoothstep",
        });
      }

      // Build edges from next_step references
      for (const step of (currentPlaybook.steps ?? [])) {
        if (step.next_step) {
          computedEdges.push({
            id: `e-${step.id}-${step.next_step}`,
            source: step.id,
            target: step.next_step,
            type: "smoothstep",
          });
        }
      }

      const layouted = autoLayout(allNodes, computedEdges);
      setNodes(layouted);
      setEdges(computedEdges);
    }
  }, [currentPlaybook, setNodes, setEdges]);

  // Node types memoized to avoid re-renders
  const memoNodeTypes = useMemo(() => nodeTypes, []);

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  const onConnect: OnConnect = useCallback(
    (params) => {
      if (!isValidConnection(params, nodes)) return;

      setEdges((eds) =>
        addEdge(
          {
            ...params,
            type: "smoothstep",
            style: { stroke: "#64748b", strokeWidth: 2 },
          },
          eds,
        ),
      );
    },
    [nodes, setEdges],
  );

  const onNodeClick = useCallback(
    (_event: React.MouseEvent, node: Node) => {
      setSelectedNode(node.id);
    },
    [setSelectedNode],
  );

  const onPaneClick = useCallback(() => {
    setSelectedNode(null);
  }, [setSelectedNode]);

  const onInit = useCallback((instance: ReactFlowInstance) => {
    reactFlowInstance.current = instance;
  }, []);

  // Drag & drop from palette
  const onDragOver = useCallback((event: DragEvent) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  }, []);

  const onDrop = useCallback(
    (event: DragEvent) => {
      event.preventDefault();

      const type = event.dataTransfer.getData("application/reactflow");
      if (!type || !reactFlowInstance.current || !reactFlowWrapper.current) return;

      const bounds = reactFlowWrapper.current.getBoundingClientRect();
      const position = reactFlowInstance.current.screenToFlowPosition({
        x: event.clientX - bounds.left,
        y: event.clientY - bounds.top,
      });

      const newNode: Node = {
        id: generateNodeId(type),
        type,
        position,
        data: defaultNodeData(type),
      };

      setNodes((nds) => [...nds, newNode]);
      setSelectedNode(newNode.id);
    },
    [setNodes, setSelectedNode],
  );

  // Toolbar actions
  const handleSave = useCallback(async () => {
    if (id) {
      await savePlaybook(id);
    }
  }, [id, savePlaybook]);

  const handleValidate = useCallback(() => {
    const issues: string[] = [];
    const triggerNodes = nodes.filter((n) => n.type === "trigger");
    const endNodes = nodes.filter((n) => n.type === "end");

    if (triggerNodes.length === 0) issues.push("Missing trigger node");
    if (triggerNodes.length > 1) issues.push("Only one trigger node allowed");
    if (endNodes.length === 0) issues.push("Missing end node");

    // Check for disconnected nodes (except trigger with its output)
    for (const node of nodes) {
      if (node.type === "trigger") {
        const hasOutput = edges.some((e) => e.source === node.id);
        if (!hasOutput) issues.push(`Trigger "${String((node.data as Record<string, unknown>).label)}" has no connections`);
      } else if (node.type === "end") {
        const hasInput = edges.some((e) => e.target === node.id);
        if (!hasInput) issues.push(`End node "${String((node.data as Record<string, unknown>).label)}" has no incoming connection`);
      } else {
        const hasInput = edges.some((e) => e.target === node.id);
        const hasOutput = edges.some((e) => e.source === node.id);
        if (!hasInput && !hasOutput) {
          issues.push(`Node "${String((node.data as Record<string, unknown>).label)}" is disconnected`);
        }
      }
    }

    // Decision nodes must have both Yes and No outputs
    for (const node of nodes.filter((n) => n.type === "decision")) {
      const outEdges = edges.filter((e) => e.source === node.id);
      const hasYes = outEdges.some((e) => e.sourceHandle === "yes");
      const hasNo = outEdges.some((e) => e.sourceHandle === "no");
      if (!hasYes || !hasNo) {
        issues.push(`Decision "${String((node.data as Record<string, unknown>).label)}" needs both Yes and No connections`);
      }
    }

    if (issues.length === 0) {
      setValidationMsg("Playbook is valid!");
    } else {
      setValidationMsg(`Issues found:\n${issues.map((i) => `  - ${i}`).join("\n")}`);
    }
    setTimeout(() => setValidationMsg(null), 5000);
  }, [nodes, edges]);

  const handleExportYaml = useCallback(() => {
    const yaml = nodesToYAML(nodes, edges);
    const blob = new Blob([yaml], { type: "text/yaml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${currentPlaybook?.name ?? "playbook"}.yaml`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [nodes, edges, currentPlaybook]);

  const handleImportYaml = useCallback(() => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".yaml,.yml";
    input.onchange = (event) => {
      const file = (event.target as HTMLInputElement).files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        const yaml = e.target?.result as string;
        try {
          const { nodes: importedNodes, edges: importedEdges } = yamlToNodes(yaml);
          setNodes(importedNodes);
          setEdges(importedEdges);
        } catch (err) {
          console.error("Failed to import YAML:", err);
        }
      };
      reader.readAsText(file);
    };
    input.click();
  }, [setNodes, setEdges]);

  // ---------------------------------------------------------------------------
  // Desktop-only guard
  // ---------------------------------------------------------------------------

  return (
    <div className="flex flex-col h-full">
      {/* Mobile warning */}
      <div className="md:hidden flex items-center justify-center h-full p-8 text-center">
        <div className="space-y-3">
          <Monitor className="w-12 h-12 text-slate-500 mx-auto" />
          <h2 className="text-lg font-semibold text-slate-200">Desktop Required</h2>
          <p className="text-sm text-slate-400 max-w-sm">
            The visual playbook builder requires a desktop-sized screen. Please use a larger display to access this feature.
          </p>
          <button
            onClick={() => navigate("/playbooks")}
            className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-blue-400 bg-blue-500/10 border border-blue-500/20 rounded-lg hover:bg-blue-500/20 transition-colors"
          >
            <ArrowLeft className="w-4 h-4" />
            Back to Playbooks
          </button>
        </div>
      </div>

      {/* Desktop builder */}
      <div className="hidden md:flex flex-col h-full">
        {/* Toolbar */}
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
              {currentPlaybook?.name ?? "New Playbook"}
            </h2>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={handleValidate}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 border border-slate-700 rounded-md hover:bg-slate-700 transition-colors"
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              Validate
            </button>
            <button
              onClick={handleImportYaml}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 border border-slate-700 rounded-md hover:bg-slate-700 transition-colors"
            >
              <FileUp className="w-3.5 h-3.5" />
              Import YAML
            </button>
            <button
              onClick={handleExportYaml}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-slate-300 bg-slate-800 border border-slate-700 rounded-md hover:bg-slate-700 transition-colors"
            >
              <FileDown className="w-3.5 h-3.5" />
              Export YAML
            </button>
            <button
              onClick={() => setShowYaml(!showYaml)}
              className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md transition-colors ${
                showYaml
                  ? "text-blue-400 bg-blue-500/10 border border-blue-500/20"
                  : "text-slate-300 bg-slate-800 border border-slate-700 hover:bg-slate-700"
              }`}
            >
              YAML
            </button>
            <button
              onClick={handleSave}
              disabled={isLoading || !id}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-white bg-blue-600 rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              <Save className="w-3.5 h-3.5" />
              Save
            </button>
          </div>
        </div>

        {/* Validation / error messages */}
        {(validationMsg || error) && (
          <div
            className={`px-4 py-2 text-xs font-mono whitespace-pre-wrap border-b ${
              error
                ? "bg-red-500/10 border-red-500/20 text-red-400"
                : validationMsg?.startsWith("Playbook is valid")
                  ? "bg-green-500/10 border-green-500/20 text-green-400"
                  : "bg-amber-500/10 border-amber-500/20 text-amber-400"
            }`}
          >
            {error || validationMsg}
            {error && (
              <button onClick={clearError} className="ml-2 underline">
                dismiss
              </button>
            )}
          </div>
        )}

        {/* Main area: palette + canvas + panels */}
        <div className="flex flex-1 min-h-0">
          {/* Left: Node palette */}
          <PlaybookNodePalette />

          {/* Center: React Flow canvas */}
          <div className="flex-1 flex min-w-0">
            <div
              className={`${showYaml ? "w-[70%]" : "w-full"} relative`}
              ref={reactFlowWrapper}
            >
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onNodeClick={onNodeClick}
                onPaneClick={onPaneClick}
                onInit={onInit}
                onDragOver={onDragOver}
                onDrop={onDrop}
                nodeTypes={memoNodeTypes}
                isValidConnection={(connection) => isValidConnection(connection, nodes)}
                fitView
                defaultEdgeOptions={{
                  type: "smoothstep",
                  style: { stroke: "#64748b", strokeWidth: 2 },
                }}
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
                    switch (node.type) {
                      case "trigger":
                        return "#22c55e";
                      case "action":
                        return "#3b82f6";
                      case "decision":
                        return "#f59e0b";
                      case "hitlGate":
                        return "#ef4444";
                      case "parallelFork":
                        return "#a855f7";
                      case "end":
                        return "#64748b";
                      default:
                        return "#64748b";
                    }
                  }}
                  maskColor="rgba(15, 23, 42, 0.7)"
                />
                <Background
                  variant={BackgroundVariant.Dots}
                  gap={20}
                  size={1}
                  color="#1e293b"
                />
              </ReactFlow>
            </div>

            {/* Right: YAML preview (toggleable) */}
            {showYaml && (
              <div className="w-[30%]">
                <PlaybookYAMLEditor />
              </div>
            )}
          </div>

          {/* Right: Config panel */}
          {selectedNodeId && <PlaybookConfigPanel />}
        </div>
      </div>
    </div>
  );
}
