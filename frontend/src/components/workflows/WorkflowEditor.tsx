import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
  type OnConnect,
  type ReactFlowInstance,
  addEdge,
  useEdgesState,
  useNodesState,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { AlertTriangle, ArrowLeft, Loader2, Save, Trash2 } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Textarea } from "@/components/ds/textarea";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  createVersion,
  getNodeCatalog,
  getVersion,
  getWorkflow,
  updateVersion,
  type NodeCatalogEntry,
  type WorkflowDefinition,
  type WorkflowVersion,
} from "@/api/workflows";
import { autoLayout } from "@/utils/playbook-graph";

/**
 * Workflow authoring canvas (Phase 4, slice D).
 *
 * Editing model:
 *   - Versions in ``draft`` state are edited in place (PATCH the definition).
 *   - Versions in ``published`` or ``deprecated`` are immutable; saving here
 *     forks them into a NEW draft version (POST /workflows/{id}/versions).
 *     The new version is what the redirect lands on so the analyst can keep
 *     editing.
 *
 * Editor v1 -- deliberate scope:
 *   - Drag-from-palette + drop on canvas; connect edges; delete selected
 *     node(s) or edge(s) via Delete/Backspace or the trash button.
 *   - Per-node config editor is a raw JSON textarea. A per-node-class typed
 *     form generator (one entry per ``input_schema``) is a separate slice
 *     because every engine Node has its own pydantic schema.
 *   - No live compiler validation; you find shape errors when you launch a
 *     run from the detail page.
 */

const CAT_ORDER: string[] = [
  "trigger",
  "integration",
  "reasoning",
  "decision",
  "data",
  "knowledge",
  "output",
];

const CAT_VARIANT: Record<string, "high" | "medium" | "low" | "secondary" | "info"> = {
  trigger: "high",
  integration: "medium",
  reasoning: "info",
  decision: "secondary",
  data: "low",
  knowledge: "low",
  output: "secondary",
};

const DELETE_KEYS = ["Delete", "Backspace"];

interface FlowNodeData extends Record<string, unknown> {
  label: string;
  catalogId: string;
  configJson: string; // textarea source of truth; serialised back on save
}

function definitionToFlow(def: WorkflowDefinition): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = (def.nodes ?? []).map((n) => ({
    id: n.step_id,
    position: { x: 0, y: 0 },
    data: {
      label: n.name || n.node_id,
      catalogId: n.node_id,
      configJson: JSON.stringify(n.config ?? {}, null, 2),
    } satisfies FlowNodeData,
    type: "default",
  }));
  const edges: Edge[] = (def.edges ?? []).map((e, idx) => ({
    id: `${e.source}-${e.target}-${idx}`,
    source: e.source,
    target: e.target,
    label: e.label && e.label !== "next" ? e.label : undefined,
    data: { engineLabel: e.label || "next" },
  }));
  return { nodes: autoLayout(nodes, edges), edges };
}

function flowToDefinition(
  nodes: Node[],
  edges: Edge[],
  prior: WorkflowDefinition,
): { definition: WorkflowDefinition; errors: string[] } {
  const errors: string[] = [];
  const stepIds = new Set<string>();
  const outNodes = nodes.map((n) => {
    const data = n.data as FlowNodeData;
    let config: Record<string, unknown> = {};
    try {
      const raw = data.configJson?.trim() || "{}";
      const parsed = JSON.parse(raw);
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
        config = parsed as Record<string, unknown>;
      } else {
        errors.push(`${n.id}: config must be a JSON object`);
      }
    } catch {
      errors.push(`${n.id}: invalid JSON in config`);
    }
    stepIds.add(n.id);
    return {
      step_id: n.id,
      node_id: data.catalogId,
      name: data.label,
      config,
    };
  });
  const outEdges = edges
    .filter((e) => stepIds.has(e.source) && stepIds.has(e.target))
    .map((e) => ({
      source: e.source,
      target: e.target,
      label:
        (e.data as { engineLabel?: string } | undefined)?.engineLabel ??
        (typeof e.label === "string" && e.label ? e.label : "next"),
    }));
  return {
    definition: {
      name: prior.name || "untitled",
      version: prior.version || "1.0",
      description: prior.description || "",
      trigger: prior.trigger ?? {},
      nodes: outNodes,
      edges: outEdges,
    },
    errors,
  };
}

function uniqueStepId(catalogId: string, used: Set<string>): string {
  // Last dotted segment is the most informative ("greynoise.lookup_ip" -> "lookup_ip").
  const stem = catalogId.split(".").pop() || "step";
  let i = 1;
  while (used.has(`${stem}_${i}`)) i += 1;
  return `${stem}_${i}`;
}

export function WorkflowEditor() {
  const { id, version: versionParam } = useParams<{ id: string; version: string }>();
  const versionNumber = versionParam ? Number(versionParam) : NaN;
  const navigate = useNavigate();

  const [workflowName, setWorkflowName] = useState<string>("");
  const [version, setVersion] = useState<WorkflowVersion | null>(null);
  const [catalog, setCatalog] = useState<NodeCatalogEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);

  const rfInstance = useRef<ReactFlowInstance | null>(null);

  // Load workflow + version + catalog in parallel.
  useEffect(() => {
    if (!id || !Number.isFinite(versionNumber)) return;
    let cancelled = false;
    const run = async () => {
      setLoading(true);
      setError(null);
      try {
        const [wf, v, cat] = await Promise.all([
          getWorkflow(id),
          getVersion(id, versionNumber),
          getNodeCatalog(),
        ]);
        if (cancelled) return;
        setWorkflowName(wf.name);
        setVersion(v);
        setCatalog(cat.items);
        const flow = definitionToFlow(v.definition ?? {});
        setNodes(flow.nodes);
        setEdges(flow.edges);
      } catch (e) {
        if (!cancelled) {
          setError(e instanceof Error ? e.message : "Failed to load editor");
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run();
    return () => {
      cancelled = true;
    };
  }, [id, versionNumber, setNodes, setEdges]);

  const groupedCatalog = useMemo(() => {
    const buckets = new Map<string, NodeCatalogEntry[]>();
    for (const item of catalog) {
      const cat = (item.category as string) || "other";
      const arr = buckets.get(cat) ?? [];
      arr.push(item);
      buckets.set(cat, arr);
    }
    for (const arr of buckets.values()) {
      arr.sort((a, b) => a.name.localeCompare(b.name));
    }
    return [...buckets.entries()].sort(
      (a, b) =>
        (CAT_ORDER.indexOf(a[0]) === -1 ? 999 : CAT_ORDER.indexOf(a[0])) -
        (CAT_ORDER.indexOf(b[0]) === -1 ? 999 : CAT_ORDER.indexOf(b[0])),
    );
  }, [catalog]);

  const onConnect: OnConnect = useCallback(
    (connection) =>
      setEdges((eds) =>
        addEdge(
          { ...connection, data: { engineLabel: "next" } },
          eds,
        ),
      ),
    [setEdges],
  );

  // Palette drag start: stash the catalog id for the drop handler.
  const onPaletteDragStart = useCallback(
    (event: React.DragEvent<HTMLDivElement>, item: NodeCatalogEntry) => {
      event.dataTransfer.setData("application/btagent-node-id", item.id);
      event.dataTransfer.setData("application/btagent-node-name", item.name);
      event.dataTransfer.effectAllowed = "move";
    },
    [],
  );

  const onCanvasDragOver = useCallback((event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    event.dataTransfer.dropEffect = "move";
  }, []);

  const onCanvasDrop = useCallback(
    (event: React.DragEvent<HTMLDivElement>) => {
      event.preventDefault();
      const catalogId = event.dataTransfer.getData("application/btagent-node-id");
      const name =
        event.dataTransfer.getData("application/btagent-node-name") || catalogId;
      if (!catalogId || !rfInstance.current) return;
      const position = rfInstance.current.screenToFlowPosition({
        x: event.clientX,
        y: event.clientY,
      });
      setNodes((existing) => {
        const used = new Set(existing.map((n) => n.id));
        const stepId = uniqueStepId(catalogId, used);
        const newNode: Node = {
          id: stepId,
          position,
          data: { label: name, catalogId, configJson: "{}" } satisfies FlowNodeData,
          type: "default",
        };
        return [...existing, newNode];
      });
    },
    [setNodes],
  );

  const onCanvasKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (!DELETE_KEYS.includes(event.key)) return;
      const target = event.target as HTMLElement | null;
      // Don't swallow Backspace while the user is typing in the config panel etc.
      if (
        target &&
        (target.tagName === "INPUT" ||
          target.tagName === "TEXTAREA" ||
          target.isContentEditable)
      ) {
        return;
      }
      setNodes((ns) => ns.filter((n) => !n.selected));
      setEdges((es) => es.filter((e) => !e.selected));
    },
    [setNodes, setEdges],
  );

  const selectedNode = useMemo(
    () => (selectedNodeId ? nodes.find((n) => n.id === selectedNodeId) ?? null : null),
    [selectedNodeId, nodes],
  );

  const onPanelNameChange = useCallback(
    (label: string) => {
      if (!selectedNodeId) return;
      setNodes((ns) =>
        ns.map((n) =>
          n.id === selectedNodeId
            ? { ...n, data: { ...(n.data as FlowNodeData), label } }
            : n,
        ),
      );
    },
    [selectedNodeId, setNodes],
  );

  const onPanelStepIdChange = useCallback(
    (newId: string) => {
      if (!selectedNodeId || !newId.trim() || newId === selectedNodeId) return;
      // Rename: replace the node id + rewrite any edges that pointed to/from it.
      setNodes((ns) =>
        ns.map((n) => (n.id === selectedNodeId ? { ...n, id: newId } : n)),
      );
      setEdges((es) =>
        es.map((e) => ({
          ...e,
          source: e.source === selectedNodeId ? newId : e.source,
          target: e.target === selectedNodeId ? newId : e.target,
        })),
      );
      setSelectedNodeId(newId);
    },
    [selectedNodeId, setNodes, setEdges],
  );

  const onPanelConfigChange = useCallback(
    (configJson: string) => {
      if (!selectedNodeId) return;
      setNodes((ns) =>
        ns.map((n) =>
          n.id === selectedNodeId
            ? { ...n, data: { ...(n.data as FlowNodeData), configJson } }
            : n,
        ),
      );
    },
    [selectedNodeId, setNodes],
  );

  const onPanelDelete = useCallback(() => {
    if (!selectedNodeId) return;
    setNodes((ns) => ns.filter((n) => n.id !== selectedNodeId));
    setEdges((es) =>
      es.filter((e) => e.source !== selectedNodeId && e.target !== selectedNodeId),
    );
    setSelectedNodeId(null);
  }, [selectedNodeId, setNodes, setEdges]);

  const handleSave = useCallback(async () => {
    if (!id || !version) return;
    setSaving(true);
    setSaveError(null);
    try {
      const { definition, errors } = flowToDefinition(
        nodes,
        edges,
        version.definition ?? {},
      );
      if (errors.length > 0) {
        throw new Error(`Fix config JSON before saving: ${errors.join("; ")}`);
      }
      if (version.state === "draft") {
        const updated = await updateVersion(id, version.version_number, { definition });
        setVersion(updated);
      } else {
        const created = await createVersion(id, { definition });
        setVersion(created);
        navigate(`/workflows/${id}/versions/${created.version_number}/edit`);
      }
    } catch (e) {
      setSaveError(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSaving(false);
    }
  }, [id, version, nodes, edges, navigate]);

  if (!id || !Number.isFinite(versionNumber)) {
    return (
      <>
        <Header title="Workflow editor" />
        <div className="p-6 text-sm text-destructive">Bad URL — missing id or version.</div>
      </>
    );
  }

  const editingDraft = version?.state === "draft";

  return (
    <>
      <Header title={workflowName ? `${workflowName} — edit` : "Workflow editor"} />
      <div
        className="flex-1 flex flex-col"
        data-testid="workflow-editor"
        tabIndex={0}
        onKeyDown={onCanvasKeyDown}
      >
        {/* Toolbar */}
        <div className="flex items-center gap-3 px-6 py-3 border-b border-border">
          <Button variant="ghost" size="sm" onClick={() => navigate(`/workflows/${id}`)}>
            <ArrowLeft className="w-4 h-4 mr-1.5" />
            Back
          </Button>
          {version && (
            <>
              <span className="text-sm font-medium">v{version.version_number}</span>
              <Badge variant={editingDraft ? "medium" : "secondary"}>
                {version.state}
              </Badge>
              {!editingDraft && (
                <Badge variant="outline" className="gap-1">
                  <AlertTriangle className="w-3 h-3" />
                  saving will fork a new draft
                </Badge>
              )}
              <span className="text-xs text-muted-foreground">
                {nodes.length} node(s), {edges.length} edge(s)
              </span>
            </>
          )}
          <div className="ml-auto flex items-center gap-2">
            <Button
              onClick={handleSave}
              disabled={!version || saving}
              data-testid="workflow-editor-save"
            >
              {saving ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" /> Saving…
                </>
              ) : (
                <>
                  <Save className="w-4 h-4 mr-2" />
                  {editingDraft ? "Save draft" : "Save as new draft"}
                </>
              )}
            </Button>
          </div>
        </div>

        {saveError && (
          <div
            className="mx-6 mt-3 rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
            role="alert"
            data-testid="workflow-editor-save-error"
          >
            {saveError}
          </div>
        )}
        {error && (
          <div
            className="mx-6 mt-3 rounded-md border border-destructive/30 bg-destructive/10 p-2.5 text-sm text-destructive"
            role="alert"
          >
            {error}
          </div>
        )}

        {loading ? (
          <div className="flex items-center gap-2 text-muted-foreground text-sm p-6">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        ) : (
          <div className="flex-1 flex min-h-0">
            {/* Palette */}
            <aside
              className="w-64 border-r border-border overflow-y-auto"
              data-testid="workflow-editor-palette"
            >
              <div className="p-3">
                <p className="text-xs font-semibold text-muted-foreground uppercase">
                  Node palette
                </p>
                <p className="text-xs text-muted-foreground mt-1">
                  Drag onto the canvas. {catalog.length} nodes registered.
                </p>
              </div>
              <div className="px-3 pb-6 space-y-4">
                {groupedCatalog.map(([category, items]) => (
                  <PaletteSection
                    key={category}
                    category={category}
                    items={items}
                    onDragStart={onPaletteDragStart}
                  />
                ))}
              </div>
            </aside>

            {/* Canvas */}
            <div
              className="flex-1 bg-background relative"
              onDragOver={onCanvasDragOver}
              onDrop={onCanvasDrop}
              data-testid="workflow-editor-canvas"
            >
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                onInit={(inst) => {
                  rfInstance.current = inst;
                }}
                onNodeClick={(_, node) => setSelectedNodeId(node.id)}
                onPaneClick={() => setSelectedNodeId(null)}
                fitView
                fitViewOptions={{ padding: 0.2 }}
                proOptions={{ hideAttribution: true }}
              >
                <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
                <Controls />
                <MiniMap pannable zoomable />
              </ReactFlow>
            </div>

            {/* Config panel */}
            <aside
              className="w-80 border-l border-border overflow-y-auto"
              data-testid="workflow-editor-config-panel"
            >
              {selectedNode ? (
                <NodeConfigPanel
                  node={selectedNode}
                  onNameChange={onPanelNameChange}
                  onStepIdChange={onPanelStepIdChange}
                  onConfigChange={onPanelConfigChange}
                  onDelete={onPanelDelete}
                />
              ) : (
                <div className="p-4 text-sm text-muted-foreground">
                  <p className="font-semibold text-foreground mb-1">No node selected</p>
                  <p>Click a node on the canvas to edit its name, step id, and config.</p>
                  <p className="mt-2">
                    Delete / Backspace removes the current selection (nodes or edges).
                  </p>
                </div>
              )}
            </aside>
          </div>
        )}
      </div>
    </>
  );
}

interface PaletteSectionProps {
  category: string;
  items: NodeCatalogEntry[];
  onDragStart: (
    event: React.DragEvent<HTMLDivElement>,
    item: NodeCatalogEntry,
  ) => void;
}

function PaletteSection({ category, items, onDragStart }: PaletteSectionProps) {
  return (
    <Card>
      <CardHeader className="py-3">
        <CardTitle className="text-xs uppercase tracking-wide flex items-center gap-2">
          <Badge variant={CAT_VARIANT[category] ?? "secondary"}>{category}</Badge>
          <span className="text-muted-foreground normal-case font-normal">
            {items.length}
          </span>
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-1.5 pt-0">
        {items.map((item) => (
          <div
            key={item.id}
            draggable
            onDragStart={(e) => onDragStart(e, item)}
            className="rounded-md border border-border p-2 text-xs cursor-grab hover:border-primary/40 hover:bg-accent/40 transition-colors"
            data-testid="palette-item"
            data-node-id={item.id}
            title={item.description || item.id}
          >
            <p className="font-medium text-foreground">{item.name}</p>
            <p className="text-muted-foreground font-mono truncate">{item.id}</p>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}

interface NodeConfigPanelProps {
  node: Node;
  onNameChange: (label: string) => void;
  onStepIdChange: (id: string) => void;
  onConfigChange: (json: string) => void;
  onDelete: () => void;
}

function NodeConfigPanel({
  node,
  onNameChange,
  onStepIdChange,
  onConfigChange,
  onDelete,
}: NodeConfigPanelProps) {
  const data = node.data as FlowNodeData;
  const [stepIdDraft, setStepIdDraft] = useState(node.id);
  // Keep the controlled draft in sync when a different node is selected.
  useEffect(() => {
    setStepIdDraft(node.id);
  }, [node.id]);

  return (
    <div className="p-4 space-y-3" data-testid="workflow-editor-config-form">
      <div className="flex items-start gap-2">
        <div className="flex-1 space-y-1.5">
          <p className="text-xs font-semibold text-muted-foreground uppercase">Selected</p>
          <p className="text-sm font-mono break-all">{data.catalogId}</p>
        </div>
        <Button
          variant="ghost"
          size="sm"
          onClick={onDelete}
          data-testid="workflow-editor-delete-node"
          aria-label="Delete node"
        >
          <Trash2 className="w-4 h-4 text-destructive" />
        </Button>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="node-step-id">Step id</Label>
        <Input
          id="node-step-id"
          value={stepIdDraft}
          onChange={(e) => setStepIdDraft(e.target.value)}
          onBlur={() => onStepIdChange(stepIdDraft.trim() || node.id)}
          data-testid="workflow-editor-step-id"
        />
        <p className="text-xs text-muted-foreground">
          Unique within the workflow. Edge endpoints update automatically when renamed.
        </p>
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="node-label">Display name</Label>
        <Input
          id="node-label"
          value={data.label}
          onChange={(e) => onNameChange(e.target.value)}
        />
      </div>
      <div className="space-y-1.5">
        <Label htmlFor="node-config">Config (JSON)</Label>
        <Textarea
          id="node-config"
          value={data.configJson}
          onChange={(e) => onConfigChange(e.target.value)}
          rows={10}
          className="font-mono text-xs"
          data-testid="workflow-editor-config-json"
        />
        <p className="text-xs text-muted-foreground">
          Raw config. Validated against the node's input_schema only at run time.
        </p>
      </div>
    </div>
  );
}
