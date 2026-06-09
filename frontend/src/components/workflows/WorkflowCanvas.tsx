import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import {
  Background,
  BackgroundVariant,
  Controls,
  MiniMap,
  ReactFlow,
  type Edge,
  type Node,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { ArrowLeft, Loader2 } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { getVersion, getWorkflow, type WorkflowVersion } from "@/api/workflows";
import { autoLayout } from "@/utils/playbook-graph";

/**
 * Read-only canvas for a workflow version's definition (Phase 4, slice C).
 *
 * Loads ``version.definition`` and renders its engine graph nodes/edges with
 * a simple top-to-bottom auto-layout. Editing (palette, drag/drop, config
 * panel, save-as-new-draft) is slice D. Keeping this read-only first lets us
 * validate node-id resolution + layout against real definitions before
 * exposing a write path.
 */

function definitionToFlow(version: WorkflowVersion): { nodes: Node[]; edges: Edge[] } {
  const def = version.definition ?? {};
  const nodes: Node[] = (def.nodes ?? []).map((n) => ({
    id: n.step_id,
    position: { x: 0, y: 0 }, // overridden by autoLayout below
    data: { label: n.name || n.node_id, nodeId: n.node_id, config: n.config },
    // Plain default ReactFlow nodes — slice D will swap to category-typed nodes.
    type: "default",
  }));
  const edges: Edge[] = (def.edges ?? []).map((e, idx) => ({
    id: `${e.source}-${e.target}-${idx}`,
    source: e.source,
    target: e.target,
    label: e.label && e.label !== "next" ? e.label : undefined,
  }));
  return { nodes: autoLayout(nodes, edges), edges };
}

export function WorkflowCanvas() {
  const { id, version: versionParam } = useParams<{ id: string; version: string }>();
  const versionNumber = versionParam ? Number(versionParam) : NaN;
  const navigate = useNavigate();

  const [workflowName, setWorkflowName] = useState<string>("");
  const [version, setVersion] = useState<WorkflowVersion | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!id || !Number.isFinite(versionNumber)) return;
    setLoading(true);
    setError(null);
    try {
      const [wf, v] = await Promise.all([getWorkflow(id), getVersion(id, versionNumber)]);
      setWorkflowName(wf.name);
      setVersion(v);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load workflow version");
    } finally {
      setLoading(false);
    }
  }, [id, versionNumber]);

  useEffect(() => {
    void load();
  }, [load]);

  const flow = useMemo(() => (version ? definitionToFlow(version) : null), [version]);

  if (!id || !Number.isFinite(versionNumber)) {
    return (
      <>
        <Header title="Workflow canvas" />
        <div className="p-6 text-sm text-destructive">Bad URL — missing id or version.</div>
      </>
    );
  }

  return (
    <>
      <Header title={workflowName ? `${workflowName} — canvas` : "Workflow canvas"} />
      <div className="flex-1 flex flex-col" data-testid="workflow-canvas">
        <div className="flex items-center gap-3 px-6 py-3 border-b border-border">
          <Button variant="ghost" size="sm" onClick={() => navigate(`/workflows/${id}`)}>
            <ArrowLeft className="w-4 h-4 mr-1.5" />
            Back
          </Button>
          {version && (
            <>
              <span className="text-sm font-medium">v{version.version_number}</span>
              <Badge
                variant={
                  version.state === "published"
                    ? "high"
                    : version.state === "draft"
                      ? "medium"
                      : "secondary"
                }
              >
                {version.state}
              </Badge>
              <span className="text-xs text-muted-foreground">
                {(version.definition?.nodes?.length ?? 0)} node(s),{" "}
                {(version.definition?.edges?.length ?? 0)} edge(s)
              </span>
            </>
          )}
          <Badge variant="outline" className="ml-auto">
            read-only
          </Badge>
        </div>

        {loading && (
          <div className="flex items-center gap-2 text-muted-foreground text-sm p-6">
            <Loader2 className="w-4 h-4 animate-spin" /> Loading…
          </div>
        )}
        {error && (
          <div
            className="m-6 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {error}
          </div>
        )}

        {flow && (flow.nodes.length === 0 ? (
          <div className="p-6 text-sm text-muted-foreground" data-testid="workflow-canvas-empty">
            This version has no nodes yet. Authoring (drag/drop palette + save as new
            draft) lands in slice D.
          </div>
        ) : (
          <div
            className="flex-1 bg-background"
            style={{ minHeight: 400 }}
            data-testid="workflow-canvas-flow"
          >
            <ReactFlow
              nodes={flow.nodes}
              edges={flow.edges}
              fitView
              fitViewOptions={{ padding: 0.2 }}
              nodesDraggable={false}
              nodesConnectable={false}
              edgesFocusable={false}
              elementsSelectable={false}
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
              <Controls showInteractive={false} />
              <MiniMap pannable zoomable />
            </ReactFlow>
          </div>
        ))}
      </div>
    </>
  );
}
