/**
 * Live OAuth-grant graph (#116 Phase C).
 *
 * Renders the principal × app grant graph from the live
 * ``GET /api/v1/identity/grants`` endpoint as an interactive node-link diagram
 * via @xyflow/react (already a dependency — used by the playbook builder).
 *
 * The pure ``buildGrantGraph`` helper in ``identityStore`` does the layout +
 * edge derivation (unit-tested without a DOM); this component is the thin
 * presentational shell that maps that output onto ReactFlow nodes/edges and
 * styles edges by consent type / revocation.
 *
 * Replaces the static Phase-B ``GrantTable`` (which derived the same data
 * client-side from finding evidence) with the live, server-derived graph.
 */

import { useMemo } from "react";
import {
  ReactFlow,
  Background,
  BackgroundVariant,
  Controls,
  Position,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { KeyRound, Loader2 } from "lucide-react";

import { buildGrantGraph } from "@/stores/identityStore";
import type { OAuthGrant, OAuthConsentType } from "@/types/identity_hunt";

/** Edge colour by consent type — pre_authorized is the highest-risk signal. */
const CONSENT_EDGE_COLOR: Record<OAuthConsentType, string> = {
  pre_authorized: "#fb7185", // rose-400
  admin: "#a78bfa", // violet-400
  user: "#60a5fa", // blue-400
  unknown: "#64748b", // slate-500
};

// Assumed session→principal edges use a distinct amber, dashed, non-animated
// style so they read as "inferred linkage", not a consented grant.
const ASSUMED_EDGE_COLOR = "#fbbf24"; // amber-400

function nodeStyle(kind: "principal" | "app" | "session"): React.CSSProperties {
  const base: React.CSSProperties = {
    fontSize: 11,
    padding: "6px 10px",
    borderRadius: 8,
    border: "1px solid",
    color: "#e2e8f0",
    maxWidth: 220,
  };
  if (kind === "principal") {
    return { ...base, background: "rgba(8,145,178,0.15)", borderColor: "rgba(34,211,238,0.4)" };
  }
  if (kind === "session") {
    // Sessions get an amber, dashed border to distinguish the inferred layer.
    return {
      ...base,
      background: "rgba(120,53,15,0.18)",
      borderColor: "rgba(251,191,36,0.45)",
      borderStyle: "dashed",
    };
  }
  return { ...base, background: "rgba(30,41,59,0.6)", borderColor: "rgba(100,116,139,0.4)" };
}

export function IdentityGrantsGraph({
  grants,
  loading,
  error,
}: {
  grants: OAuthGrant[];
  loading: boolean;
  error: string | null;
}) {
  const { nodes, edges } = useMemo(() => {
    const graph = buildGrantGraph(grants);
    const rfNodes: Node[] = graph.nodes.map((n) => ({
      id: n.id,
      position: n.position,
      data: { label: n.label },
      style: nodeStyle(n.kind),
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
    }));
    const rfEdges: Edge[] = graph.edges.map((e) => {
      const assumed = e.relation === "assumed";
      return {
        id: e.id,
        source: e.source,
        target: e.target,
        // Assumed session edges carry no scope semantics — label them instead.
        label: assumed
          ? "session"
          : e.scope_count > 0
            ? `${e.scope_count} scope${e.scope_count === 1 ? "" : "s"}`
            : undefined,
        animated: !assumed && !e.revoked,
        style: {
          stroke: assumed
            ? ASSUMED_EDGE_COLOR
            : (CONSENT_EDGE_COLOR[e.consent_type] ?? CONSENT_EDGE_COLOR.unknown),
          strokeWidth: 1.5,
          strokeDasharray: assumed || e.revoked ? "4 3" : undefined,
          opacity: e.revoked ? 0.5 : 1,
        },
        labelStyle: { fontSize: 9, fill: assumed ? "#fbbf24" : "#94a3b8" },
      };
    });
    return { nodes: rfNodes, edges: rfEdges };
  }, [grants]);

  return (
    <section
      className="rounded-lg border border-slate-700/50 bg-slate-800/30"
      data-testid="identity-grant-graph"
    >
      <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-700/50">
        <KeyRound className="w-4 h-4 text-cyan-400" />
        <h2 className="text-sm font-semibold text-slate-200">OAuth grant graph</h2>
        <span className="text-xs text-slate-500">
          (live · principal → app · {grants.length} grant{grants.length === 1 ? "" : "s"})
        </span>
        {loading && <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-500" />}
      </div>

      {error ? (
        <p className="px-4 py-6 text-xs text-destructive" role="alert">
          {error}
        </p>
      ) : nodes.length === 0 ? (
        <p
          className="px-4 py-6 text-xs text-slate-500"
          data-testid="identity-grant-graph-empty"
        >
          No OAuth grants found in the current identity findings.
        </p>
      ) : (
        <div style={{ height: 360 }} data-testid="identity-grant-graph-canvas">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            fitView
            nodesDraggable={false}
            nodesConnectable={false}
            elementsSelectable={false}
            proOptions={{ hideAttribution: true }}
          >
            <Background variant={BackgroundVariant.Dots} gap={16} size={1} />
            <Controls showInteractive={false} />
          </ReactFlow>
        </div>
      )}
    </section>
  );
}
