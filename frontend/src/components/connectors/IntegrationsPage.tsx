import { useState, useEffect, useCallback } from "react";
import { Loader2, Plug, ShieldAlert, ChevronDown, ChevronRight } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  listConnectors,
  getConnector,
  type ConnectorSummary,
  type ConnectorManifest,
  type Capability,
} from "@/api/connectors";

const TLP_VARIANT: Record<string, "destructive" | "high" | "medium" | "low"> = {
  red: "destructive",
  amber_strict: "high",
  amber: "medium",
  green: "low",
  white: "low",
};

function CapabilityRow({ cap }: { cap: Capability }) {
  return (
    <div
      className="flex flex-col gap-1 border-t border-border/50 py-2 text-sm"
      data-testid={`capability-${cap.id}`}
    >
      <div className="flex flex-wrap items-center gap-2">
        <code className="font-mono text-xs">{cap.id}</code>
        <Badge variant="low">{cap.kind}</Badge>
        <Badge variant={TLP_VARIANT[cap.tlp_egress] ?? "low"}>tlp:{cap.tlp_egress}</Badge>
        {cap.hitl_required && (
          <Badge variant="destructive" data-testid={`hitl-${cap.id}`}>
            <ShieldAlert className="mr-1 h-3 w-3" />
            HITL
          </Badge>
        )}
        {cap.kind === "action" && cap.blast_radius && (
          <Badge variant="medium">blast:{cap.blast_radius}</Badge>
        )}
      </div>
      {cap.description && <p className="text-muted-foreground">{cap.description}</p>}
      {cap.ocsf_emits.length > 0 && (
        <div className="flex flex-wrap gap-1">
          {cap.ocsf_emits.map((c) => (
            <Badge key={c} variant="low" className="font-mono text-[10px]">
              {c}
            </Badge>
          ))}
        </div>
      )}
    </div>
  );
}

function ConnectorCard({ summary }: { summary: ConnectorSummary }) {
  const [expanded, setExpanded] = useState(false);
  const [manifest, setManifest] = useState<ConnectorManifest | null>(null);
  const [loadingDetail, setLoadingDetail] = useState(false);

  const toggle = useCallback(async () => {
    const next = !expanded;
    setExpanded(next);
    if (next && manifest === null) {
      setLoadingDetail(true);
      try {
        setManifest(await getConnector(summary.name));
      } finally {
        setLoadingDetail(false);
      }
    }
  }, [expanded, manifest, summary.name]);

  const caps: Capability[] = manifest
    ? [...manifest.queries, ...manifest.actions, ...manifest.streams]
    : [];

  return (
    <Card data-testid={`connector-card-${summary.name}`}>
      <CardHeader>
        <button
          type="button"
          onClick={toggle}
          className="flex w-full items-start justify-between gap-3 text-left"
          data-testid={`connector-toggle-${summary.name}`}
          aria-expanded={expanded}
        >
          <div className="flex flex-col gap-1">
            <CardTitle className="flex items-center gap-2">
              {expanded ? (
                <ChevronDown className="h-4 w-4" />
              ) : (
                <ChevronRight className="h-4 w-4" />
              )}
              {summary.name}
              <span className="text-xs font-normal text-muted-foreground">
                v{summary.version}
              </span>
            </CardTitle>
            <CardDescription>{summary.description}</CardDescription>
          </div>
          <div className="flex shrink-0 flex-wrap justify-end gap-1">
            <Badge variant="low">{summary.transport}</Badge>
            <Badge variant="low">auth:{summary.auth}</Badge>
            <Badge variant="medium">
              {summary.query_count}Q · {summary.action_count}A · {summary.stream_count}S
            </Badge>
            {summary.has_hitl_actions && (
              <Badge variant="destructive" data-testid={`card-hitl-${summary.name}`}>
                HITL
              </Badge>
            )}
          </div>
        </button>
      </CardHeader>
      {expanded && (
        <CardContent data-testid={`connector-detail-${summary.name}`}>
          {loadingDetail ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" /> Loading capabilities…
            </div>
          ) : (
            <div>
              {caps.map((cap) => (
                <CapabilityRow key={`${cap.kind}-${cap.id}`} cap={cap} />
              ))}
            </div>
          )}
        </CardContent>
      )}
    </Card>
  );
}

export function IntegrationsPage() {
  const [connectors, setConnectors] = useState<ConnectorSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [actionsOnly, setActionsOnly] = useState(false);

  const load = useCallback(async (hasActions?: boolean) => {
    setLoading(true);
    setError(null);
    try {
      const resp = await listConnectors(
        hasActions ? { hasActions: true } : undefined,
      );
      setConnectors(resp.items);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load connectors");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const onToggleActionsOnly = useCallback(() => {
    const next = !actionsOnly;
    setActionsOnly(next);
    void load(next ? true : undefined);
  }, [actionsOnly, load]);

  return (
    <div className="flex flex-col h-full">
      <Header title="Integrations" />
      <div className="flex-1 overflow-y-auto p-6">
        <div className="mx-auto max-w-4xl space-y-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Plug className="h-4 w-4" />
              <span data-testid="connector-count">
                {connectors.length} connector{connectors.length === 1 ? "" : "s"} installed
              </span>
            </div>
            <label className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={actionsOnly}
                onChange={onToggleActionsOnly}
                data-testid="filter-actions-only"
              />
              Action-capable only
            </label>
          </div>

          {loading && (
            <div
              className="flex items-center gap-2 text-sm text-muted-foreground"
              data-testid="connectors-loading"
            >
              <Loader2 className="h-4 w-4 animate-spin" /> Loading connectors…
            </div>
          )}

          {error && (
            <div className="text-sm text-destructive" data-testid="connectors-error">
              {error}
            </div>
          )}

          {!loading && !error && connectors.length === 0 && (
            <div className="text-sm text-muted-foreground" data-testid="connectors-empty">
              No connectors match the current filter.
            </div>
          )}

          {!loading &&
            !error &&
            connectors.map((c) => <ConnectorCard key={c.name} summary={c} />)}
        </div>
      </div>
    </div>
  );
}
