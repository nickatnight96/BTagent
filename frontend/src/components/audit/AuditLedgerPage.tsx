import { useState, useEffect, useCallback } from "react";
import { ShieldCheck, ShieldAlert, RefreshCw, Loader2 } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  listAuditEntries,
  verifyAuditChain,
  getAuditLineage,
  type AuditEntry,
  type ChainVerify,
  type LineageGraph,
} from "@/api/audit";

const CATEGORY_VARIANT: Record<string, "secondary" | "info" | "medium" | "destructive"> = {
  authentication: "info",
  authorization: "info",
  investigation: "secondary",
  containment: "destructive",
  config_change: "medium",
  agent_action: "secondary",
  data_access: "info",
};

export function AuditLedgerPage() {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [verify, setVerify] = useState<ChainVerify | null>(null);
  const [lineage, setLineage] = useState<LineageGraph | null>(null);
  const [replayCutoff, setReplayCutoff] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async (upToHash?: string | null) => {
    setLoading(true);
    setError(null);
    try {
      const [list, chain, graph] = await Promise.all([
        listAuditEntries({ limit: 100 }),
        verifyAuditChain(),
        getAuditLineage(upToHash ?? undefined),
      ]);
      setEntries(list.items);
      setVerify(chain);
      setLineage(graph);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load audit ledger");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load(replayCutoff);
  }, [load, replayCutoff]);

  return (
    <>
      <Header title="Audit Ledger" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="audit-ledger">
        {/* Chain integrity banner */}
        {verify && (
          <Card className={verify.valid ? "border-severity-low/40" : "border-destructive/40"}>
            <CardContent className="flex items-center justify-between py-4">
              <div className="flex items-center gap-3">
                {verify.valid ? (
                  <ShieldCheck className="w-7 h-7 text-severity-low shrink-0" />
                ) : (
                  <ShieldAlert className="w-7 h-7 text-destructive shrink-0" />
                )}
                <div>
                  <p className="font-semibold text-foreground">
                    {verify.valid
                      ? "Hash chain verified — ledger is tamper-evident and intact"
                      : `Chain integrity FAILED — ${verify.errors.length} error(s)`}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    SHA-256 append-only chain · 7-year retention
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button variant="ghost" size="sm" onClick={load} disabled={loading}>
                  {loading ? (
                    <Loader2 className="w-4 h-4 animate-spin" />
                  ) : (
                    <RefreshCw className="w-4 h-4" />
                  )}
                </Button>
                <a href="/api/v1/audit/export" download>
                  <Button variant="outline" size="sm">
                    Export CSV
                  </Button>
                </a>
              </div>
            </CardContent>
          </Card>
        )}

        {error && (
          <div
            className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
            role="alert"
          >
            {error}
          </div>
        )}

        {/* Entries */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Lineage entries</CardTitle>
            <CardDescription>
              Newest first. Every prompt, action, and decision is appended to the
              chain with its predecessor's hash.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto rounded-md border border-border">
              <table className="w-full text-xs" data-testid="audit-table">
                <thead className="bg-card sticky top-0">
                  <tr className="text-left text-muted-foreground">
                    <th className="px-2 py-2 font-medium">#</th>
                    <th className="px-2 py-2 font-medium">Timestamp</th>
                    <th className="px-2 py-2 font-medium">Actor</th>
                    <th className="px-2 py-2 font-medium">Category</th>
                    <th className="px-2 py-2 font-medium">Action</th>
                    <th className="px-2 py-2 font-medium">Outcome</th>
                    <th className="px-2 py-2 font-medium">Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((e) => (
                    <tr key={e.id} className="border-t border-border/40">
                      <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                        {e.seq}
                      </td>
                      <td className="px-2 py-1.5 whitespace-nowrap text-foreground">
                        {new Date(e.timestamp).toLocaleString()}
                      </td>
                      <td className="px-2 py-1.5 font-mono">{e.actor}</td>
                      <td className="px-2 py-1.5">
                        <Badge variant={CATEGORY_VARIANT[e.category] ?? "secondary"}>
                          {e.category}
                        </Badge>
                      </td>
                      <td className="px-2 py-1.5">{e.action}</td>
                      <td className="px-2 py-1.5">
                        <Badge
                          variant={e.outcome === "success" ? "low" : "destructive"}
                        >
                          {e.outcome}
                        </Badge>
                      </td>
                      <td className="px-2 py-1.5 font-mono text-muted-foreground">
                        {e.hash.slice(0, 12)}…
                      </td>
                    </tr>
                  ))}
                  {entries.length === 0 && !loading && (
                    <tr>
                      <td colSpan={7} className="px-2 py-8 text-center text-muted-foreground">
                        No audit entries.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* Lineage graph — UC-7.1 */}
        {lineage && (
          <Card data-testid="audit-lineage">
            <CardHeader>
              <CardTitle className="text-base flex items-center justify-between">
                <span>
                  Lineage graph — {lineage.nodes.length} node
                  {lineage.nodes.length === 1 ? "" : "s"} ·{" "}
                  {lineage.edges.length} edge{lineage.edges.length === 1 ? "" : "s"}
                </span>
                {replayCutoff && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setReplayCutoff(null)}
                    data-testid="lineage-clear-replay"
                  >
                    Clear replay
                  </Button>
                )}
              </CardTitle>
              <CardDescription>
                Each row is one chain link; click <em>Replay to here</em> to view
                the chain prefix as it stood when that entry was appended.
                {!lineage.intact && (
                  <span className="block mt-1 text-destructive">
                    Chain integrity break detected at{" "}
                    <span className="font-mono">{lineage.broken_at?.slice(0, 12)}…</span>
                  </span>
                )}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto rounded-md border border-border">
                <table className="w-full text-xs" data-testid="audit-lineage-table">
                  <thead className="bg-card sticky top-0">
                    <tr className="text-left text-muted-foreground">
                      <th className="px-2 py-2 font-medium">#</th>
                      <th className="px-2 py-2 font-medium">Action</th>
                      <th className="px-2 py-2 font-medium">Actor</th>
                      <th className="px-2 py-2 font-medium">Parent → Hash</th>
                      <th className="px-2 py-2 font-medium text-right" />
                    </tr>
                  </thead>
                  <tbody>
                    {lineage.nodes.map((n) => {
                      const broken = lineage.broken_at === n.id;
                      return (
                        <tr
                          key={n.id}
                          className={
                            broken
                              ? "border-t border-destructive/50 bg-destructive/5"
                              : "border-t border-border/40"
                          }
                        >
                          <td className="px-2 py-1.5 tabular-nums text-muted-foreground">
                            {n.sequence}
                          </td>
                          <td className="px-2 py-1.5">{n.action}</td>
                          <td className="px-2 py-1.5 font-mono">{n.actor}</td>
                          <td className="px-2 py-1.5 font-mono text-muted-foreground">
                            {n.sequence === 0 ? (
                              <span>genesis → {n.id.slice(0, 12)}…</span>
                            ) : (
                              <span>
                                {n.prev_hash.slice(0, 8)}… → {n.id.slice(0, 12)}…
                              </span>
                            )}
                          </td>
                          <td className="px-2 py-1.5 text-right">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => setReplayCutoff(n.id)}
                              disabled={replayCutoff === n.id}
                              data-testid={`lineage-replay-${n.sequence}`}
                            >
                              {replayCutoff === n.id ? "Replaying" : "Replay to here"}
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                    {lineage.nodes.length === 0 && (
                      <tr>
                        <td
                          colSpan={5}
                          className="px-2 py-8 text-center text-muted-foreground"
                        >
                          No lineage to show.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </>
  );
}
