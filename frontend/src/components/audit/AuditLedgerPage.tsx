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
  type AuditEntry,
  type ChainVerify,
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
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [list, chain] = await Promise.all([
        listAuditEntries({ limit: 100 }),
        verifyAuditChain(),
      ]);
      setEntries(list.items);
      setVerify(chain);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load audit ledger");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

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
      </div>
    </>
  );
}
