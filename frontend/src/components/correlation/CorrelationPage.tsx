import { useState, useCallback } from "react";
import { Loader2, Workflow, ArrowRight } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import { NativeSelect } from "@/components/ds/native-select";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import { correlateEntity, type CorrelationTimeline } from "@/api/correlation";

const ENTITY_TYPES = [
  { value: "ip", label: "IP address" },
  { value: "domain", label: "Domain" },
  { value: "hash_sha256", label: "SHA256 hash" },
  { value: "other", label: "User / host (other)" },
];

export function CorrelationPage() {
  const [entityType, setEntityType] = useState("ip");
  const [entityValue, setEntityValue] = useState("");
  const [timeline, setTimeline] = useState<CorrelationTimeline | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleCorrelate = useCallback(async () => {
    if (!entityValue.trim()) return;
    setLoading(true);
    setError(null);
    setTimeline(null);
    try {
      const tl = await correlateEntity({
        entity_type: entityType,
        entity_value: entityValue.trim(),
      });
      setTimeline(tl);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Correlation failed");
    } finally {
      setLoading(false);
    }
  }, [entityType, entityValue]);

  return (
    <>
      <Header title="Correlation Workbench" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="correlation">
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Workflow className="w-5 h-5 text-primary" />
              Cross-Platform IOC Pivot
            </CardTitle>
            <CardDescription>
              Enter an entity. The agent fans out across SIEM, EDR, firewall, and
              identity, normalizes field names + timestamps into one timeline, tags
              MITRE techniques, and suggests next pivots. (Read-only — L1.)
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
              <div className="space-y-1.5">
                <Label htmlFor="entity-type">Entity type</Label>
                <NativeSelect
                  id="entity-type"
                  value={entityType}
                  onChange={(e) => setEntityType(e.target.value)}
                  className="sm:w-48"
                >
                  {ENTITY_TYPES.map((t) => (
                    <option key={t.value} value={t.value}>
                      {t.label}
                    </option>
                  ))}
                </NativeSelect>
              </div>
              <div className="space-y-1.5 flex-1">
                <Label htmlFor="entity-value">Entity value</Label>
                <Input
                  id="entity-value"
                  value={entityValue}
                  onChange={(e) => setEntityValue(e.target.value)}
                  placeholder="e.g. 10.1.42.17"
                  data-testid="correlation-input"
                />
              </div>
              <Button onClick={handleCorrelate} disabled={loading || !entityValue.trim()}>
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Correlating…
                  </>
                ) : (
                  "Correlate"
                )}
              </Button>
            </div>
            <div className="mt-2">
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setEntityType("ip");
                  setEntityValue("10.1.42.17");
                }}
                disabled={loading}
              >
                Use sample entity (10.1.42.17)
              </Button>
            </div>
            {error && (
              <div
                className="mt-3 rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                role="alert"
              >
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        {timeline && (
          <div className="space-y-6" data-testid="correlation-result">
            {/* Sources */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">
                  Unified timeline — {timeline.events.length} events across{" "}
                  {timeline.sources_queried.length} sources
                </CardTitle>
                <CardDescription>
                  Field names + timestamps normalized to one OCSF-aligned shape.
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2 mb-3">
                  {timeline.sources_queried.map((s) => (
                    <Badge key={s} variant="secondary">
                      {s}
                    </Badge>
                  ))}
                </div>
                <div className="overflow-x-auto rounded-md border border-border">
                  <table className="w-full text-xs">
                    <thead className="bg-card">
                      <tr className="text-left text-muted-foreground">
                        <th className="px-2 py-2 font-medium">Time (UTC)</th>
                        <th className="px-2 py-2 font-medium">Source</th>
                        <th className="px-2 py-2 font-medium">OCSF class</th>
                        <th className="px-2 py-2 font-medium">Src → Dst</th>
                        <th className="px-2 py-2 font-medium">MITRE</th>
                      </tr>
                    </thead>
                    <tbody>
                      {timeline.events.map((e) => (
                        <tr key={e.event_id} className="border-t border-border/40">
                          <td className="px-2 py-1.5 whitespace-nowrap text-foreground">
                            {new Date(e.timestamp).toISOString().slice(11, 19)}
                          </td>
                          <td className="px-2 py-1.5">
                            <Badge variant="outline">{e.source_connector}</Badge>
                          </td>
                          <td className="px-2 py-1.5 text-muted-foreground">
                            {e.ocsf_event_class}
                          </td>
                          <td className="px-2 py-1.5 font-mono">
                            {e.source_ip ?? "?"} → {e.dest_ip ?? "-"}
                          </td>
                          <td className="px-2 py-1.5">
                            {e.mitre_techniques.map((t) => (
                              <Badge key={t.technique_id} variant="critical" className="mr-1">
                                {t.technique_id}
                              </Badge>
                            ))}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>

            {/* Pivots */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Suggested pivots</CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {timeline.pivots.map((p, i) => (
                  <div
                    key={i}
                    className="flex items-start gap-2 rounded-md border border-border p-3 text-sm"
                  >
                    <ArrowRight className="w-4 h-4 text-primary shrink-0 mt-0.5" />
                    <div>
                      <span className="font-mono text-foreground">{p.entity_value}</span>
                      <p className="text-muted-foreground text-xs mt-0.5">{p.rationale}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Audit */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Audit trail</CardTitle>
                <CardDescription>
                  Every source queried, with per-event lineage back to the raw log.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-1 text-xs">
                {timeline.audit_trail.map((a, i) => (
                  <div
                    key={i}
                    className="flex items-center justify-between rounded border border-border/50 px-2 py-1.5"
                  >
                    <span className="font-mono">{a.connector}</span>
                    <span className="text-muted-foreground">
                      {a.event_count} events · {new Date(a.queried_at).toLocaleTimeString()}
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </>
  );
}
