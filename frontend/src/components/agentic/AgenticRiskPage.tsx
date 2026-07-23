import { useState, useCallback, useEffect } from "react";
import {
  Loader2,
  Bot,
  ShieldAlert,
  Ghost,
  KeyRound,
  FileWarning,
  Play,
} from "lucide-react";
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
import { listAgenticFindings, type HuntFinding } from "@/api/agentic";
import { runAgenticHunt } from "@/api/hunt";

/** Detection buckets emitted by the four #121 Phase A detectors
 *  (evidence.detection values). Unknown values fall into "other". */
const BUCKETS = [
  {
    key: "prompt_injection",
    label: "Prompt injection",
    icon: ShieldAlert,
    match: (d: string) => d.startsWith("prompt_injection"),
  },
  {
    key: "shadow_agent",
    label: "Shadow agents",
    icon: Ghost,
    match: (d: string) => d.startsWith("shadow"),
  },
  {
    key: "identity_abuse",
    label: "Identity abuse",
    icon: KeyRound,
    match: (d: string) => d.startsWith("identity") || d.includes("role"),
  },
  {
    key: "llm_exfil",
    label: "LLM exfil",
    icon: FileWarning,
    match: (d: string) => d.startsWith("llm_exfil"),
  },
] as const;

export function bucketOf(finding: HuntFinding): string {
  const detection = String(
    (finding.evidence as Record<string, unknown> | null)?.["detection"] ?? "",
  );
  for (const b of BUCKETS) {
    if (b.match(detection)) return b.key;
  }
  return "other";
}

function severityVariant(sev: string): "destructive" | "secondary" | "outline" {
  if (sev === "critical" || sev === "high") return "destructive";
  if (sev === "medium") return "secondary";
  return "outline";
}

function formatRelativeTime(dateStr: string): string {
  const diffMins = Math.floor((Date.now() - new Date(dateStr).getTime()) / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return new Date(dateStr).toLocaleDateString();
}

export function AgenticRiskPage() {
  const [findings, setFindings] = useState<HuntFinding[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [activeBucket, setActiveBucket] = useState<string | null>(null);

  const fetchFindings = useCallback(async () => {
    try {
      const resp = await listAgenticFindings({ state: "active", page_size: 200 });
      setFindings(resp.findings);
      setTotal(resp.total_findings);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load agentic findings");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void fetchFindings();
  }, [fetchFindings]);

  const handleRun = useCallback(async () => {
    setRunning(true);
    setError(null);
    try {
      await runAgenticHunt();
      await fetchFindings();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to run agentic hunt");
    } finally {
      setRunning(false);
    }
  }, [fetchFindings]);

  const counts: Record<string, number> = {};
  for (const f of findings) {
    const b = bucketOf(f);
    counts[b] = (counts[b] ?? 0) + 1;
  }
  const visible = activeBucket
    ? findings.filter((f) => bucketOf(f) === activeBucket)
    : findings;

  return (
    <>
      <Header title="Agentic Risk" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="agentic-risk-page">
        <Card>
          <CardHeader>
            <div className="flex items-center justify-between gap-3">
              <div>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Bot className="w-5 h-5 text-primary" />
                  Agentic-AI misuse surface
                </CardTitle>
                <CardDescription>
                  Prompt injection, shadow agents, identity abuse, and LLM exfil
                  across the org&apos;s agent telemetry — {total} active finding(s).
                </CardDescription>
              </div>
              <Button onClick={handleRun} disabled={running} data-testid="run-agentic-hunt">
                {running ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Hunting…
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4 mr-2" />
                    Run agentic hunt
                  </>
                )}
              </Button>
            </div>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
              {BUCKETS.map((b) => {
                const Icon = b.icon;
                const selected = activeBucket === b.key;
                return (
                  <button
                    key={b.key}
                    type="button"
                    onClick={() => setActiveBucket(selected ? null : b.key)}
                    className={`rounded-md border p-3 text-left transition-colors ${
                      selected ? "border-primary bg-primary/10" : "border-border hover:bg-muted/50"
                    }`}
                    data-testid={`bucket-${b.key}`}
                    aria-pressed={selected}
                  >
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      <Icon className="w-3.5 h-3.5" />
                      {b.label}
                    </div>
                    <p className="mt-1 text-2xl font-semibold text-foreground">
                      {counts[b.key] ?? 0}
                    </p>
                  </button>
                );
              })}
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

        <Card>
          <CardHeader>
            <CardTitle className="text-base">
              Findings{activeBucket ? ` — ${BUCKETS.find((b) => b.key === activeBucket)?.label}` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {loading ? (
              <div className="flex items-center gap-2 text-sm text-muted-foreground">
                <Loader2 className="w-4 h-4 animate-spin" /> Loading…
              </div>
            ) : visible.length === 0 ? (
              <p className="text-sm text-muted-foreground" data-testid="agentic-empty">
                No active agentic findings
                {activeBucket ? " in this category" : ""}. Run the agentic hunt to
                scan the latest telemetry.
              </p>
            ) : (
              visible.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center justify-between gap-3 rounded-md border border-border p-3 text-sm"
                  data-testid={`agentic-finding-${f.id}`}
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium text-foreground">{f.title}</p>
                    <p className="text-xs text-muted-foreground">
                      {bucketOf(f)} · {f.technique_ids.join(", ") || "—"} ·{" "}
                      {formatRelativeTime(f.created_at)}
                    </p>
                  </div>
                  <Badge variant={severityVariant(f.severity)} className="shrink-0 uppercase">
                    {f.severity}
                  </Badge>
                </div>
              ))
            )}
          </CardContent>
        </Card>
      </div>
    </>
  );
}
