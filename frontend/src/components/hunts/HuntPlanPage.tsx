import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import {
  Play,
  Loader2,
  Map,
  Target,
  Code2,
  ListChecks,
  HelpCircle,
  Gauge,
  History,
  ChevronDown,
  ChevronRight,
  ScanSearch,
} from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import {
  generateHuntPlan,
  listHuntPlans,
  getHuntPlan,
  executeHuntPlan,
  listHuntPlanRuns,
  type HuntPlan,
  type HuntPlanSummary,
  type ExecuteHuntPlanResponse,
  type HuntPlanRun,
} from "@/api/hunts";

const HISTORY_PAGE_SIZE = 20;

/** Split a comma/space-separated text field into trimmed non-empty tokens. */
function tokens(raw: string): string[] {
  return raw
    .split(/[,\s]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

function formatRelativeTime(dateStr: string): string {
  const date = new Date(dateStr);
  const diffMins = Math.floor((Date.now() - date.getTime()) / 60000);
  const diffHours = Math.floor(diffMins / 60);
  const diffDays = Math.floor(diffHours / 24);
  if (diffMins < 1) return "Just now";
  if (diffMins < 60) return `${diffMins}m ago`;
  if (diffHours < 24) return `${diffHours}h ago`;
  if (diffDays < 7) return `${diffDays}d ago`;
  return date.toLocaleDateString();
}

/** Compact "what this plan hunts" label from a history summary. */
function planLabel(s: HuntPlanSummary): string {
  const parts = [...s.adversaries, ...s.ttps];
  if (parts.length === 0) return s.id;
  return parts.slice(0, 4).join(", ") + (parts.length > 4 ? ` +${parts.length - 4}` : "");
}

export function HuntPlanPage() {
  const navigate = useNavigate();
  const [adversariesText, setAdversariesText] = useState("");
  const [ttpsText, setTtpsText] = useState("");
  const [plan, setPlan] = useState<HuntPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Plan history (#337): stored runbooks, re-openable in place.
  const [history, setHistory] = useState<HuntPlanSummary[]>([]);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historyOpen, setHistoryOpen] = useState(false);
  const [reopeningId, setReopeningId] = useState<string | null>(null);

  // Runbook execution (#339): run the open plan, hits land in triage.
  const [executing, setExecuting] = useState(false);
  const [execResult, setExecResult] = useState<ExecuteHuntPlanResponse | null>(null);

  // Per-run history (#341) of the open stored plan.
  const [runs, setRuns] = useState<HuntPlanRun[]>([]);

  const fetchRuns = useCallback(async (planId: string) => {
    try {
      const resp = await listHuntPlanRuns(planId, { page_size: 10 });
      setRuns(resp.items);
    } catch {
      // Run history is auxiliary — never block the runbook view on it.
    }
  }, []);

  useEffect(() => {
    setRuns([]);
    if (plan?.id) void fetchRuns(plan.id);
  }, [plan, fetchRuns]);

  const fetchHistory = useCallback(async () => {
    try {
      const resp = await listHuntPlans({ page_size: HISTORY_PAGE_SIZE });
      setHistory(resp.items);
      setHistoryTotal(resp.total);
    } catch {
      // History is auxiliary — never block plan generation on it.
    }
  }, []);

  useEffect(() => {
    void fetchHistory();
  }, [fetchHistory]);

  const adversaries = tokens(adversariesText);
  const ttps = tokens(ttpsText);
  const hasTarget = adversaries.length > 0 || ttps.length > 0;

  const handleGenerate = useCallback(async () => {
    if (!hasTarget) return;
    setLoading(true);
    setError(null);
    setPlan(null);
    try {
      const result = await generateHuntPlan({ adversaries, ttps });
      setPlan(result);
      setExecResult(null);
      void fetchHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate hunt plan");
    } finally {
      setLoading(false);
    }
    // tokens() derivations are stable for the same text inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasTarget, adversariesText, ttpsText, fetchHistory]);

  const handleReopen = useCallback(async (id: string) => {
    setReopeningId(id);
    setError(null);
    try {
      const result = await getHuntPlan(id);
      setPlan(result);
      setExecResult(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to re-open hunt plan");
    } finally {
      setReopeningId(null);
    }
  }, []);

  const handleExecute = useCallback(async () => {
    if (!plan?.id) return;
    setExecuting(true);
    setError(null);
    setExecResult(null);
    try {
      const result = await executeHuntPlan(plan.id);
      setExecResult(result);
      void fetchRuns(plan.id);
      void fetchHistory();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to execute hunt plan");
    } finally {
      setExecuting(false);
    }
  }, [plan, fetchRuns, fetchHistory]);

  return (
    <>
      <Header title="Hunt Planner" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="hunt-plan-page">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <Map className="w-5 h-5 text-primary" />
              Adversary / TTPs → Hunt Runbook
            </CardTitle>
            <CardDescription>
              Name an adversary group and/or ATT&CK technique ids. The agent
              builds a prioritized runbook: hypotheses, per-backend queries,
              expected noise, pivot questions, and evidence checklists.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-1.5">
                <Label htmlFor="plan-adversaries">Adversaries</Label>
                <Input
                  id="plan-adversaries"
                  value={adversariesText}
                  onChange={(e) => setAdversariesText(e.target.value)}
                  placeholder="APT29, FIN7…"
                  data-testid="plan-adversaries-input"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="plan-ttps">ATT&CK techniques</Label>
                <Input
                  id="plan-ttps"
                  value={ttpsText}
                  onChange={(e) => setTtpsText(e.target.value)}
                  placeholder="T1059.001, T1078.004…"
                  className="font-mono"
                  data-testid="plan-ttps-input"
                />
              </div>
            </div>
            <Button
              onClick={handleGenerate}
              disabled={loading || !hasTarget}
              data-testid="generate-plan"
            >
              {loading ? (
                <>
                  <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                  Planning…
                </>
              ) : (
                "Generate hunt plan"
              )}
            </Button>
            {error && (
              <div
                className="rounded-md border border-destructive/30 bg-destructive/10 p-3 text-sm text-destructive"
                role="alert"
              >
                {error}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Plan history (#337) — collapsible, click to re-open */}
        {history.length > 0 && (
          <Card data-testid="plan-history">
            <CardHeader className="py-3">
              <button
                type="button"
                className="flex w-full items-center gap-2 text-left"
                onClick={() => setHistoryOpen((o) => !o)}
                data-testid="plan-history-toggle"
                aria-expanded={historyOpen}
              >
                {historyOpen ? (
                  <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-muted-foreground shrink-0" />
                )}
                <History className="w-4 h-4 text-primary shrink-0" />
                <CardTitle className="text-base">
                  Plan history{" "}
                  <span className="font-normal text-muted-foreground">
                    ({historyTotal})
                  </span>
                </CardTitle>
              </button>
            </CardHeader>
            {historyOpen && (
              <CardContent className="space-y-2 pt-0">
                {history.map((h) => (
                  <button
                    key={h.id}
                    type="button"
                    onClick={() => void handleReopen(h.id)}
                    disabled={reopeningId !== null || h.status !== "ready"}
                    className="flex w-full items-center justify-between gap-3 rounded-md border border-border p-3 text-left text-sm hover:bg-muted/50 disabled:opacity-60"
                    data-testid={`plan-history-item-${h.id}`}
                  >
                    <div className="min-w-0">
                      <p className="truncate font-medium text-foreground">
                        {planLabel(h)}
                        {plan?.id === h.id && (
                          <span className="ml-2 text-xs text-primary">(open)</span>
                        )}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        {h.hypothesis_count} hypotheses · {h.entry_count} entries ·{" "}
                        {formatRelativeTime(h.created_at)}
                        {h.last_run_findings != null && h.last_run_at && (
                          <span data-testid={`last-run-${h.id}`}>
                            {" "}
                            · last run: {h.last_run_findings} finding(s){" "}
                            {formatRelativeTime(h.last_run_at)}
                          </span>
                        )}
                      </p>
                    </div>
                    <div className="flex shrink-0 items-center gap-1.5">
                      {reopeningId === h.id && (
                        <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
                      )}
                      {h.from_proposal && (
                        <Badge
                          variant="outline"
                          className="text-xs"
                          data-testid={`proposal-badge-${h.id}`}
                        >
                          <ScanSearch className="w-3 h-3 mr-1" />
                          proposal
                        </Badge>
                      )}
                      {h.status !== "ready" && (
                        <Badge variant="secondary" className="text-xs">
                          {h.status}
                        </Badge>
                      )}
                    </div>
                  </button>
                ))}
              </CardContent>
            )}
          </Card>
        )}

        {/* Plan */}
        {plan && (
          <div className="space-y-6" data-testid="hunt-plan-result">
            {/* Executive summary */}
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between gap-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Gauge className="w-4 h-4 text-primary" />
                    Executive summary
                    <Badge variant="secondary" className="ml-2 uppercase">
                      {plan.state}
                    </Badge>
                  </CardTitle>
                  {plan.id && (
                    <Button
                      onClick={handleExecute}
                      disabled={executing}
                      data-testid="execute-plan"
                    >
                      {executing ? (
                        <>
                          <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                          Executing…
                        </>
                      ) : (
                        <>
                          <Play className="w-4 h-4 mr-2" />
                          Execute runbook
                        </>
                      )}
                    </Button>
                  )}
                </div>
              </CardHeader>
              <CardContent className="space-y-2 text-sm">
                {plan.executive_summary.adversary_profile && (
                  <p className="text-foreground">
                    {plan.executive_summary.adversary_profile}
                  </p>
                )}
                {plan.executive_summary.success_criteria && (
                  <p className="text-muted-foreground">
                    <span className="font-semibold text-foreground">Success: </span>
                    {plan.executive_summary.success_criteria}
                  </p>
                )}
                <p className="text-muted-foreground">
                  {plan.hypotheses.length} hypotheses · {plan.ttp_entries.length}{" "}
                  runbook entries
                  {plan.executive_summary.estimated_effort_hours != null &&
                    ` · ~${plan.executive_summary.estimated_effort_hours}h estimated`}
                </p>
              </CardContent>
            </Card>

            {/* Execution outcome (#339) */}
            {execResult && (
              <Card
                className="border-severity-low/40"
                data-testid="execute-result"
              >
                <CardContent className="flex items-center justify-between gap-3 py-4 text-sm">
                  <p className="text-foreground">
                    {execResult.queued
                      ? "Execution queued on the worker — re-open the plan shortly for the run summary."
                      : `Runbook executed — ${execResult.findings_created} finding(s) landed in the triage inbox.`}
                  </p>
                  {!execResult.queued && (
                    <Button
                      variant="outline"
                      onClick={() => navigate("/hunt")}
                      data-testid="open-triage-inbox"
                    >
                      Open triage inbox
                    </Button>
                  )}
                </CardContent>
              </Card>
            )}

            {/* Per-run execution history (#341) */}
            {runs.length > 0 && (
              <Card data-testid="run-history">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <History className="w-4 h-4 text-primary" />
                    Run history
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {runs.map((r) => (
                    <div
                      key={r.id}
                      className="flex items-center justify-between gap-3 rounded-md border border-border p-3 text-sm"
                      data-testid={`run-row-${r.id}`}
                    >
                      <p className="text-muted-foreground">
                        <span className="font-medium text-foreground">
                          {r.findings_created} finding(s)
                        </span>{" "}
                        · {r.hit_count} hits · {r.error_count} errors ·{" "}
                        {formatRelativeTime(r.started_at)}
                      </p>
                      <Badge
                        variant={r.status === "completed" ? "secondary" : "outline"}
                        className="shrink-0"
                      >
                        {r.status}
                      </Badge>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Hypotheses */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" />
                  Hypotheses
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {plan.hypotheses.map((h) => (
                  <div
                    key={h.id}
                    className="flex items-start justify-between gap-3 rounded-md border border-border p-3 text-sm"
                    data-testid={`hypothesis-${h.id}`}
                  >
                    <div className="min-w-0">
                      <p className="font-medium text-foreground">
                        {h.ttp_id} — {h.ttp_name}
                      </p>
                      <p className="text-muted-foreground">{h.rationale}</p>
                    </div>
                    <Badge variant="outline" className="shrink-0 font-mono">
                      {h.priority.toFixed(2)}
                    </Badge>
                  </div>
                ))}
              </CardContent>
            </Card>

            {/* Per-TTP runbook entries */}
            {plan.ttp_entries.map((entry) => (
              <Card key={entry.ttp_id} data-testid={`runbook-${entry.ttp_id}`}>
                <CardHeader>
                  <CardTitle className="text-base font-mono">
                    {entry.ttp_id}{" "}
                    <span className="font-sans font-semibold">{entry.ttp_name}</span>
                  </CardTitle>
                  <CardDescription>{entry.rationale}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 text-sm">
                  {entry.behavioral_description && (
                    <p className="text-muted-foreground">
                      {entry.behavioral_description}
                    </p>
                  )}

                  {Object.keys(entry.queries).length > 0 && (
                    <div>
                      <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                        <Code2 className="w-3.5 h-3.5" /> Queries
                      </p>
                      {Object.entries(entry.queries).map(([backend, q]) => (
                        <div key={backend} className="mb-2">
                          <Badge variant="outline" className="mb-1">
                            {backend}
                          </Badge>
                          <pre className="rounded-md bg-muted p-2 text-xs overflow-x-auto whitespace-pre-wrap font-mono">
                            {q.query}
                          </pre>
                        </div>
                      ))}
                    </div>
                  )}

                  {entry.expected_noise.expected_hits_per_day != null && (
                    <p className="text-xs text-muted-foreground">
                      Expected noise: ~{entry.expected_noise.expected_hits_per_day}{" "}
                      hits/day
                      {entry.expected_noise.sample_window_days != null &&
                        ` over a ${entry.expected_noise.sample_window_days}-day sample`}
                    </p>
                  )}

                  {entry.pivot_questions.length > 0 && (
                    <div>
                      <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                        <HelpCircle className="w-3.5 h-3.5" /> Pivot questions on hit
                      </p>
                      <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
                        {entry.pivot_questions.map((q, i) => (
                          <li key={i}>{q}</li>
                        ))}
                      </ul>
                    </div>
                  )}

                  {entry.evidence_checklist.length > 0 && (
                    <div>
                      <p className="mb-1 flex items-center gap-1.5 text-xs font-semibold text-muted-foreground">
                        <ListChecks className="w-3.5 h-3.5" /> Evidence to collect
                      </p>
                      <ul className="list-disc space-y-0.5 pl-5 text-muted-foreground">
                        {entry.evidence_checklist.map((c, i) => (
                          <li key={i}>{c}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </div>
    </>
  );
}
