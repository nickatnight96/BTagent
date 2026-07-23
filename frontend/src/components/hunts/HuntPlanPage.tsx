import { useState, useCallback } from "react";
import {
  Loader2,
  Map,
  Target,
  Code2,
  ListChecks,
  HelpCircle,
  Gauge,
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
import { generateHuntPlan, type HuntPlan } from "@/api/hunts";

/** Split a comma/space-separated text field into trimmed non-empty tokens. */
function tokens(raw: string): string[] {
  return raw
    .split(/[,\s]+/)
    .map((t) => t.trim())
    .filter(Boolean);
}

export function HuntPlanPage() {
  const [adversariesText, setAdversariesText] = useState("");
  const [ttpsText, setTtpsText] = useState("");
  const [plan, setPlan] = useState<HuntPlan | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

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
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate hunt plan");
    } finally {
      setLoading(false);
    }
    // tokens() derivations are stable for the same text inputs.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [hasTarget, adversariesText, ttpsText]);

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

        {/* Plan */}
        {plan && (
          <div className="space-y-6" data-testid="hunt-plan-result">
            {/* Executive summary */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Gauge className="w-4 h-4 text-primary" />
                  Executive summary
                  <Badge variant="secondary" className="ml-2 uppercase">
                    {plan.state}
                  </Badge>
                </CardTitle>
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
