import { useState, useCallback } from "react";
import { Loader2, ShieldAlert, ListChecks, ArrowUp, Gauge } from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { Textarea } from "@/components/ds/textarea";
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
import { triageAlert, type Severity, type TriageResult } from "@/api/triage";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const SEV_VARIANT: Record<string, "critical" | "high" | "medium" | "low" | "info"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "info",
};

const DISPOSITION_VARIANT: Record<string, "destructive" | "medium" | "low" | "secondary"> = {
  escalate: "destructive",
  investigate: "medium",
  monitor: "secondary",
  close_benign: "low",
  close_false_positive: "low",
};

const SAMPLE = {
  title: "Cobalt Strike beaconing detected from finance workstation",
  description:
    "Periodic callback to 185.220.101.42 every 60s with jittered TLS; matches known C2 profile.",
  source: "crowdstrike",
  severity: "low" as Severity,
};

export function AlertTriagePage() {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState<Severity>("medium");
  const [result, setResult] = useState<TriageResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleTriage = useCallback(async () => {
    if (!title.trim()) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await triageAlert({
        title: title.trim(),
        description: description.trim(),
        source: source.trim(),
        severity,
      });
      setResult(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Triage failed");
    } finally {
      setLoading(false);
    }
  }, [title, description, source, severity]);

  return (
    <>
      <Header title="Alert Triage" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="alert-triage">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <ShieldAlert className="w-5 h-5 text-primary" />
              Auto-triage an alert
            </CardTitle>
            <CardDescription>
              Paste a raw alert. The agent classifies its Typed Intent, proposes a
              severity + disposition with a confidence score and evidence trail, and
              recommends read-only next steps. Nothing is executed — you review and
              approve. (UC-3.1)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-1.5">
              <Label htmlFor="title">Alert title</Label>
              <Input
                id="title"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="e.g. Ransomware payload quarantined on WS-12"
                data-testid="alert-triage-title"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="desc">Description / detail</Label>
              <Textarea
                id="desc"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                placeholder="Detector output, observed behaviour, surrounding context…"
              />
            </div>
            <div className="flex flex-col sm:flex-row gap-3 sm:items-end">
              <div className="space-y-1.5 flex-1">
                <Label htmlFor="src">Source</Label>
                <Input
                  id="src"
                  value={source}
                  onChange={(e) => setSource(e.target.value)}
                  placeholder="splunk / sentinel / crowdstrike"
                />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="sev">Source severity</Label>
                <NativeSelect
                  id="sev"
                  value={severity}
                  onChange={(e) => setSeverity(e.target.value as Severity)}
                  className="sm:w-40"
                >
                  {SEVERITIES.map((s) => (
                    <option key={s} value={s}>
                      {s}
                    </option>
                  ))}
                </NativeSelect>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <Button
                onClick={handleTriage}
                disabled={loading || !title.trim()}
                data-testid="alert-triage-submit"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Triaging…
                  </>
                ) : (
                  "Triage alert"
                )}
              </Button>
              <Button
                variant="ghost"
                onClick={() => {
                  setTitle(SAMPLE.title);
                  setDescription(SAMPLE.description);
                  setSource(SAMPLE.source);
                  setSeverity(SAMPLE.severity);
                }}
                disabled={loading}
              >
                Use sample alert
              </Button>
            </div>
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

        {/* Result */}
        {result && (
          <div className="space-y-6" data-testid="alert-triage-result">
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex flex-wrap items-center gap-2">
                  <Badge variant={DISPOSITION_VARIANT[result.disposition] ?? "secondary"}>
                    {result.disposition.replace(/_/g, " ")}
                  </Badge>
                  <span className="text-foreground">{result.typed_intent.replace(/_/g, " ")}</span>
                  <Badge variant={SEV_VARIANT[result.proposed_severity] ?? "secondary"}>
                    {result.proposed_severity}
                  </Badge>
                  {result.severity_escalated && (
                    <Badge variant="medium" className="gap-1">
                      <ArrowUp className="w-3 h-3" /> escalated
                    </Badge>
                  )}
                  <span className="ml-auto inline-flex items-center gap-1 text-sm text-muted-foreground">
                    <Gauge className="w-4 h-4" />
                    {Math.round(result.confidence * 100)}% confidence
                  </span>
                </CardTitle>
                <CardDescription>{result.explanation}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {result.evidence.length > 0 && (
                  <div>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">Evidence</p>
                    <div className="flex flex-wrap gap-2">
                      {result.evidence.map((e, i) => (
                        <Badge key={i} variant="outline">
                          {e}
                        </Badge>
                      ))}
                    </div>
                  </div>
                )}
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-2 flex items-center gap-1">
                    <ListChecks className="w-4 h-4" /> Recommended next steps (read-only — you
                    approve)
                  </p>
                  <ol className="space-y-2">
                    {result.next_steps.map((s, i) => (
                      <li
                        key={i}
                        className="rounded-md border border-border p-3 text-sm"
                      >
                        <span className="font-medium text-foreground">
                          {i + 1}. {s.action}
                        </span>
                        {s.rationale && (
                          <p className="text-muted-foreground text-xs mt-0.5">{s.rationale}</p>
                        )}
                      </li>
                    ))}
                  </ol>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </>
  );
}
