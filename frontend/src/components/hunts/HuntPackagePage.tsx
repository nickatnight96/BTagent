import { useState, useCallback } from "react";
import {
  Loader2,
  ShieldAlert,
  ShieldCheck,
  FileSearch,
  Target,
  Code2,
} from "lucide-react";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Textarea } from "@/components/ds/textarea";
import { Label } from "@/components/ds/label";
import { Badge } from "@/components/ds/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ds/card";
import { generateHuntPackage, type HuntPackage } from "@/api/hunts";

const SAMPLE = `CISA advisory AA26-001: threat actor infrastructure includes 10.1.42.17 and evil-c2.example, distributing payloads via hxxps://evil-c2[.]example/payload.bin. Observed SHA256 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855. Exploited CVE-2026-12345.`;

export function HuntPackagePage() {
  const [text, setText] = useState("");
  const [pkg, setPkg] = useState<HuntPackage | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    if (!text.trim()) return;
    setLoading(true);
    setError(null);
    setPkg(null);
    try {
      const result = await generateHuntPackage({
        text: text.trim(),
        source_label: "pasted-advisory",
        backends: ["splunk", "sentinel", "sigma"],
      });
      setPkg(result);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to generate hunt package");
    } finally {
      setLoading(false);
    }
  }, [text]);

  return (
    <>
      <Header title="Hunt Package" />
      <div className="flex-1 overflow-y-auto p-6 space-y-6" data-testid="hunt-package">
        {/* Input */}
        <Card>
          <CardHeader>
            <CardTitle className="text-lg flex items-center gap-2">
              <FileSearch className="w-5 h-5 text-primary" />
              Intel Report → Hunt Package
            </CardTitle>
            <CardDescription>
              Paste an advisory. The agent extracts indicators, checks 90 days of
              telemetry for sightings, builds per-backend hunt queries, and drafts
              Sigma detections. (Analyst reviews before anything runs — L2.)
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Label htmlFor="advisory">Advisory text</Label>
            <Textarea
              id="advisory"
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder="Paste a CISA advisory, vendor report, or ISAC bulletin…"
              rows={6}
              className="font-mono text-xs"
              data-testid="hunt-package-input"
            />
            <div className="flex items-center gap-3">
              <Button onClick={handleGenerate} disabled={loading || !text.trim()}>
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Generating…
                  </>
                ) : (
                  "Generate hunt package"
                )}
              </Button>
              <Button
                variant="ghost"
                onClick={() => setText(SAMPLE)}
                disabled={loading}
              >
                Use sample advisory
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

        {/* Results */}
        {pkg && (
          <div className="space-y-6" data-testid="hunt-package-result">
            {/* Verdict banner */}
            <Card
              className={
                pkg.retro_report?.compromise_suspected
                  ? "border-destructive/40"
                  : "border-severity-low/40"
              }
            >
              <CardContent className="flex items-center gap-3 py-4">
                {pkg.retro_report?.compromise_suspected ? (
                  <ShieldAlert className="w-8 h-8 text-destructive shrink-0" />
                ) : (
                  <ShieldCheck className="w-8 h-8 text-severity-low shrink-0" />
                )}
                <div>
                  <p className="font-semibold text-foreground">
                    {pkg.retro_report?.compromise_suspected
                      ? "Historical sightings found — possible prior compromise"
                      : "No historical sightings — clean over the window"}
                  </p>
                  <p className="text-sm text-muted-foreground">
                    {pkg.extracted_ioc_count} indicators extracted ·{" "}
                    {pkg.derived_techniques.length} techniques ·{" "}
                    {pkg.retro_report?.window_days ?? 90}-day lookback
                  </p>
                </div>
              </CardContent>
            </Card>

            {/* Derived techniques */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Target className="w-4 h-4 text-primary" />
                  Derived ATT&CK techniques
                </CardTitle>
              </CardHeader>
              <CardContent className="flex flex-wrap gap-2">
                {pkg.derived_techniques.map((t) => (
                  <Badge key={t} variant="secondary">
                    {t}
                  </Badge>
                ))}
              </CardContent>
            </Card>

            {/* Sightings */}
            {pkg.retro_report && pkg.retro_report.sightings.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Sightings</CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {pkg.retro_report.sightings.map((s, i) => (
                    <div
                      key={i}
                      className="flex items-center justify-between rounded-md border border-border p-3 text-sm"
                    >
                      <div>
                        <span className="font-mono text-foreground">{s.ioc_value}</span>
                        <span className="text-muted-foreground">
                          {" "}
                          → {s.technique_id} ({s.tactic})
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground">
                        {s.event_count} events · {s.source_connectors.join(", ")}
                      </div>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}

            {/* Pre-built queries */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Code2 className="w-4 h-4 text-primary" />
                  Pre-built hunt queries
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {Object.entries(pkg.queries).map(([ttp, byBackend]) => (
                  <div key={ttp}>
                    <p className="text-xs font-semibold text-muted-foreground mb-1">
                      {ttp}
                    </p>
                    {Object.entries(byBackend).map(([backend, q]) => (
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
                ))}
              </CardContent>
            </Card>

            {/* Sigma drafts */}
            {pkg.sigma_drafts.length > 0 && (
              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Draft Sigma detections</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  {pkg.sigma_drafts.map((d, i) => (
                    <div key={i}>
                      <p className="text-xs font-semibold text-foreground mb-1">
                        {d.title}
                      </p>
                      <pre className="rounded-md bg-muted p-2 text-xs overflow-x-auto whitespace-pre-wrap font-mono">
                        {d.sigma_yaml}
                      </pre>
                    </div>
                  ))}
                </CardContent>
              </Card>
            )}
          </div>
        )}
      </div>
    </>
  );
}
