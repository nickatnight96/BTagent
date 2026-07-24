/**
 * IOC Detection Rules panel (EPIC-6 UC-6.2, #113 adjacency).
 *
 * Surfaces `POST /reports/detection-content`: turn an investigation's IOCs
 * into platform-specific SIEM rules (Splunk SPL / Elastic / Sentinel KQL) for
 * quick deployment while the formal CTI→Sigma proposal flow above goes
 * through review. Mounted on the Detection Proposals page since both flows
 * end in detection content; RBAC is enforced server-side
 * (remediation:generate + investigation scope).
 */

import { useCallback, useState } from "react";
import { Loader2, Play, Radar } from "lucide-react";
import { Button } from "@/components/ds/button";
import { Card, CardContent } from "@/components/ds/card";
import { generateDetectionContent } from "@/api/reports";
import type { SiemPlatform } from "@/api/reports";
import type { DetectionContentResponse } from "@/types/reports";

const PLATFORMS: Array<{ value: SiemPlatform; label: string }> = [
  { value: "splunk", label: "Splunk (SPL)" },
  { value: "elastic", label: "Elastic" },
  { value: "sentinel", label: "Sentinel (KQL)" },
];

export function IocRulesPanel() {
  const [investigationId, setInvestigationId] = useState("");
  const [platform, setPlatform] = useState<SiemPlatform>("splunk");
  const [content, setContent] = useState<DetectionContentResponse | null>(null);
  const [isGenerating, setIsGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleGenerate = useCallback(async () => {
    const id = investigationId.trim();
    if (!id) return;
    setIsGenerating(true);
    setError(null);
    try {
      const resp = await generateDetectionContent(id, platform);
      setContent(resp);
    } catch {
      setError("Rule generation failed. Check the investigation ID and try again.");
      setContent(null);
    } finally {
      setIsGenerating(false);
    }
  }, [investigationId, platform]);

  return (
    <Card data-testid="ioc-rules-panel">
      <CardContent className="py-4 space-y-4">
        <div className="flex items-center gap-2">
          <Radar className="w-4 h-4 text-sky-400" aria-hidden="true" />
          <span className="text-sm font-semibold text-foreground">IOC detection rules</span>
          <span className="text-xs text-muted-foreground">
            Generate deployable SIEM rules from a case&apos;s IOCs
          </span>
        </div>

        <div className="flex flex-wrap items-end gap-3">
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Investigation ID</span>
            <input
              type="text"
              value={investigationId}
              onChange={(e) => setInvestigationId(e.target.value)}
              placeholder="inv_…"
              data-testid="ioc-rules-investigation-input"
              className="w-64 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </label>
          <label className="flex flex-col gap-1 text-sm">
            <span className="text-muted-foreground">Platform</span>
            <select
              value={platform}
              onChange={(e) => setPlatform(e.target.value as SiemPlatform)}
              data-testid="ioc-rules-platform"
              className="w-48 rounded-md border border-border bg-background px-3 py-1.5 text-sm text-foreground focus:outline-none focus:ring-1 focus:ring-sky-500"
            >
              {PLATFORMS.map((p) => (
                <option key={p.value} value={p.value}>
                  {p.label}
                </option>
              ))}
            </select>
          </label>
          <Button
            variant="outline"
            size="sm"
            onClick={() => void handleGenerate()}
            disabled={investigationId.trim() === "" || isGenerating}
            data-testid="ioc-rules-generate"
            title="Generate platform-specific detection rules from the case's IOCs"
          >
            {isGenerating ? (
              <Loader2 className="w-4 h-4 animate-spin" />
            ) : (
              <Play className="w-4 h-4" />
            )}
            <span className="ml-2">Generate rules</span>
          </Button>
        </div>

        {error && (
          <div
            className="rounded-md border border-rose-500/30 bg-rose-600/10 px-4 py-2 text-sm text-rose-300"
            data-testid="ioc-rules-error"
          >
            {error}
          </div>
        )}

        {content && (
          <div className="space-y-3" data-testid="ioc-rules-result">
            <div className="text-xs text-muted-foreground">
              {content.rule_count} rule{content.rule_count === 1 ? "" : "s"} for{" "}
              {content.platform} · generated {content.generated_at}
            </div>
            {content.rules.map((r, idx) => (
              <div
                key={`${r.name}-${idx}`}
                className="rounded-md border border-border/50 bg-background/50 p-3 space-y-2"
                data-testid={`ioc-rule-${idx}`}
              >
                <div className="flex items-center justify-between gap-2">
                  <div className="min-w-0">
                    <div className="text-sm font-medium text-foreground">{r.name}</div>
                    <div className="text-xs text-muted-foreground">{r.description}</div>
                  </div>
                  <span className="shrink-0 rounded border border-sky-500/40 px-1.5 py-0.5 text-[10px] font-medium uppercase tracking-wide text-sky-300">
                    {r.language}
                  </span>
                </div>
                <pre className="overflow-x-auto whitespace-pre-wrap font-mono text-xs text-foreground">
                  {r.rule}
                </pre>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
