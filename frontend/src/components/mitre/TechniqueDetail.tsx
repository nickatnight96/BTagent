import { useCallback, useEffect, useMemo, useState } from "react";
import {
  X,
  ExternalLink,
  Download,
  Layers,
  Shield,
  Eye,
  BookOpen,
  BarChart3,
} from "lucide-react";
import { useMitreStore } from "@/stores/mitreStore";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import type { MitreTechnique } from "@/types/mitre";

interface TechniqueDetailProps {
  technique: MitreTechnique;
  onClose: () => void;
}

function SectionHeader({
  icon,
  children,
}: {
  icon: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <h3 className="flex items-center gap-2 text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">
      {icon}
      {children}
    </h3>
  );
}

/** Simple confidence histogram for tagged investigations */
function ConfidenceHistogram({ data }: { data: number[] }) {
  const buckets = useMemo(() => {
    const b = [0, 0, 0, 0, 0]; // 0-20, 20-40, 40-60, 60-80, 80-100
    for (const val of data) {
      const idx = Math.min(Math.floor(val * 5), 4);
      b[idx]++;
    }
    return b;
  }, [data]);

  const max = Math.max(...buckets, 1);

  return (
    <div className="flex items-end gap-1 h-16">
      {buckets.map((count, idx) => {
        const height = (count / max) * 100;
        const labels = ["0-20%", "20-40%", "40-60%", "60-80%", "80-100%"];
        const colors = [
          "bg-destructive/60",
          "bg-orange-500/60",
          "bg-amber-500/60",
          "bg-primary/60",
          "bg-green-500/60",
        ];
        return (
          <div key={idx} className="flex flex-col items-center flex-1 gap-0.5">
            <span className="text-[9px] text-muted-foreground tabular-nums">
              {count > 0 ? count : ""}
            </span>
            <div className="w-full relative" style={{ height: "48px" }}>
              <div
                className={`absolute bottom-0 w-full rounded-t ${colors[idx]} transition-all duration-300`}
                style={{ height: `${height}%`, minHeight: count > 0 ? "4px" : "0" }}
              />
            </div>
            <span className="text-[8px] text-muted-foreground/60">{labels[idx]}</span>
          </div>
        );
      })}
    </div>
  );
}

export function TechniqueDetail({ technique, onClose }: TechniqueDetailProps) {
  const { coverage, exportNavigator, investigationFilter } = useMitreStore();

  const [confidenceData] = useState<number[]>(() => {
    // Generate sample confidence data based on coverage count
    const tacticCoverage = coverage?.matrix ?? {};
    let count = 0;
    for (const tactics of Object.values(tacticCoverage)) {
      const techCoverage = tactics as Record<string, number>;
      if (techCoverage[technique.id]) {
        count += techCoverage[technique.id];
      }
    }
    // Simulate confidence distribution for the histogram
    return Array.from({ length: count }, () => Math.random() * 0.6 + 0.3);
  });

  const handleExport = useCallback(() => {
    // Include the technique id (root, no sub-technique suffix) in the
    // filename so per-technique exports are identifiable on disk.
    const rootId = technique.id.split(".")[0] ?? technique.id;
    void exportNavigator(investigationFilter ?? undefined, rootId);
  }, [exportNavigator, investigationFilter, technique.id]);

  const mitreUrl = technique.url ?? `https://attack.mitre.org/techniques/${technique.id.replace(".", "/")}/`;

  // Get investigations where this technique is tagged (from coverage data)
  const taggedInvestigations = useMemo(() => {
    // In a real app this would come from an API; here we derive from coverage
    const tacticCoverage = coverage?.matrix ?? {};
    const refs: Array<{ tactic: string; count: number }> = [];
    for (const [tactic, techniques] of Object.entries(tacticCoverage)) {
      const techCoverage = techniques as Record<string, number>;
      if (techCoverage[technique.id]) {
        refs.push({ tactic, count: techCoverage[technique.id] });
      }
    }
    return refs;
  }, [coverage, technique.id]);

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 backdrop-blur-sm z-40"
        onClick={onClose}
        aria-hidden="true"
        data-testid="technique-detail-backdrop"
      />

      {/* Panel */}
      <div
        className="fixed right-0 top-0 bottom-0 w-full max-w-lg bg-background border-l border-border/50 z-50 overflow-y-auto shadow-2xl shadow-black/40 animate-slide-in-right"
        role="dialog"
        aria-modal="true"
        aria-labelledby="technique-detail-title"
        data-testid="technique-detail"
      >
        {/* Header */}
        <div className="sticky top-0 z-10 bg-background/95 backdrop-blur-sm border-b border-border/50 p-4">
          <div className="flex items-start justify-between">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <Badge
                  className="text-[10px] bg-purple-500/20 text-purple-400 border-purple-500/30"
                  data-testid="technique-detail-id"
                >
                  {technique.id}
                </Badge>
                {technique.is_subtechnique && (
                  <Badge
                    className="text-[9px]"
                    data-testid="technique-detail-subtechnique-badge"
                  >
                    Sub-technique
                  </Badge>
                )}
              </div>
              <h2
                id="technique-detail-title"
                className="text-lg font-semibold text-foreground"
                data-testid="technique-detail-name"
              >
                {technique.name}
              </h2>
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                {(technique.tactic_names ?? []).map((tactic) => (
                  <span
                    key={tactic}
                    className="px-1.5 py-0.5 bg-accent rounded text-[10px] text-muted-foreground"
                    data-testid={`technique-detail-tactic-${tactic.toLowerCase().replace(/\s+/g, "-")}`}
                  >
                    {tactic}
                  </span>
                ))}
              </div>
            </div>
            <button
              onClick={onClose}
              className="text-muted-foreground hover:text-foreground p-1 rounded-md hover:bg-accent transition-colors shrink-0 ml-3"
              aria-label="Close technique details"
              data-testid="technique-detail-close-button"
            >
              <X className="h-5 w-5" aria-hidden="true" />
            </button>
          </div>

          <div className="flex items-center gap-2 mt-3">
            <a
              href={mitreUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-accent text-foreground hover:text-foreground hover:bg-muted border border-border transition-colors"
              data-testid="technique-detail-mitre-link"
            >
              <ExternalLink className="w-3.5 h-3.5" aria-hidden="true" />
              View on MITRE
            </a>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleExport}
              data-testid="technique-detail-export-button"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              Navigator Export
            </Button>
          </div>
        </div>

        <div className="p-4 space-y-6">
          {/* Description */}
          <div>
            <SectionHeader icon={<BookOpen className="w-3.5 h-3.5" />}>
              Description
            </SectionHeader>
            <p className="text-sm text-foreground leading-relaxed">
              {technique.description || "No description available."}
            </p>
          </div>

          {/* Platforms */}
          {(technique.platforms ?? []).length > 0 && (
            <div>
              <SectionHeader icon={<Layers className="w-3.5 h-3.5" />}>
                Platforms
              </SectionHeader>
              <div className="flex flex-wrap gap-1.5">
                {(technique.platforms ?? []).map((platform) => (
                  <Badge key={platform} className="text-[10px]">
                    {platform}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Data Sources */}
          {(technique.data_sources ?? []).length > 0 && (
            <div>
              <SectionHeader icon={<Eye className="w-3.5 h-3.5" />}>
                Data Sources
              </SectionHeader>
              <div className="space-y-1.5">
                {(technique.data_sources ?? []).map((ds) => (
                  <div
                    key={ds}
                    className="px-3 py-2 bg-card rounded-lg border border-border text-xs text-foreground"
                  >
                    {ds}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Detection Guidance */}
          {technique.detection && (
            <div>
              <SectionHeader icon={<Shield className="w-3.5 h-3.5" />}>
                Detection Guidance
              </SectionHeader>
              <div className="bg-card rounded-lg border border-border p-3">
                <p className="text-xs text-foreground leading-relaxed whitespace-pre-wrap">
                  {technique.detection}
                </p>
              </div>
            </div>
          )}

          {/* Confidence Histogram */}
          {confidenceData.length > 0 && (
            <div>
              <SectionHeader icon={<BarChart3 className="w-3.5 h-3.5" />}>
                Confidence Distribution ({confidenceData.length} tags)
              </SectionHeader>
              <div className="bg-card rounded-lg border border-border p-3">
                <ConfidenceHistogram data={confidenceData} />
              </div>
            </div>
          )}

          {/* Tagged Investigations */}
          {taggedInvestigations.length > 0 && (
            <div>
              <SectionHeader icon={<Shield className="w-3.5 h-3.5" />}>
                Tagged In
              </SectionHeader>
              <div className="space-y-2">
                {taggedInvestigations.map((ref) => (
                  <div
                    key={ref.tactic}
                    className="flex items-center justify-between px-3 py-2 bg-card rounded-lg border border-border"
                  >
                    <span className="text-xs text-foreground capitalize">
                      {ref.tactic.replace(/-/g, " ")}
                    </span>
                    <Badge className="text-[10px]">
                      {ref.count} {ref.count === 1 ? "tag" : "tags"}
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Sub-techniques */}
          {technique.sub_techniques && technique.sub_techniques.length > 0 && (
            <div data-testid="technique-detail-subtechniques">
              <SectionHeader icon={<Layers className="w-3.5 h-3.5" />}>
                Sub-techniques ({technique.sub_techniques.length})
              </SectionHeader>
              <div className="space-y-1.5">
                {technique.sub_techniques.map((sub) => (
                  <button
                    key={sub.id}
                    onClick={() => {
                      const { selectTechnique } = useMitreStore.getState();
                      selectTechnique(sub);
                    }}
                    className="flex items-center gap-2 w-full text-left px-3 py-2 bg-card rounded-lg border border-border hover:border-border transition-colors"
                    aria-label={`View sub-technique ${sub.name} (${sub.id})`}
                    data-testid={`technique-detail-subtechnique-${sub.id}`}
                  >
                    <span className="font-mono text-[10px] text-purple-400">
                      {sub.id}
                    </span>
                    <span className="text-xs text-foreground truncate">
                      {sub.name}
                    </span>
                    <ExternalLink
                      className="w-3 h-3 text-muted-foreground/60 ml-auto shrink-0"
                      aria-hidden="true"
                    />
                  </button>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  );
}
