import { useEffect, useState, useCallback, useMemo } from "react";
import {
  Search,
  Download,
  Loader2,
  AlertTriangle,
  Grid3X3,
  BarChart3,
} from "lucide-react";
import { useMitreStore } from "@/stores/mitreStore";
import { useInvestigationStore } from "@/stores/investigationStore";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { TechniqueDetail } from "./TechniqueDetail";

/** The 14 Enterprise ATT&CK tactic columns in kill-chain order */
const TACTIC_ORDER = [
  "reconnaissance",
  "resource-development",
  "initial-access",
  "execution",
  "persistence",
  "privilege-escalation",
  "defense-evasion",
  "credential-access",
  "discovery",
  "lateral-movement",
  "collection",
  "command-and-control",
  "exfiltration",
  "impact",
] as const;

const TACTIC_LABELS: Record<string, string> = {
  "reconnaissance": "Recon",
  "resource-development": "Resource Dev",
  "initial-access": "Initial Access",
  "execution": "Execution",
  "persistence": "Persistence",
  "privilege-escalation": "Priv Esc",
  "defense-evasion": "Defense Evasion",
  "credential-access": "Cred Access",
  "discovery": "Discovery",
  "lateral-movement": "Lateral Move",
  "collection": "Collection",
  "command-and-control": "C2",
  "exfiltration": "Exfiltration",
  "impact": "Impact",
};

/** Map a count to a color intensity class */
function countToColor(count: number): string {
  if (count === 0) return "bg-accent/50 border-border/30";
  if (count === 1) return "bg-primary/30/40 border-primary/30";
  if (count <= 3) return "bg-primary/50 border-primary/30";
  if (count <= 5) return "bg-orange-900/50 border-orange-600/30";
  if (count <= 10) return "bg-destructive/30/50 border-red-600/30";
  return "bg-destructive/60 border-red-500/40";
}

function countToTextColor(count: number): string {
  if (count === 0) return "text-muted-foreground/60";
  if (count === 1) return "text-primary";
  if (count <= 3) return "text-primary";
  if (count <= 5) return "text-orange-400";
  if (count <= 10) return "text-destructive";
  return "text-destructive";
}

export function MitreMatrix() {
  const {
    techniques,
    coverage,
    selectedTechnique,
    investigationFilter,
    isLoading,
    error,
    fetchTechniques,
    fetchTactics,
    fetchCoverage,
    selectTechnique,
    setInvestigationFilter,
    exportNavigator,
    searchTechniques,
  } = useMitreStore();

  const { investigations, fetchInvestigations } = useInvestigationStore();

  const [searchQuery, setSearchQuery] = useState("");
  const [viewMode, setViewMode] = useState<"global" | "investigation">("global");

  // Initial data fetch
  useEffect(() => {
    void fetchTactics();
    void fetchTechniques();
    void fetchCoverage();
    void fetchInvestigations();
  }, [fetchTactics, fetchTechniques, fetchCoverage, fetchInvestigations]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (searchQuery.trim()) {
        void searchTechniques(searchQuery);
      } else {
        void fetchTechniques();
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, searchTechniques, fetchTechniques]);

  const handleExportNavigator = useCallback(() => {
    void exportNavigator(investigationFilter ?? undefined);
  }, [exportNavigator, investigationFilter]);

  const handleViewToggle = useCallback(
    (mode: "global" | "investigation") => {
      setViewMode(mode);
      if (mode === "global") {
        setInvestigationFilter(null);
      }
    },
    [setInvestigationFilter],
  );

  /** Build the matrix: tactic -> array of { technique, count } */
  const matrixData = useMemo(() => {
    const matrix: Record<
      string,
      Array<{ id: string; name: string; count: number }>
    > = {};

    for (const tactic of TACTIC_ORDER) {
      matrix[tactic] = [];
    }

    // Group techniques by tactic. The backend returns ``tactic`` as a
    // single shortname string (e.g. "initial-access"); the optional
    // ``tactic_names`` array is legacy and may be missing on every row
    // in current builds — falling back to the singular field is what
    // makes the matrix render cells.
    const techByTactic = new Map<string, typeof techniques>();
    for (const tech of techniques) {
      const names = tech.tactic_names && tech.tactic_names.length > 0
        ? tech.tactic_names
        : tech.tactic
          ? [tech.tactic]
          : [];
      for (const tacticName of names) {
        const key = tacticName.toLowerCase().replace(/\s+/g, "-");
        if (!techByTactic.has(key)) {
          techByTactic.set(key, []);
        }
        techByTactic.get(key)!.push(tech);
      }
    }

    for (const tactic of TACTIC_ORDER) {
      const techs = techByTactic.get(tactic) ?? [];
      const tacticCoverage = coverage?.matrix?.[tactic] ?? {};

      matrix[tactic] = techs.map((tech) => ({
        id: tech.id,
        name: tech.name,
        count: tacticCoverage[tech.id] ?? 0,
      }));

      // Sort: tagged first (desc count), then alphabetical
      matrix[tactic].sort((a, b) => {
        if (b.count !== a.count) return b.count - a.count;
        return a.name.localeCompare(b.name);
      });
    }

    return matrix;
  }, [techniques, coverage]);

  const maxRows = useMemo(
    () =>
      Math.max(
        ...Object.values(matrixData).map((col) => col.length),
        1,
      ),
    [matrixData],
  );

  return (
    <>
      <Header title="MITRE ATT&CK Matrix" />

      <div className="flex-1 overflow-hidden flex flex-col p-6" data-testid="mitre-matrix">
        {/* Toolbar */}
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3 flex-1 w-full lg:w-auto">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                aria-hidden="true"
              />
              <input
                type="text"
                placeholder="Search techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search techniques"
                data-testid="mitre-matrix-search-input"
                className="w-full bg-card border border-border/50 rounded-lg pl-10 pr-4 py-2 text-sm text-foreground placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-primary/50 transition-colors"
              />
            </div>

            {/* View toggle */}
            <div
              className="flex items-center gap-0.5 bg-card border border-border/50 rounded-lg p-0.5"
              role="tablist"
              aria-label="Matrix view mode"
              data-testid="mitre-matrix-view-toggle"
            >
              <button
                onClick={() => handleViewToggle("global")}
                role="tab"
                aria-selected={viewMode === "global"}
                data-testid="mitre-matrix-view-toggle-global"
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  viewMode === "global"
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Global
              </button>
              <button
                onClick={() => handleViewToggle("investigation")}
                role="tab"
                aria-selected={viewMode === "investigation"}
                data-testid="mitre-matrix-view-toggle-investigation"
                className={`px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  viewMode === "investigation"
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:text-foreground"
                }`}
              >
                Per Investigation
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {/* Investigation filter (when in investigation mode) */}
            {viewMode === "investigation" && (
              <select
                value={investigationFilter ?? ""}
                onChange={(e) =>
                  setInvestigationFilter(e.target.value || null)
                }
                aria-label="Filter by investigation"
                data-testid="mitre-matrix-investigation-filter-input"
                className="bg-accent border border-border/50 rounded-md px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/50 max-w-[200px]"
              >
                <option value="">Select Investigation</option>
                {investigations.map((inv) => (
                  <option key={inv.id} value={inv.id}>
                    {inv.title}
                  </option>
                ))}
              </select>
            )}

            <Button
              variant="secondary"
              size="sm"
              onClick={handleExportNavigator}
              data-testid="mitre-matrix-export-button"
            >
              <Download className="w-4 h-4" aria-hidden="true" />
              Navigator Export
            </Button>
          </div>
        </div>

        {/* Coverage score badge */}
        {coverage && (
          <div
            className="flex items-center gap-4 mb-4 p-3 bg-card/50 border border-border rounded-lg"
            data-testid="mitre-matrix-coverage"
          >
            <div className="flex items-center gap-2">
              <BarChart3 className="w-4 h-4 text-primary" aria-hidden="true" />
              <span className="text-xs font-medium text-muted-foreground">
                Coverage Score
              </span>
              <Badge
                data-testid="mitre-matrix-coverage-score"
                className={`text-sm font-bold ${
                  (coverage?.coverage_score ?? 0) >= 70
                    ? "bg-green-500/20 text-green-400 border-green-500/30"
                    : (coverage?.coverage_score ?? 0) >= 40
                      ? "bg-amber-500/20 text-amber-400 border-amber-500/30"
                      : "bg-destructive/20 text-destructive border-red-500/30"
                }`}
              >
                {(coverage?.coverage_score ?? 0)}%
              </Badge>
            </div>
            <div className="flex items-center gap-4 text-xs text-muted-foreground">
              <span>
                <span className="text-foreground font-medium">
                  {(coverage?.total_tagged ?? 0)}
                </span>{" "}
                techniques tagged
              </span>
              <span>
                of{" "}
                <span className="text-foreground font-medium">
                  {(coverage?.total_techniques ?? 0)}
                </span>{" "}
                total
              </span>
            </div>
            {/* Color legend */}
            <div className="flex items-center gap-2 ml-auto text-[10px] text-muted-foreground">
              <span>Intensity:</span>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-accent/50 border border-border/30" />
                <span>0</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-primary/30/40 border border-primary/30" />
                <span>1</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-primary/50 border border-primary/30" />
                <span>2-3</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-orange-900/50 border border-orange-600/30" />
                <span>4-5</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-destructive/30/50 border border-red-600/30" />
                <span>6-10</span>
              </div>
              <div className="flex items-center gap-1">
                <div className="w-3 h-3 rounded bg-destructive/60 border border-red-500/40" />
                <span>10+</span>
              </div>
            </div>
          </div>
        )}

        {/* Matrix */}
        {isLoading && techniques.length === 0 ? (
          <div
            className="flex items-center justify-center py-20"
            data-testid="mitre-matrix-loading"
          >
            <Loader2
              className="w-8 h-8 text-muted-foreground animate-spin"
              aria-label="Loading MITRE techniques"
            />
          </div>
        ) : error ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            role="alert"
            data-testid="mitre-matrix-error"
          >
            <AlertTriangle
              className="w-10 h-10 text-amber-500 mb-3"
              aria-hidden="true"
            />
            <p className="text-sm">{error}</p>
            <Button
              variant="ghost"
              size="sm"
              onClick={() => {
                void fetchTechniques();
                void fetchCoverage();
              }}
              className="mt-3"
              data-testid="mitre-matrix-retry-button"
            >
              Retry
            </Button>
          </div>
        ) : techniques.length === 0 ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            data-testid="mitre-matrix-empty"
          >
            <Grid3X3 className="w-10 h-10 text-muted-foreground/60 mb-3" aria-hidden="true" />
            <p className="text-sm font-medium text-foreground">
              No techniques loaded
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              MITRE ATT&CK data may need to be synced from the backend
            </p>
          </div>
        ) : (
          <div className="flex-1 overflow-auto">
            <div
              className="grid gap-px min-w-[1200px]"
              style={{
                gridTemplateColumns: `repeat(${TACTIC_ORDER.length}, minmax(90px, 1fr))`,
              }}
              role="grid"
              aria-label="MITRE ATT&CK technique matrix"
              data-testid="mitre-matrix-grid"
            >
              {/* Tactic headers */}
              {TACTIC_ORDER.map((tactic) => (
                <div
                  key={`header-${tactic}`}
                  className="sticky top-0 z-10 bg-card border-b border-border/50 px-2 py-2.5 text-center"
                  role="columnheader"
                  aria-label={`Tactic: ${TACTIC_LABELS[tactic] ?? tactic}`}
                  data-testid={`mitre-tactic-column-${tactic}`}
                >
                  <span className="text-[10px] font-semibold text-muted-foreground uppercase tracking-wider leading-tight">
                    {TACTIC_LABELS[tactic] ?? tactic}
                  </span>
                  <div className="text-[9px] text-muted-foreground/60 mt-0.5">
                    {matrixData[tactic]?.length ?? 0} techniques
                  </div>
                </div>
              ))}

              {/* Technique cells */}
              {Array.from({ length: Math.min(maxRows, 60) }).map((_, rowIdx) =>
                TACTIC_ORDER.map((tactic) => {
                  const cell = matrixData[tactic]?.[rowIdx];
                  if (!cell) {
                    return (
                      <div
                        key={`empty-${tactic}-${rowIdx}`}
                        className="min-h-[36px]"
                      />
                    );
                  }
                  return (
                    <button
                      key={`${tactic}-${cell.id}`}
                      onClick={() => {
                        const tech = techniques.find(
                          (t) => t.id === cell.id,
                        );
                        if (tech) selectTechnique(tech);
                      }}
                      className={`group relative min-h-[36px] px-1.5 py-1.5 border rounded text-left transition-all duration-150 hover:scale-[1.02] hover:z-10 hover:shadow-lg hover:shadow-black/30 ${countToColor(cell.count)}`}
                      title={`${cell.id}: ${cell.name} (${cell.count} tagged)`}
                      aria-label={`${cell.name} (${cell.id}) under ${TACTIC_LABELS[tactic] ?? tactic}, ${cell.count} tagged`}
                      data-testid={`mitre-technique-cell-${cell.id}`}
                    >
                      <div className="text-[9px] font-mono text-muted-foreground group-hover:text-muted-foreground leading-none">
                        {cell.id}
                      </div>
                      <div className="text-[10px] text-muted-foreground group-hover:text-foreground leading-tight mt-0.5 line-clamp-2">
                        {cell.name}
                      </div>
                      {cell.count > 0 && (
                        <div
                          className={`absolute top-1 right-1 text-[9px] font-bold tabular-nums ${countToTextColor(cell.count)}`}
                        >
                          {cell.count}
                        </div>
                      )}
                    </button>
                  );
                }),
              )}
            </div>

            {maxRows > 60 && (
              <p
                className="text-[10px] text-muted-foreground/60 text-center mt-2"
                data-testid="mitre-matrix-truncation-notice"
              >
                Showing first 60 rows. Use search to find specific techniques.
              </p>
            )}
          </div>
        )}
      </div>

      {/* Technique detail panel */}
      {selectedTechnique && (
        <TechniqueDetail
          technique={selectedTechnique}
          onClose={() => selectTechnique(null)}
        />
      )}
    </>
  );
}
