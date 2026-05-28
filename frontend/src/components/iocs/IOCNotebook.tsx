import { useEffect, useState, useCallback, useMemo } from "react";
import {
  Search,
  Download,
  Upload,
  RefreshCw,
  CheckCircle2,
  Circle,
  Loader2,
  AlertTriangle,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  Zap,
  Database,
  XCircle,
} from "lucide-react";
import { useIOCStore } from "@/stores/iocStore";
import { useInvestigationStore } from "@/stores/investigationStore";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Badge } from "@/components/ds/badge";
import { IOCDetailPanel } from "./IOCDetailPanel";
import { IOCImportModal } from "./IOCImportModal";
import { IOCExportDialog } from "./IOCExportDialog";
import type { IOCType, IOCSortField, EnrichmentStatus } from "@/types/ioc";

const IOC_TYPE_OPTIONS: { label: string; value: IOCType | "" }[] = [
  { label: "All Types", value: "" },
  { label: "IP Address", value: "ip" },
  { label: "Domain", value: "domain" },
  { label: "MD5 Hash", value: "hash_md5" },
  { label: "SHA1 Hash", value: "hash_sha1" },
  { label: "SHA256 Hash", value: "hash_sha256" },
  { label: "URL", value: "url" },
  { label: "Email", value: "email" },
  { label: "CVE", value: "cve" },
  { label: "File Path", value: "file_path" },
  { label: "Other", value: "other" },
];

const TYPE_LABELS: Record<IOCType, string> = {
  ip: "IP",
  domain: "Domain",
  hash_md5: "MD5",
  hash_sha1: "SHA1",
  hash_sha256: "SHA256",
  url: "URL",
  email: "Email",
  cve: "CVE",
  file_path: "Path",
  other: "Other",
};

function ConfidenceBar({ confidence }: { confidence: number }) {
  const color =
    confidence < 0.3
      ? "bg-destructive"
      : confidence < 0.7
        ? "bg-amber-500"
        : "bg-green-500";
  const bgColor =
    confidence < 0.3
      ? "bg-destructive/20"
      : confidence < 0.7
        ? "bg-amber-500/20"
        : "bg-green-500/20";

  return (
    <div className="flex items-center gap-2">
      <div className={`w-20 h-2 rounded-full ${bgColor}`}>
        <div
          className={`h-full rounded-full ${color} transition-all duration-300`}
          style={{ width: `${Math.round(confidence * 100)}%` }}
        />
      </div>
      <span className="text-xs text-muted-foreground tabular-nums w-8">
        {Math.round(confidence * 100)}%
      </span>
    </div>
  );
}

function EnrichmentIcon({ status }: { status: EnrichmentStatus }) {
  switch (status) {
    case "enriched":
      return <CheckCircle2 className="w-4 h-4 text-green-400" />;
    case "enriching":
      return <Loader2 className="w-4 h-4 text-primary animate-spin" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-destructive" />;
    default:
      return <Circle className="w-4 h-4 text-muted-foreground" />;
  }
}

export function IOCNotebook() {
  const {
    iocs,
    isLoading,
    isEnriching,
    error,
    filters,
    sort,
    total,
    selectedIOCId,
    selectedIds,
    fetchIOCs,
    setFilters,
    setSort,
    selectIOC,
    toggleSelected,
    selectAll,
    clearSelection,
    bulkEnrich,
  } = useIOCStore();

  const { investigations, fetchInvestigations } = useInvestigationStore();

  const [searchQuery, setSearchQuery] = useState("");
  const [showImport, setShowImport] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [confidenceMin, setConfidenceMin] = useState(0);
  const [enrichedFilter, setEnrichedFilter] = useState<"all" | "enriched" | "not_enriched">("all");

  // Fetch investigations for the filter dropdown
  useEffect(() => {
    void fetchInvestigations();
  }, [fetchInvestigations]);

  // Fetch IOCs when filters/sort change
  useEffect(() => {
    void fetchIOCs();
  }, [fetchIOCs, filters, sort]);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      setFilters({ search: searchQuery || undefined });
    }, 300);
    return () => clearTimeout(timer);
  }, [searchQuery, setFilters]);

  // Confidence filter
  useEffect(() => {
    setFilters({ confidence_min: confidenceMin > 0 ? confidenceMin : undefined });
  }, [confidenceMin, setFilters]);

  // Enriched filter
  useEffect(() => {
    setFilters({
      enriched:
        enrichedFilter === "all"
          ? undefined
          : enrichedFilter === "enriched",
    });
  }, [enrichedFilter, setFilters]);

  const handleSort = useCallback(
    (field: IOCSortField) => {
      setSort({
        field,
        direction:
          sort.field === field && sort.direction === "asc" ? "desc" : "asc",
      });
    },
    [sort, setSort],
  );

  const handleBulkEnrich = useCallback(async () => {
    if (selectedIds.size === 0) return;
    await bulkEnrich(Array.from(selectedIds));
  }, [selectedIds, bulkEnrich]);

  const handleRefresh = useCallback(() => {
    void fetchIOCs();
  }, [fetchIOCs]);

  const allSelected = useMemo(
    () => iocs.length > 0 && iocs.every((ioc) => selectedIds.has(ioc.id)),
    [iocs, selectedIds],
  );

  function SortHeader({
    field,
    children,
  }: {
    field: IOCSortField;
    children: React.ReactNode;
  }) {
    const active = sort.field === field;
    return (
      <button
        className="inline-flex items-center gap-1 text-xs font-medium text-muted-foreground hover:text-foreground uppercase tracking-wide transition-colors"
        onClick={() => handleSort(field)}
        data-testid={`ioc-notebook-sort-${field}-button`}
      >
        {children}
        {active ? (
          sort.direction === "asc" ? (
            <ArrowUp className="w-3 h-3" aria-hidden="true" />
          ) : (
            <ArrowDown className="w-3 h-3" aria-hidden="true" />
          )
        ) : (
          <ArrowUpDown className="w-3 h-3 opacity-40" aria-hidden="true" />
        )}
      </button>
    );
  }

  return (
    <>
      <Header title="IOC Notebook" />

      <div className="flex-1 overflow-hidden flex flex-col p-6" data-testid="ioc-notebook">
        {/* Toolbar */}
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3 flex-1 w-full lg:w-auto">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" aria-hidden="true" />
              <input
                type="text"
                placeholder="Search IOCs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search IOCs"
                data-testid="ioc-notebook-search-input"
                className="w-full bg-card border border-border/50 rounded-lg pl-10 pr-4 py-2 text-sm text-foreground placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-primary/50 transition-colors"
              />
            </div>

            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              aria-label="Refresh IOC list"
              data-testid="ioc-notebook-refresh-button"
            >
              <RefreshCw className="w-4 h-4" aria-hidden="true" />
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowImport(true)}
              data-testid="ioc-notebook-import-button"
            >
              <Upload className="w-4 h-4" aria-hidden="true" />
              Import IOCs
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowExport(true)}
              data-testid="ioc-notebook-export-button"
            >
              <Download className="w-4 h-4" aria-hidden="true" />
              Export
            </Button>
          </div>
        </div>

        {/* Filter bar */}
        <div
          className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-card/50 border border-border rounded-lg"
          data-testid="ioc-notebook-filters"
        >
          {/* Type filter */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground font-medium">Type</label>
            <select
              value={filters.type ?? ""}
              onChange={(e) =>
                setFilters({
                  type: (e.target.value as IOCType) || undefined,
                })
              }
              aria-label="Filter by IOC type"
              data-testid="ioc-notebook-type-filter-input"
              className="bg-accent border border-border/50 rounded-md px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/50"
            >
              {IOC_TYPE_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label}
                </option>
              ))}
            </select>
          </div>

          {/* Confidence slider */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground font-medium">
              Confidence
            </label>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={confidenceMin * 100}
              onChange={(e) => setConfidenceMin(Number(e.target.value) / 100)}
              aria-label="Minimum confidence filter"
              data-testid="ioc-notebook-confidence-filter-input"
              className="w-24 accent-blue-500"
            />
            <span className="text-xs text-muted-foreground tabular-nums w-8">
              {Math.round(confidenceMin * 100)}%
            </span>
          </div>

          {/* Enriched toggle */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-muted-foreground font-medium">
              Enrichment
            </label>
            <div
              className="flex items-center gap-0.5 bg-accent rounded-md p-0.5"
              role="tablist"
              aria-label="Filter by enrichment status"
            >
              {(["all", "enriched", "not_enriched"] as const).map((val) => (
                <button
                  key={val}
                  onClick={() => setEnrichedFilter(val)}
                  role="tab"
                  aria-selected={enrichedFilter === val}
                  data-testid={`ioc-notebook-enrichment-filter-${val}`}
                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                    enrichedFilter === val
                      ? "bg-primary/20 text-primary"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {val === "all"
                    ? "All"
                    : val === "enriched"
                      ? "Enriched"
                      : "Pending"}
                </button>
              ))}
            </div>
          </div>

          {/* Investigation selector */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-muted-foreground font-medium">
              Investigation
            </label>
            <select
              value={filters.investigation_id ?? ""}
              onChange={(e) =>
                setFilters({
                  investigation_id: e.target.value || undefined,
                })
              }
              aria-label="Filter by investigation"
              data-testid="ioc-notebook-investigation-filter-input"
              className="bg-accent border border-border/50 rounded-md px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/50 max-w-[200px]"
            >
              <option value="">All Investigations</option>
              {investigations.map((inv) => (
                <option key={inv.id} value={inv.id}>
                  {inv.title}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Bulk actions bar */}
        {selectedIds.size > 0 && (
          <div
            className="flex items-center gap-3 mb-4 p-3 bg-primary/10 border border-primary/20 rounded-lg"
            data-testid="ioc-notebook-bulk-actions"
          >
            <span className="text-xs text-primary font-medium">
              {selectedIds.size} selected
            </span>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleBulkEnrich}
              disabled={isEnriching}
              data-testid="ioc-notebook-bulk-enrich-button"
            >
              {isEnriching ? (
                <Loader2 className="w-3.5 h-3.5 mr-1 animate-spin" />
              ) : (
                <Zap className="w-3.5 h-3.5 mr-1" aria-hidden="true" />
              )}
              Bulk Enrich
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowExport(true)}
              data-testid="ioc-notebook-bulk-export-button"
            >
              <Download className="w-3.5 h-3.5" aria-hidden="true" />
              Export Selected
            </Button>
            <Button
              variant="ghost"
              size="sm"
              onClick={clearSelection}
              data-testid="ioc-notebook-bulk-clear-button"
            >
              Clear
            </Button>
          </div>
        )}

        {/* Table */}
        {isLoading && iocs.length === 0 ? (
          <div
            className="flex items-center justify-center py-20"
            data-testid="ioc-notebook-loading"
          >
            <Loader2
              className="w-8 h-8 text-muted-foreground animate-spin"
              aria-label="Loading IOCs"
            />
          </div>
        ) : error ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            role="alert"
            data-testid="ioc-notebook-error"
          >
            <AlertTriangle className="w-10 h-10 text-amber-500 mb-3" aria-hidden="true" />
            <p className="text-sm">{error}</p>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              className="mt-3"
              data-testid="ioc-notebook-retry-button"
            >
              Retry
            </Button>
          </div>
        ) : iocs.length === 0 ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            data-testid="ioc-notebook-empty"
          >
            <Database className="w-10 h-10 text-muted-foreground/60 mb-3" aria-hidden="true" />
            <p className="text-sm font-medium text-foreground">
              No IOCs found
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {searchQuery || filters.type
                ? "Try adjusting your filters"
                : "Import IOCs or start an investigation to populate this notebook"}
            </p>
            <Button
              size="sm"
              onClick={() => setShowImport(true)}
              className="mt-4"
              data-testid="ioc-notebook-empty-import-button"
            >
              <Upload className="w-4 h-4" aria-hidden="true" />
              Import IOCs
            </Button>
          </div>
        ) : (
          <div className="flex-1 overflow-auto rounded-lg border border-border/50">
            <table className="w-full text-sm" data-testid="ioc-notebook-table">
              <thead className="sticky top-0 z-10">
                <tr className="bg-card border-b border-border/50">
                  <th className="px-3 py-3 text-left w-10">
                    <input
                      type="checkbox"
                      checked={allSelected}
                      onChange={() => {
                        if (allSelected) {
                          clearSelection();
                        } else {
                          selectAll();
                        }
                      }}
                      aria-label={allSelected ? "Deselect all IOCs" : "Select all IOCs"}
                      data-testid="ioc-notebook-select-all-input"
                      className="rounded border-border bg-accent text-primary focus:ring-blue-500/50 focus:ring-offset-slate-900"
                    />
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "type"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="type">Type</SortHeader>
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "value"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="value">Value</SortHeader>
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "confidence"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="confidence">Confidence</SortHeader>
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "source"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="source">Source</SortHeader>
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "enrichment_status"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="enrichment_status">
                      Enriched
                    </SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
                      MITRE Tags
                    </span>
                  </th>
                  <th
                    className="px-3 py-3 text-left"
                    aria-sort={
                      sort.field === "first_seen"
                        ? sort.direction === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <SortHeader field="first_seen">First Seen</SortHeader>
                  </th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, index) => (
                  <tr
                    key={ioc.id}
                    onClick={() => selectIOC(ioc.id)}
                    data-testid={`ioc-notebook-row-${ioc.id}`}
                    className={`border-b border-border/50 cursor-pointer transition-colors ${
                      selectedIOCId === ioc.id
                        ? "bg-primary/10 border-primary/20"
                        : index % 2 === 0
                          ? "bg-background"
                          : "bg-card/50"
                    } hover:bg-accent/50`}
                  >
                    <td
                      className="px-3 py-2.5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        type="checkbox"
                        checked={selectedIds.has(ioc.id)}
                        onChange={() => toggleSelected(ioc.id)}
                        aria-label={`Select IOC ${ioc.value}`}
                        data-testid={`ioc-notebook-row-${ioc.id}-select-input`}
                        className="rounded border-border bg-accent text-primary focus:ring-blue-500/50 focus:ring-offset-slate-900"
                      />
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge className="text-[10px]">
                        {TYPE_LABELS[ioc.type] ?? ioc.type}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="font-mono text-xs text-foreground truncate max-w-[240px] inline-block">
                        {ioc.value}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <ConfidenceBar confidence={ioc.confidence} />
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">
                        {ioc.source}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <EnrichmentIcon status={ioc.enrichment_status ?? "pending"} />
                    </td>
                    <td className="px-3 py-2.5">
                      <div className="flex items-center gap-1 flex-wrap max-w-[200px]">
                        {(ioc.mitre_tags ?? []).slice(0, 3).map((tag) => (
                          <span
                            key={tag.technique_id}
                            className="inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium bg-purple-500/15 text-purple-400 border border-purple-500/20"
                            title={`${tag.technique_id}: ${tag.technique_name}`}
                          >
                            {tag.technique_id}
                          </span>
                        ))}
                        {(ioc.mitre_tags ?? []).length > 3 && (
                          <span className="text-[10px] text-muted-foreground">
                            +{(ioc.mitre_tags ?? []).length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-muted-foreground">
                        {new Date(ioc.first_seen).toLocaleDateString(undefined, {
                          month: "short",
                          day: "numeric",
                          year: "numeric",
                        })}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Pagination summary */}
        {iocs.length > 0 && (
          <div className="flex items-center justify-between mt-3 text-xs text-muted-foreground">
            <span>
              Showing {iocs.length} of {total} IOCs
            </span>
            {isLoading && (
              <Loader2 className="w-3.5 h-3.5 text-muted-foreground animate-spin" />
            )}
          </div>
        )}
      </div>

      {/* Detail panel (slide-over) */}
      {selectedIOCId && (
        <IOCDetailPanel
          onClose={() => selectIOC(null)}
        />
      )}

      {/* Import modal */}
      <IOCImportModal open={showImport} onOpenChange={setShowImport} />

      {/* Export dialog */}
      <IOCExportDialog open={showExport} onOpenChange={setShowExport} />
    </>
  );
}
