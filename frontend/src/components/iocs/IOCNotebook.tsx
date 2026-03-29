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
import { Button } from "@/components/ui/Button";
import { Badge } from "@/components/ui/Badge";
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
      ? "bg-red-500"
      : confidence < 0.7
        ? "bg-amber-500"
        : "bg-green-500";
  const bgColor =
    confidence < 0.3
      ? "bg-red-500/20"
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
      <span className="text-xs text-slate-400 tabular-nums w-8">
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
      return <Loader2 className="w-4 h-4 text-blue-400 animate-spin" />;
    case "failed":
      return <XCircle className="w-4 h-4 text-red-400" />;
    default:
      return <Circle className="w-4 h-4 text-slate-500" />;
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
        className="inline-flex items-center gap-1 text-xs font-medium text-slate-400 hover:text-slate-200 uppercase tracking-wide transition-colors"
        onClick={() => handleSort(field)}
      >
        {children}
        {active ? (
          sort.direction === "asc" ? (
            <ArrowUp className="w-3 h-3" />
          ) : (
            <ArrowDown className="w-3 h-3" />
          )
        ) : (
          <ArrowUpDown className="w-3 h-3 opacity-40" />
        )}
      </button>
    );
  }

  return (
    <>
      <Header title="IOC Notebook" />

      <div className="flex-1 overflow-hidden flex flex-col p-6">
        {/* Toolbar */}
        <div className="flex flex-col lg:flex-row items-start lg:items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3 flex-1 w-full lg:w-auto">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search IOCs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700/50 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-colors"
              />
            </div>

            <Button variant="ghost" size="sm" onClick={handleRefresh}>
              <RefreshCw className="w-4 h-4" />
            </Button>
          </div>

          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowImport(true)}
            >
              <Upload className="w-4 h-4" />
              Import IOCs
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowExport(true)}
            >
              <Download className="w-4 h-4" />
              Export
            </Button>
          </div>
        </div>

        {/* Filter bar */}
        <div className="flex flex-wrap items-center gap-3 mb-4 p-3 bg-slate-900/50 border border-slate-800 rounded-lg">
          {/* Type filter */}
          <div className="flex items-center gap-2">
            <label className="text-xs text-slate-500 font-medium">Type</label>
            <select
              value={filters.type ?? ""}
              onChange={(e) =>
                setFilters({
                  type: (e.target.value as IOCType) || undefined,
                })
              }
              className="bg-slate-800 border border-slate-600/50 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50"
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
            <label className="text-xs text-slate-500 font-medium">
              Confidence
            </label>
            <input
              type="range"
              min="0"
              max="100"
              step="5"
              value={confidenceMin * 100}
              onChange={(e) => setConfidenceMin(Number(e.target.value) / 100)}
              className="w-24 accent-blue-500"
            />
            <span className="text-xs text-slate-400 tabular-nums w-8">
              {Math.round(confidenceMin * 100)}%
            </span>
          </div>

          {/* Enriched toggle */}
          <div className="flex items-center gap-1">
            <label className="text-xs text-slate-500 font-medium">
              Enrichment
            </label>
            <div className="flex items-center gap-0.5 bg-slate-800 rounded-md p-0.5">
              {(["all", "enriched", "not_enriched"] as const).map((val) => (
                <button
                  key={val}
                  onClick={() => setEnrichedFilter(val)}
                  className={`px-2 py-1 rounded text-xs font-medium transition-colors ${
                    enrichedFilter === val
                      ? "bg-blue-600/20 text-blue-400"
                      : "text-slate-400 hover:text-slate-200"
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
            <label className="text-xs text-slate-500 font-medium">
              Investigation
            </label>
            <select
              value={filters.investigation_id ?? ""}
              onChange={(e) =>
                setFilters({
                  investigation_id: e.target.value || undefined,
                })
              }
              className="bg-slate-800 border border-slate-600/50 rounded-md px-2 py-1.5 text-xs text-slate-200 focus:outline-none focus:ring-2 focus:ring-blue-500/50 max-w-[200px]"
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
          <div className="flex items-center gap-3 mb-4 p-3 bg-blue-600/10 border border-blue-500/20 rounded-lg">
            <span className="text-xs text-blue-400 font-medium">
              {selectedIds.size} selected
            </span>
            <Button
              variant="secondary"
              size="sm"
              onClick={handleBulkEnrich}
              isLoading={isEnriching}
            >
              <Zap className="w-3.5 h-3.5" />
              Bulk Enrich
            </Button>
            <Button
              variant="secondary"
              size="sm"
              onClick={() => setShowExport(true)}
            >
              <Download className="w-3.5 h-3.5" />
              Export Selected
            </Button>
            <Button variant="ghost" size="sm" onClick={clearSelection}>
              Clear
            </Button>
          </div>
        )}

        {/* Table */}
        {isLoading && iocs.length === 0 ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-slate-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <AlertTriangle className="w-10 h-10 text-amber-500 mb-3" />
            <p className="text-sm">{error}</p>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              className="mt-3"
            >
              Retry
            </Button>
          </div>
        ) : iocs.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <Database className="w-10 h-10 text-slate-600 mb-3" />
            <p className="text-sm font-medium text-slate-300">
              No IOCs found
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {searchQuery || filters.type
                ? "Try adjusting your filters"
                : "Import IOCs or start an investigation to populate this notebook"}
            </p>
            <Button
              size="sm"
              onClick={() => setShowImport(true)}
              className="mt-4"
            >
              <Upload className="w-4 h-4" />
              Import IOCs
            </Button>
          </div>
        ) : (
          <div className="flex-1 overflow-auto rounded-lg border border-slate-700/50">
            <table className="w-full text-sm">
              <thead className="sticky top-0 z-10">
                <tr className="bg-slate-900 border-b border-slate-700/50">
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
                      className="rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/50 focus:ring-offset-slate-900"
                    />
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="type">Type</SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="value">Value</SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="confidence">Confidence</SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="source">Source</SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="enrichment_status">
                      Enriched
                    </SortHeader>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <span className="text-xs font-medium text-slate-400 uppercase tracking-wide">
                      MITRE Tags
                    </span>
                  </th>
                  <th className="px-3 py-3 text-left">
                    <SortHeader field="first_seen">First Seen</SortHeader>
                  </th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((ioc, index) => (
                  <tr
                    key={ioc.id}
                    onClick={() => selectIOC(ioc.id)}
                    className={`border-b border-slate-800/50 cursor-pointer transition-colors ${
                      selectedIOCId === ioc.id
                        ? "bg-blue-600/10 border-blue-500/20"
                        : index % 2 === 0
                          ? "bg-slate-950"
                          : "bg-slate-900/50"
                    } hover:bg-slate-800/50`}
                  >
                    <td
                      className="px-3 py-2.5"
                      onClick={(e) => e.stopPropagation()}
                    >
                      <input
                        type="checkbox"
                        checked={selectedIds.has(ioc.id)}
                        onChange={() => toggleSelected(ioc.id)}
                        className="rounded border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500/50 focus:ring-offset-slate-900"
                      />
                    </td>
                    <td className="px-3 py-2.5">
                      <Badge className="text-[10px]">
                        {TYPE_LABELS[ioc.type] ?? ioc.type}
                      </Badge>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="font-mono text-xs text-slate-200 truncate max-w-[240px] inline-block">
                        {ioc.value}
                      </span>
                    </td>
                    <td className="px-3 py-2.5">
                      <ConfidenceBar confidence={ioc.confidence} />
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-slate-400">
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
                          <span className="text-[10px] text-slate-500">
                            +{(ioc.mitre_tags ?? []).length - 3}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-3 py-2.5">
                      <span className="text-xs text-slate-500">
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
          <div className="flex items-center justify-between mt-3 text-xs text-slate-500">
            <span>
              Showing {iocs.length} of {total} IOCs
            </span>
            {isLoading && (
              <Loader2 className="w-3.5 h-3.5 text-slate-500 animate-spin" />
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
