import { useEffect, useState, useCallback } from "react";
import { Plus, Search, Filter, Loader2, AlertTriangle } from "lucide-react";
import { useInvestigationStore } from "@/stores/investigationStore";
import { InvestigationStatus } from "@/types/config";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ui/Button";
import { InvestigationCard } from "./InvestigationCard";
import { NewInvestigationModal } from "./NewInvestigationModal";

const statusFilters: { label: string; value: string }[] = [
  { label: "All", value: "" },
  { label: "Running", value: InvestigationStatus.RUNNING },
  { label: "Pending", value: InvestigationStatus.PENDING },
  { label: "Awaiting HITL", value: InvestigationStatus.AWAITING_HITL },
  { label: "Paused", value: InvestigationStatus.PAUSED },
  { label: "Completed", value: InvestigationStatus.COMPLETED },
  { label: "Failed", value: InvestigationStatus.FAILED },
];

export function InvestigationList() {
  const { investigations, isLoading, error, fetchInvestigations } =
    useInvestigationStore();

  const [showNewModal, setShowNewModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");

  useEffect(() => {
    void fetchInvestigations({
      status: statusFilter || undefined,
      search: searchQuery || undefined,
    });
  }, [fetchInvestigations, statusFilter, searchQuery]);

  const handleRefresh = useCallback(() => {
    void fetchInvestigations({
      status: statusFilter || undefined,
      search: searchQuery || undefined,
    });
  }, [fetchInvestigations, statusFilter, searchQuery]);

  const filteredInvestigations = investigations.filter((inv) => {
    if (statusFilter && inv.status !== statusFilter) return false;
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      return (
        inv.title.toLowerCase().includes(q) ||
        inv.description.toLowerCase().includes(q) ||
        inv.tags.some((t) => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <>
      <Header title="PunchList" />

      <div className="flex-1 overflow-y-auto p-6">
        {/* Toolbar */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3 flex-1 w-full md:w-auto">
            {/* Search */}
            <div className="relative flex-1 max-w-md">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="text"
                placeholder="Search investigations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="w-full bg-slate-900 border border-slate-700/50 rounded-lg pl-10 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/50 focus:border-blue-500/50 transition-colors"
              />
            </div>

            {/* Refresh */}
            <Button variant="ghost" size="sm" onClick={handleRefresh}>
              <Filter className="w-4 h-4" />
            </Button>
          </div>

          {/* New Investigation */}
          <Button onClick={() => setShowNewModal(true)} size="md">
            <Plus className="w-4 h-4" />
            New Investigation
          </Button>
        </div>

        {/* Status filter tabs */}
        <div className="flex items-center gap-1 mb-6 overflow-x-auto pb-2">
          {statusFilters.map((filter) => (
            <button
              key={filter.value}
              onClick={() => setStatusFilter(filter.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap transition-colors ${
                statusFilter === filter.value
                  ? "bg-blue-600/20 text-blue-400 border border-blue-500/30"
                  : "text-slate-400 hover:text-slate-200 hover:bg-slate-800 border border-transparent"
              }`}
            >
              {filter.label}
            </button>
          ))}
        </div>

        {/* Content */}
        {isLoading && investigations.length === 0 ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-slate-500 animate-spin" />
          </div>
        ) : error ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <AlertTriangle className="w-10 h-10 text-amber-500 mb-3" />
            <p className="text-sm">{error}</p>
            <Button variant="ghost" size="sm" onClick={handleRefresh} className="mt-3">
              Retry
            </Button>
          </div>
        ) : filteredInvestigations.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 text-slate-400">
            <Search className="w-10 h-10 text-slate-600 mb-3" />
            <p className="text-sm font-medium text-slate-300">
              No investigations found
            </p>
            <p className="text-xs text-slate-500 mt-1">
              {searchQuery || statusFilter
                ? "Try adjusting your filters"
                : "Create your first investigation to get started"}
            </p>
            {!searchQuery && !statusFilter && (
              <Button
                size="sm"
                onClick={() => setShowNewModal(true)}
                className="mt-4"
              >
                <Plus className="w-4 h-4" />
                New Investigation
              </Button>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
            {filteredInvestigations.map((investigation) => (
              <InvestigationCard
                key={investigation.id}
                investigation={investigation}
              />
            ))}
          </div>
        )}
      </div>

      {/* New Investigation Modal */}
      <NewInvestigationModal open={showNewModal} onOpenChange={setShowNewModal} />
    </>
  );
}
