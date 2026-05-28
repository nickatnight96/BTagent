import { useEffect, useState, useCallback } from "react";
import {
  Plus,
  Search as SearchIcon,
  Filter,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { useInvestigationStore } from "@/stores/investigationStore";
import { InvestigationStatus } from "@/types/config";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { cn } from "@/lib/utils";
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
        (inv.title ?? "").toLowerCase().includes(q) ||
        (inv.description ?? "").toLowerCase().includes(q) ||
        (inv.tags ?? []).some((t) => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  return (
    <>
      <Header title="PunchList" />

      <div
        className="flex-1 overflow-y-auto p-6"
        data-testid="investigation-list"
      >
        {/* Toolbar */}
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 mb-6">
          <div className="flex items-center gap-3 flex-1 w-full md:w-auto">
            <div className="relative flex-1 max-w-md">
              <SearchIcon
                className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground"
                aria-hidden="true"
              />
              <Input
                type="text"
                placeholder="Search investigations..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search investigations"
                data-testid="investigation-list-search-input"
                className="pl-10"
              />
            </div>

            <Button
              variant="ghost"
              size="icon"
              onClick={handleRefresh}
              aria-label="Refresh investigation list"
              data-testid="investigation-list-refresh-button"
            >
              <Filter className="w-4 h-4" aria-hidden="true" />
            </Button>
          </div>

          <Button
            onClick={() => setShowNewModal(true)}
            data-testid="investigation-list-new-button"
          >
            <Plus className="w-4 h-4 mr-2" aria-hidden="true" />
            New Investigation
          </Button>
        </div>

        {/* Status filter tabs (custom pill row instead of Tabs for now —
         * preserves keyboard/aria behaviour of the existing component) */}
        <div
          className="flex items-center gap-1 mb-6 overflow-x-auto pb-2"
          role="tablist"
          aria-label="Filter by status"
          data-testid="investigation-list-filters"
        >
          {statusFilters.map((filter) => {
            const active = statusFilter === filter.value;
            return (
              <button
                key={filter.value}
                onClick={() => setStatusFilter(filter.value)}
                role="tab"
                aria-selected={active}
                data-testid={`investigation-list-filter-${
                  filter.value || "all"
                }`}
                className={cn(
                  "px-3 py-1.5 rounded-md text-xs font-medium whitespace-nowrap transition-colors border",
                  active
                    ? "bg-primary/10 text-primary border-primary/30"
                    : "text-muted-foreground hover:text-foreground hover:bg-accent border-transparent"
                )}
              >
                {filter.label}
              </button>
            );
          })}
        </div>

        {/* Content */}
        {isLoading && investigations.length === 0 ? (
          <div
            className="flex items-center justify-center py-20"
            data-testid="investigation-list-loading"
          >
            <Loader2
              className="w-8 h-8 text-muted-foreground animate-spin"
              aria-label="Loading investigations"
            />
          </div>
        ) : error ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            role="alert"
            data-testid="investigation-list-error"
          >
            <AlertTriangle
              className="w-10 h-10 text-severity-medium mb-3"
              aria-hidden="true"
            />
            <p className="text-sm">{error}</p>
            <Button
              variant="ghost"
              size="sm"
              onClick={handleRefresh}
              className="mt-3"
              data-testid="investigation-list-retry-button"
            >
              Retry
            </Button>
          </div>
        ) : filteredInvestigations.length === 0 ? (
          <div
            className="flex flex-col items-center justify-center py-20 text-muted-foreground"
            data-testid="investigation-list-empty"
          >
            <SearchIcon
              className="w-10 h-10 text-muted-foreground/50 mb-3"
              aria-hidden="true"
            />
            <p className="text-sm font-medium text-foreground">
              No investigations found
            </p>
            <p className="text-xs text-muted-foreground mt-1">
              {searchQuery || statusFilter
                ? "Try adjusting your filters"
                : "Create your first investigation to get started"}
            </p>
            {!searchQuery && !statusFilter && (
              <Button
                size="sm"
                onClick={() => setShowNewModal(true)}
                className="mt-4"
                data-testid="investigation-list-empty-new-button"
              >
                <Plus className="w-4 h-4 mr-2" aria-hidden="true" />
                New Investigation
              </Button>
            )}
          </div>
        ) : (
          <div
            className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4"
            data-testid="investigation-list-grid"
          >
            {filteredInvestigations.map((investigation) => (
              <InvestigationCard
                key={investigation.id}
                investigation={investigation}
              />
            ))}
          </div>
        )}
      </div>

      <NewInvestigationModal open={showNewModal} onOpenChange={setShowNewModal} />
    </>
  );
}
