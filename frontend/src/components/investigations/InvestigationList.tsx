import { useEffect, useState, useCallback, useRef } from "react";
import {
  Plus,
  Search as SearchIcon,
  Filter,
  Loader2,
  AlertTriangle,
} from "lucide-react";
import { getDashboardLayout } from "@/api/dashboard";
import { useInvestigationStore } from "@/stores/investigationStore";
import { useLiveEventRefresh } from "@/hooks/useLiveEventRefresh";
import { EventType } from "@/types/events";
import { InvestigationStatus } from "@/types/config";
import type { DashboardLayout, DashboardLayoutResponse } from "@/types/dashboard";
import { Header } from "@/components/layout/Header";
import { Button } from "@/components/ds/button";
import { Input } from "@/components/ds/input";
import { cn } from "@/lib/utils";
import { InvestigationCard } from "./InvestigationCard";
import { HandoverCard } from "./HandoverCard";
import { LayoutSettings } from "./LayoutSettings";
import { NewInvestigationModal } from "./NewInvestigationModal";

// Investigation-lifecycle events that should refresh the board (F11).
const INVESTIGATION_LIFECYCLE_EVENTS = [
  EventType.INVESTIGATION_INIT,
  EventType.INVESTIGATION_COMPLETE,
  EventType.INVESTIGATION_FAILED,
  EventType.INVESTIGATION_PAUSED,
  EventType.INVESTIGATION_RESUMED,
] as const;

// Every real InvestigationStatus gets a pill, so no case is unreachable by
// filtering. The value is sent verbatim to `GET /investigations?status=` and
// compared against the stored status, so these must be the backend's values —
// the previous list offered "running" / "awaiting_hitl" / "completed", which
// the API never writes, so those three pills always returned nothing.
const statusFilters: { label: string; value: string }[] = [
  { label: "All", value: "" },
  { label: "Pending", value: InvestigationStatus.PENDING },
  { label: "Triaging", value: InvestigationStatus.TRIAGING },
  { label: "Investigating", value: InvestigationStatus.INVESTIGATING },
  { label: "Awaiting HITL", value: InvestigationStatus.PAUSED_HITL },
  { label: "Paused", value: InvestigationStatus.PAUSED },
  { label: "Contained", value: InvestigationStatus.CONTAINED },
  { label: "Remediated", value: InvestigationStatus.REMEDIATED },
  { label: "Closed", value: InvestigationStatus.CLOSED },
  { label: "Failed", value: InvestigationStatus.FAILED },
  { label: "Cancelled", value: InvestigationStatus.CANCELLED },
  { label: "Archived", value: InvestigationStatus.ARCHIVED },
];

export function InvestigationList() {
  const { investigations, isLoading, error, fetchInvestigations } =
    useInvestigationStore();

  const [showNewModal, setShowNewModal] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  // Role-tuned view (#108): the saved/role-default layout preselects a status
  // pill and decides section visibility. Null until loaded; a fetch failure
  // leaves the stock layout (everything visible, All preselected).
  const [layout, setLayout] = useState<DashboardLayout | null>(null);
  const [layoutSource, setLayoutSource] = useState("role_default");
  // Once the user clicks a pill themselves, the preference must not clobber
  // their choice — even if the (async) layout fetch resolves afterwards.
  const filterTouched = useRef(false);

  useEffect(() => {
    let cancelled = false;
    getDashboardLayout()
      .then((resp) => {
        if (cancelled) return;
        setLayout(resp.layout);
        setLayoutSource(resp.source);
        const pref = resp.layout.default_status_filter;
        if (
          pref &&
          !filterTouched.current &&
          statusFilters.some((f) => f.value === pref)
        ) {
          setStatusFilter(pref);
        }
      })
      .catch(() => {
        // Preference is a nicety — the PunchList must render without it.
      });
    return () => {
      cancelled = true;
    };
  }, []);

  // Save/reset from the view-settings dropdown: section visibility applies
  // immediately; the default filter only takes effect on the next visit
  // (changing it mid-session would yank the board out from under the user).
  const handleLayoutApplied = useCallback((resp: DashboardLayoutResponse) => {
    setLayout(resp.layout);
    setLayoutSource(resp.source);
  }, []);

  const showHandover = layout ? layout.sections.includes("handover") : true;

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

  // F11: the SOC landing board had no refresh path at all (no poll, no live
  // hook). Reuse the shared live-refresh hook the hunt pages already use — it
  // refetches on any investigation-lifecycle event and keeps a 30 s polling
  // safety net when the WS is unavailable, so the board can't silently stale.
  useLiveEventRefresh(handleRefresh, INVESTIGATION_LIFECYCLE_EVENTS);

  // The server applies both the status filter and the search (it did not used
  // to — `search` was sent to a route that never declared it, so this list
  // re-filtered whatever page had already been fetched). Re-filtering here now
  // would only hide rows: the server matches on description too, and the `tags`
  // branch that used to be here read a field no API response carries.
  //
  // Leaving it out also keeps `total` honest — the count in the header is the
  // server's count for the same query, so it no longer disagrees with the rows
  // on screen.
  const filteredInvestigations = investigations;

  return (
    <>
      <Header title="PunchList" />

      <div
        className="flex-1 overflow-y-auto p-6"
        data-testid="investigation-list"
      >
        {/* Shift-handover rollup (UC-5.1) — renders nothing on fetch failure;
         * hidden entirely when the user's layout omits the section (#108). */}
        {showHandover && <HandoverCard />}

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

            {/* View settings appear once the preference has loaded — saving
             * before then could clobber a customization with the stock view. */}
            {layout && (
              <LayoutSettings
                layout={layout}
                source={layoutSource}
                statusOptions={statusFilters}
                onApplied={handleLayoutApplied}
              />
            )}
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
                onClick={() => {
                  filterTouched.current = true;
                  setStatusFilter(filter.value);
                }}
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
