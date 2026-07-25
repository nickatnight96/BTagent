import { useEffect, useRef, useState } from "react";
import { Settings2, RotateCcw } from "lucide-react";
import { toast } from "sonner";
import { putDashboardLayout, resetDashboardLayout } from "@/api/dashboard";
import type { DashboardLayout, DashboardLayoutResponse } from "@/types/dashboard";
import { Button } from "@/components/ds/button";
import { NativeSelect } from "@/components/ds/native-select";

/**
 * PunchList view settings (#108 role-tuned views): a small dropdown that
 * saves the caller's dashboard-layout preference (handover visibility +
 * default status pill) or resets it to the role default. The parent owns the
 * live layout state; this component only edits and persists it.
 */
export interface LayoutSettingsProps {
  layout: DashboardLayout;
  /** "user" when a customization is saved; anything else = role default. */
  source: string;
  /** Status-pill choices, as rendered by the parent's filter row. */
  statusOptions: { label: string; value: string }[];
  onApplied: (resp: DashboardLayoutResponse) => void;
}

export function LayoutSettings({
  layout,
  source,
  statusOptions,
  onApplied,
}: LayoutSettingsProps) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDocClick = (e: MouseEvent) => {
      if (rootRef.current && !rootRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener("mousedown", onDocClick);
    return () => document.removeEventListener("mousedown", onDocClick);
  }, [open]);

  const showHandover = layout.sections.includes("handover");

  const persist = async (next: DashboardLayout) => {
    setBusy(true);
    try {
      const resp = await putDashboardLayout(next);
      onApplied(resp);
    } catch {
      toast.error("Could not save the view preference");
    } finally {
      setBusy(false);
    }
  };

  const handleHandoverToggle = () => {
    const sections = showHandover
      ? layout.sections.filter((s) => s !== "handover")
      : (["handover", ...layout.sections] as DashboardLayout["sections"]);
    void persist({ ...layout, sections });
  };

  const handleFilterChange = (value: string) => {
    void persist({ ...layout, default_status_filter: value });
  };

  const handleReset = async () => {
    setBusy(true);
    try {
      const resp = await resetDashboardLayout();
      onApplied(resp);
      toast.success("View reset to your role's default");
    } catch {
      toast.error("Could not reset the view preference");
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="relative" ref={rootRef}>
      <Button
        variant="ghost"
        size="icon"
        onClick={() => setOpen((v) => !v)}
        aria-label="View settings"
        aria-expanded={open}
        data-testid="layout-settings-button"
      >
        <Settings2 className="w-4 h-4" aria-hidden="true" />
      </Button>

      {open && (
        <div
          className="absolute right-0 top-full mt-2 w-64 rounded-md border border-border bg-popover p-4 shadow-lg z-20"
          data-testid="layout-settings-panel"
        >
          <div className="flex items-center justify-between mb-3">
            <p className="text-sm font-medium">View settings</p>
            <span
              className="text-[10px] uppercase tracking-wide text-muted-foreground"
              data-testid="layout-settings-source"
            >
              {source === "user" ? "Customized" : "Role default"}
            </span>
          </div>

          <label className="flex items-center gap-2 mb-3 text-sm cursor-pointer">
            <input
              type="checkbox"
              checked={showHandover}
              disabled={busy}
              onChange={handleHandoverToggle}
              className="h-4 w-4 accent-primary"
              data-testid="layout-settings-handover-toggle"
            />
            Show shift handover
          </label>

          <label className="block text-xs text-muted-foreground mb-1">
            Default status filter
          </label>
          <NativeSelect
            value={layout.default_status_filter}
            disabled={busy}
            onChange={(e) => handleFilterChange(e.target.value)}
            className="h-9 mb-3"
            data-testid="layout-settings-filter-select"
          >
            {statusOptions.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </NativeSelect>

          <Button
            variant="ghost"
            size="sm"
            onClick={() => void handleReset()}
            disabled={busy || source !== "user"}
            className="w-full"
            data-testid="layout-settings-reset-button"
          >
            <RotateCcw className="w-3.5 h-3.5 mr-2" aria-hidden="true" />
            Reset to role default
          </Button>
        </div>
      )}
    </div>
  );
}
