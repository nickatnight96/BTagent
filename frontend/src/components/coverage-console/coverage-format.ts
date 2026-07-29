/**
 * Pure presentation helpers for the Coverage Console (#501).
 *
 * Kept out of the components so they can be unit-tested without rendering, and
 * so the heatmap's colour vocabulary is defined exactly once. Nothing here
 * *derives* coverage — every status/state value is read straight off the
 * server payload; these functions only decide how to say it.
 */

import type { BrokenRuleState, CoverageStatus, TechniqueCoverageCell } from "@/types/coverage";

/** Heatmap swatch per band. Green = proven, amber = unknown, red = hole. */
export const STATUS_SWATCH: Record<CoverageStatus, string> = {
  fresh: "bg-emerald-500/70 border-emerald-400/60 text-emerald-50",
  stale: "bg-amber-500/70 border-amber-400/60 text-amber-50",
  never: "bg-rose-600/70 border-rose-400/60 text-rose-50",
  silent_gap: "bg-rose-600/90 border-rose-300/70 text-rose-50",
};

/** Human label per band — used in the legend and in cell tooltips. */
export const STATUS_LABEL: Record<CoverageStatus, string> = {
  fresh: "Validated recently",
  stale: "Stale — overdue for re-validation",
  never: "Never validated",
  silent_gap: "Silent gap — emulated and nothing fired",
};

/** Text accent per broken-rule state. */
export const RULE_STATE_STYLE: Record<BrokenRuleState, string> = {
  errored: "text-rose-400",
  over_firing: "text-amber-400",
  under_firing: "text-sky-400",
};

export const RULE_STATE_LABEL: Record<BrokenRuleState, string> = {
  errored: "errored",
  over_firing: "over-firing",
  under_firing: "under-firing",
};

/**
 * How long ago a technique was last proven working.
 *
 * A never-validated technique must never render as "today" — a null day count
 * is the *worst* case, not the freshest one.
 */
export function ageLabel(cell: TechniqueCoverageCell): string {
  if (cell.last_validated == null || cell.days_since_validated == null) {
    return "never validated";
  }
  return cell.days_since_validated === 0 ? "today" : `${cell.days_since_validated}d ago`;
}

/** ``credential_access`` → ``Credential Access``. */
export function tacticLabel(tactic: string): string {
  if (!tactic) return "Unknown";
  return tactic
    .replace(/[-_]/g, " ")
    .split(" ")
    .filter(Boolean)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(" ");
}

/** One cell's tooltip: what it is, and why it is that colour. */
export function cellTitle(cell: TechniqueCoverageCell): string {
  const name = cell.name ? ` ${cell.name}` : "";
  const detection = cell.has_detection ? "detection authored" : "no detection authored";
  return `${cell.technique_id}${name} — ${STATUS_LABEL[cell.status]} (${ageLabel(cell)}, ${detection})`;
}
