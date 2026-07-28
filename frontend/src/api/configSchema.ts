/** Configuration inventory client (#418). */

import api from "./client";
import type { AutonomyConfig, ConfigSchema } from "@/types/configSchema";

/** The consolidated configuration inventory (read-only; secrets redacted). */
export async function getConfigSchema(): Promise<ConfigSchema> {
  return api.get<ConfigSchema>("/v1/config/schema");
}

/** Effective per-category autonomy levels (defaults merged with org overrides). */
export async function getAutonomyConfig(): Promise<AutonomyConfig> {
  return api.get<AutonomyConfig>("/v1/config/autonomy");
}

/**
 * Replace the org's autonomy overrides wholesale (admin): the stored set is
 * exactly `overrides` — always send the FULL dict; `{}` reverts to defaults.
 * Containment categories are rejected server-side (422).
 */
export async function putAutonomyOverrides(
  overrides: Record<string, string>,
): Promise<AutonomyConfig> {
  return api.put<AutonomyConfig>("/v1/config/autonomy", { overrides });
}

export interface FeatureFlags {
  flags: Record<string, boolean>;
}

/** The caller's org's feature flags. */
export async function getFeatureFlags(): Promise<FeatureFlags> {
  return api.get<FeatureFlags>("/v1/config/feature-flags");
}

/**
 * Replace the org's flag set wholesale (admin): the stored set after the
 * call is exactly `flags` — always send the FULL updated dict.
 */
export async function putFeatureFlags(
  flags: Record<string, boolean>,
): Promise<FeatureFlags> {
  return api.put<FeatureFlags>("/v1/config/feature-flags", { flags });
}

// --------------------------------------------------------------------------
// Data retention (#418)
//
// The stats read is `config:view`; the cleanup run is `config:edit` (admin)
// and IRREVERSIBLY deletes events + archives investigations, so the UI treats
// it as a destructive action rather than a refresh button.
// --------------------------------------------------------------------------

export interface RetentionStats {
  events: { total: number; stale: number; retention_days: number };
  audit_logs: { total: number; retention_years: number; policy: string };
  investigations: { total: number; archivable: number; retention_days: number };
}

export interface RetentionRunResult {
  events: { deleted_count: number; retention_days: number; cutoff: string };
  investigations: { archived_count: number; retention_days: number; cutoff: string };
  audit_verification: {
    total_entries: number;
    earliest_entry: string | null;
    latest_entry: string | null;
    retention_years: number;
    compliance_boundary: string;
    compliant: boolean;
    issues?: string[];
  };
}

/** Current retention posture: what is held, what is past its window. */
export async function getRetentionStats(): Promise<RetentionStats> {
  return api.get<RetentionStats>("/v1/config/retention");
}

/**
 * Run the cleanup now. **Destructive and irreversible** — deletes stale events
 * and archives closed investigations past the window. Audited server-side with
 * the counts it affected.
 */
export async function runRetentionCleanup(): Promise<RetentionRunResult> {
  return api.post<RetentionRunResult>("/v1/config/retention/run", {});
}
