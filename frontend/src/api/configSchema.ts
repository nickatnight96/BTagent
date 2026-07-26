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
