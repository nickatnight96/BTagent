/** Configuration inventory client (#418). */

import api from "./client";
import type { AutonomyConfig, ConfigSchema } from "@/types/configSchema";

/** The consolidated configuration inventory (read-only; secrets redacted). */
export async function getConfigSchema(): Promise<ConfigSchema> {
  return api.get<ConfigSchema>("/v1/config/schema");
}

/** Effective per-category autonomy levels (read-only until editing lands). */
export async function getAutonomyConfig(): Promise<AutonomyConfig> {
  return api.get<AutonomyConfig>("/v1/config/autonomy");
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
