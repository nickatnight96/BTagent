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
