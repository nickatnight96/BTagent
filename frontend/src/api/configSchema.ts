/** Configuration inventory client (#418). */

import api from "./client";
import type { ConfigSchema } from "@/types/configSchema";

/** The consolidated configuration inventory (read-only; secrets redacted). */
export async function getConfigSchema(): Promise<ConfigSchema> {
  return api.get<ConfigSchema>("/v1/config/schema");
}
