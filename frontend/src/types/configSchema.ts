/** Configuration inventory types (#418, `GET /api/v1/config/schema`). */

export interface RuntimeSurface {
  key: string;
  title: string;
  description: string;
  scope: "org" | "user" | "global" | string;
  /** null = self-scoped (no extra permission needed). */
  write_permission: string | null;
  /** null = no runtime API yet (documented gap). */
  api: string | null;
  ui: string | null;
}

export interface DeployTimeEntry {
  field: string;
  env: string;
  type: string;
  sensitive: boolean;
  /** null when sensitive — only configured-ness is surfaced. */
  value: unknown;
  is_default: boolean;
}

export interface ConfigSchema {
  runtime: RuntimeSurface[];
  deploy_time: DeployTimeEntry[];
}

/** Effective autonomy levels (#418 slice 3, `GET /api/v1/config/autonomy`). */
export interface AutonomyCategory {
  key: string;
  level: string;
  /** Containment categories are HITL-gated in code regardless of level. */
  hitl_forced: boolean;
  /** True when the org has a stored override for this category. */
  overridden?: boolean;
}

export interface AutonomyConfig {
  categories: AutonomyCategory[];
  levels: Record<string, string>;
  editable: boolean;
}
