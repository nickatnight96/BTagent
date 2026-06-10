/**
 * JSON-Schema → config-form field extraction (Phase 4 follow-up).
 *
 * The node catalog serves each engine Node's pydantic `input_schema` as
 * JSON Schema (`model_json_schema()`). These helpers translate that schema
 * into a flat field list the editor's typed config form can render, and
 * coerce user input back into config values.
 *
 * Semantics that matter for correctness:
 *
 * - **Config is a partial overlay.** The Runner merges a step's static
 *   config on top of the upstream payload, so a schema-`required` field is
 *   NOT required *in the config* — it may legitimately arrive from the
 *   previous node's output. Required markers are rendered as hints, never
 *   enforced.
 * - **Templates are legal anywhere.** Config values may be `{{ ... }}`
 *   template strings even for numeric fields (resolved at run time by
 *   `render_payload`). Numeric inputs therefore fall back to storing the
 *   raw string when it doesn't parse as a number.
 * - **Empty input = unset.** Clearing a field removes the key from the
 *   config entirely so the engine default (or upstream payload) applies,
 *   rather than writing `""` over it.
 */

export interface JsonSchemaObject {
  type?: string;
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchemaProperty>;
  required?: string[];
  $defs?: Record<string, JsonSchemaProperty>;
  [key: string]: unknown;
}

export interface JsonSchemaProperty {
  type?: string;
  title?: string;
  description?: string;
  default?: unknown;
  examples?: unknown[];
  enum?: unknown[];
  $ref?: string;
  anyOf?: JsonSchemaProperty[];
  [key: string]: unknown;
}

export type FieldKind = "string" | "number" | "integer" | "boolean" | "enum" | "json";

export interface SchemaField {
  name: string;
  label: string;
  description: string;
  required: boolean;
  kind: FieldKind;
  /** Present when kind === "enum". */
  enumOptions?: string[];
  /** Schema default, when declared. */
  defaultValue?: unknown;
  /** First schema example, for placeholder text. */
  example?: string;
}

/** Resolve a local `#/$defs/X` reference against the root schema. */
function resolveRef(prop: JsonSchemaProperty, root: JsonSchemaObject): JsonSchemaProperty {
  if (!prop.$ref) return prop;
  const defName = /^#\/\$defs\/(.+)$/.exec(prop.$ref)?.[1];
  const resolved = defName !== undefined ? root.$defs?.[defName] : undefined;
  // Merge: sibling keys on the $ref site (description, default) win over
  // the $def body, matching how pydantic emits Annotated field overrides.
  return resolved ? { ...resolved, ...stripRef(prop) } : stripRef(prop);
}

function stripRef(prop: JsonSchemaProperty): JsonSchemaProperty {
  const { $ref: _ignored, ...rest } = prop;
  return rest;
}

/**
 * Collapse pydantic's `X | None` encoding (`anyOf: [X, {type: "null"}]`)
 * to the non-null branch. Multi-branch unions stay unresolved → "json".
 */
function collapseNullableUnion(
  prop: JsonSchemaProperty,
  root: JsonSchemaObject,
): JsonSchemaProperty {
  if (!prop.anyOf) return prop;
  const nonNull = prop.anyOf.filter((b) => b.type !== "null");
  const only = nonNull.length === 1 ? nonNull[0] : undefined;
  if (!only) return prop; // genuine union — caller maps to "json"
  const branch = resolveRef(only, root);
  // Keep outer metadata (title/description/default declared on the field).
  const { anyOf: _ignored, ...outer } = prop;
  return { ...branch, ...outer };
}

function kindOf(prop: JsonSchemaProperty): FieldKind {
  if (Array.isArray(prop.enum)) return "enum";
  switch (prop.type) {
    case "string":
      return "string";
    case "integer":
      return "integer";
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    default:
      // objects, arrays, unresolved unions, missing type → raw JSON field
      return "json";
  }
}

/**
 * Flatten a node input_schema into renderable fields.
 *
 * Returns `[]` when the schema has no object properties — the editor then
 * offers only the raw-JSON textarea for that node.
 */
export function extractFields(schema: JsonSchemaObject | undefined | null): SchemaField[] {
  if (!schema || typeof schema !== "object") return [];
  const props = schema.properties;
  if (!props || typeof props !== "object") return [];
  const required = new Set(schema.required ?? []);

  return Object.entries(props).map(([name, rawProp]) => {
    const prop = collapseNullableUnion(resolveRef(rawProp, schema), schema);
    const kind = kindOf(prop);
    const example = Array.isArray(prop.examples) && prop.examples.length > 0
      ? String(prop.examples[0])
      : undefined;
    const field: SchemaField = {
      name,
      label: prop.title || name,
      description: prop.description ?? "",
      required: required.has(name),
      kind,
      defaultValue: prop.default,
      example,
    };
    if (kind === "enum") {
      field.enumOptions = (prop.enum ?? []).map((v) => String(v));
    }
    return field;
  });
}

/** True when the schema yields at least one renderable form field. */
export function formUsable(schema: JsonSchemaObject | undefined | null): boolean {
  return extractFields(schema).length > 0;
}

/** Render a stored config value into the text shown in an input. */
export function valueToInput(value: unknown, kind: FieldKind): string {
  if (value === undefined) return "";
  if (kind === "json") return JSON.stringify(value, null, 2);
  if (typeof value === "string") return value;
  return JSON.stringify(value);
}

// Full-string numeric literal (int or float, optional sign/exponent).
const NUMERIC_RE = /^-?(\d+\.?\d*|\.\d+)([eE][+-]?\d+)?$/;

export interface CoerceResult {
  /** `true` → remove the key from config (field cleared). */
  remove?: boolean;
  /** Parsed value to store. Absent when remove or error is set. */
  value?: unknown;
  /** Human-readable parse error (json kind only). */
  error?: string;
}

/**
 * Coerce raw input text back into a config value for *field*.
 *
 * Empty input always removes the key (engine default / upstream payload
 * applies). Numeric kinds store a number when the text is a numeric
 * literal and otherwise keep the string verbatim so `{{ templates }}`
 * survive. The boolean kind receives "true"/"false" from its select.
 */
export function coerceInput(kind: FieldKind, raw: string): CoerceResult {
  const text = raw.trim();
  if (text === "") return { remove: true };

  switch (kind) {
    case "string":
    case "enum":
      return { value: raw };
    case "integer":
    case "number":
      return NUMERIC_RE.test(text) ? { value: Number(text) } : { value: raw };
    case "boolean":
      if (text === "true") return { value: true };
      if (text === "false") return { value: false };
      return { value: raw }; // template string fallback
    case "json":
      try {
        return { value: JSON.parse(text) };
      } catch {
        return { error: "invalid JSON" };
      }
  }
}

/**
 * Apply one field edit to a parsed config object, returning the new
 * config. Returns `null` when the input is unparsable (json kind) — the
 * caller keeps the previous config and surfaces the error.
 */
export function applyFieldInput(
  config: Record<string, unknown>,
  field: SchemaField,
  raw: string,
): Record<string, unknown> | null {
  const result = coerceInput(field.kind, raw);
  if (result.error) return null;
  const next = { ...config };
  if (result.remove) {
    delete next[field.name];
  } else {
    next[field.name] = result.value;
  }
  return next;
}

/**
 * Keys present in the config that the schema doesn't know about.
 * Preserved verbatim by the form (they round-trip untouched); surfaced so
 * the analyst knows they exist and can edit them in JSON mode.
 */
export function extraConfigKeys(
  config: Record<string, unknown>,
  fields: SchemaField[],
): string[] {
  const known = new Set(fields.map((f) => f.name));
  return Object.keys(config).filter((k) => !known.has(k));
}

/** Parse a configJson string; null when not a plain JSON object. */
export function parseConfigObject(configJson: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(configJson.trim() || "{}");
    if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) {
      return parsed as Record<string, unknown>;
    }
    return null;
  } catch {
    return null;
  }
}
