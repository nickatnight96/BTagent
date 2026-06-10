import { describe, expect, it } from "vitest";
import {
  applyFieldInput,
  coerceInput,
  extraConfigKeys,
  extractFields,
  formUsable,
  parseConfigObject,
  valueToInput,
  type JsonSchemaObject,
} from "@/utils/schema-form";

// Mirrors the shape pydantic's model_json_schema() emits for
// SplunkSearchInput — string + defaults + required + integer.
const SPLUNK_SCHEMA: JsonSchemaObject = {
  type: "object",
  title: "SplunkSearchInput",
  required: ["query"],
  properties: {
    query: {
      type: "string",
      title: "Query",
      description: "SPL search string.",
      examples: ["index=authentication action=failure"],
    },
    earliest_time: { type: "string", title: "Earliest Time", default: "-24h" },
    max_count: { type: "integer", title: "Max Count", default: 100 },
  },
};

// Pydantic `X | None` + enum-in-$defs encodings.
const UNION_ENUM_SCHEMA: JsonSchemaObject = {
  type: "object",
  properties: {
    severity: { $ref: "#/$defs/Severity", description: "Alert severity." },
    note: {
      anyOf: [{ type: "string" }, { type: "null" }],
      title: "Note",
      default: null,
    },
    payload: { type: "object", title: "Payload" },
    enabled: { type: "boolean", title: "Enabled", default: true },
  },
  $defs: {
    Severity: { enum: ["low", "medium", "high"], type: "string", title: "Severity" },
  },
};

describe("extractFields", () => {
  it("flattens simple properties with required/default/description", () => {
    const fields = extractFields(SPLUNK_SCHEMA);
    expect(fields.map((f) => f.name)).toEqual(["query", "earliest_time", "max_count"]);

    const query = fields[0]!;
    expect(query.kind).toBe("string");
    expect(query.required).toBe(true);
    expect(query.description).toBe("SPL search string.");
    expect(query.example).toBe("index=authentication action=failure");

    const earliest = fields[1]!;
    expect(earliest.required).toBe(false);
    expect(earliest.defaultValue).toBe("-24h");

    expect(fields[2]!.kind).toBe("integer");
  });

  it("resolves $defs enums and nullable unions", () => {
    const fields = extractFields(UNION_ENUM_SCHEMA);
    const byName = Object.fromEntries(fields.map((f) => [f.name, f]));

    expect(byName.severity!.kind).toBe("enum");
    expect(byName.severity!.enumOptions).toEqual(["low", "medium", "high"]);
    // Sibling description on the $ref site survives resolution.
    expect(byName.severity!.description).toBe("Alert severity.");

    // string | null collapses to a plain string field.
    expect(byName.note!.kind).toBe("string");

    // objects fall back to the per-field JSON editor.
    expect(byName.payload!.kind).toBe("json");

    expect(byName.enabled!.kind).toBe("boolean");
  });

  it("returns [] for unusable schemas", () => {
    expect(extractFields(undefined)).toEqual([]);
    expect(extractFields(null)).toEqual([]);
    expect(extractFields({})).toEqual([]);
    expect(formUsable({})).toBe(false);
    expect(formUsable(SPLUNK_SCHEMA)).toBe(true);
  });
});

describe("coerceInput", () => {
  it("empty input removes the key", () => {
    expect(coerceInput("string", "")).toEqual({ remove: true });
    expect(coerceInput("integer", "   ")).toEqual({ remove: true });
  });

  it("numeric kinds parse numbers but keep template strings verbatim", () => {
    expect(coerceInput("integer", "42")).toEqual({ value: 42 });
    expect(coerceInput("number", "-3.5e2")).toEqual({ value: -350 });
    // {{ templates }} are resolved at run time — must survive as strings.
    expect(coerceInput("integer", "{{ trigger.payload.count }}")).toEqual({
      value: "{{ trigger.payload.count }}",
    });
  });

  it("boolean select values map to real booleans", () => {
    expect(coerceInput("boolean", "true")).toEqual({ value: true });
    expect(coerceInput("boolean", "false")).toEqual({ value: false });
  });

  it("json kind parses or reports an error without writing", () => {
    expect(coerceInput("json", '{"a": 1}')).toEqual({ value: { a: 1 } });
    expect(coerceInput("json", "{nope")).toEqual({ error: "invalid JSON" });
  });
});

describe("applyFieldInput", () => {
  const field = extractFields(SPLUNK_SCHEMA)[2]!; // max_count (integer)

  it("sets, replaces, and removes keys immutably", () => {
    const base = { query: "index=x" };
    const withCount = applyFieldInput(base, field, "50");
    expect(withCount).toEqual({ query: "index=x", max_count: 50 });
    expect(base).toEqual({ query: "index=x" }); // untouched

    const removed = applyFieldInput(withCount!, field, "");
    expect(removed).toEqual({ query: "index=x" });
  });

  it("returns null on unparsable json-kind input (config preserved)", () => {
    const jsonField = extractFields(UNION_ENUM_SCHEMA).find((f) => f.name === "payload")!;
    expect(applyFieldInput({ a: 1 }, jsonField, "{broken")).toBeNull();
  });
});

describe("round-trip helpers", () => {
  it("valueToInput renders scalars and JSON", () => {
    expect(valueToInput(undefined, "string")).toBe("");
    expect(valueToInput("abc", "string")).toBe("abc");
    expect(valueToInput(42, "integer")).toBe("42");
    expect(valueToInput(true, "boolean")).toBe("true");
    expect(valueToInput({ a: 1 }, "json")).toBe('{\n  "a": 1\n}');
  });

  it("extraConfigKeys surfaces keys the schema doesn't know", () => {
    const fields = extractFields(SPLUNK_SCHEMA);
    expect(extraConfigKeys({ query: "x", custom_key: 1 }, fields)).toEqual(["custom_key"]);
  });

  it("parseConfigObject accepts only plain objects", () => {
    expect(parseConfigObject('{"a": 1}')).toEqual({ a: 1 });
    expect(parseConfigObject("")).toEqual({});
    expect(parseConfigObject("[1]")).toBeNull();
    expect(parseConfigObject("not json")).toBeNull();
  });
});
