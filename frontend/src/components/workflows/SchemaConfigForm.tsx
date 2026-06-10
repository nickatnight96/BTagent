import { useEffect, useMemo, useState } from "react";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { NativeSelect } from "@/components/ds/native-select";
import { Textarea } from "@/components/ds/textarea";
import {
  applyFieldInput,
  coerceInput,
  extraConfigKeys,
  extractFields,
  valueToInput,
  type JsonSchemaObject,
  type SchemaField,
} from "@/utils/schema-form";

/**
 * Typed per-node config form, generated from the node's `input_schema`
 * JSON Schema served by the node catalog.
 *
 * The parsed config *object* is the unit of exchange — the parent owns the
 * `configJson` string and re-serialises on every field change, so the raw
 * JSON view and this form always agree. Schema-`required` fields are
 * marked but never enforced (config is a partial overlay; upstream payload
 * may supply them). Clearing a field removes its key so engine defaults
 * apply.
 *
 * Numeric and JSON fields buffer keystrokes in a local draft and commit on
 * blur: committing numerics per keystroke would collapse intermediate
 * states ("0." → 0, "0.50" → 0.5 mid-typing), and committing JSON per
 * keystroke would reject every intermediate unparsable state.
 */

interface SchemaConfigFormProps {
  schema: JsonSchemaObject;
  config: Record<string, unknown>;
  onConfigChange: (next: Record<string, unknown>) => void;
}

export function SchemaConfigForm({ schema, config, onConfigChange }: SchemaConfigFormProps) {
  const fields = useMemo(() => extractFields(schema), [schema]);
  const extras = useMemo(() => extraConfigKeys(config, fields), [config, fields]);

  return (
    <div className="space-y-3" data-testid="schema-config-form">
      {fields.map((field) => (
        <SchemaFieldRow
          key={field.name}
          field={field}
          value={config[field.name]}
          onInput={(raw) => {
            const next = applyFieldInput(config, field, raw);
            if (next !== null) onConfigChange(next);
          }}
        />
      ))}
      {extras.length > 0 && (
        <p className="text-xs text-muted-foreground" data-testid="schema-config-extra-keys">
          Keys not in this node's schema (kept as-is, edit in JSON view):{" "}
          <span className="font-mono">{extras.join(", ")}</span>
        </p>
      )}
    </div>
  );
}

interface SchemaFieldRowProps {
  field: SchemaField;
  value: unknown;
  onInput: (raw: string) => void;
}

function SchemaFieldRow({ field, value, onInput }: SchemaFieldRowProps) {
  const inputId = `schema-field-${field.name}`;
  const committed = valueToInput(value, field.kind);
  // Draft buffer for blur-committed kinds (numeric + json). null = not
  // editing; the committed value renders. Reset when the underlying value
  // changes from outside (e.g. an edit made in the raw JSON view).
  const [draft, setDraft] = useState<string | null>(null);
  const [jsonError, setJsonError] = useState(false);
  useEffect(() => {
    setDraft(null);
    setJsonError(false);
  }, [committed]);

  const placeholder =
    field.defaultValue !== undefined
      ? `default: ${String(field.defaultValue)}`
      : field.example;

  const commitDraft = (raw: string) => {
    if (field.kind === "json") {
      const result = coerceInput("json", raw);
      if (result.error) {
        // Keep the broken text visible + flag it; the previous valid
        // value stays in the config (nothing is silently overwritten).
        setJsonError(true);
        return;
      }
      setJsonError(false);
    }
    onInput(raw);
    setDraft(null);
  };

  return (
    <div className="space-y-1.5" data-testid={`schema-field-${field.name}`}>
      <Label htmlFor={inputId}>
        {field.label}
        {field.required && (
          <span
            className="text-destructive ml-0.5"
            title="Required by the node's input schema (may also be supplied by the upstream step's output)"
          >
            *
          </span>
        )}
      </Label>

      {field.kind === "enum" && (
        <NativeSelect id={inputId} value={committed} onChange={(e) => onInput(e.target.value)}>
          <option value="">(unset)</option>
          {(field.enumOptions ?? []).map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </NativeSelect>
      )}

      {field.kind === "boolean" && (
        <NativeSelect id={inputId} value={committed} onChange={(e) => onInput(e.target.value)}>
          <option value="">(unset)</option>
          <option value="true">true</option>
          <option value="false">false</option>
        </NativeSelect>
      )}

      {field.kind === "string" && (
        <Input
          id={inputId}
          value={committed}
          placeholder={placeholder}
          onChange={(e) => onInput(e.target.value)}
        />
      )}

      {(field.kind === "integer" || field.kind === "number") && (
        <Input
          id={inputId}
          // Deliberately type="text": values may be "{{ template }}"
          // strings, which a number input would reject. Coercion to a
          // number happens on blur so intermediate states like "0." or
          // "0.50" survive while typing.
          value={draft ?? committed}
          placeholder={placeholder}
          inputMode="decimal"
          onChange={(e) => setDraft(e.target.value)}
          onBlur={() => {
            if (draft !== null) commitDraft(draft);
          }}
        />
      )}

      {field.kind === "json" && (
        <>
          <Textarea
            id={inputId}
            value={draft ?? committed}
            placeholder={placeholder ?? "{ }"}
            rows={3}
            className={`font-mono text-xs ${jsonError ? "border-destructive" : ""}`}
            onChange={(e) => setDraft(e.target.value)}
            onBlur={() => {
              if (draft !== null) commitDraft(draft);
            }}
          />
          {jsonError && (
            <p
              className="text-xs text-destructive"
              role="alert"
              data-testid={`schema-field-${field.name}-error`}
            >
              Invalid JSON — this field's change is not saved until fixed.
            </p>
          )}
        </>
      )}

      {field.description && (
        <p className="text-xs text-muted-foreground">{field.description}</p>
      )}
    </div>
  );
}
