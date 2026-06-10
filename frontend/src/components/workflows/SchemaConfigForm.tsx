import { useMemo } from "react";
import { Input } from "@/components/ds/input";
import { Label } from "@/components/ds/label";
import { NativeSelect } from "@/components/ds/native-select";
import { Textarea } from "@/components/ds/textarea";
import {
  applyFieldInput,
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
  const text = valueToInput(value, field.kind);
  const placeholder =
    field.defaultValue !== undefined
      ? `default: ${String(field.defaultValue)}`
      : field.example;

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
        <NativeSelect id={inputId} value={text} onChange={(e) => onInput(e.target.value)}>
          <option value="">(unset)</option>
          {(field.enumOptions ?? []).map((opt) => (
            <option key={opt} value={opt}>
              {opt}
            </option>
          ))}
        </NativeSelect>
      )}

      {field.kind === "boolean" && (
        <NativeSelect id={inputId} value={text} onChange={(e) => onInput(e.target.value)}>
          <option value="">(unset)</option>
          <option value="true">true</option>
          <option value="false">false</option>
        </NativeSelect>
      )}

      {(field.kind === "string" || field.kind === "integer" || field.kind === "number") && (
        <Input
          id={inputId}
          value={text}
          placeholder={placeholder}
          // Deliberately type="text" even for numerics: config values may be
          // "{{ trigger.payload.x }}" template strings, which a number input
          // would reject. Coercion to number happens in coerceInput.
          inputMode={field.kind === "string" ? undefined : "decimal"}
          onChange={(e) => onInput(e.target.value)}
        />
      )}

      {field.kind === "json" && (
        <Textarea
          id={inputId}
          // Uncontrolled while typing (intermediate states are unparsable);
          // the key remounts it whenever the committed value changes so an
          // external config edit (e.g. JSON view) still propagates in.
          key={`${field.name}:${text}`}
          defaultValue={text}
          placeholder={placeholder ?? "{ }"}
          rows={3}
          className="font-mono text-xs"
          // json fields commit on blur: committing per keystroke would
          // reject every intermediate (unparsable) state while typing.
          onBlur={(e) => onInput(e.target.value)}
        />
      )}

      {field.description && (
        <p className="text-xs text-muted-foreground">{field.description}</p>
      )}
    </div>
  );
}
