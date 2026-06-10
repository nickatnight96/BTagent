import { describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { SchemaConfigForm } from "@/components/workflows/SchemaConfigForm";
import type { JsonSchemaObject } from "@/utils/schema-form";

const SCHEMA: JsonSchemaObject = {
  type: "object",
  properties: {
    threshold: { type: "number", title: "Threshold" },
    payload: { type: "object", title: "Payload" },
  },
};

describe("SchemaConfigForm numeric drafts (Codex P2: intermediate decimals)", () => {
  it("preserves '0.' and '0.50' while typing; coerces only on blur", () => {
    const onConfigChange = vi.fn();
    render(<SchemaConfigForm schema={SCHEMA} config={{}} onConfigChange={onConfigChange} />);

    const input = screen.getByLabelText("Threshold") as HTMLInputElement;

    // Intermediate states are NOT committed (no rerender can eat the dot).
    fireEvent.change(input, { target: { value: "0." } });
    expect(input.value).toBe("0.");
    expect(onConfigChange).not.toHaveBeenCalled();

    fireEvent.change(input, { target: { value: "0.50" } });
    expect(input.value).toBe("0.50");
    expect(onConfigChange).not.toHaveBeenCalled();

    // Blur commits the coerced number.
    fireEvent.blur(input);
    expect(onConfigChange).toHaveBeenCalledWith({ threshold: 0.5 });
  });

  it("keeps template strings verbatim on blur", () => {
    const onConfigChange = vi.fn();
    render(<SchemaConfigForm schema={SCHEMA} config={{}} onConfigChange={onConfigChange} />);

    const input = screen.getByLabelText("Threshold");
    fireEvent.change(input, { target: { value: "{{ trigger.payload.n }}" } });
    fireEvent.blur(input);
    expect(onConfigChange).toHaveBeenCalledWith({ threshold: "{{ trigger.payload.n }}" });
  });
});

describe("SchemaConfigForm json fields (Codex P2: silent rejection)", () => {
  it("flags malformed JSON on blur, keeps the broken text, commits nothing", () => {
    const onConfigChange = vi.fn();
    render(
      <SchemaConfigForm
        schema={SCHEMA}
        config={{ payload: { a: 1 } }}
        onConfigChange={onConfigChange}
      />,
    );

    const textarea = screen.getByLabelText("Payload") as HTMLTextAreaElement;
    fireEvent.change(textarea, { target: { value: "{broken" } });
    fireEvent.blur(textarea);

    // The edit is rejected loudly, not silently: error visible, broken
    // text still in the field, previous config untouched.
    expect(screen.getByTestId("schema-field-payload-error")).toBeInTheDocument();
    expect(textarea.value).toBe("{broken");
    expect(onConfigChange).not.toHaveBeenCalled();
  });

  it("clears the error and commits once the JSON is fixed", () => {
    const onConfigChange = vi.fn();
    render(<SchemaConfigForm schema={SCHEMA} config={{}} onConfigChange={onConfigChange} />);

    const textarea = screen.getByLabelText("Payload");
    fireEvent.change(textarea, { target: { value: "{bad" } });
    fireEvent.blur(textarea);
    expect(screen.getByTestId("schema-field-payload-error")).toBeInTheDocument();

    fireEvent.change(textarea, { target: { value: '{"a": 2}' } });
    fireEvent.blur(textarea);
    expect(screen.queryByTestId("schema-field-payload-error")).toBeNull();
    expect(onConfigChange).toHaveBeenCalledWith({ payload: { a: 2 } });
  });
});
