/**
 * WebSocket wire-contract test — the browser half of the anti-drift chokepoint.
 *
 * Its sibling is backend/tests/test_ws_contract.py. Between them:
 *
 *   Python types  ──(re-derived + diffed)──>  ws-contract.fixture.json
 *                                                     │
 *                                    (diffed here)────┤
 *                                                     v
 *                                            events.generated.ts
 *
 * The fixture is produced from REAL Pydantic serialization
 * (`EventEnvelope.model_dump_json()` / `ClientMessage`), so neither side can
 * describe a shape the wire doesn't actually carry. This file additionally
 * pushes the fixture's real payload through the real `WebSocketClient`, which
 * is the assertion that would have caught the original defect: the frontend
 * decoded `event_id` / `event_type` / `payload` while the wire carries
 * `id` / `type` / `data`, so every event became all-`undefined` — and BOTH
 * test suites stayed green.
 *
 * Regenerate after an intentional protocol change with:
 *   BTAGENT_REGEN_WS_CONTRACT=1 pytest backend/tests/test_ws_contract.py
 */
import { describe, it, expect, beforeEach, afterEach, vi } from "vitest";

// `?raw` (Vite) rather than `node:fs` — the frontend package has no
// @types/node, so rather than widen the tsconfig for one test we let the
// bundler inline the fixture as a string.
//
// The fixture is the shared artifact; it cannot be read directly from the
// Python source here (Vitest's fs sandbox refuses imports outside the
// frontend root). That direction — live Python types -> fixture -> the
// generated TS file, byte for byte — is asserted by
// backend/tests/test_ws_contract.py, which runs in the same CI.
import fixtureRaw from "@/types/ws-contract.fixture.json?raw";

import {
  EventType,
  ClientMessageType,
  ServerMessageType,
  envelopeToEvent,
} from "@/types/events";
import type { EventEnvelope } from "@/types/events";
import { WebSocketClient } from "@/api/ws";

interface Contract {
  envelope_fields: string[];
  event_types: Record<string, string>;
  sample_envelope_json: string;
  client_message_fields: string[];
  client_message_types: Record<string, string>;
  client_message_sample_json: string;
  server_message_types: Record<string, string>;
}

const contract: Contract = JSON.parse(fixtureRaw) as Contract;

describe("WS contract — TypeScript matches the Python-derived fixture", () => {
  it("EventType has exactly the Python members, with the same values", () => {
    expect(Object.fromEntries(Object.entries(EventType))).toEqual(
      contract.event_types,
    );
  });

  it("ClientMessageType has exactly the Python members", () => {
    expect(Object.fromEntries(Object.entries(ClientMessageType))).toEqual(
      contract.client_message_types,
    );
  });

  it("ServerMessageType has exactly the Python members", () => {
    expect(Object.fromEntries(Object.entries(ServerMessageType))).toEqual(
      contract.server_message_types,
    );
  });

  it("the EventEnvelope interface covers exactly the Python model fields", () => {
    // Structural interfaces are erased at runtime, so assert against the keys
    // of a real serialized envelope — which is what the interface describes.
    const sample = JSON.parse(contract.sample_envelope_json) as Record<
      string,
      unknown
    >;
    expect(Object.keys(sample).sort()).toEqual(
      [...contract.envelope_fields].sort(),
    );
    // The aliased names the old decoder read must not exist on the wire.
    for (const absent of ["event_id", "event_type", "payload"]) {
      expect(sample).not.toHaveProperty(absent);
    }
  });

  it("the ClientMessage interface covers exactly the Python model fields", () => {
    const sample = JSON.parse(contract.client_message_sample_json) as Record<
      string,
      unknown
    >;
    expect(Object.keys(sample).sort()).toEqual(
      [...contract.client_message_fields].sort(),
    );
    // Payload fields live under `data`, never at the top level.
    expect(sample).not.toHaveProperty("message");
    expect(sample.data).toEqual({ message: "what happened?" });
  });
});

describe("WS contract — the enum the app imports is the generated one", () => {
  it("types/events.ts re-exports rather than re-declaring EventType", async () => {
    // The original drift started as a hand-written enum in types/events.ts
    // that grew members (`hitl_requested`, `message_complete`,
    // `status_changed`, `timeline_entry`, `hunt_finding_updated`) no Python
    // member ever emitted. Assert the app-facing module and the generated
    // module are the SAME object, so a hand-written member can't sneak back
    // in alongside the generated one.
    const generated = await import("@/types/events.generated");
    const appFacing = await import("@/types/events");
    expect(appFacing.EventType).toBe(generated.EventType);
    expect(appFacing.ClientMessageType).toBe(generated.ClientMessageType);
    expect(appFacing.ServerMessageType).toBe(generated.ServerMessageType);
  });
});

describe("WS contract — real payload through the real client", () => {
  class FakeWS {
    static OPEN = 1;
    static CLOSED = 3;
    static CONNECTING = 0;
    static CLOSING = 2;
    readyState: number = FakeWS.OPEN;
    onopen: ((e: Event) => void) | null = null;
    onmessage: ((e: MessageEvent) => void) | null = null;
    onclose: ((e: CloseEvent) => void) | null = null;
    onerror: ((e: Event) => void) | null = null;
    sent: string[] = [];
    constructor(_url: string) {
      instances.push(this);
    }
    close(): void {}
    send(data: string): void {
      this.sent.push(data);
    }
  }

  let instances: FakeWS[] = [];
  let originalWebSocket: typeof WebSocket;

  beforeEach(() => {
    instances = [];
    originalWebSocket = globalThis.WebSocket;
    // @ts-expect-error — overriding the global for the test
    globalThis.WebSocket = FakeWS;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("decodes the exact bytes Pydantic emits into a fully-populated AgentEvent", () => {
    const onEvent = vi.fn();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      onEvent,
    });
    client.connect();
    // `sample_envelope_json` is verbatim `EventEnvelope.model_dump_json()`.
    instances[0]!.onmessage?.({
      data: contract.sample_envelope_json,
    } as MessageEvent);

    expect(onEvent).toHaveBeenCalledTimes(1);
    const decoded = onEvent.mock.calls[0]![0] as ReturnType<
      typeof envelopeToEvent
    >;

    // Every field must be defined — the original defect made all of them
    // `undefined` while both suites stayed green.
    expect(decoded.id).toBeTypeOf("string");
    expect(decoded.id.length).toBeGreaterThan(0);
    expect(decoded.investigation_id).toBeTypeOf("string");
    expect(decoded.timestamp).toBeTypeOf("string");
    expect(decoded.type).toBe(EventType.OUTPUT_CHUNK);
    expect(decoded.data).toEqual({ text: "hello", index: 1 });

    // ...and it agrees with a direct decode of the same bytes.
    expect(decoded).toEqual(
      envelopeToEvent(JSON.parse(contract.sample_envelope_json) as EventEnvelope),
    );
  });

  it("emits a client frame byte-compatible with the Python ClientMessage sample", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();
    const ws = instances[0]!;
    ws.sent.length = 0;

    client.sendChat("inv_01CONTRACTSAMPLE0000000000", "what happened?");

    expect(JSON.parse(ws.sent[0]!)).toEqual(
      JSON.parse(contract.client_message_sample_json),
    );
  });
});
