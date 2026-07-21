import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { WebSocketClient } from "@/api/ws";

/**
 * Phase C2 invariant: the WebSocket client must NEVER append `?token=` (or any
 * other token query parameter) to the upgrade URL. Auth travels as an httpOnly
 * cookie on the upgrade handshake.
 */
describe("WebSocketClient — Phase C2 cookie auth", () => {
  let constructed: string[];
  let originalWebSocket: typeof WebSocket;

  beforeEach(() => {
    constructed = [];
    originalWebSocket = globalThis.WebSocket;
    // Replace WebSocket with a real constructable stub that captures the URL
    // and avoids any real network activity.
    class FakeWS {
      static OPEN = 1;
      static CLOSED = 3;
      static CONNECTING = 0;
      static CLOSING = 2;
      readyState = FakeWS.CONNECTING;
      onopen: ((e: Event) => void) | null = null;
      onmessage: ((e: MessageEvent) => void) | null = null;
      onclose: ((e: CloseEvent) => void) | null = null;
      onerror: ((e: Event) => void) | null = null;
      constructor(url: string) {
        constructed.push(url);
      }
      close() {}
      send() {}
    }
    // @ts-expect-error — overriding the global for the test
    globalThis.WebSocket = FakeWS;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("does not append ?token= to the URL on connect()", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();

    expect(constructed).toHaveLength(1);
    const url = constructed[0]!;
    expect(url).toBe("ws://localhost:8000/ws");
    expect(url).not.toMatch(/[?&]token=/);
  });

  it("connect() takes no token argument (signature is auth-free)", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    // Compile-time guarantee: connect must accept zero args. We assert the
    // runtime arity matches.
    expect(client.connect.length).toBe(0);
  });

  it("preserves any pre-existing query params on the URL — but never adds a token", () => {
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws?investigation=inv_01ABC",
    });
    client.connect();

    const url = constructed[0]!;
    expect(url).toBe("ws://localhost:8000/ws?investigation=inv_01ABC");
    expect(url).not.toMatch(/[?&]token=/);
  });
});

/**
 * Message routing: ServerMessage {type:"notification"} goes to onNotification;
 * everything else takes the EventEnvelope → onEvent path.
 */
describe("WebSocketClient — notification message routing", () => {
  let instances: FakeRoutingWS[];
  let originalWebSocket: typeof WebSocket;

  class FakeRoutingWS {
    static OPEN = 1;
    static CLOSED = 3;
    static CONNECTING = 0;
    static CLOSING = 2;
    readyState = FakeRoutingWS.OPEN;
    onopen: ((e: Event) => void) | null = null;
    onmessage: ((e: MessageEvent) => void) | null = null;
    onclose: ((e: CloseEvent) => void) | null = null;
    onerror: ((e: Event) => void) | null = null;
    constructor(_url: string) {
      instances.push(this);
    }
    close() {}
    send() {}
  }

  beforeEach(() => {
    instances = [];
    originalWebSocket = globalThis.WebSocket;
    // @ts-expect-error — overriding the global for the test
    globalThis.WebSocket = FakeRoutingWS;
  });

  afterEach(() => {
    globalThis.WebSocket = originalWebSocket;
    vi.restoreAllMocks();
  });

  it("routes {type:'notification'} to onNotification, not onEvent", () => {
    const onEvent = vi.fn();
    const onNotification = vi.fn();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      onEvent,
      onNotification,
    });
    client.connect();

    const payload = { id: "ntf_1", title: "Critical finding", read: false };
    instances[0]!.onmessage?.({
      data: JSON.stringify({ type: "notification", data: payload }),
    } as MessageEvent);

    expect(onNotification).toHaveBeenCalledTimes(1);
    expect(onNotification).toHaveBeenCalledWith(payload);
    expect(onEvent).not.toHaveBeenCalled();
  });

  it("routes non-notification messages to onEvent", () => {
    const onEvent = vi.fn();
    const onNotification = vi.fn();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      onEvent,
      onNotification,
    });
    client.connect();

    instances[0]!.onmessage?.({
      data: JSON.stringify({
        event_id: "evt_1",
        event_type: "output",
        investigation_id: "inv_1",
        timestamp: "2026-07-21T12:00:00Z",
        payload: { text: "hi" },
      }),
    } as MessageEvent);

    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onNotification).not.toHaveBeenCalled();
  });
});
