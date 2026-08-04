import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { WebSocketClient } from "@/api/ws";
import { EventType } from "@/types/events";

/**
 * A constructable WebSocket stub with real readyState transitions, so tests
 * can drive open/close/message and observe what the client sends.
 */
class FakeWS {
  static OPEN = 1;
  static CLOSED = 3;
  static CONNECTING = 0;
  static CLOSING = 2;
  readyState: number = FakeWS.CONNECTING;
  onopen: ((e: Event) => void) | null = null;
  onmessage: ((e: MessageEvent) => void) | null = null;
  onclose: ((e: CloseEvent) => void) | null = null;
  onerror: ((e: Event) => void) | null = null;
  sent: string[] = [];
  closeCalls: { code?: number; reason?: string }[] = [];
  url: string;

  constructor(url: string) {
    this.url = url;
    instances.push(this);
  }

  close(code?: number, reason?: string): void {
    this.closeCalls.push({ code, reason });
    this.readyState = FakeWS.CLOSED;
  }

  send(data: string): void {
    this.sent.push(data);
  }

  /** Drive the handshake completing. */
  open(): void {
    this.readyState = FakeWS.OPEN;
    this.onopen?.(new Event("open"));
  }

  /** Drive a server-initiated close. */
  serverClose(code = 1006, reason = "abnormal"): void {
    this.readyState = FakeWS.CLOSED;
    this.onclose?.({ code, reason } as CloseEvent);
  }

  deliver(payload: unknown): void {
    this.onmessage?.({ data: JSON.stringify(payload) } as MessageEvent);
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
  vi.useRealTimers();
});

function parseSent(ws: FakeWS): Record<string, unknown>[] {
  return ws.sent.map((s) => JSON.parse(s) as Record<string, unknown>);
}

/**
 * Phase C2 invariant: the WebSocket client must NEVER append `?token=` (or any
 * other token query parameter) to the upgrade URL. Auth travels as an httpOnly
 * cookie on the upgrade handshake.
 */
describe("WebSocketClient — Phase C2 cookie auth", () => {
  it("does not append ?token= to the URL on connect()", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();

    expect(instances).toHaveLength(1);
    const url = instances[0]!.url;
    expect(url).toBe("ws://localhost:8000/ws");
    expect(url).not.toMatch(/[?&]token=/);
  });

  it("connect() takes no token argument (signature is auth-free)", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    expect(client.connect.length).toBe(0);
  });

  it("preserves any pre-existing query params on the URL — but never adds a token", () => {
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws?investigation=inv_01ABC",
    });
    client.connect();

    const url = instances[0]!.url;
    expect(url).toBe("ws://localhost:8000/ws?investigation=inv_01ABC");
    expect(url).not.toMatch(/[?&]token=/);
  });
});

/**
 * Message routing.
 *
 * The previous version of this suite fed the client a frame shaped
 * `{event_id, event_type, payload}` and asserted only that `onEvent` fired at
 * all. That shape has never existed on the wire — the hub forwards
 * `EventEnvelope.model_dump_json()`, i.e. `{id, type, data}` — so the test was
 * green while every real event decoded to all-`undefined`. It now uses the
 * real shape and asserts the DECODED FIELDS, not just the call count.
 */
describe("WebSocketClient — message routing", () => {
  function connected(opts: ConstructorParameters<typeof WebSocketClient>[0] = {}) {
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      ...opts,
    });
    client.connect();
    const ws = instances[0]!;
    ws.open();
    return { client, ws };
  }

  it("routes ServerMessage {type:'notification'} to onNotification, not onEvent", () => {
    const onEvent = vi.fn();
    const onNotification = vi.fn();
    const { ws } = connected({ onEvent, onNotification });

    const payload = { id: "ntf_1", title: "Critical finding", read: false };
    ws.deliver({ type: "notification", data: payload });

    expect(onNotification).toHaveBeenCalledTimes(1);
    expect(onNotification).toHaveBeenCalledWith(payload);
    expect(onEvent).not.toHaveBeenCalled();
  });

  it("decodes a real EventEnvelope into an AgentEvent with populated fields", () => {
    const onEvent = vi.fn();
    const { ws } = connected({ onEvent });

    ws.deliver({
      type: "output_chunk",
      id: "evt_1",
      investigation_id: "inv_1",
      parent_id: null,
      trace_id: "trace_1",
      timestamp: "2026-07-21T12:00:00Z",
      data: { text: "hi", index: 1 },
    });

    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onEvent).toHaveBeenCalledWith(
      expect.objectContaining({
        id: "evt_1",
        type: EventType.OUTPUT_CHUNK,
        investigation_id: "inv_1",
        timestamp: "2026-07-21T12:00:00Z",
        data: { text: "hi", index: 1 },
      }),
    );
  });

  it("distinguishes a NOTIFICATION *event* from a notification ServerMessage", () => {
    // EventType.NOTIFICATION and ServerMessageType.NOTIFICATION share the
    // literal "notification"; only the envelope carries id/investigation_id.
    const onEvent = vi.fn();
    const onNotification = vi.fn();
    const { ws } = connected({ onEvent, onNotification });

    ws.deliver({
      type: "notification",
      id: "evt_9",
      investigation_id: "inv_1",
      parent_id: null,
      trace_id: null,
      timestamp: "2026-07-21T12:00:00Z",
      data: { title: "x" },
    });

    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onNotification).not.toHaveBeenCalled();
  });

  it("swallows protocol frames (pong / subscribed / error) instead of emitting them as events", () => {
    const onEvent = vi.fn();
    const { ws } = connected({ onEvent });

    ws.deliver({ type: "pong", data: {} });
    ws.deliver({ type: "subscribed", data: { investigation_id: "inv_1" } });
    ws.deliver({ type: "unsubscribed", data: { investigation_id: "inv_1" } });
    ws.deliver({ type: "error", data: { detail: "nope" } });

    expect(onEvent).not.toHaveBeenCalled();
  });
});

/**
 * Registration list — replaces the single mutable `onEvent` slot.
 */
describe("WebSocketClient — subscriber registration", () => {
  it("dispatches to every registered handler and unsubscribes individually", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();
    const ws = instances[0]!;
    ws.open();

    const a = vi.fn();
    const b = vi.fn();
    const offA = client.onEvent(a);
    client.onEvent(b);

    const envelope = {
      type: "thinking",
      id: "evt_1",
      investigation_id: "inv_1",
      parent_id: null,
      trace_id: null,
      timestamp: "2026-07-21T12:00:00Z",
      data: {},
    };
    ws.deliver(envelope);
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(1);

    // Non-LIFO teardown: removing the FIRST-registered handler must not
    // affect the second (the GH #390 bug class).
    offA();
    ws.deliver({ ...envelope, id: "evt_2" });
    expect(a).toHaveBeenCalledTimes(1);
    expect(b).toHaveBeenCalledTimes(2);
  });

  it("a throwing subscriber does not starve the others", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();
    const ws = instances[0]!;
    ws.open();
    vi.spyOn(console, "error").mockImplementation(() => {});

    const good = vi.fn();
    client.onEvent(() => {
      throw new Error("boom");
    });
    client.onEvent(good);

    ws.deliver({
      type: "thinking",
      id: "evt_1",
      investigation_id: "inv_1",
      parent_id: null,
      trace_id: null,
      timestamp: "2026-07-21T12:00:00Z",
      data: {},
    });

    expect(good).toHaveBeenCalledTimes(1);
  });
});

/**
 * D2: client -> server frames must nest their payload under `data`. The server
 * model (`ClientMessage`) reads payload fields only from there and Pydantic
 * silently drops unknown top-level keys — a flat frame arrives as `data == {}`
 * with no error anywhere.
 */
describe("WebSocketClient — outbound frame shape", () => {
  function openClient() {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();
    const ws = instances[0]!;
    ws.open();
    ws.sent.length = 0;
    return { client, ws };
  }

  it("nests the chat message under data", () => {
    const { client, ws } = openClient();
    expect(client.sendChat("inv_1", "what happened?")).toBe(true);

    expect(parseSent(ws)).toEqual([
      {
        type: "chat",
        investigation_id: "inv_1",
        data: { message: "what happened?" },
      },
    ]);
  });

  it("nests the HITL decision under data", () => {
    const { client, ws } = openClient();
    expect(client.sendHITLResponse("inv_1", "cp_1", true, "looks legit")).toBe(
      true,
    );

    expect(parseSent(ws)).toEqual([
      {
        type: "hitl_response",
        investigation_id: "inv_1",
        data: { checkpoint_id: "cp_1", approved: true, comment: "looks legit" },
      },
    ]);
  });

  it("reports failure (does not throw) when the socket is not open", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    // Never connected.
    expect(client.sendChat("inv_1", "hi")).toBe(false);
    expect(client.sendHITLResponse("inv_1", "cp_1", false)).toBe(false);
  });
});

/**
 * D3: the hub delivers non-global channels only to clients that sent a
 * `subscribe` frame, and RedisEmitter publishes agent events ONLY to
 * `btagent:events:{investigation_id}`.
 */
describe("WebSocketClient — channel subscription", () => {
  it("sends a subscribe frame and an unsubscribe frame", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.connect();
    const ws = instances[0]!;
    ws.open();
    ws.sent.length = 0;

    const off = client.subscribeToInvestigation("inv_1");
    expect(client.subscriptions).toEqual(["inv_1"]);
    off();
    expect(client.subscriptions).toEqual([]);

    expect(parseSent(ws)).toEqual([
      { type: "subscribe", investigation_id: "inv_1" },
      { type: "unsubscribe", investigation_id: "inv_1" },
    ]);
  });

  it("replays subscriptions after a reconnect", () => {
    vi.useFakeTimers();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      initialReconnectDelayMs: 10,
    });
    client.connect();
    const first = instances[0]!;
    first.open();
    client.subscribeToInvestigation("inv_1");

    // Server drops the connection; the hub's per-connection subscription
    // state goes with it.
    first.serverClose();
    vi.advanceTimersByTime(20);

    const second = instances[1]!;
    expect(second).toBeDefined();
    second.open();

    expect(parseSent(second)).toEqual([
      { type: "subscribe", investigation_id: "inv_1" },
    ]);
  });

  it("queues the subscribe intent even when the socket is not open yet", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    vi.spyOn(console, "warn").mockImplementation(() => {});
    client.subscribeToInvestigation("inv_1");
    expect(client.subscriptions).toEqual(["inv_1"]);

    client.connect();
    instances[0]!.open();
    expect(parseSent(instances[0]!)).toEqual([
      { type: "subscribe", investigation_id: "inv_1" },
    ]);
  });
});

/**
 * D6: reconnect churn. `doConnect()` used to close the previous socket with
 * its handlers still attached; that socket's `onclose` saw
 * `intentionalClose === false`, scheduled a reconnect, and the reconnect then
 * killed the healthy replacement — a permanent ~1s cycle. Its `onclose` also
 * called `stopHeartbeat()`, killing the NEW socket's heartbeat.
 */
describe("WebSocketClient — connect idempotency and reconnect hygiene", () => {
  it("connect() is a no-op while CONNECTING or OPEN", () => {
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });

    client.connect();
    expect(instances).toHaveLength(1);

    // Still CONNECTING.
    client.connect();
    expect(instances).toHaveLength(1);

    instances[0]!.open();
    client.connect();
    client.connect();
    expect(instances).toHaveLength(1);
    expect(instances[0]!.closeCalls).toHaveLength(0);
  });

  it("does not fire onDisconnect or schedule a reconnect for a replaced socket", () => {
    vi.useFakeTimers();
    const onDisconnect = vi.fn();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      onDisconnect,
      initialReconnectDelayMs: 10,
    });

    client.connect();
    const first = instances[0]!;
    first.open();

    // Force a replacement the way a real reconnect does, then let the old
    // socket's close fire late. Detached handlers mean it is inert.
    first.serverClose();
    vi.advanceTimersByTime(20);
    expect(instances).toHaveLength(2);
    const second = instances[1]!;
    second.open();
    onDisconnect.mockClear();

    // The replaced socket emitting a late close must not touch live state.
    first.onclose?.({ code: 1006, reason: "late" } as CloseEvent);
    expect(onDisconnect).not.toHaveBeenCalled();

    // ...and no third socket appears from a churn loop.
    vi.advanceTimersByTime(1_000);
    expect(instances).toHaveLength(2);
  });

  it("keeps the heartbeat alive on the replacement socket", () => {
    vi.useFakeTimers();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      heartbeatIntervalMs: 100,
      initialReconnectDelayMs: 10,
    });

    client.connect();
    const first = instances[0]!;
    first.open();
    first.serverClose();
    vi.advanceTimersByTime(20);

    const second = instances[1]!;
    second.open();
    second.sent.length = 0;
    vi.advanceTimersByTime(250);

    // `ping` is a real ClientMessageType; the server answers with `pong`.
    // It used to be an invalid frame that made the server emit an ERROR
    // every heartbeat.
    const pings = parseSent(second).filter((f) => f.type === "ping");
    expect(pings.length).toBeGreaterThanOrEqual(2);
    expect(pings[0]).toEqual({ type: "ping" });
  });

  it("disconnect() stops the reconnect loop", () => {
    vi.useFakeTimers();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      initialReconnectDelayMs: 10,
    });
    client.connect();
    instances[0]!.open();

    client.disconnect();
    vi.advanceTimersByTime(1_000);
    expect(instances).toHaveLength(1);
    expect(client.isConnected).toBe(false);
  });
});

/**
 * An authorization refusal is a decision, not an outage.
 *
 * `ws/access.py` closes an unauthorized subscribe with **4404** — chosen in
 * the 4000-4999 range precisely so browsers deliver it instead of collapsing
 * it to a generic 1006 — and falls back to **1008** if the transport rejects
 * the custom code. This client used to reconnect on every non-intentional
 * close, so that carefully-encoded signal was delivered and thrown away, and
 * a stale or revoked tab retried forever: a handshake, a JWT decode and an
 * investigation lookup every 30s per client, indefinitely, while the user saw
 * only a page that quietly stopped updating.
 */
describe("WebSocketClient — terminal close codes", () => {
  function connected(initialReconnectDelayMs = 10) {
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      initialReconnectDelayMs,
    });
    client.connect();
    instances[0]!.open();
    return client;
  }

  it.each([
    [4404, "not found"],
    [1008, "policy violation"],
  ])("does not reconnect after a %i close", (code, reason) => {
    vi.useFakeTimers();
    const client = connected();

    instances[0]!.serverClose(code, reason);
    vi.advanceTimersByTime(120_000);

    expect(instances).toHaveLength(1);
    expect(client.isTerminallyClosed).toBe(true);
    expect(client.terminalCloseInfo).toEqual({ code, reason });
  });

  it.each([
    [1006, "abnormal"],
    [1011, "server error"],
    [1012, "service restart"],
    [1000, "server hung up"],
  ])("still reconnects after a %i close", (code, reason) => {
    vi.useFakeTimers();
    const client = connected();

    instances[0]!.serverClose(code, reason);
    vi.advanceTimersByTime(50);

    expect(instances.length).toBeGreaterThan(1);
    expect(client.isTerminallyClosed).toBe(false);
    expect(client.terminalCloseInfo).toBeNull();
  });

  it("reports the refusal to disconnect listeners", () => {
    const onDisconnect = vi.fn();
    const client = new WebSocketClient({
      url: "ws://localhost:8000/ws",
      onDisconnect,
    });
    client.connect();
    instances[0]!.open();

    instances[0]!.serverClose(4404, "not found");

    expect(onDisconnect).toHaveBeenCalledWith(4404, "not found");
  });

  it("latches before notifying, so a listener sees the terminal state", () => {
    // Otherwise a listener that reacts by inspecting the client would decide
    // "still retrying" during the very callback announcing the refusal.
    let seen: boolean | null = null;
    const client = new WebSocketClient({ url: "ws://localhost:8000/ws" });
    client.onDisconnect(() => {
      seen = client.isTerminallyClosed;
    });
    client.connect();
    instances[0]!.open();

    instances[0]!.serverClose(4404, "not found");

    expect(seen).toBe(true);
  });

  it("schedules no reconnect timer at all after a refusal", () => {
    // Distinguishes the two guards. The timer's own `!terminalClose` check
    // would neuter a scheduled retry, so a test that only counts sockets
    // passes even if the call-site guard is removed — the loop is stopped,
    // but a pointless timer is armed and the backoff keeps doubling. This
    // asserts the call site itself declined to schedule.
    vi.useFakeTimers();
    const client = connected();
    // Open socket => one heartbeat interval pending.
    expect(vi.getTimerCount()).toBe(1);

    instances[0]!.serverClose(4404, "not found");

    // The close stops the heartbeat; nothing must replace it. A count of 1
    // here means a reconnect was armed and merely neutered later — which is
    // the M1 regression, and why `toBeLessThanOrEqual` was not good enough:
    // -1 heartbeat +1 reconnect lands on the same number.
    expect(vi.getTimerCount()).toBe(0);
    expect(client.isTerminallyClosed).toBe(true);
  });

  it("connect() clears the latch so re-auth recovers without a reload", () => {
    vi.useFakeTimers();
    const client = connected();
    instances[0]!.serverClose(4404, "not found");
    expect(client.isTerminallyClosed).toBe(true);

    client.connect();

    expect(client.isTerminallyClosed).toBe(false);
    expect(client.terminalCloseInfo).toBeNull();
    expect(instances).toHaveLength(2);
  });

  it("a refusal on a retry does not restart the loop", () => {
    // The ordering that a call-site-only guard misses: a transient close
    // schedules a reconnect, and the connection it produces is refused.
    vi.useFakeTimers();
    const client = connected();

    instances[0]!.serverClose(1006, "abnormal");
    vi.advanceTimersByTime(50);
    expect(instances).toHaveLength(2);

    instances[1]!.open();
    instances[1]!.serverClose(4404, "not found");
    vi.advanceTimersByTime(120_000);

    expect(instances).toHaveLength(2);
    expect(client.isTerminallyClosed).toBe(true);
  });
});
