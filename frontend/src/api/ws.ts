import {
  ClientMessageType,
  ServerMessageType,
  envelopeToEvent,
  isEventEnvelope,
} from "@/types/events";
import type { AgentEvent, ClientMessage } from "@/types/events";
import type { AppNotification } from "@/types/notification";

type OnEventCallback = (event: AgentEvent) => void;
type OnNotificationCallback = (notification: AppNotification) => void;
type OnConnectCallback = () => void;
type OnDisconnectCallback = (code: number, reason: string) => void;
type OnErrorCallback = (error: Event) => void;

/** Handle returned by every `on*` registration; call it to deregister. */
export type Unsubscribe = () => void;

/**
 * Close codes that mean "retrying will not help".
 *
 * The backend closes an unauthorized subscribe with **4404** — deliberately
 * in the 4000-4999 range so browsers deliver it cleanly rather than
 * collapsing it to a generic 1006 — and falls back to **1008** if a transport
 * rejects the custom code. Both encode an authorization *decision*: this user
 * may not stream this case. Nothing about reconnecting changes that.
 *
 * Reconnecting on them anyway is what this client used to do, because
 * `onclose` retried on every non-intentional close. The result was a stale or
 * revoked tab hammering the server forever — a WS handshake, a JWT decode and
 * an investigation lookup every `maxReconnectDelay` (30s by default), per
 * client, with no upper bound — while the user saw only a page that silently
 * never received events. The close code the backend went to trouble to encode
 * was emitted, delivered, and thrown away.
 *
 * 1006 (abnormal), 1011 (server error), 1012/1013 (restart/try-later) and a
 * server-initiated 1000 stay retryable: those are transport or lifecycle
 * conditions that a later attempt genuinely can resolve.
 */
export const TERMINAL_CLOSE_CODES: ReadonlySet<number> = new Set([
  4404, // access denied / not found — see backend ws/access.py
  1008, // policy violation (the 4404 fallback)
]);

interface WebSocketClientOptions {
  url?: string;
  onEvent?: OnEventCallback;
  onNotification?: OnNotificationCallback;
  onConnect?: OnConnectCallback;
  onDisconnect?: OnDisconnectCallback;
  onError?: OnErrorCallback;
  heartbeatIntervalMs?: number;
  maxReconnectDelayMs?: number;
  initialReconnectDelayMs?: number;
}

/**
 * Multi-subscriber registration list.
 *
 * Replaces the old single mutable `onEvent` slot. That slot forced every
 * consumer into a save-prev / call-prev / restore-prev dance which is only
 * correct when consumer lifetimes are strictly LIFO; any other ordering
 * silently unhooks a live consumer (GH #390). A registration list has no
 * ordering requirement at all.
 */
class Listeners<T extends (...args: never[]) => void> {
  private set = new Set<T>();

  add(fn: T): Unsubscribe {
    this.set.add(fn);
    return () => {
      this.set.delete(fn);
    };
  }

  emit(...args: Parameters<T>): void {
    // Iterate a copy: a handler may register/deregister during dispatch.
    for (const fn of [...this.set]) {
      try {
        fn(...args);
      } catch (err) {
        // One broken subscriber must never starve the others.
        console.error("[WS] listener threw:", err);
      }
    }
  }

  get size(): number {
    return this.set.size;
  }
}

/**
 * WebSocket client — Phase C2 (httpOnly cookie auth).
 *
 * Authentication travels on the WebSocket upgrade as cookies, the same way
 * `credentials: "include"` works for fetch. Browsers attach same-origin
 * cookies on the upgrade handshake automatically — there is no API to set
 * `credentials` on `new WebSocket()`, but for same-origin WS (and for the
 * dev-mode Vite proxy at /ws, which preserves cookies on upgrade) the
 * cookie travels on the handshake.
 *
 * As a result we no longer pass `?token=...` in the URL — that would leak
 * the bearer token into server access logs and proxy buffers, which is
 * exactly the class of bug Phase C is trying to close out.
 *
 * The default endpoint is the GLOBAL stream (`/ws`). The hub only delivers
 * non-global channels to clients that have sent a `subscribe` frame, so a
 * consumer that wants an investigation's agent events must call
 * `subscribeToInvestigation()` — see `subscribeToInvestigation` below.
 */
export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private reconnectDelay: number;
  private maxReconnectDelay: number;
  private initialReconnectDelay: number;
  private heartbeatInterval: number;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;

  /**
   * Set once the server closes us with a code in {@link TERMINAL_CLOSE_CODES}.
   *
   * Distinct from `intentionalClose` (which means *we* hung up): this is the
   * server refusing, and it suppresses reconnects until something changes the
   * caller's situation. `connect()` clears it, so re-authenticating or
   * navigating to a case the user can actually see recovers without a reload.
   */
  private terminalClose: { code: number; reason: string } | null = null;

  /**
   * Channels this client wants to be on. Kept independently of the socket so
   * the subscriptions can be replayed after a reconnect — otherwise a dropped
   * connection silently downgrades the workspace to a global-only stream.
   */
  private desiredSubscriptions = new Set<string>();

  private eventListeners = new Listeners<OnEventCallback>();
  private notificationListeners = new Listeners<OnNotificationCallback>();
  private connectListeners = new Listeners<OnConnectCallback>();
  private disconnectListeners = new Listeners<OnDisconnectCallback>();
  private errorListeners = new Listeners<OnErrorCallback>();

  constructor(options: WebSocketClientOptions = {}) {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.url = options.url ?? `${wsProtocol}//${window.location.host}/ws`;
    if (options.onEvent) this.eventListeners.add(options.onEvent);
    if (options.onNotification)
      this.notificationListeners.add(options.onNotification);
    if (options.onConnect) this.connectListeners.add(options.onConnect);
    if (options.onDisconnect) this.disconnectListeners.add(options.onDisconnect);
    if (options.onError) this.errorListeners.add(options.onError);
    this.heartbeatInterval = options.heartbeatIntervalMs ?? 30000;
    this.maxReconnectDelay = options.maxReconnectDelayMs ?? 30000;
    this.initialReconnectDelay = options.initialReconnectDelayMs ?? 1000;
    this.reconnectDelay = this.initialReconnectDelay;
  }

  // ---------------------------------------------------------------------
  // Subscriber registration (all return an unsubscribe handle)
  // ---------------------------------------------------------------------

  /**
   * Register an agent-event handler. Returns an unsubscribe function.
   *
   * Note this is a METHOD, not an assignable field: `ws.onEvent = fn` no
   * longer compiles, which is deliberate. That assignment was the entry point
   * to the save/restore pattern that could unhook live consumers.
   */
  onEvent(handler: OnEventCallback): Unsubscribe {
    return this.eventListeners.add(handler);
  }

  onNotification(handler: OnNotificationCallback): Unsubscribe {
    return this.notificationListeners.add(handler);
  }

  onConnect(handler: OnConnectCallback): Unsubscribe {
    return this.connectListeners.add(handler);
  }

  onDisconnect(handler: OnDisconnectCallback): Unsubscribe {
    return this.disconnectListeners.add(handler);
  }

  onError(handler: OnErrorCallback): Unsubscribe {
    return this.errorListeners.add(handler);
  }

  // ---------------------------------------------------------------------
  // Connection lifecycle
  // ---------------------------------------------------------------------

  /**
   * Open the WebSocket. No auth argument: the browser sends the
   * httpOnly auth cookies on the upgrade handshake automatically.
   *
   * Idempotent — a call while a socket is CONNECTING or OPEN is a no-op.
   * Without that, React StrictMode's double-invoked effects (dev) and any
   * effect re-run on a changed dependency identity (prod) would tear down a
   * healthy socket and start a permanent reconnect churn loop.
   */
  connect(): void {
    this.intentionalClose = false;
    // An explicit connect is the caller saying the situation changed — a new
    // token, a different case. Clear the latch so a refused socket is not a
    // permanent one requiring a page reload.
    this.terminalClose = null;
    if (
      this.ws &&
      (this.ws.readyState === WebSocket.CONNECTING ||
        this.ws.readyState === WebSocket.OPEN)
    ) {
      return;
    }
    this.doConnect();
  }

  private doConnect(): void {
    if (this.ws) {
      // Detach handlers BEFORE closing. Otherwise the outgoing socket's
      // `onclose` fires with `intentionalClose === false`, schedules a
      // reconnect that then kills the healthy replacement, and calls
      // `stopHeartbeat()` — killing the NEW socket's heartbeat too.
      this.detach(this.ws);
      try {
        this.ws.close(1000, "Replaced");
      } catch {
        /* already closing */
      }
      this.ws = null;
    }

    // No `?token=` — cookies authenticate the upgrade.
    const ws = new WebSocket(this.url);
    this.ws = ws;

    ws.onopen = () => {
      this.reconnectDelay = this.initialReconnectDelay;
      this.startHeartbeat();
      // Replay channel subscriptions: the hub's subscription state lives on
      // the connection, so a reconnect starts with none of them.
      for (const investigationId of this.desiredSubscriptions) {
        this.sendFrame({
          type: ClientMessageType.SUBSCRIBE,
          investigation_id: investigationId,
        });
      }
      this.connectListeners.emit();
    };

    ws.onmessage = (event: MessageEvent) => {
      this.handleMessage(event);
    };

    ws.onclose = (event: CloseEvent) => {
      // A stale socket's close must not touch current state.
      if (this.ws !== ws) return;
      this.ws = null;
      this.stopHeartbeat();

      // Latch *before* notifying, so a listener that inspects
      // `isTerminallyClosed` from inside its own callback sees the truth.
      if (TERMINAL_CLOSE_CODES.has(event.code)) {
        this.terminalClose = { code: event.code, reason: event.reason };
      }

      this.disconnectListeners.emit(event.code, event.reason);

      if (!this.intentionalClose && !this.terminalClose) {
        this.scheduleReconnect();
      }
    };

    ws.onerror = (event: Event) => {
      if (this.ws !== ws) return;
      this.errorListeners.emit(event);
    };
  }

  /** Strip our handlers off a socket so its close can't call back into us. */
  private detach(ws: WebSocket): void {
    ws.onopen = null;
    ws.onmessage = null;
    ws.onclose = null;
    ws.onerror = null;
  }

  private handleMessage(event: MessageEvent): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(event.data as string);
    } catch {
      console.warn("[WS] Failed to parse message:", event.data);
      return;
    }

    if (typeof parsed !== "object" || parsed === null) return;
    const frame = parsed as { type?: string; data?: unknown };

    // Protocol-level ServerMessages are `{type, data}` with NO `id` /
    // `investigation_id`. `EventType.NOTIFICATION` and
    // `ServerMessageType.NOTIFICATION` share the literal "notification", so
    // the envelope check — not the type string — is what disambiguates.
    if (!isEventEnvelope(frame)) {
      switch (frame.type) {
        case ServerMessageType.NOTIFICATION:
          if (frame.data) {
            this.notificationListeners.emit(frame.data as AppNotification);
          }
          return;
        case ServerMessageType.PONG:
          // Heartbeat ack — not an event.
          return;
        case ServerMessageType.SUBSCRIBED:
        case ServerMessageType.UNSUBSCRIBED:
          return;
        case ServerMessageType.ERROR:
          console.warn("[WS] server error frame:", frame.data);
          return;
        default:
          console.warn("[WS] Ignoring unrecognised frame:", frame);
          return;
      }
    }

    this.eventListeners.emit(envelopeToEvent(frame));
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      // `ping` is a real ClientMessageType; the server answers with a `pong`
      // ServerMessage. It used to be an unrecognised frame, so every
      // heartbeat produced a server ERROR frame that the browser then fed
      // through its event handler chain as junk.
      this.sendFrame({ type: ClientMessageType.PING });
    }, this.heartbeatInterval);
  }

  private stopHeartbeat(): void {
    if (this.heartbeatTimer) {
      clearInterval(this.heartbeatTimer);
      this.heartbeatTimer = null;
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.reconnectDelay = Math.min(
        this.reconnectDelay * 2,
        this.maxReconnectDelay,
      );
      // Belt-and-braces. With the `onclose` guard in place no timer is ever
      // armed after a refusal, so this branch is unreachable today and no
      // test can reach it — deliberately not dressed up as load-bearing. It
      // costs nothing and means a future call site that schedules a retry
      // without checking the latch still cannot restart the loop.
      if (!this.intentionalClose && !this.terminalClose) {
        this.doConnect();
      }
    }, this.reconnectDelay);
  }

  // ---------------------------------------------------------------------
  // Channel subscription
  // ---------------------------------------------------------------------

  /**
   * Subscribe this connection to an investigation's event channel.
   *
   * REQUIRED for agent events: the hub delivers non-global channels only to
   * clients that have sent a `subscribe` frame, and `RedisEmitter` publishes
   * agent events ONLY to `btagent:events:{investigation_id}`. Without this
   * call, a browser on the global `/ws` stream receives zero agent events.
   *
   * Remembered across reconnects. Returns an unsubscribe handle.
   */
  subscribeToInvestigation(investigationId: string): Unsubscribe {
    this.desiredSubscriptions.add(investigationId);
    this.sendFrame({
      type: ClientMessageType.SUBSCRIBE,
      investigation_id: investigationId,
    });
    return () => this.unsubscribeFromInvestigation(investigationId);
  }

  unsubscribeFromInvestigation(investigationId: string): void {
    this.desiredSubscriptions.delete(investigationId);
    this.sendFrame({
      type: ClientMessageType.UNSUBSCRIBE,
      investigation_id: investigationId,
    });
  }

  /** Investigation channels this client wants to be on (test/diagnostic aid). */
  get subscriptions(): readonly string[] {
    return [...this.desiredSubscriptions];
  }

  // ---------------------------------------------------------------------
  // Outbound application messages
  // ---------------------------------------------------------------------

  /**
   * Send a HITL decision. Returns false when the socket wasn't open, so the
   * caller can avoid optimistically resolving a checkpoint that never left
   * the browser (an approve/reject on a containment action silently
   * evaporating is not an acceptable failure mode).
   */
  sendHITLResponse(
    investigationId: string,
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ): boolean {
    return this.sendFrame({
      type: ClientMessageType.HITL_RESPONSE,
      investigation_id: investigationId,
      // MUST be nested under `data`: the server's `ClientMessage` model only
      // reads payload fields from there and Pydantic drops unknown top-level
      // keys without erroring.
      data: { checkpoint_id: checkpointId, approved, comment },
    });
  }

  /** Send a chat message. Returns false when the socket wasn't open. */
  sendChat(investigationId: string, message: string): boolean {
    return this.sendFrame({
      type: ClientMessageType.CHAT,
      investigation_id: investigationId,
      data: { message },
    });
  }

  /** Serialize and send one `ClientMessage`. Returns false if not connected. */
  private sendFrame(frame: ClientMessage): boolean {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(frame));
      return true;
    }
    console.warn("[WS] Cannot send, WebSocket is not open.");
    return false;
  }

  disconnect(): void {
    this.intentionalClose = true;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.desiredSubscriptions.clear();
    if (this.ws) {
      const ws = this.ws;
      this.ws = null;
      this.detach(ws);
      try {
        ws.close(1000, "Client disconnect");
      } catch {
        /* already closing */
      }
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * True when the server refused this client and no reconnect is pending.
   *
   * Lets the UI distinguish "disconnected, retrying" — which resolves itself —
   * from "you may not stream this case", which does not. Without it both look
   * identical to a user: a page that simply stops updating.
   */
  get isTerminallyClosed(): boolean {
    return this.terminalClose !== null;
  }

  /** The refusal's `{ code, reason }`, or null if we were not refused. */
  get terminalCloseInfo(): { code: number; reason: string } | null {
    return this.terminalClose;
  }
}

// Singleton instance
let wsClient: WebSocketClient | null = null;

export function getWSClient(): WebSocketClient {
  if (!wsClient) {
    wsClient = new WebSocketClient();
  }
  return wsClient;
}

/**
 * Tear the singleton down and drop every registered subscriber.
 *
 * MUST be called on logout and on any 401: the socket is authenticated by the
 * cookie presented at upgrade time, so a live socket keeps streaming user A's
 * events after A logs out — and user B logging in on the same tab would ride
 * A's connection and A's org context.
 */
export function resetWSClient(): void {
  if (wsClient) {
    wsClient.disconnect();
    wsClient = null;
  }
}
