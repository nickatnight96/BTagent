import { EventEnvelope, envelopeToEvent, AgentEvent } from "@/types/events";
import type { AppNotification } from "@/types/notification";

type OnEventCallback = (event: AgentEvent) => void;
type OnNotificationCallback = (notification: AppNotification) => void;
type OnConnectCallback = () => void;
type OnDisconnectCallback = (code: number, reason: string) => void;
type OnErrorCallback = (error: Event) => void;

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

  // Callbacks are public so consumers can (re)assign handlers after
  // construction — e.g. the investigation workspace swaps `onEvent` per
  // mounted investigation and detaches it on unmount.
  onEvent: OnEventCallback;
  onNotification: OnNotificationCallback;
  onConnect: OnConnectCallback;
  onDisconnect: OnDisconnectCallback;
  onError: OnErrorCallback;

  constructor(options: WebSocketClientOptions = {}) {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.url = options.url ?? `${wsProtocol}//${window.location.host}/ws`;
    this.onEvent = options.onEvent ?? (() => {});
    this.onNotification = options.onNotification ?? (() => {});
    this.onConnect = options.onConnect ?? (() => {});
    this.onDisconnect = options.onDisconnect ?? (() => {});
    this.onError = options.onError ?? (() => {});
    this.heartbeatInterval = options.heartbeatIntervalMs ?? 30000;
    this.maxReconnectDelay = options.maxReconnectDelayMs ?? 30000;
    this.initialReconnectDelay = options.initialReconnectDelayMs ?? 1000;
    this.reconnectDelay = this.initialReconnectDelay;
  }

  /**
   * Open the WebSocket. No auth argument: the browser sends the
   * httpOnly auth cookies on the upgrade handshake automatically.
   */
  connect(): void {
    this.intentionalClose = false;
    this.doConnect();
  }

  private doConnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    // No `?token=` — cookies authenticate the upgrade.
    this.ws = new WebSocket(this.url);

    this.ws.onopen = () => {
      this.reconnectDelay = this.initialReconnectDelay;
      this.startHeartbeat();
      this.onConnect();
    };

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const parsed = JSON.parse(event.data as string) as {
          type?: string;
          data?: unknown;
        };
        // Per-user in-app notifications arrive as ServerMessage
        // {type:"notification", data:{...}} — not EventEnvelopes.
        if (parsed?.type === "notification" && parsed.data) {
          this.onNotification(parsed.data as AppNotification);
          return;
        }
        const agentEvent = envelopeToEvent(parsed as EventEnvelope);
        this.onEvent(agentEvent);
      } catch {
        console.warn("[WS] Failed to parse message:", event.data);
      }
    };

    this.ws.onclose = (event: CloseEvent) => {
      this.stopHeartbeat();
      this.onDisconnect(event.code, event.reason);

      if (!this.intentionalClose) {
        this.scheduleReconnect();
      }
    };

    this.ws.onerror = (event: Event) => {
      this.onError(event);
    };
  }

  private startHeartbeat(): void {
    this.stopHeartbeat();
    this.heartbeatTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        this.ws.send(JSON.stringify({ type: "ping" }));
      }
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
      this.reconnectDelay = Math.min(
        this.reconnectDelay * 2,
        this.maxReconnectDelay,
      );
      this.doConnect();
    }, this.reconnectDelay);
  }

  sendHITLResponse(
    investigationId: string,
    checkpointId: string,
    approved: boolean,
    comment?: string,
  ): void {
    this.send({
      type: "hitl_response",
      investigation_id: investigationId,
      checkpoint_id: checkpointId,
      approved,
      comment,
    });
  }

  sendChat(investigationId: string, message: string): void {
    this.send({
      type: "chat",
      investigation_id: investigationId,
      message,
    });
  }

  private send(data: Record<string, unknown>): void {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    } else {
      console.warn("[WS] Cannot send, WebSocket is not open.");
    }
  }

  disconnect(): void {
    this.intentionalClose = true;
    this.stopHeartbeat();
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    if (this.ws) {
      this.ws.close(1000, "Client disconnect");
      this.ws = null;
    }
  }

  get isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
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

export function resetWSClient(): void {
  if (wsClient) {
    wsClient.disconnect();
    wsClient = null;
  }
}
