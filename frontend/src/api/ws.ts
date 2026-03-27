import { EventEnvelope, envelopeToEvent, AgentEvent } from "@/types/events";

type OnEventCallback = (event: AgentEvent) => void;
type OnConnectCallback = () => void;
type OnDisconnectCallback = (code: number, reason: string) => void;
type OnErrorCallback = (error: Event) => void;

interface WebSocketClientOptions {
  url?: string;
  onEvent?: OnEventCallback;
  onConnect?: OnConnectCallback;
  onDisconnect?: OnDisconnectCallback;
  onError?: OnErrorCallback;
  heartbeatIntervalMs?: number;
  maxReconnectDelayMs?: number;
  initialReconnectDelayMs?: number;
}

export class WebSocketClient {
  private ws: WebSocket | null = null;
  private url: string;
  private token: string | null = null;
  private reconnectDelay: number;
  private maxReconnectDelay: number;
  private initialReconnectDelay: number;
  private heartbeatInterval: number;
  private heartbeatTimer: ReturnType<typeof setInterval> | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private intentionalClose = false;

  private onEvent: OnEventCallback;
  private onConnect: OnConnectCallback;
  private onDisconnect: OnDisconnectCallback;
  private onError: OnErrorCallback;

  constructor(options: WebSocketClientOptions = {}) {
    const wsProtocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    this.url = options.url ?? `${wsProtocol}//${window.location.host}/ws`;
    this.onEvent = options.onEvent ?? (() => {});
    this.onConnect = options.onConnect ?? (() => {});
    this.onDisconnect = options.onDisconnect ?? (() => {});
    this.onError = options.onError ?? (() => {});
    this.heartbeatInterval = options.heartbeatIntervalMs ?? 30000;
    this.maxReconnectDelay = options.maxReconnectDelayMs ?? 30000;
    this.initialReconnectDelay = options.initialReconnectDelayMs ?? 1000;
    this.reconnectDelay = this.initialReconnectDelay;
  }

  connect(token: string): void {
    this.token = token;
    this.intentionalClose = false;
    this.doConnect();
  }

  private doConnect(): void {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }

    const separator = this.url.includes("?") ? "&" : "?";
    const fullUrl = `${this.url}${separator}token=${encodeURIComponent(this.token ?? "")}`;

    this.ws = new WebSocket(fullUrl);

    this.ws.onopen = () => {
      this.reconnectDelay = this.initialReconnectDelay;
      this.startHeartbeat();
      this.onConnect();
    };

    this.ws.onmessage = (event: MessageEvent) => {
      try {
        const data = JSON.parse(event.data as string) as EventEnvelope;
        const agentEvent = envelopeToEvent(data);
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
