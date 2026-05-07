/**
 * WebSocket assertion helpers for E2E.
 *
 * The BTagent backend pushes investigation events on
 * ``ws://…/ws/investigations/{id}`` after Phase B2 hardening:
 *
 *   * Auth source: HttpOnly cookie (the SPA path) OR ``?token=…`` query
 *     (compat shim, slated for removal). The helper supports both.
 *   * Per-message: 64 KiB cap, oversize closes the socket with code 1009.
 *   * Per-investigation access check: caller must own / be assigned to /
 *     have a senior_analyst|incident_commander role for the same org.
 *
 * Tests use ``waitForEvent({type: "investigation.updated"})`` to drive
 * assertions on live agent output, HITL pauses, evidence-chain entries,
 * etc.
 */
import { type APIRequestContext, type Browser } from "@playwright/test";

const API_HOST = process.env.E2E_API_URL ?? "http://localhost:8000";
const WS_HOST = API_HOST.replace(/^http/, "ws");

export interface WsEvent {
  /** Engine-style event type ("investigation.updated", "agent.message", "hitl.pause", etc.) */
  type: string;
  payload: Record<string, unknown>;
  ts?: string;
  // The backend may add other fields; tests should only assert on the
  // ones they care about.
  [key: string]: unknown;
}

export interface WsListener {
  /** All events seen on the socket so far, in arrival order. */
  events: WsEvent[];
  /** Resolve when an event matching the predicate arrives. */
  waitForEvent(
    predicate: (e: WsEvent) => boolean,
    timeoutMs?: number,
  ): Promise<WsEvent>;
  /** Send a message back up the socket (analyst chat, HITL approve, etc.) */
  send(payload: Record<string, unknown>): Promise<void>;
  /** Close the socket. */
  close(): Promise<void>;
  /** Underlying close-code if the socket has closed (1000 = normal, 1009 = oversize). */
  closeCode(): number | null;
}

export interface WsConnectOptions {
  investigationId: string;
  /** Pre-authenticated browser context (carries the cookie). */
  ctxOrApi: APIRequestContext;
  /** Override transport — default is "cookie". Use "query-token" to
   *  exercise the compat shim explicitly. */
  authMode?: "cookie" | "query-token";
  /** When ``authMode === "query-token"``, the bearer token to attach. */
  bearerToken?: string;
}

/**
 * Connect to ``/ws/investigations/{id}`` and return a listener with
 * convenience methods. Internally uses Playwright's APIRequestContext
 * (so the cookie jar is shared) by routing the WS upgrade through the
 * same browser context — done via launching a tiny page that opens the
 * socket on our behalf. This avoids hand-rolling cookie forwarding.
 */
export async function connectInvestigationWs(
  browser: Browser,
  options: WsConnectOptions,
  storageStatePath: string,
): Promise<WsListener> {
  const ctx = await browser.newContext({
    storageState: storageStatePath,
    extraHTTPHeaders: { "x-e2e-test": "1" },
  });
  const page = await ctx.newPage();
  // Navigate to the SPA root so cookies are scoped correctly under the
  // app origin before we open the WS.
  await page.goto("/");

  const url =
    options.authMode === "query-token" && options.bearerToken
      ? `${WS_HOST}/ws/investigations/${options.investigationId}?token=${options.bearerToken}`
      : `${WS_HOST}/ws/investigations/${options.investigationId}`;

  const events: WsEvent[] = [];
  let socketClosed: number | null = null;

  await page.evaluate((wsUrl) => {
    return new Promise<void>((resolve, reject) => {
      const ws = new WebSocket(wsUrl);
      // Stash on window so the page handle can interact later.
      (window as unknown as { __e2eWs?: WebSocket }).__e2eWs = ws;
      const buffered: unknown[] = [];
      (window as unknown as { __e2eEvents?: unknown[] }).__e2eEvents = buffered;
      let closeCode: number | null = null;
      (window as unknown as { __e2eCloseCode?: () => number | null }).__e2eCloseCode =
        () => closeCode;
      ws.onopen = () => resolve();
      ws.onerror = (err) => reject(err);
      ws.onmessage = (msg) => {
        try {
          buffered.push(JSON.parse(msg.data));
        } catch {
          buffered.push({ raw: msg.data });
        }
      };
      ws.onclose = (ev) => {
        closeCode = ev.code;
      };
    });
  }, url);

  const flushBuffer = async () => {
    const fresh = await page.evaluate(
      () => {
        const w = window as unknown as {
          __e2eEvents?: unknown[];
          __e2eCloseCode?: () => number | null;
        };
        const out = (w.__e2eEvents ?? []).slice();
        if (w.__e2eEvents) w.__e2eEvents.length = 0;
        return { events: out, closeCode: w.__e2eCloseCode?.() ?? null };
      },
    );
    for (const ev of fresh.events) {
      events.push(ev as WsEvent);
    }
    socketClosed = fresh.closeCode;
  };

  return {
    events,

    async waitForEvent(
      predicate: (e: WsEvent) => boolean,
      timeoutMs = 10_000,
    ): Promise<WsEvent> {
      const deadline = Date.now() + timeoutMs;
      while (Date.now() < deadline) {
        await flushBuffer();
        const hit = events.find(predicate);
        if (hit) return hit;
        await new Promise((r) => setTimeout(r, 50));
      }
      throw new Error(
        `WS event timeout after ${timeoutMs}ms. Seen ${events.length} events; no match.`,
      );
    },

    async send(payload: Record<string, unknown>): Promise<void> {
      await page.evaluate((data) => {
        const w = window as unknown as { __e2eWs?: WebSocket };
        if (!w.__e2eWs || w.__e2eWs.readyState !== WebSocket.OPEN) {
          throw new Error("WS is not open");
        }
        w.__e2eWs.send(JSON.stringify(data));
      }, payload);
    },

    async close(): Promise<void> {
      await page.evaluate(() => {
        const w = window as unknown as { __e2eWs?: WebSocket };
        w.__e2eWs?.close();
      });
      await flushBuffer();
      await ctx.close();
    },

    closeCode(): number | null {
      return socketClosed;
    },
  };
}
