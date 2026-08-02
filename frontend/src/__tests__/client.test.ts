import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";

// A 401 means the cookie that authenticated the WebSocket upgrade is dead, so
// the socket must be torn down with the session (GH: `resetWSClient` used to
// have zero call sites).
const resetWSClient = vi.fn();
vi.mock("@/api/ws", () => ({
  resetWSClient: () => resetWSClient(),
}));

import {
  api,
  ApiError,
  setAuthStoreAccessor,
  setUnauthenticatedHandler,
} from "@/api/client";

describe("api client — Phase C2 cookie auth", () => {
  // vi.fn() in vitest 4 returns a Mock typed as `Procedure | Constructable`,
  // which TS strict-mode refuses to treat as plain `() => void`. Cast
  // through unknown so we can both record calls and satisfy the signatures.
  type Spy = (() => void) & { mock: { calls: unknown[][] } };
  let logoutSpy: Spy;
  let clearLocalUserSpy: Spy;
  let unauthSpy: Spy;

  beforeEach(() => {
    resetWSClient.mockReset();
    logoutSpy = vi.fn() as unknown as Spy;
    clearLocalUserSpy = vi.fn() as unknown as Spy;
    unauthSpy = vi.fn() as unknown as Spy;
    setAuthStoreAccessor(() => ({
      logout: logoutSpy,
      clearLocalUser: clearLocalUserSpy,
    }));
    setUnauthenticatedHandler(unauthSpy);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("attaches credentials: 'include' on every request", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.get("/v1/anything");

    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const init = (fetchSpy.mock.calls[0]![1] ?? {}) as RequestInit;
    expect(init.credentials).toBe("include");
  });

  it("does NOT add an Authorization: Bearer header (cookies are the source of truth)", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await api.get("/v1/anything");

    const init = (fetchSpy.mock.calls[0]![1] ?? {}) as RequestInit;
    const headers = new Headers(init.headers);
    expect(headers.has("Authorization")).toBe(false);
  });

  it("on 401, calls logout, fires the unauthenticated handler, and throws ApiError(401)", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "Not authenticated" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await expect(api.get("/v1/anything")).rejects.toMatchObject({
      status: 401,
    });
    // The 401 handler clears the LOCAL user only — calling
    // ``logout()`` here would round-trip /auth/logout and revoke
    // the cookie's jti, cascading into other tabs sharing the
    // session. See ``api/client.ts:request`` for the rationale.
    expect(clearLocalUserSpy).toHaveBeenCalledTimes(1);
    expect(logoutSpy).not.toHaveBeenCalled();
    expect(unauthSpy).toHaveBeenCalledTimes(1);
    // ...and the now-unauthenticated socket is torn down.
    expect(resetWSClient).toHaveBeenCalled();
  });

  it("still tears the WebSocket down when the auth-store accessor throws", async () => {
    setAuthStoreAccessor(() => {
      throw new Error("accessor not configured");
    });
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 401 }),
    );

    await expect(api.get("/v1/anything")).rejects.toBeInstanceOf(ApiError);
    expect(resetWSClient).toHaveBeenCalled();
  });

  it("does NOT trigger the unauthenticated handler when skipAuth is set", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 401 }),
    );

    await expect(
      api.get("/v1/login-probe", { skipAuth: true }),
    ).rejects.toBeInstanceOf(ApiError);
    expect(logoutSpy).not.toHaveBeenCalled();
    expect(clearLocalUserSpy).not.toHaveBeenCalled();
    expect(unauthSpy).not.toHaveBeenCalled();
    expect(resetWSClient).not.toHaveBeenCalled();
  });

  it("F8: a non-JSON error body yields ApiError, not a stream-read TypeError", async () => {
    // A gateway HTML 502 is the realistic case: reading it as JSON fails, and
    // the old .text() fallback threw 'body stream already read'.
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response("<html><body>502 Bad Gateway</body></html>", {
        status: 502,
        headers: { "Content-Type": "text/html" },
      }),
    );

    const err = (await api.get("/v1/thing").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.status).toBe(502);
    // The raw HTML text is preserved as the body, not swallowed.
    expect(String(err.body)).toContain("502 Bad Gateway");
  });

  it("F8: a JSON error body is still parsed into an object", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ detail: "nope" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const err = (await api.get("/v1/thing").catch((e) => e)) as ApiError;
    expect(err).toBeInstanceOf(ApiError);
    expect(err.body).toEqual({ detail: "nope" });
  });
});
