import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
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
  let unauthSpy: Spy;

  beforeEach(() => {
    logoutSpy = vi.fn() as unknown as Spy;
    unauthSpy = vi.fn() as unknown as Spy;
    setAuthStoreAccessor(() => ({ logout: logoutSpy }));
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
    expect(logoutSpy).toHaveBeenCalledTimes(1);
    expect(unauthSpy).toHaveBeenCalledTimes(1);
  });

  it("does NOT trigger the unauthenticated handler when skipAuth is set", async () => {
    vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 401 }),
    );

    await expect(
      api.get("/v1/login-probe", { skipAuth: true }),
    ).rejects.toBeInstanceOf(ApiError);
    expect(logoutSpy).not.toHaveBeenCalled();
    expect(unauthSpy).not.toHaveBeenCalled();
  });
});
