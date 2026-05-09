import { describe, it, expect, beforeEach, vi, afterEach } from "vitest";
import { useAuthStore } from "@/stores/authStore";
import { UserRole, type User } from "@/types/config";

const sampleUser: User = {
  id: "usr_01TEST",
  username: "alice",
  role: UserRole.ANALYST,
};

describe("authStore — Phase C2 cookie auth", () => {
  beforeEach(() => {
    // Reset the store to a fully logged-out state for every test.
    useAuthStore.setState({
      user: null,
      isLoading: false,
      isBootstrapping: true,
      error: null,
    });
    localStorage.clear();
    // Reset the global fetch mock between tests.
    vi.restoreAllMocks();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("does NOT persist accessToken or refreshToken to localStorage", () => {
    // Drop a user into the store and let zustand-persist write through.
    useAuthStore.setState({ user: sampleUser });
    // Force the persist middleware to flush.
    void useAuthStore.persist.rehydrate();

    const raw = localStorage.getItem("btagent-auth");
    expect(raw).not.toBeNull();
    const parsed = JSON.parse(raw!) as {
      state: Record<string, unknown>;
    };
    // Whitelist: only `user` may be persisted. Tokens are httpOnly cookies.
    expect(parsed.state).toHaveProperty("user");
    expect(parsed.state).not.toHaveProperty("accessToken");
    expect(parsed.state).not.toHaveProperty("refreshToken");
    expect(parsed.state).not.toHaveProperty("access_token");
    expect(parsed.state).not.toHaveProperty("refresh_token");
    // Sanity: the persisted user matches what we set.
    expect((parsed.state.user as User).id).toBe("usr_01TEST");
  });

  it("isAuthenticated is derived from the user, not from a token", () => {
    expect(useAuthStore.getState().user).toBeNull();

    useAuthStore.setState({ user: sampleUser });
    expect(useAuthStore.getState().user).not.toBeNull();

    useAuthStore.setState({ user: null });
    expect(useAuthStore.getState().user).toBeNull();
  });

  it("logout clears local user state and POSTs to /auth/logout", async () => {
    useAuthStore.setState({ user: sampleUser });

    const fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(null, { status: 204 }),
    );

    await useAuthStore.getState().logout();

    expect(useAuthStore.getState().user).toBeNull();
    expect(fetchSpy).toHaveBeenCalledTimes(1);
    const call = fetchSpy.mock.calls[0]!;
    const url = call[0] as string;
    const init = (call[1] ?? {}) as RequestInit;
    expect(url).toMatch(/\/v1\/auth\/logout$/);
    expect(init.method).toBe("POST");
    // Critical: must send credentials so the server's Set-Cookie clears
    // the auth cookies on this origin.
    expect(init.credentials).toBe("include");
  });

  it("login reads the user from /auth/me — never from response body tokens", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(
      async (input: RequestInfo | URL): Promise<Response> => {
        const url = typeof input === "string" ? input : input.toString();
        if (url.endsWith("/v1/auth/login")) {
          // Backend keeps tokens in the body for B/C, but we ignore them.
          return new Response(
            JSON.stringify({
              access_token: "do-not-touch",
              refresh_token: "do-not-touch",
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          );
        }
        if (url.endsWith("/v1/auth/me")) {
          return new Response(JSON.stringify(sampleUser), {
            status: 200,
            headers: { "Content-Type": "application/json" },
          });
        }
        throw new Error(`Unexpected fetch: ${url}`);
      },
    );

    const ok = await useAuthStore.getState().login("alice", "pw");
    expect(ok).toBe(true);

    // User is hydrated.
    expect(useAuthStore.getState().user).toEqual(sampleUser);

    // Both calls used credentials: "include" so cookies travel correctly.
    for (const call of fetchSpy.mock.calls) {
      const init = (call[1] ?? {}) as RequestInit;
      expect(init.credentials).toBe("include");
    }

    // Persisted slice still must not contain tokens.
    const raw = localStorage.getItem("btagent-auth");
    if (raw) {
      const parsed = JSON.parse(raw) as { state: Record<string, unknown> };
      expect(parsed.state).not.toHaveProperty("accessToken");
      expect(parsed.state).not.toHaveProperty("refreshToken");
    }
  });

  it("fetchMe sets user on 200 and clears it on 401", async () => {
    // Success path
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(JSON.stringify(sampleUser), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );
    await useAuthStore.getState().fetchMe();
    expect(useAuthStore.getState().user).toEqual(sampleUser);
    expect(useAuthStore.getState().isBootstrapping).toBe(false);

    // 401 path — must clear user
    useAuthStore.setState({ user: sampleUser, isBootstrapping: true });
    vi.spyOn(globalThis, "fetch").mockResolvedValueOnce(
      new Response(null, { status: 401 }),
    );
    await useAuthStore.getState().fetchMe();
    expect(useAuthStore.getState().user).toBeNull();
    expect(useAuthStore.getState().isBootstrapping).toBe(false);
  });
});
