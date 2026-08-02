/**
 * Session-scoped WebSocket lifecycle (D5 + D8).
 *
 * D5: the ONLY `connect()` call site used to be InvestigationWorkspace's
 * effect, so the socket existed only while an investigation was open — the
 * notification bell, the TLP violation alerter and `useLiveEventRefresh` on
 * the hunt/coverage pages were dead on every other route. The Layout shell now
 * owns the connection via `useWebSocketSession`.
 *
 * D8: `resetWSClient()` had ZERO call sites. A socket authenticated as user A
 * kept streaming after A logged out, and user B signing in on the same tab
 * rode A's connection and A's org context.
 */
import { describe, it, expect, beforeEach, vi } from "vitest";
import { renderHook, act } from "@testing-library/react";

const connect = vi.fn();
const resetWSClient = vi.fn();

vi.mock("@/api/ws", () => ({
  getWSClient: () => ({ connect }),
  resetWSClient: () => resetWSClient(),
}));

import { useWebSocketSession } from "@/hooks/useWebSocketSession";
import { useAuthStore } from "@/stores/authStore";
import { UserRole } from "@/types/config";

const USER_A = { id: "usr_a", username: "amy", role: UserRole.ANALYST };
const USER_B = { id: "usr_b", username: "ben", role: UserRole.ANALYST };

beforeEach(() => {
  connect.mockReset();
  resetWSClient.mockReset();
  useAuthStore.setState({ user: null });
});

describe("useWebSocketSession", () => {
  it("connects once there is an authenticated user", () => {
    useAuthStore.setState({ user: USER_A });
    renderHook(() => useWebSocketSession());
    expect(connect).toHaveBeenCalled();
  });

  it("does not connect without a user, and tears any socket down", () => {
    renderHook(() => useWebSocketSession());
    expect(connect).not.toHaveBeenCalled();
    expect(resetWSClient).toHaveBeenCalled();
  });

  it("does not reconnect when the user OBJECT changes but the id does not", () => {
    // `fetchMe()` replaces the user object on bootstrap with an equal-but-not-
    // identical value. An effect keyed on the object re-runs here; keyed on
    // the id it does not. (Combined with `connect()` being idempotent, this is
    // what kills the reconnect churn loop.)
    useAuthStore.setState({ user: USER_A });
    renderHook(() => useWebSocketSession());
    const callsAfterMount = connect.mock.calls.length;

    act(() => {
      useAuthStore.setState({ user: { ...USER_A } });
    });

    expect(connect.mock.calls.length).toBe(callsAfterMount);
  });

  it("tears the socket down when the session ends, and reconnects for the next user", () => {
    useAuthStore.setState({ user: USER_A });
    renderHook(() => useWebSocketSession());
    resetWSClient.mockClear();
    connect.mockClear();

    act(() => {
      useAuthStore.setState({ user: null });
    });
    expect(resetWSClient).toHaveBeenCalled();
    expect(connect).not.toHaveBeenCalled();

    act(() => {
      useAuthStore.setState({ user: USER_B });
    });
    expect(connect).toHaveBeenCalledTimes(1);
  });
});

describe("auth teardown calls resetWSClient", () => {
  it("logout tears the socket down", async () => {
    const fetchMock = vi.fn().mockResolvedValue({ ok: true });
    vi.stubGlobal("fetch", fetchMock);
    useAuthStore.setState({ user: USER_A });

    await useAuthStore.getState().logout();

    expect(resetWSClient).toHaveBeenCalled();
    vi.unstubAllGlobals();
  });

  it("clearLocalUser (the 401 path) tears the socket down", () => {
    useAuthStore.setState({ user: USER_A });
    useAuthStore.getState().clearLocalUser();
    expect(resetWSClient).toHaveBeenCalled();
  });
});
