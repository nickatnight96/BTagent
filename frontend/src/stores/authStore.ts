import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "@/types/config";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

/**
 * Auth store — Phase C2 (httpOnly cookie auth).
 *
 * Tokens (access_token / refresh_token) are NEVER stored in the browser.
 * The backend issues them as httpOnly, Secure, SameSite=Strict cookies on
 * /api/v1/auth/login. Browsers attach the cookies automatically on subsequent
 * fetch() calls (with `credentials: "include"`) and on same-origin WebSocket
 * upgrade handshakes. The frontend only persists the User profile so that
 * route guards can render synchronously on reload while /auth/me is in flight.
 */
interface AuthState {
  user: User | null;
  isLoading: boolean;
  isBootstrapping: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<boolean>;
  logout: () => Promise<void>;
  // Local-only sibling of ``logout``: clears the in-memory user
  // state without round-tripping ``/auth/logout``. Use when the
  // server has already invalidated the session (e.g. a 401 came
  // back) so calling the network logout would just put the cookie's
  // jti on the revocation list and propagate the revocation to
  // other tabs / parallel test workers sharing the access token.
  clearLocalUser: () => void;
  fetchMe: () => Promise<boolean>;
  setUser: (user: User | null) => void;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set) => ({
      user: null,
      isLoading: false,
      isBootstrapping: true,
      error: null,

      login: async (username: string, password: string): Promise<boolean> => {
        set({ isLoading: true, error: null });
        try {
          const response = await fetch(`${BASE_URL}/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            credentials: "include",
            body: JSON.stringify({ username, password }),
          });

          if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            const message =
              (body as { detail?: string }).detail ?? "Invalid credentials";
            set({ isLoading: false, error: message, user: null });
            return false;
          }

          // Tokens arrived as httpOnly cookies; ignore the response body.
          // Hydrate the user profile via /auth/me so that the cookie-bearing
          // session is verified end-to-end before we trust it for routing.
          const meResponse = await fetch(`${BASE_URL}/v1/auth/me`, {
            credentials: "include",
          });

          if (!meResponse.ok) {
            set({
              isLoading: false,
              error: "Failed to load user profile",
              user: null,
            });
            return false;
          }

          const user = (await meResponse.json()) as User;
          set({ user, isLoading: false, error: null });
          return true;
        } catch (err) {
          const message = err instanceof Error ? err.message : "Login failed";
          set({ isLoading: false, error: message, user: null });
          return false;
        }
      },

      logout: async (): Promise<void> => {
        // Clear local state immediately so any concurrent renders see a
        // logged-out store, then ask the backend to clear the cookies.
        set({ user: null, error: null });
        try {
          await fetch(`${BASE_URL}/v1/auth/logout`, {
            method: "POST",
            credentials: "include",
          });
        } catch {
          // Best-effort: cookies will still expire server-side.
        }
      },

      clearLocalUser: (): void => {
        // Local-only cleanup. Used by the 401 handler in api/client
        // — see ``AuthStoreSlice.clearLocalUser`` for why we don't
        // round-trip ``/auth/logout`` from the API client.
        set({ user: null, error: null });
      },

      fetchMe: async (): Promise<boolean> => {
        try {
          const response = await fetch(`${BASE_URL}/v1/auth/me`, {
            credentials: "include",
          });
          if (!response.ok) {
            set({ user: null, isBootstrapping: false });
            return false;
          }
          const user = (await response.json()) as User;
          set({ user, isBootstrapping: false });
          return true;
        } catch {
          set({ user: null, isBootstrapping: false });
          return false;
        }
      },

      setUser: (user: User | null) => set({ user }),

      clearError: () => set({ error: null }),
    }),
    {
      name: "btagent-auth",
      // Persist ONLY the user profile. Tokens live in httpOnly cookies that
      // JavaScript cannot read — this is the whole point of Phase C2.
      partialize: (state) => ({
        user: state.user,
      }),
    },
  ),
);

/**
 * `isAuthenticated` is now derived from "do we have a user?" rather than
 * "do we have a token?". The backend is the source of truth for session
 * validity (cookies); the user object is just a UI hint.
 */
export const useIsAuthenticated = () =>
  useAuthStore((state) => state.user !== null);
