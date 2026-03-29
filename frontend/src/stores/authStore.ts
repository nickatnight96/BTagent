import { create } from "zustand";
import { persist } from "zustand/middleware";
import type { User } from "@/types/config";

const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? "/api";

interface AuthState {
  accessToken: string | null;
  refreshToken: string | null;
  user: User | null;
  isLoading: boolean;
  error: string | null;

  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
  refreshTokens: () => Promise<boolean>;
  clearError: () => void;
}

export const useAuthStore = create<AuthState>()(
  persist(
    (set, get) => ({
      accessToken: null,
      refreshToken: null,
      user: null,
      isLoading: false,
      error: null,

      login: async (username: string, password: string): Promise<boolean> => {
        set({ isLoading: true, error: null });
        try {
          const response = await fetch(`${BASE_URL}/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username, password }),
          });

          if (!response.ok) {
            const body = await response.json().catch(() => ({}));
            const message =
              (body as { detail?: string }).detail ?? "Invalid credentials";
            set({ isLoading: false, error: message });
            return false;
          }

          const data = (await response.json()) as {
            access_token: string;
            refresh_token: string;
          };

          // Fetch user profile using the new token
          const meResponse = await fetch(`${BASE_URL}/v1/auth/me`, {
            headers: { Authorization: `Bearer ${data.access_token}` },
          });
          const user = meResponse.ok
            ? ((await meResponse.json()) as User)
            : { id: "unknown", username, role: "analyst" as const };

          set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
            user,
            isLoading: false,
            error: null,
          });

          return true;
        } catch (err) {
          const message =
            err instanceof Error ? err.message : "Login failed";
          set({ isLoading: false, error: message });
          return false;
        }
      },

      logout: () => {
        set({
          accessToken: null,
          refreshToken: null,
          user: null,
          error: null,
        });
      },

      refreshTokens: async (): Promise<boolean> => {
        const { refreshToken } = get();
        if (!refreshToken) return false;

        try {
          const response = await fetch(`${BASE_URL}/v1/auth/refresh`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ refresh_token: refreshToken }),
          });

          if (!response.ok) {
            set({ accessToken: null, refreshToken: null, user: null });
            return false;
          }

          const data = (await response.json()) as {
            access_token: string;
            refresh_token: string;
          };

          set({
            accessToken: data.access_token,
            refreshToken: data.refresh_token,
          });

          return true;
        } catch {
          set({ accessToken: null, refreshToken: null, user: null });
          return false;
        }
      },

      clearError: () => set({ error: null }),
    }),
    {
      name: "btagent-auth",
      partialize: (state) => ({
        accessToken: state.accessToken,
        refreshToken: state.refreshToken,
        user: state.user,
      }),
    },
  ),
);

// Computed selector for isAuthenticated
export const useIsAuthenticated = () =>
  useAuthStore((state) => state.accessToken !== null);
