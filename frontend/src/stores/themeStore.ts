import { create } from "zustand";
import { persist } from "zustand/middleware";

export type Theme = "dark" | "light" | "system";

interface ThemeState {
  theme: Theme;
  setTheme: (t: Theme) => void;
}

/**
 * Theme store. Persists the user's choice to localStorage so the page
 * doesn't flash the wrong palette on reload. Initialised in
 * `components/theme-provider.tsx`, which is also responsible for
 * propagating the active palette to `<html>`'s class list.
 *
 * Default = "dark" because the existing app is dark-only today; light
 * mode is opt-in.
 */
export const useThemeStore = create<ThemeState>()(
  persist(
    (set) => ({
      theme: "dark",
      setTheme: (theme) => set({ theme }),
    }),
    { name: "btagent-theme" }
  )
);
