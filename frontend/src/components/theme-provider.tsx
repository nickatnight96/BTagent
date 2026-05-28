import { useEffect, type ReactNode } from "react";
import { useThemeStore, type Theme } from "@/stores/themeStore";

/**
 * Resolves "system" to the OS preference; otherwise echoes the user choice.
 */
function resolveTheme(theme: Theme): "dark" | "light" {
  if (theme === "system") {
    return window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light";
  }
  return theme;
}

/**
 * ThemeProvider — applies the active palette to <html> and listens to OS
 * preference changes when the user has selected "system".
 *
 * Wrap the application root with this once. Components downstream can read
 * the current preference via `useThemeStore`.
 */
export function ThemeProvider({ children }: { children: ReactNode }) {
  const theme = useThemeStore((s) => s.theme);

  useEffect(() => {
    const root = window.document.documentElement;
    const apply = () => {
      const resolved = resolveTheme(theme);
      root.classList.remove("light", "dark");
      root.classList.add(resolved);
    };
    apply();

    if (theme !== "system") return;
    const mql = window.matchMedia("(prefers-color-scheme: dark)");
    mql.addEventListener("change", apply);
    return () => mql.removeEventListener("change", apply);
  }, [theme]);

  return <>{children}</>;
}
