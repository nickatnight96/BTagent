import type { Config } from "tailwindcss";

/**
 * Tailwind config — shadcn/ui-pattern token system.
 *
 * Colours below resolve to CSS variables defined in `src/index.css`,
 * which lets us swap entire palettes (light <-> dark) by toggling a
 * single `.dark` / `.light` class on `<html>`. Theme switching lives
 * in `src/stores/themeStore.ts`.
 *
 * Why CSS variables instead of dark: utilities:
 *   - works for first-party + shadcn components without forks
 *   - third-party portals (Radix) inherit the theme even when mounted
 *     outside the React tree
 *   - one source of truth for designers (the .css file)
 */
const config: Config = {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    container: {
      center: true,
      padding: "2rem",
      screens: { "2xl": "1400px" },
    },
    extend: {
      colors: {
        // shadcn semantic tokens — every UI component reads these
        border: "hsl(var(--border) / <alpha-value>)",
        input: "hsl(var(--input) / <alpha-value>)",
        ring: "hsl(var(--ring) / <alpha-value>)",
        background: "hsl(var(--background) / <alpha-value>)",
        foreground: "hsl(var(--foreground) / <alpha-value>)",
        primary: {
          DEFAULT: "hsl(var(--primary) / <alpha-value>)",
          foreground: "hsl(var(--primary-foreground) / <alpha-value>)",
        },
        secondary: {
          DEFAULT: "hsl(var(--secondary) / <alpha-value>)",
          foreground: "hsl(var(--secondary-foreground) / <alpha-value>)",
        },
        destructive: {
          DEFAULT: "hsl(var(--destructive) / <alpha-value>)",
          foreground: "hsl(var(--destructive-foreground) / <alpha-value>)",
        },
        muted: {
          DEFAULT: "hsl(var(--muted) / <alpha-value>)",
          foreground: "hsl(var(--muted-foreground) / <alpha-value>)",
        },
        accent: {
          DEFAULT: "hsl(var(--accent) / <alpha-value>)",
          foreground: "hsl(var(--accent-foreground) / <alpha-value>)",
        },
        popover: {
          DEFAULT: "hsl(var(--popover) / <alpha-value>)",
          foreground: "hsl(var(--popover-foreground) / <alpha-value>)",
        },
        card: {
          DEFAULT: "hsl(var(--card) / <alpha-value>)",
          foreground: "hsl(var(--card-foreground) / <alpha-value>)",
        },

        // Security-specific severity tokens — also resolve to CSS vars
        // so they can be tuned per-theme (less saturated in light).
        severity: {
          critical: "hsl(var(--severity-critical) / <alpha-value>)",
          high: "hsl(var(--severity-high) / <alpha-value>)",
          medium: "hsl(var(--severity-medium) / <alpha-value>)",
          low: "hsl(var(--severity-low) / <alpha-value>)",
          info: "hsl(var(--severity-info) / <alpha-value>)",
        },

        // Legacy surface tokens — preserved so existing views that
        // reference `bg-surface-raised` keep rendering during the
        // migration. Removed once the last view is refactored onto
        // semantic tokens.
        surface: {
          DEFAULT: "hsl(var(--background) / <alpha-value>)",
          raised: "hsl(var(--card) / <alpha-value>)",
          overlay: "hsl(var(--popover) / <alpha-value>)",
        },
      },
      borderRadius: {
        lg: "var(--radius)",
        md: "calc(var(--radius) - 2px)",
        sm: "calc(var(--radius) - 4px)",
      },
      fontFamily: {
        sans: [
          "Inter",
          "system-ui",
          "-apple-system",
          "Segoe UI",
          "Roboto",
          "sans-serif",
        ],
        mono: [
          "JetBrains Mono",
          "Fira Code",
          "Cascadia Code",
          "monospace",
        ],
      },
      keyframes: {
        "accordion-down": {
          from: { height: "0" },
          to: { height: "var(--radix-accordion-content-height)" },
        },
        "accordion-up": {
          from: { height: "var(--radix-accordion-content-height)" },
          to: { height: "0" },
        },
        slideIn: {
          "0%": { transform: "translateY(10px)", opacity: "0" },
          "100%": { transform: "translateY(0)", opacity: "1" },
        },
        slideInRight: {
          "0%": { transform: "translateX(100%)", opacity: "0" },
          "100%": { transform: "translateX(0)", opacity: "1" },
        },
      },
      animation: {
        "accordion-down": "accordion-down 0.2s ease-out",
        "accordion-up": "accordion-up 0.2s ease-out",
        "pulse-slow": "pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite",
        "slide-in": "slideIn 0.2s ease-out",
        "slide-in-right": "slideInRight 0.25s ease-out",
      },
    },
  },
  plugins: [require("tailwindcss-animate")],
};

export default config;
