import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

// #146 perf: vendor-chunk grouping for manualChunks (below).
const REACT_VENDOR = /[\\/]node_modules[\\/](react|react-dom|react-router|react-router-dom|scheduler)[\\/]/;
const UI_VENDOR = /[\\/]node_modules[\\/](@radix-ui|cmdk)[\\/]/;

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  // #146 perf: split long-lived vendor code into its own cacheable chunks so
  // a deploy that only touches app code doesn't bust the (large, rarely
  // changing) framework bundle. Route-level code-splitting lives in
  // ``router.tsx`` via ``React.lazy``; this only governs vendor grouping.
  build: {
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes("node_modules")) return undefined;
          // React core + router travel together — almost every chunk needs
          // them, so keep them in one shared vendor file.
          if (REACT_VENDOR.test(id)) return "vendor-react";
          // Radix primitives + the cmdk palette: the design-system layer.
          if (UI_VENDOR.test(id)) return "vendor-ui";
          return "vendor";
        },
      },
    },
  },
  server: {
    port: 3000,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:8000",
        ws: true,
      },
    },
  },
  // ``vite preview`` (used by the E2E job to serve the prod bundle) needs its
  // own proxy block — it does not reliably inherit ``server.proxy`` across
  // Vite versions. Mirror the dev proxy so the served SPA reaches the backend.
  preview: {
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: true,
      },
      "/ws": {
        target: "ws://localhost:8000",
        ws: true,
      },
    },
  },
});
