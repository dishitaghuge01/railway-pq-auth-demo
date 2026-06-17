// @lovable.dev/vite-tanstack-config already includes the following — do NOT add them manually
// or the app will break with duplicate plugins:
//   - tanstackStart, viteReact, tailwindcss, tsConfigPaths, nitro (build-only using cloudflare as a default target),
//     componentTagger (dev-only), VITE_* env injection, @ path alias, React/TanStack dedupe,
//     error logger plugins, and sandbox detection (port/host/strictPort).
// You can pass additional config via defineConfig({ vite: { ... }, etc... }) if needed.
import { defineConfig } from "@lovable.dev/vite-tanstack-config";

export default defineConfig({
  tanstackStart: {
    // Redirect TanStack Start's bundled server entry to src/server.ts (our SSR error wrapper).
    // nitro/vite builds from this
    server: { entry: "server" },
  },
  vite: {
    server: {
      proxy: {
        "/api/prs": {
          target: "http://localhost:8000",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/prs/, ""),
        },
        "/api/cris": {
          target: "http://localhost:8001",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/cris/, ""),
        },
        "/api/audit": {
          target: "http://localhost:8002",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/audit/, ""),
        },
        "/api/hht": {
          target: "http://localhost:8003",
          changeOrigin: true,
          rewrite: (path) => path.replace(/^\/api\/hht/, ""),
        },
      },
    },
  },
});
