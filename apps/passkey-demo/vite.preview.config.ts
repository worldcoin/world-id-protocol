import { defineConfig } from "vite";

const crossOriginIsolationHeaders = {
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export default defineConfig({
  server: {
    host: "localhost",
    port: 5179,
    strictPort: true,
    headers: crossOriginIsolationHeaders,
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
  preview: {
    host: "localhost",
    port: 5179,
    strictPort: true,
    headers: crossOriginIsolationHeaders,
    proxy: {
      "/api": "http://127.0.0.1:8787",
    },
  },
});
