import basicSsl from "@vitejs/plugin-basic-ssl";
import { defineConfig } from "vite";

const crossOriginIsolationHeaders = {
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export default defineConfig(({ isPreview }) => ({
  plugins: isPreview ? [] : [basicSsl()],
  // The SDK resolves its bundled WASM glue relative to import.meta.url. Vite's
  // dependency prebundler replaces that URL, so serve the package as native ESM.
  optimizeDeps: {
    exclude: ["@worldcoin/provekit"],
  },
  server: {
    https: {},
    port: 5178,
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
}));
