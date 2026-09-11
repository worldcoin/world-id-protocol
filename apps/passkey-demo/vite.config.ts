import { defineConfig, loadEnv } from "vite";

// Cross-origin isolation lets ProveKit use SharedArrayBuffer-backed threads.
const crossOriginIsolationHeaders = {
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export default defineConfig(({ mode }) => {
  const bridgePort = loadEnv(mode, process.cwd(), "").PASSKEY_DEMO_BRIDGE_PORT ?? "8787";
  // `localhost` over plain HTTP is a WebAuthn secure context; an IP address is not a valid RP ID.
  const server = {
    host: "localhost",
    strictPort: true,
    headers: crossOriginIsolationHeaders,
    proxy: { "/api": `http://127.0.0.1:${bridgePort}` },
  };

  return {
    // The SDK resolves its bundled WASM glue relative to import.meta.url. Vite's
    // dependency prebundler replaces that URL, so serve the package as native ESM.
    optimizeDeps: { exclude: ["@worldcoin/provekit"] },
    server: { ...server, port: 5178 },
    preview: { ...server, port: 5179 },
  };
});
