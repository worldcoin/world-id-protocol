import { defineConfig, loadEnv } from "vite";

const crossOriginIsolationHeaders = {
  "Cross-Origin-Embedder-Policy": "require-corp",
  "Cross-Origin-Opener-Policy": "same-origin",
};

export default defineConfig(({ mode }) => {
  const bridgePort = loadEnv(mode, process.cwd(), "").PASSKEY_DEMO_BRIDGE_PORT ?? "8787";
  return ({
  server: {
    host: "localhost",
    port: 5179,
    strictPort: true,
    headers: crossOriginIsolationHeaders,
    proxy: {
      "/api": `http://127.0.0.1:${bridgePort}`,
    },
  },
  preview: {
    host: "localhost",
    port: 5179,
    strictPort: true,
    headers: crossOriginIsolationHeaders,
    proxy: {
      "/api": `http://127.0.0.1:${bridgePort}`,
    },
  },
  });
});
