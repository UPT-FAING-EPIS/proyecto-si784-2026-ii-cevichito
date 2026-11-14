/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// En desarrollo, Vite reenvía /api a la API (docker compose en :8080) para mantener el mismo origen
// y que la cookie de sesión y la comprobación de Origin funcionen igual que en producción.
const apiTarget = process.env.SAST_API ?? "http://localhost:8080";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: apiTarget,
        // Se reescribe Origin al de la API: el backend solo acepta su PUBLIC_ORIGIN.
        changeOrigin: true,
        headers: { Origin: apiTarget },
      },
    },
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
    chunkSizeWarningLimit: 900,
  },
  test: {
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    testTimeout: 20000,
  },
});
