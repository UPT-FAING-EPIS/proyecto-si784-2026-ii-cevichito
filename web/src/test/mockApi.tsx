import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { vi } from "vitest";
import { AppRoutes } from "@/App";
import { AuthProvider } from "@/auth/AuthProvider";
import type { Me, PublicConfig } from "@/api/types";

export const CONFIG: PublicConfig = {
  version: "2.0.0",
  auth: { oidc: false, google: false, provider: "Google", dev_login: true },
  limits: {
    max_upload_mb: 25,
    max_snippet_kb: 1024,
    max_zip_entries: 10000,
    max_total_uncompressed_mb: 200,
    max_compression_ratio: 100,
    github_max_mb: 50,
    scan_timeout_s: 300,
    scans_per_hour: 30,
    retention_days: 90,
  },
};

export const ME: Me = { id: "u1", email: "ana@example.com", name: "Ana", csrf_token: "token-csrf-123" };

type Handler = unknown | ((req: { method: string; url: URL; body: unknown; headers: Headers }) => unknown);
export interface Call {
  method: string;
  path: string;
  headers: Headers;
  body: unknown;
}

/**
 * Sustituye fetch por una tabla "MÉTODO /ruta" -> respuesta. Una respuesta `{ __status, ...}` permite
 * devolver errores con el formato de la API. Devuelve la lista de llamadas para hacer aserciones.
 */
export function mockApi(routes: Record<string, Handler>) {
  const calls: Call[] = [];
  const all: Record<string, Handler> = { "GET /api/v1/config": CONFIG, "GET /api/v1/auth/me": ME, ...routes };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const url = new URL(String(input), "http://localhost");
      const method = (init.method ?? "GET").toUpperCase();
      const headers = new Headers(init.headers);
      const body = typeof init.body === "string" ? JSON.parse(init.body) : init.body;
      calls.push({ method, path: url.pathname + url.search, headers, body });
      const handler = all[`${method} ${url.pathname}`];
      if (handler === undefined) {
        return new Response(JSON.stringify({ error: { code: "not_found", message: "No encontrado", request_id: "req-404" } }), {
          status: 404,
          headers: { "Content-Type": "application/json" },
        });
      }
      const value = typeof handler === "function" ? (handler as (r: unknown) => unknown)({ method, url, body, headers }) : handler;
      const v = value as { __status?: number } | undefined;
      if (v && typeof v === "object" && "__status" in v) {
        const { __status, ...rest } = v as Record<string, unknown>;
        return new Response(JSON.stringify(rest), { status: __status as number, headers: { "Content-Type": "application/json" } });
      }
      if (value === null) return new Response(null, { status: 204 });
      return new Response(JSON.stringify(value), { status: 200, headers: { "Content-Type": "application/json" } });
    }),
  );
  return calls;
}

export function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <AppRoutes />
      </AuthProvider>
    </MemoryRouter>,
  );
}

export function apiError(status: number, code: string, message: string, request_id = "req-1") {
  return { __status: status, error: { code, message, request_id } };
}
