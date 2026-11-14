import { describe, expect, it, vi } from "vitest";
import { ApiError, UNAUTHORIZED_EVENT, api, setCsrfToken } from "@/api/client";
import { apiError, mockApi } from "./mockApi";

describe("cliente de /api/v1", () => {
  it("envía la cookie (credentials: include) y el X-CSRF-Token solo en métodos no seguros", async () => {
    const calls = mockApi({ "POST /api/v1/projects": { id: "p1" }, "GET /api/v1/projects": { items: [], next_cursor: null } });
    setCsrfToken("tok-1");
    await api.get("/projects");
    await api.post("/projects", { name: "x" });
    const fetchMock = vi.mocked(fetch);
    expect(fetchMock.mock.calls.every(([, init]) => init?.credentials === "include")).toBe(true);
    expect(calls[0].headers.get("X-CSRF-Token")).toBeNull();
    expect(calls[1].headers.get("X-CSRF-Token")).toBe("tok-1");
    expect(calls[1].body).toEqual({ name: "x" });
    setCsrfToken(null);
  });

  it("convierte el formato de error de la API en ApiError con request_id", async () => {
    mockApi({ "GET /api/v1/projects/p9": apiError(404, "not_found", "Recurso no encontrado", "req-77") });
    const err = await api.get("/projects/p9").catch((e) => e);
    expect(err).toBeInstanceOf(ApiError);
    expect(err).toMatchObject({ status: 404, code: "not_found", message: "Recurso no encontrado", requestId: "req-77" });
  });

  it("avisa a la sesión cuando la API responde 401", async () => {
    mockApi({ "GET /api/v1/projects": apiError(401, "unauthorized", "Inicia sesión") });
    const listener = vi.fn();
    window.addEventListener(UNAUTHORIZED_EVENT, listener);
    await api.get("/projects").catch(() => {});
    window.removeEventListener(UNAUTHORIZED_EVENT, listener);
    expect(listener).toHaveBeenCalledOnce();
  });

  it("da un mensaje en español si el servidor no responde", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new TypeError("Failed to fetch")));
    const err = (await api.get("/projects").catch((e: unknown) => e)) as ApiError;
    expect(err.code).toBe("network");
    expect(err.message).toMatch(/No se pudo conectar/);
  });

  it("no guarda nada de la sesión en localStorage", async () => {
    mockApi({ "POST /api/v1/auth/dev-login": { id: "u", email: "a@b.c", name: "a", csrf_token: "t" } });
    const spy = vi.spyOn(Storage.prototype, "setItem");
    await api.post("/auth/dev-login", { email: "a@b.c" });
    expect(spy).not.toHaveBeenCalled();
  });
});
