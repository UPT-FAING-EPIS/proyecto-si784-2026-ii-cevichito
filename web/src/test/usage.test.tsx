import { screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import type { Usage } from "@/api/types";
import { ME, apiError, mockApi, renderApp } from "./mockApi";

const USAGE: Usage = {
  days: 30,
  from: "2026-10-19T00:00:00Z",
  to: "2026-11-18T00:00:00Z",
  totals: {
    users: 12, active_users: 7, new_users: 3, projects: 9, scans: 41, findings: 180, issues_fixed: 25,
    challenge_attempts: 10, challenges_solved: 6, scan_seconds_median: 1.4, scan_seconds_p95: 8.2, failure_rate: 0.05,
  },
  by_status: { done: 39, failed: 2 },
  by_source: { snippet: 30, reto: 11 },
  daily: [{ date: "2026-11-17", scans: 5, failed: 0, active_users: 3, new_users: 1 }],
  top_rules: [{ rule_id: "py/sql-injection", count: 22 }],
  challenges: [{ id: "01-login-sql", title: "Inicio de sesión con inyección SQL", attempts: 4, solved: 3 }],
};

describe("Dashboard de uso", () => {
  it("muestra las cifras y el enlace en el menú para un administrador", async () => {
    mockApi({ "GET /api/v1/auth/me": { ...ME, is_admin: true }, "GET /api/v1/usage": USAGE });
    renderApp("/uso");
    expect(await screen.findByRole("heading", { name: "Uso del producto" }, { timeout: 5000 })).toBeInTheDocument();
    expect(await screen.findByText("41")).toBeInTheDocument();
    expect(screen.getByText("py/sql-injection")).toBeInTheDocument();
    expect(screen.getByText("Inicio de sesión con inyección SQL")).toBeInTheDocument();
    expect(screen.getAllByRole("link", { name: "Uso" }).length).toBeGreaterThan(0);
  });

  it("explica el error a quien no es administrador y no muestra el enlace", async () => {
    mockApi({ "GET /api/v1/usage": apiError(403, "forbidden", "Esta página es solo para administradores.") });
    renderApp("/uso");
    expect(await screen.findByText(/solo para administradores/, {}, { timeout: 5000 })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Uso" })).not.toBeInTheDocument();
  });
});
