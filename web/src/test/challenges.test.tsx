import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ChallengeAttempt, ChallengeDetail, ChallengeSummary, Finding, Rule } from "@/api/types";
import { mockApi, renderApp } from "./mockApi";

const RULE: Rule = {
  id: "py/sql-injection",
  name: "Inyección SQL",
  severity: "critical",
  confidence: "high",
  cwe: ["CWE-89"],
  owasp: ["A03:2021"],
  kind: "path-problem",
  languages: ["python"],
  engine: "taint",
  security_severity: 9.8,
  message: "Una entrada no confiable ({source}) llega a {sink}.",
  explanation_es: "El texto del usuario se pega en la consulta.",
  remediation_es: "Usa consultas parametrizadas.",
  example_bad: "db.execute('...' + x)",
  example_good: "db.execute('... = ?', (x,))",
  references: [],
};

const SUMMARY: ChallengeSummary = {
  id: "01-login-sql",
  order: 1,
  title: "Inicio de sesión con inyección SQL",
  level: "básico",
  cwe: "CWE-89",
  rules: ["py/sql-injection"],
  summary: "El formulario arma la consulta pegando lo que escribe el usuario.",
  state: "sin_empezar",
};

const EMPTY: ChallengeAttempt = { state: "sin_empezar", scan_id: null, submissions: 0, solved_at: null, remaining: [], silenced: [], new: [] };

const FINDING: Finding = {
  occurrence_id: "o1",
  issue_id: "i1",
  rule_id: "py/sql-injection",
  severity: "critical",
  confidence: "high",
  path: "app.py",
  start_line: 18,
  end_line: 18,
  start_col: 0,
  message: "Una entrada no confiable llega a `execute`.",
  snippet: null,
  trace: [],
  variant: null,
  change: "persisting",
  triage: "untriaged",
  lifecycle: "open",
  suppressed: false,
  suppression_reason: null,
};

function detail(attempt: ChallengeAttempt = EMPTY): ChallengeDetail {
  return {
    ...SUMMARY,
    statement: "Corrige `login` para que los datos del usuario no formen parte de la consulta.",
    hints: ["Busca la concatenación.", "Usa marcadores `?`."],
    filename: "app.py",
    starter: "def login():\n    pass\n",
    keep: ["login"],
    rule_details: [RULE],
    attempt,
  };
}

describe("retos de corrección", () => {
  it("la lista muestra el progreso y el estado de cada reto en texto", async () => {
    mockApi({
      "GET /api/v1/challenges": [SUMMARY, { ...SUMMARY, id: "02", order: 2, title: "Ping", state: "superado" }],
    });
    renderApp("/retos");
    expect(await screen.findByRole("heading", { name: "Retos de corrección" })).toBeInTheDocument();
    expect(await screen.findByText("Superados 1 de 2")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /1\. Inicio de sesión con inyección SQL/ })).toHaveAttribute("href", "/retos/01-login-sql");
    expect(screen.getByText("Superado")).toBeInTheDocument();
  });

  it("las pistas se revelan de una en una", async () => {
    mockApi({ "GET /api/v1/challenges/01-login-sql": detail() });
    renderApp("/retos/01-login-sql");
    expect(await screen.findByRole("heading", { name: "Inicio de sesión con inyección SQL" })).toBeInTheDocument();
    expect(screen.queryByText("Busca la concatenación.")).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Ver una pista/ }));
    expect(screen.getByText("Busca la concatenación.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Ver otra pista/ }));
    expect(screen.queryByRole("button", { name: /pista/ })).not.toBeInTheDocument();
  });

  it("comprobar envía el código con CSRF y muestra dónde sigue el fallo", async () => {
    let polls = 0;
    const calls = mockApi({
      "GET /api/v1/challenges/01-login-sql": detail(),
      "POST /api/v1/challenges/01-login-sql/submissions": { scan_id: "s2", status: "queued" },
      "GET /api/v1/challenges/01-login-sql/attempt": () => {
        polls += 1;
        return polls === 1 ? { ...EMPTY, state: "analizando", submissions: 1 } : { ...EMPTY, state: "sigue", submissions: 1, remaining: [FINDING] };
      },
    });
    renderApp("/retos/01-login-sql");
    await userEvent.click(await screen.findByRole("button", { name: "Comprobar" }));
    expect(await screen.findByRole("heading", { name: "La vulnerabilidad sigue presente" }, { timeout: 4000 })).toBeInTheDocument();
    expect(screen.getByText("línea 18")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Ver explicación" })).toHaveAttribute("href", "/issues/i1");
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.headers.get("X-CSRF-Token")).toBe("token-csrf-123");
    expect(post.body).toEqual({ code: "def login():\n    pass\n" });
  });

  it("silenciar con un comentario no cuenta como corregir", async () => {
    mockApi({
      "GET /api/v1/challenges/01-login-sql": detail({ ...EMPTY, state: "silenciado", submissions: 1, silenced: [{ ...FINDING, suppressed: true }] }),
    });
    renderApp("/retos/01-login-sql");
    expect(await screen.findByRole("heading", { name: "Silenciar no es corregir" })).toBeInTheDocument();
  });

  it("un reto superado lo dice y recuerda probar el programa", async () => {
    mockApi({
      "GET /api/v1/challenges/01-login-sql": detail({ ...EMPTY, state: "superado", submissions: 2, solved_at: "2026-11-15T10:00:00Z" }),
    });
    renderApp("/retos/01-login-sql");
    expect(await screen.findByRole("heading", { name: "¡Reto superado!" })).toBeInTheDocument();
    expect(screen.getByText(/no que el programa siga funcionando igual/)).toBeInTheDocument();
    expect(screen.getByText(/2 envíos/)).toBeInTheDocument();
  });

  it("un error de sintaxis del envío se muestra sin perder el código", async () => {
    mockApi({
      "GET /api/v1/challenges/01-login-sql": detail(),
      "POST /api/v1/challenges/01-login-sql/submissions": {
        __status: 422,
        error: { code: "syntax_error", message: "El código tiene un error de sintaxis en la línea 2.", request_id: "r" },
      },
    });
    renderApp("/retos/01-login-sql");
    await userEvent.click(await screen.findByRole("button", { name: "Comprobar" }));
    expect(await screen.findByText("El código tiene un error de sintaxis en la línea 2.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Comprobar" })).toBeEnabled();
  });
});
