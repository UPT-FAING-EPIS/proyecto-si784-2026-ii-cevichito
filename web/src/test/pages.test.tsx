import { fireEvent, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { Finding, Issue, Scan } from "@/api/types";
import { CONFIG, apiError, mockApi, renderApp } from "./mockApi";

const SCAN: Scan = {
  id: "s1",
  project_id: "p1",
  status: "done",
  source: "snippet",
  source_ref: "app.py",
  category: "default",
  commit_sha: null,
  progress: { files_done: 1, files_total: 1 },
  queued_at: "2026-11-13T10:00:00Z",
  started_at: "2026-11-13T10:00:01Z",
  finished_at: "2026-11-13T10:00:02Z",
  summary: { by_severity: { critical: 1, high: 1 }, new: 2, fixed: 0, persisting: 0, reopened: 0, suppressed: 0, total: 2 },
  rule_errors: [],
  error_code: null,
  cancel_requested: false,
  files_scanned: 1,
  loc_total: 40,
  engine_version: "2.0.0",
  baseline_scan_id: null,
  rules_requested: null,
};

function finding(over: Partial<Finding>): Finding {
  return {
    occurrence_id: "o1",
    issue_id: "i1",
    rule_id: "py/sql-injection",
    severity: "critical",
    confidence: "high",
    path: "app.py",
    start_line: 12,
    end_line: 12,
    start_col: 4,
    message: "Consulta SQL construida con datos del usuario",
    snippet: 'cur.execute("SELECT * FROM u WHERE id=" + uid)',
    trace: [
      { line: 10, description: "uid = request.args['id']" },
      { line: 12, description: "cur.execute(...)" },
    ],
    variant: null,
    change: "new",
    triage: "untriaged",
    lifecycle: "open",
    suppressed: false,
    suppression_reason: null,
    ...over,
  };
}

const FINDINGS = [
  finding({}),
  finding({ occurrence_id: "o2", issue_id: "i2", rule_id: "py/weak-hash", severity: "high", path: "util/hash.py", start_line: 3, message: "MD5 no sirve para contraseñas", trace: [] }),
];

const RULE = {
  id: "py/sql-injection",
  name: "Inyección SQL",
  severity: "critical",
  confidence: "high",
  cwe: ["CWE-89"],
  owasp: ["A03:2021"],
  kind: "problem",
  languages: ["python"],
  engine: "taint",
  security_severity: 9.8,
  message: "Consulta SQL con datos sin parametrizar",
  explanation_es: "Concatenar datos del usuario en SQL permite cambiar la consulta.",
  remediation_es: "Usa consultas parametrizadas.",
  example_bad: 'cur.execute("... " + x)',
  example_good: 'cur.execute("... %s", (x,))',
  references: ["https://owasp.org/Top10/A03_2021-Injection/"],
};

describe("inicio de sesión", () => {
  it("sin sesión redirige a /login y muestra el acceso de desarrollo, sin Google si no está configurado", async () => {
    mockApi({ "GET /api/v1/auth/me": apiError(401, "unauthorized", "Inicia sesión") });
    renderApp("/proyectos");
    expect(await screen.findByRole("heading", { name: "Inicia sesión" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Acceso de desarrollo" })).toBeInTheDocument();
    expect(screen.queryByText("Continuar con Google")).not.toBeInTheDocument();
  });

  it("con Google configurado ofrece el botón y conserva la ruta de destino", async () => {
    mockApi({
      "GET /api/v1/config": { ...CONFIG, auth: { oidc: true, google: true, provider: "Google", dev_login: false } },
      "GET /api/v1/auth/me": apiError(401, "unauthorized", "Inicia sesión"),
    });
    renderApp("/reglas");
    const link = await screen.findByRole("link", { name: /Continuar con Google/ });
    expect(link).toHaveAttribute("href", "/api/v1/auth/login?next=%2Freglas");
    expect(screen.queryByText("Acceso de desarrollo")).not.toBeInTheDocument();
  });
});

describe("proyectos", () => {
  it("estado vacío con llamada a la acción", async () => {
    mockApi({ "GET /api/v1/projects": { items: [], next_cursor: null } });
    renderApp("/proyectos");
    expect(await screen.findByText("Todavía no tienes proyectos")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Crear el primero" })).toBeInTheDocument();
  });

  it("estado de error con identificador de petición y reintento", async () => {
    mockApi({ "GET /api/v1/projects": apiError(500, "internal", "Error interno", "req-500") });
    renderApp("/proyectos");
    const alert = await screen.findByRole("alert");
    expect(within(alert).getByText("Error interno")).toBeInTheDocument();
    expect(within(alert).getByText("req-500")).toBeInTheDocument();
    expect(within(alert).getByRole("button", { name: "Reintentar" })).toBeInTheDocument();
  });

  it("la barra de severidad da el desglose en texto, no solo color", async () => {
    mockApi({
      "GET /api/v1/projects": {
        items: [{ id: "p1", name: "practica", created_at: "2026-11-01T00:00:00Z", last_scan: { id: "s1", status: "done", finished_at: "2026-11-13T10:00:02Z", summary: SCAN.summary } }],
        next_cursor: null,
      },
    });
    renderApp("/proyectos");
    expect(await screen.findByRole("link", { name: "practica" })).toBeInTheDocument();
    expect(screen.getByText(/1 crítica, 1 alta/)).toBeInTheDocument();
  });

  it("crear un proyecto manda el token CSRF y lleva a nuevo escaneo", async () => {
    const calls = mockApi({
      "GET /api/v1/projects": { items: [], next_cursor: null },
      "POST /api/v1/projects": { id: "p2", name: "nuevo", created_at: "2026-11-13T00:00:00Z", last_scan: null },
      "GET /api/v1/projects/p2": { id: "p2", name: "nuevo", created_at: "2026-11-13T00:00:00Z", last_scan: null },
      "GET /api/v1/rules": [RULE],
    });
    renderApp("/proyectos");
    await userEvent.click(await screen.findByRole("button", { name: "Nuevo proyecto" }));
    await userEvent.type(screen.getByLabelText("Nombre"), "nuevo");
    await userEvent.click(screen.getByRole("button", { name: "Crear y escanear" }));
    expect(await screen.findByRole("heading", { name: "Nuevo escaneo" })).toBeInTheDocument();
    const post = calls.find((c) => c.method === "POST")!;
    expect(post.headers.get("X-CSRF-Token")).toBe("token-csrf-123");
  });
});

describe("resultados del escaneo", () => {
  const routes = {
    "GET /api/v1/scans/s1": SCAN,
    "GET /api/v1/projects/p1": { id: "p1", name: "practica", created_at: "2026-11-01T00:00:00Z", last_scan: null },
    "GET /api/v1/scans/s1/findings": { items: FINDINGS, next_cursor: null },
    "GET /api/v1/rules/py/sql-injection": RULE,
  };

  it("filtra por severidad y lo refleja en el contador", async () => {
    mockApi(routes);
    renderApp("/escaneos/s1");
    expect(await screen.findByText("2 hallazgos", { exact: false })).toBeInTheDocument();
    await userEvent.selectOptions(screen.getByLabelText("Severidad"), "high");
    expect(screen.getByText(/1 de 2 hallazgos/)).toBeInTheDocument();
    const grid = screen.getByRole("grid", { name: "Hallazgos" });
    expect(within(grid).queryByText("py/sql-injection")).not.toBeInTheDocument();
    expect(within(grid).getByText("py/weak-hash")).toBeInTheDocument();
  });

  it("j/k mueven la selección y Enter abre el panel con la traza y la lección", async () => {
    mockApi(routes);
    renderApp("/escaneos/s1");
    await screen.findByRole("grid", { name: "Hallazgos" });
    const rows = screen.getAllByRole("row").slice(1);
    expect(rows[0]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(window, { key: "j" });
    expect(screen.getAllByRole("row")[2]).toHaveAttribute("aria-selected", "true");
    fireEvent.keyDown(window, { key: "k" });
    fireEvent.keyDown(window, { key: "Enter" });
    const panel = await screen.findByRole("dialog");
    expect(within(panel).getByText("Recorrido del dato")).toBeInTheDocument();
    expect(await within(panel).findByText("Usa consultas parametrizadas.")).toBeInTheDocument();
    expect(within(panel).getByRole("link", { name: "Revisar y anotar" })).toHaveAttribute("href", "/issues/i1");
  });

  it("un escaneo fallido explica el motivo en español", async () => {
    mockApi({ ...routes, "GET /api/v1/scans/s1": { ...SCAN, status: "failed", error_code: "compression_ratio" } });
    renderApp("/escaneos/s1");
    expect(await screen.findByText(/posible bomba ZIP/)).toBeInTheDocument();
  });

  it("un escaneo en curso muestra el progreso y permite cancelarlo", async () => {
    const calls = mockApi({
      ...routes,
      "GET /api/v1/scans/s1": { ...SCAN, status: "running", progress: { files_done: 3, files_total: 12 } },
      "POST /api/v1/scans/s1/cancel": { status: "canceling" },
    });
    renderApp("/escaneos/s1");
    expect(await screen.findByText(/3 de 12 archivos \(25 %\)/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Cancelar escaneo" }));
    await waitFor(() => expect(calls.some((c) => c.method === "POST" && c.path.endsWith("/cancel"))).toBe(true));
  });

  it("un escaneo en cola dice cuántos hay delante y cuánto falta", async () => {
    mockApi({ ...routes, "GET /api/v1/scans/s1": { ...SCAN, status: "queued", queue: { ahead: 3, eta_s: 240 } } });
    renderApp("/escaneos/s1");
    expect(await screen.findByText("Hay 3 escaneos delante; unos 4 min de espera.")).toBeInTheDocument();
  });

  it("avisa de un resultado parcial y de uno reutilizado", async () => {
    mockApi({
      ...routes,
      "GET /api/v1/scans/s1": { ...SCAN, partial: true, result_reused: true, progress: { files_done: 40, files_total: 120 } },
    });
    renderApp("/escaneos/s1");
    expect(await screen.findByText(/se analizaron 40 de 120 archivos/)).toBeInTheDocument();
    expect(screen.getByText(/Resultado reutilizado/)).toBeInTheDocument();
  });
});

describe("revisión de un issue", () => {
  const ISSUE: Issue = {
    id: "i1",
    project_id: "p1",
    rule_id: "py/sql-injection",
    category: "default",
    lifecycle: "open",
    triage: "untriaged",
    triage_justification: null,
    severity: "critical",
    path: "app.py",
    line: 12,
    message: "Consulta SQL construida con datos del usuario",
    first_seen_at: "2026-11-13T10:00:02Z",
    fixed_at: null,
    first_seen_scan_id: "s1",
    last_seen_scan_id: "s1",
    reopened_count: 0,
    fingerprint: "sastfp/v1:abc",
    last_occurrence: FINDINGS[0],
    rule: RULE as Issue["rule"],
  };

  it("marcar como falso positivo exige justificación antes de enviar", async () => {
    const calls = mockApi({
      "GET /api/v1/issues/i1": ISSUE,
      "GET /api/v1/issues/i1/events": [],
      "GET /api/v1/projects/p1": { id: "p1", name: "practica", created_at: "2026-11-01T00:00:00Z", last_scan: null },
      "PATCH /api/v1/issues/i1": { ...ISSUE, triage: "false_positive", triage_justification: "Entrada validada antes" },
    });
    renderApp("/issues/i1");
    await userEvent.selectOptions(await screen.findByLabelText("Estado"), "false_positive");
    const save = screen.getByRole("button", { name: "Guardar revisión" });
    expect(save).toBeDisabled();
    expect(screen.getByLabelText(/Justificación \(obligatoria\)/)).toHaveAttribute("aria-invalid", "true");
    await userEvent.type(screen.getByLabelText(/Justificación/), "Entrada validada antes");
    await userEvent.click(save);
    await waitFor(() => expect(calls.find((c) => c.method === "PATCH")?.body).toEqual({ triage: "false_positive", justification: "Entrada validada antes" }));
  });
});

describe("nuevo escaneo", () => {
  it("valida el repositorio de GitHub antes de enviar", async () => {
    mockApi({
      "GET /api/v1/projects/p1": { id: "p1", name: "practica", created_at: "2026-11-01T00:00:00Z", last_scan: null },
      "GET /api/v1/rules": [RULE],
    });
    renderApp("/proyectos/p1/nuevo-escaneo");
    await userEvent.click(await screen.findByRole("tab", { name: /Repositorio de GitHub/ }));
    await userEvent.type(screen.getByLabelText("Repositorio"), "no-valido");
    expect(screen.getByText("Escribe el repositorio como propietario/nombre.")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Lanzar escaneo" })).toBeDisabled();
    await userEvent.clear(screen.getByLabelText("Repositorio"));
    await userEvent.type(screen.getByLabelText("Repositorio"), "pallets/flask");
    expect(screen.getByRole("button", { name: "Lanzar escaneo" })).toBeEnabled();
  });
});
