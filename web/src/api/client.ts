// Cliente de /api/v1. Mismo origen, cookie de sesión HttpOnly (el navegador la gestiona) y
// X-CSRF-Token en todo método no seguro. Nada de la sesión se guarda en el almacenamiento del
// navegador: el token CSRF vive solo en memoria y se vuelve a pedir a /auth/me al recargar.

const BASE = "/api/v1";
const UNSAFE = new Set(["POST", "PUT", "PATCH", "DELETE"]);

let csrfToken: string | null = null;

export function setCsrfToken(token: string | null) {
  csrfToken = token;
}

export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly requestId: string | null;

  constructor(status: number, code: string, message: string, requestId: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.requestId = requestId;
  }
}

/** Evento global para que la sesión reaccione a un 401 en cualquier pantalla. */
export const UNAUTHORIZED_EVENT = "sast:unauthorized";

type Query = Record<string, string | number | undefined | null | false>;

function buildUrl(path: string, query?: Query) {
  const url = new URL(BASE + path, window.location.origin);
  for (const [k, v] of Object.entries(query ?? {})) {
    if (v !== undefined && v !== null && v !== false && v !== "") url.searchParams.set(k, String(v));
  }
  return url.pathname + url.search;
}

async function toError(res: Response): Promise<ApiError> {
  let code = `http_${res.status}`;
  let message = defaultMessage(res.status);
  let requestId: string | null = res.headers.get("X-Request-ID");
  try {
    const body = await res.json();
    if (body?.error) {
      code = body.error.code ?? code;
      message = body.error.message ?? message;
      requestId = body.error.request_id ?? requestId;
    }
  } catch {
    // respuesta sin JSON (proxy, servidor caído): se usa el mensaje por defecto
  }
  return new ApiError(res.status, code, message, requestId);
}

function defaultMessage(status: number) {
  if (status === 401) return "Tu sesión ha caducado. Vuelve a iniciar sesión.";
  if (status === 403) return "La petición no pasó la verificación de seguridad. Recarga la página.";
  if (status === 404) return "No se encontró el recurso o no tienes acceso a él.";
  if (status === 413) return "El archivo supera el tamaño permitido.";
  if (status === 429) return "Demasiadas peticiones. Espera un momento y vuelve a intentarlo.";
  if (status >= 500) return "El servidor tuvo un problema. Inténtalo de nuevo en unos segundos.";
  return "La petición no se pudo completar.";
}

interface RequestOptions {
  query?: Query;
  json?: unknown;
  form?: FormData;
  signal?: AbortSignal;
  raw?: boolean;
}

export async function request<T>(method: string, path: string, opts: RequestOptions = {}): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  let body: BodyInit | undefined;
  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(opts.json);
  } else if (opts.form) {
    body = opts.form;
  }
  if (UNSAFE.has(method) && csrfToken) headers["X-CSRF-Token"] = csrfToken;

  let res: Response;
  try {
    res = await fetch(buildUrl(path, opts.query), {
      method,
      headers,
      body,
      credentials: "include",
      signal: opts.signal,
    });
  } catch (err) {
    if ((err as Error).name === "AbortError") throw err;
    throw new ApiError(0, "network", "No se pudo conectar con el servidor. Comprueba que está en marcha.");
  }

  if (!res.ok) {
    const error = await toError(res);
    if (res.status === 401 && path !== "/auth/me") window.dispatchEvent(new Event(UNAUTHORIZED_EVENT));
    throw error;
  }
  if (res.status === 204) return undefined as T;
  if (opts.raw) return (await res.blob()) as T;
  return (await res.json()) as T;
}

export const api = {
  get: <T>(path: string, query?: Query, signal?: AbortSignal) => request<T>("GET", path, { query, signal }),
  post: <T>(path: string, json?: unknown) => request<T>("POST", path, { json: json ?? {} }),
  patch: <T>(path: string, json: unknown) => request<T>("PATCH", path, { json }),
  del: (path: string) => request<void>("DELETE", path),
  upload: <T>(path: string, form: FormData) => request<T>("POST", path, { form }),
  blob: (path: string, query?: Query) => request<Blob>("GET", path, { query, raw: true }),
};

/** Descarga un informe como archivo sin abrir otra pestaña (la cookie viaja con fetch). */
export async function downloadReport(scanId: string, format: "sarif" | "json" | "html") {
  const blob = await api.blob(`/scans/${scanId}/report`, { format });
  const ext = format === "sarif" ? "sarif" : format;
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sast-${scanId}.${ext}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}
