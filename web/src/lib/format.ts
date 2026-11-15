import type { Change, Confidence, Lifecycle, ScanStatus, Severity, Triage } from "@/api/types";

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Informativa",
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  high: "Confianza alta",
  medium: "Confianza media",
  low: "Confianza baja",
};

export const TRIAGE_LABEL: Record<Triage, string> = {
  untriaged: "Sin revisar",
  confirmed: "Confirmado",
  false_positive: "Falso positivo",
  accepted: "Riesgo aceptado",
  wont_fix: "No se corregirá",
};

/** Estados de triage que el backend exige justificar (issue_service.set_triage). */
export const TRIAGE_NEEDS_JUSTIFICATION: Triage[] = ["false_positive", "accepted", "wont_fix"];

export const CHANGE_LABEL: Record<Change, string> = {
  new: "Nuevo",
  persisting: "Persiste",
  reopened: "Reabierto",
};

export const LIFECYCLE_LABEL: Record<Lifecycle, string> = {
  open: "Abierto",
  fixed: "Corregido",
  reopened: "Reabierto",
};

export const STATUS_LABEL: Record<ScanStatus, string> = {
  queued: "En cola",
  running: "Analizando",
  done: "Terminado",
  failed: "Falló",
  canceled: "Cancelado",
};

export const SOURCE_LABEL = { snippet: "Código pegado", zip: "Archivo ZIP", github: "Repositorio de GitHub" } as const;

/** Explicación legible de los `error_code` que puede dejar el worker o el lector de ZIP. */
export const SCAN_ERROR_LABEL: Record<string, string> = {
  timeout: "El análisis superó el tiempo máximo y se detuvo.",
  worker_lost: "El proceso de análisis se cayó varias veces seguidas.",
  internal: "Error interno del analizador. Revisa los registros del servidor.",
  compression_ratio: "El ZIP tiene una razón de compresión sospechosa (posible bomba ZIP).",
  too_large: "El contenido descomprimido supera el límite permitido.",
  too_many_entries: "El ZIP tiene demasiadas entradas (contando imágenes, documentos y carpetas).",
  too_many_files: "El código tiene demasiados archivos para analizar en este servidor.",
  unsafe_path: "El ZIP contiene rutas absolutas o con «..».",
  symlink: "El ZIP contiene enlaces simbólicos.",
  invalid_zip: "El archivo no es un ZIP válido.",
  repo_not_found: "No se encontró el repositorio o la rama en GitHub (¿es público?).",
  repo_too_large: "El repositorio supera el tamaño máximo permitido.",
  github_rate_limited: "GitHub limitó las descargas. Prueba más tarde.",
  github_unreachable: "No se pudo contactar con GitHub.",
  github_timeout: "La descarga desde GitHub tardó demasiado. Inténtalo más tarde.",
  github_error: "GitHub devolvió un error inesperado.",
  bad_redirect: "GitHub respondió con una redirección inesperada.",
  invalid_repo: "El repositorio debe tener la forma propietario/nombre.",
  invalid_ref: "La rama o etiqueta no es válida.",
};

export const ENGINE_LABEL: Record<string, string> = {
  ast: "Árbol sintáctico",
  taint: "Flujo de datos (taint)",
  heuristic: "Heurística",
};

export function scanErrorText(code: string | null) {
  if (!code) return "El análisis no terminó.";
  return SCAN_ERROR_LABEL[code] ?? `El análisis no terminó (código: ${code}).`;
}

const dateFmt = new Intl.DateTimeFormat("es", { dateStyle: "medium", timeStyle: "short" });
const shortDate = new Intl.DateTimeFormat("es", { day: "numeric", month: "short" });
const rel = new Intl.RelativeTimeFormat("es", { numeric: "auto" });

export function formatDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return dateFmt.format(new Date(iso));
}

export function formatShortDate(iso: string | null | undefined) {
  if (!iso) return "—";
  return shortDate.format(new Date(iso));
}

export function formatRelative(iso: string | null | undefined, now = Date.now()) {
  if (!iso) return "—";
  const diff = (new Date(iso).getTime() - now) / 1000;
  const abs = Math.abs(diff);
  if (abs < 60) return rel.format(Math.round(diff), "second");
  if (abs < 3600) return rel.format(Math.round(diff / 60), "minute");
  if (abs < 86400) return rel.format(Math.round(diff / 3600), "hour");
  if (abs < 86400 * 30) return rel.format(Math.round(diff / 86400), "day");
  return formatShortDate(iso);
}

export function formatDuration(startIso: string | null, endIso: string | null) {
  if (!startIso || !endIso) return "—";
  const s = Math.max(0, (new Date(endIso).getTime() - new Date(startIso).getTime()) / 1000);
  if (s < 60) return `${s.toFixed(1).replace(".", ",")} s`;
  return `${Math.floor(s / 60)} min ${Math.round(s % 60)} s`;
}

export const numberFmt = new Intl.NumberFormat("es");

/** Espera estimada en palabras: «menos de 1 min», «unos 4 min», «más de 1 h». */
export function formatWait(seconds: number) {
  if (seconds < 60) return "menos de 1 min";
  const min = Math.round(seconds / 60);
  if (min >= 60) return "más de 1 h";
  return `unos ${min} min`;
}

export function plural(n: number, one: string, many: string) {
  return `${numberFmt.format(n)} ${n === 1 ? one : many}`;
}
