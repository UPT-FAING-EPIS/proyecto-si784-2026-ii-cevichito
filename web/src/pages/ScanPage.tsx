import { ArrowLeftRight, Download, ExternalLink, FileSearch, Search, TriangleAlert } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { Link, useParams, useSearchParams } from "react-router-dom";
import { api, downloadReport, type ApiError } from "@/api/client";
import { useAllFindings } from "@/api/findings";
import { CHANGES, SEVERITIES, TRIAGES, type Finding, type Project, type Rule, type Scan } from "@/api/types";
import { useApi } from "@/api/useApi";
import { FindingsTable } from "@/components/FindingsTable";
import { CodeView, RuleLesson, TaintTrace } from "@/components/Lesson";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { BlockSkeleton, EmptyState, ErrorState, TableSkeleton } from "@/components/States";
import { ScanStatusText } from "@/components/ScanStatus";
import { Button } from "@/components/ui/button";
import { Dialog, DialogDescription, DialogTitle, SheetContent } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input, NativeSelect } from "@/components/ui/input";
import { InlineCode } from "@/components/InlineCode";
import {
  CHANGE_LABEL,
  SEVERITY_LABEL,
  SOURCE_LABEL,
  TRIAGE_LABEL,
  formatDate,
  formatDuration,
  numberFmt,
  plural,
  scanErrorText,
} from "@/lib/format";

const ACTIVE = (s: Scan) => s.status === "queued" || s.status === "running";

function ScanRun({ scan, onChanged }: { scan: Scan; onChanged: () => void }) {
  const [error, setError] = useState<ApiError | null>(null);
  const [sent, setSent] = useState(false);
  const { files_done, files_total } = scan.progress;
  const pct = files_total ? Math.round(((files_done ?? 0) / files_total) * 100) : null;

  async function cancel() {
    setSent(true);
    try {
      await api.post(`/scans/${scan.id}/cancel`);
      onChanged();
    } catch (err) {
      setError(err as ApiError);
      setSent(false);
    }
  }

  return (
    <section className="grid max-w-xl gap-4" aria-live="polite">
      <div className="grid gap-2">
        <ScanStatusText status={scan.status} className="font-medium" />
        {scan.status === "queued" && <p className="text-muted-foreground">Esperando a que un proceso de análisis quede libre.</p>}
        {scan.status === "running" && (
          <>
            <progress
              className="h-1.5 w-full overflow-hidden rounded-full [&::-moz-progress-bar]:bg-foreground [&::-webkit-progress-bar]:bg-muted [&::-webkit-progress-value]:bg-foreground"
              max={files_total ?? undefined}
              value={files_total ? files_done ?? 0 : undefined}
              aria-label="Progreso del análisis"
            />
            <p className="tabular text-sm text-muted-foreground">
              {files_total
                ? `${numberFmt.format(files_done ?? 0)} de ${plural(files_total, "archivo", "archivos")} (${pct} %)`
                : "Preparando los archivos…"}
            </p>
          </>
        )}
        {scan.cancel_requested && <p className="text-sm text-muted-foreground">Cancelación pedida; se detendrá en breve.</p>}
      </div>
      <div>
        <Button variant="outline" onClick={cancel} disabled={sent || scan.cancel_requested}>
          Cancelar escaneo
        </Button>
      </div>
      {error && <ErrorState error={error} />}
    </section>
  );
}

function FindingSheet({ finding, onClose }: { finding: Finding | null; onClose: () => void }) {
  const rule = useApi<Rule>(finding ? `/rules/${finding.rule_id}` : null);
  const lines = finding?.snippet ? finding.snippet.split("\n").length : 0;
  const traceLines = finding?.trace.map((t) => t.line) ?? [];
  return (
    <Dialog open={finding !== null} onOpenChange={(o) => !o && onClose()}>
      <SheetContent>
        {finding && (
          <div className="flex min-h-0 flex-1 flex-col">
            <div className="grid gap-2 border-b p-5 pr-12">
              <div className="flex flex-wrap items-center gap-2">
                <SeverityBadge severity={finding.severity} />
                {finding.change && <span className="text-sm text-muted-foreground">{CHANGE_LABEL[finding.change]}</span>}
                <span className="text-sm text-muted-foreground">· {TRIAGE_LABEL[finding.triage]}</span>
              </div>
              <DialogTitle className="text-md">{rule.data?.name ?? finding.rule_id}</DialogTitle>
              <DialogDescription className="text-base text-foreground">
                <InlineCode text={finding.message} />
              </DialogDescription>
              <p className="break-all font-mono text-sm text-muted-foreground">
                {finding.path}:{finding.start_line}
              </p>
            </div>
            {/* auto-rows-max: sin él, en un contenedor con scroll las filas
                de los bloques overflow-hidden (el código) se encogen a 0. */}
            <div className="grid flex-1 auto-rows-max content-start gap-6 overflow-y-auto p-5">
              {finding.snippet && (
                <CodeView
                  code={finding.snippet}
                  firstLine={finding.start_line}
                  highlight={[finding.start_line, ...traceLines].filter((n) => n < finding.start_line + lines)}
                  label={finding.path}
                />
              )}
              <TaintTrace steps={finding.trace} />
              {rule.loading && <BlockSkeleton />}
              {rule.error && <ErrorState error={rule.error} onRetry={rule.reload} />}
              {rule.data && (
                <section aria-label="Explicación de la regla">
                  <RuleLesson rule={rule.data} compact />
                </section>
              )}
            </div>
            <div className="flex flex-wrap gap-2 border-t p-4">
              <Button asChild>
                <Link to={`/issues/${finding.issue_id}`}>Revisar y anotar</Link>
              </Button>
              <Button asChild variant="outline">
                <Link to={`/reglas?regla=${encodeURIComponent(finding.rule_id)}`}>
                  <ExternalLink aria-hidden /> Ver la regla
                </Link>
              </Button>
            </div>
          </div>
        )}
      </SheetContent>
    </Dialog>
  );
}

function ScanResults({ scan }: { scan: Scan }) {
  const { items, error, truncated, reload } = useAllFindings(scan.id);
  const [params, setParams] = useSearchParams();
  const [active, setActive] = useState(0);
  const [open, setOpen] = useState<Finding | null>(null);
  const searchRef = useRef<HTMLInputElement>(null);

  const f = {
    q: params.get("q") ?? "",
    severity: params.get("severidad") ?? "",
    rule: params.get("regla") ?? "",
    change: params.get("cambio") ?? "",
    triage: params.get("revision") ?? "",
  };
  const setFilter = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
    setActive(0);
  };

  const ruleIds = useMemo(() => [...new Set((items ?? []).map((i) => i.rule_id))].sort(), [items]);
  const filtered = useMemo(() => {
    const q = f.q.toLowerCase();
    return (items ?? []).filter(
      (i) =>
        (!f.severity || i.severity === f.severity) &&
        (!f.rule || i.rule_id === f.rule) &&
        (!f.change || i.change === f.change) &&
        (!f.triage || i.triage === f.triage) &&
        (!q || i.path.toLowerCase().includes(q) || i.message.toLowerCase().includes(q)),
    );
  }, [items, f.q, f.severity, f.rule, f.change, f.triage]);

  // Atajos: "/" busca, j/k recorren, Enter abre (en la fila).
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const target = e.target instanceof Element ? e.target : document.body;
      if (open || e.ctrlKey || e.metaKey || e.altKey) return;
      if (target.closest("input, textarea, select, [contenteditable=true]")) return;
      if (e.key === "/") {
        e.preventDefault();
        searchRef.current?.focus();
      } else if (e.key === "j") {
        setActive((a) => Math.min(a + 1, filtered.length - 1));
      } else if (e.key === "k") {
        setActive((a) => Math.max(a - 1, 0));
      } else if (e.key === "Enter" && filtered[active] && !target.closest("button, a, [data-row]")) {
        // Sin preventDefault, el foco pasa al botón de cerrar del panel y ese
        // mismo Enter lo pulsa: el panel se abría y se cerraba al instante.
        e.preventDefault();
        setOpen(filtered[active]);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [filtered, active, open]);

  const s = scan.summary;
  const anyFilter = Object.values(f).some(Boolean);

  return (
    <>
      <dl className="mb-4 flex flex-wrap gap-x-6 gap-y-1 text-sm">
        {[
          ["Archivos", scan.files_scanned],
          ["Líneas", scan.loc_total],
          ["Nuevos", s.new],
          ["Persisten", s.persisting],
          ["Reabiertos", s.reopened],
          ["Corregidos", s.fixed],
          ["Suprimidos", s.suppressed],
        ].map(([label, value]) => (
          <div key={label as string} className="flex gap-1.5">
            <dt className="text-muted-foreground">{label}</dt>
            <dd className="tabular font-medium">{value == null ? "—" : numberFmt.format(value as number)}</dd>
          </div>
        ))}
        <div className="flex gap-1.5">
          <dt className="text-muted-foreground">Duración</dt>
          <dd className="tabular font-medium">{formatDuration(scan.started_at, scan.finished_at)}</dd>
        </div>
      </dl>

      {scan.rule_errors.length > 0 && (
        <div role="status" className="mb-4 flex items-start gap-2 rounded-lg border p-3 text-sm">
          <TriangleAlert className="mt-0.5 size-4 shrink-0 text-sev-high-fg" aria-hidden />
          <div>
            <p className="font-medium">
              {plural(scan.rule_errors.length, "regla falló", "reglas fallaron")} durante el análisis; sus resultados pueden estar incompletos.
            </p>
            <ul className="mt-1 text-muted-foreground">
              {scan.rule_errors.slice(0, 5).map((e, i) => (
                <li key={i} className="font-mono">
                  {e.rule_id} {e.path ? `en ${e.path}` : ""}: {e.error ?? e.message}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <div className="mb-3 flex flex-wrap items-end gap-2" role="search">
        <div className="relative min-w-56 flex-1 md:max-w-xs">
          <Search className="pointer-events-none absolute left-2.5 top-2 size-4 text-muted-foreground" aria-hidden />
          <Input
            ref={searchRef}
            value={f.q}
            onChange={(e) => setFilter("q", e.target.value)}
            placeholder="Buscar ruta o mensaje"
            aria-label="Buscar por ruta o mensaje (atajo: /)"
            className="pl-8"
          />
        </div>
        <NativeSelect aria-label="Severidad" value={f.severity} onChange={(e) => setFilter("severidad", e.target.value)} className="w-auto max-w-full">
          <option value="">Toda severidad</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>
              {SEVERITY_LABEL[s]}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect aria-label="Regla" value={f.rule} onChange={(e) => setFilter("regla", e.target.value)} className="w-auto max-w-full">
          <option value="">Todas las reglas</option>
          {ruleIds.map((r) => (
            <option key={r} value={r}>
              {r}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect aria-label="Cambio respecto al escaneo anterior" value={f.change} onChange={(e) => setFilter("cambio", e.target.value)} className="w-auto max-w-full">
          <option value="">Todo cambio</option>
          {CHANGES.map((c) => (
            <option key={c} value={c}>
              {CHANGE_LABEL[c]}
            </option>
          ))}
        </NativeSelect>
        <NativeSelect aria-label="Revisión" value={f.triage} onChange={(e) => setFilter("revision", e.target.value)} className="w-auto max-w-full">
          <option value="">Toda revisión</option>
          {TRIAGES.map((t) => (
            <option key={t} value={t}>
              {TRIAGE_LABEL[t]}
            </option>
          ))}
        </NativeSelect>
        {anyFilter && (
          <Button variant="ghost" onClick={() => setParams(new URLSearchParams(), { replace: true })}>
            Quitar filtros
          </Button>
        )}
      </div>

      {error && <ErrorState error={error} onRetry={reload} />}
      {!items && !error && <TableSkeleton cols={5} rows={8} />}
      {items && items.length === 0 && (
        <EmptyState icon={FileSearch} title="Este escaneo no encontró problemas">
          Ninguna de las reglas aplicadas detectó nada. Eso no garantiza que el código sea seguro: revisa el catálogo para ver qué
          se comprueba y qué no.
        </EmptyState>
      )}
      {items && items.length > 0 && (
        <>
          <p className="mb-2 text-sm text-muted-foreground" aria-live="polite">
            {filtered.length === items.length
              ? plural(items.length, "hallazgo", "hallazgos")
              : `${numberFmt.format(filtered.length)} de ${plural(items.length, "hallazgo", "hallazgos")}`}
            {truncated && " (se muestran los primeros 10 000)"}
            {/* Los atajos no sirven sin teclado: se ocultan en pantallas táctiles y estrechas. */}
            <span className="max-md:hidden [@media(pointer:coarse)]:hidden">
              {" "}
              · <kbd>j</kbd>/<kbd>k</kbd> para moverte, <kbd>Enter</kbd> para abrir, <kbd>/</kbd> para buscar
            </span>
          </p>
          {filtered.length === 0 ? (
            <EmptyState title="Ningún hallazgo coincide con los filtros" action={<Button variant="outline" onClick={() => setParams(new URLSearchParams(), { replace: true })}>Quitar filtros</Button>} />
          ) : (
            <FindingsTable items={filtered} active={active} onActiveChange={setActive} onOpen={setOpen} />
          )}
        </>
      )}

      <FindingSheet finding={open} onClose={() => setOpen(null)} />
    </>
  );
}

export default function ScanPage() {
  const { scanId = "" } = useParams();
  const scan = useApi<Scan>(`/scans/${scanId}`, { pollMs: 1500, poll: (d) => ACTIVE(d as Scan) });
  const project = useApi<Project>(scan.data ? `/projects/${scan.data.project_id}` : null);
  const [dlError, setDlError] = useState<ApiError | null>(null);

  if (scan.error) return <ErrorState error={scan.error} onRetry={scan.reload} />;
  const s = scan.data;
  const crumbs = [
    { label: "Proyectos", to: "/proyectos" },
    ...(s ? [{ label: project.data?.name ?? "…", to: `/proyectos/${s.project_id}` }] : []),
  ];

  async function download(format: "sarif" | "json" | "html") {
    setDlError(null);
    try {
      await downloadReport(scanId, format);
    } catch (err) {
      setDlError(err as ApiError);
    }
  }

  return (
    <>
      <PageHeader
        title={s ? `Escaneo del ${formatDate(s.queued_at)}` : "Escaneo"}
        crumbs={crumbs}
        description={
          s && (
            <>
              {SOURCE_LABEL[s.source]}
              {s.source_ref && <span className="font-mono"> · {s.source_ref}</span>}
              {s.commit_sha && <span className="font-mono"> · {s.commit_sha.slice(0, 10)}</span>}
            </>
          )
        }
        actions={
          s?.status === "done" && (
            <>
              {s.baseline_scan_id && (
                <Button asChild variant="outline">
                  <Link to={`/escaneos/${s.id}/comparar`}>
                    <ArrowLeftRight aria-hidden /> Comparar con el anterior
                  </Link>
                </Button>
              )}
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline">
                    <Download aria-hidden /> Descargar informe
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => download("sarif")}>SARIF 2.1.0 (GitHub, DefectDojo)</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => download("json")}>JSON</DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => download("html")}>HTML para imprimir</DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          )
        }
      />
      {dlError && <ErrorState error={dlError} className="mb-4" />}
      {!s && <BlockSkeleton />}
      {s && ACTIVE(s) && <ScanRun scan={s} onChanged={scan.reload} />}
      {s && (s.status === "failed" || s.status === "canceled") && (
        <div className="grid max-w-xl gap-3">
          <ScanStatusText status={s.status} className="font-medium" />
          <p>{s.status === "canceled" ? "El escaneo se canceló antes de terminar." : scanErrorText(s.error_code)}</p>
          <div>
            <Button asChild variant="outline">
              <Link to={`/proyectos/${s.project_id}/nuevo-escaneo`}>Lanzar otro escaneo</Link>
            </Button>
          </div>
        </div>
      )}
      {s?.status === "done" && <ScanResults scan={s} />}
    </>
  );
}
