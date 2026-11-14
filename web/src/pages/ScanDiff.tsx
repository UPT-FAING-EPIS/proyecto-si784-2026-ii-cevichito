import { ChevronDown } from "lucide-react";
import { Link, useParams } from "react-router-dom";
import { SEVERITIES, type Finding, type Project, type Scan, type ScanDiff as Diff } from "@/api/types";
import { useApi } from "@/api/useApi";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { BlockSkeleton, EmptyState, ErrorState } from "@/components/States";
import { formatDate, numberFmt } from "@/lib/format";
import { InlineCode } from "@/components/InlineCode";

/** Lo más grave primero; a igual severidad, por archivo y línea. */
function bySeverity(a: Finding, b: Finding) {
  return (
    SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) ||
    a.path.localeCompare(b.path) ||
    a.start_line - b.start_line
  );
}

function Column({ title, items, hint, linkIssues = true }: { title: string; items: Finding[]; hint: string; linkIssues?: boolean }) {
  return (
    <details open className="group min-w-0 rounded-lg border">
      <summary className="flex cursor-pointer select-none items-center justify-between gap-2 border-b px-3 py-2 group-[:not([open])]:border-b-0">
        <span className="font-semibold">
          {title} <span className="tabular font-normal text-muted-foreground">({numberFmt.format(items.length)})</span>
        </span>
        <ChevronDown className="size-4 text-muted-foreground group-open:rotate-180" aria-hidden />
      </summary>
      {items.length === 0 ? (
        <p className="p-3 text-sm text-muted-foreground">{hint}</p>
      ) : (
        <ul className="divide-y">
          {[...items].sort(bySeverity).map((f) => (
            <li key={f.occurrence_id} className="grid gap-1 p-3 text-sm">
              <div className="flex items-center gap-2">
                <SeverityBadge severity={f.severity} />
                {linkIssues ? (
                  <Link to={`/issues/${f.issue_id}`} className="truncate font-mono hover:underline">
                    {f.rule_id}
                  </Link>
                ) : (
                  <span className="truncate font-mono">{f.rule_id}</span>
                )}
              </div>
              <span className="truncate font-mono text-muted-foreground" title={`${f.path}:${f.start_line}`}>
                {f.path}:{f.start_line}
              </span>
              <span className="line-clamp-2">
                <InlineCode text={f.message} />
              </span>
            </li>
          ))}
        </ul>
      )}
    </details>
  );
}

export default function ScanDiff() {
  const { scanId = "" } = useParams();
  const scan = useApi<Scan>(`/scans/${scanId}`);
  const diff = useApi<Diff>(`/scans/${scanId}/diff`);
  const project = useApi<Project>(scan.data ? `/projects/${scan.data.project_id}` : null);

  const error = scan.error ?? diff.error;
  if (error) return <ErrorState error={error} onRetry={() => (scan.reload(), diff.reload())} />;

  return (
    <>
      <PageHeader
        title="Cambios respecto al escaneo anterior"
        crumbs={[
          { label: "Proyectos", to: "/proyectos" },
          ...(scan.data ? [{ label: project.data?.name ?? "…", to: `/proyectos/${scan.data.project_id}` }] : []),
          { label: scan.data ? `Escaneo del ${formatDate(scan.data.queued_at)}` : "Escaneo", to: `/escaneos/${scanId}` },
        ]}
        description={
          diff.data?.base_scan_id && (
            <>
              Comparado con el <Link to={`/escaneos/${diff.data.base_scan_id}`} className="underline">escaneo anterior</Link>.{" "}
              {numberFmt.format(diff.data.persisting_count)} hallazgos siguen igual.
            </>
          )
        }
      />
      {!diff.data && <BlockSkeleton />}
      {diff.data && !diff.data.base_scan_id && (
        <EmptyState title="No hay un escaneo anterior con el que comparar">
          La comparación aparece desde el segundo escaneo del mismo proyecto y origen.
        </EmptyState>
      )}
      {diff.data?.base_scan_id && (
        <div className="grid items-start gap-4 lg:grid-cols-3">
          <Column title="Nuevos" items={diff.data.new} hint="No apareció nada nuevo." />
          <Column title="Corregidos" items={diff.data.fixed} hint="No se corrigió ningún hallazgo." />
          <Column title="Reabiertos" items={diff.data.reopened} hint="Ningún hallazgo corregido volvió a aparecer." />
        </div>
      )}
    </>
  );
}
