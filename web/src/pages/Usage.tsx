import { BarChart3 } from "lucide-react";
import { useSearchParams } from "react-router-dom";
import type { Usage as UsageData } from "@/api/types";
import { useApi } from "@/api/useApi";
import { DailyUsage } from "@/components/Charts";
import { PageHeader } from "@/components/PageHeader";
import { BlockSkeleton, EmptyState, ErrorState } from "@/components/States";
import { NativeSelect } from "@/components/ui/input";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { STATUS_LABEL, SOURCE_LABEL, numberFmt } from "@/lib/format";

const PERIODOS = [7, 30, 90, 365];
const FUENTE: Record<string, string> = { ...SOURCE_LABEL, reto: "Reto" };

function Stat({ label, value, hint }: { label: string; value: string; hint?: string }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="text-lg font-medium tabular">{value}</dd>
      {hint && <dd className="text-sm text-muted-foreground">{hint}</dd>}
    </div>
  );
}

function segundos(s: number | null) {
  return s === null ? "—" : `${numberFmt.format(s)} s`;
}

function Desglose({ titulo, datos, etiquetas }: { titulo: string; datos: Record<string, number>; etiquetas: Record<string, string> }) {
  const filas = Object.entries(datos);
  return (
    <section aria-labelledby={`t-${titulo}`}>
      <h2 id={`t-${titulo}`} className="mb-2 font-medium">{titulo}</h2>
      {filas.length === 0 ? (
        <p className="text-sm text-muted-foreground">Sin datos en este periodo.</p>
      ) : (
        <ul className="grid gap-1 text-sm">
          {filas.map(([k, n]) => (
            <li key={k} className="flex justify-between gap-4 border-b py-1 last:border-0">
              <span>{etiquetas[k] ?? k}</span>
              <span className="tabular">{numberFmt.format(n)}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}

export default function Usage() {
  const [params, setParams] = useSearchParams();
  const dias = Number(params.get("dias")) || 30;
  const { data, error, loading, reload } = useApi<UsageData>("/usage", { query: { days: dias } });

  return (
    <>
      <PageHeader
        title="Uso del producto"
        description="Cuánta gente usa SAST Studio y cómo: escaneos, hallazgos, correcciones y retos. Solo lo ven los administradores."
        actions={
          <NativeSelect
            aria-label="Periodo"
            value={dias}
            onChange={(e) => setParams({ dias: e.target.value })}
            className="w-40"
          >
            {PERIODOS.map((d) => (
              <option key={d} value={d}>
                Últimos {d} días
              </option>
            ))}
          </NativeSelect>
        }
      />
      {loading && !data && <BlockSkeleton className="h-72" />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.totals.scans === 0 && data.totals.active_users === 0 && (
        <EmptyState icon={BarChart3} title="Todavía no hay actividad en este periodo" />
      )}
      {data && (data.totals.scans > 0 || data.totals.active_users > 0) && (
        <div className="grid gap-8">
          <dl className="grid grid-cols-2 gap-x-8 gap-y-4 border-b pb-6 md:grid-cols-4">
            <Stat label="Usuarios activos" value={numberFmt.format(data.totals.active_users)}
              hint={`${numberFmt.format(data.totals.new_users)} nuevos · ${numberFmt.format(data.totals.users)} en total`} />
            <Stat label="Escaneos" value={numberFmt.format(data.totals.scans)}
              hint={data.totals.failure_rate === null ? undefined : `${numberFmt.format(data.totals.failure_rate * 100)} % fallidos`} />
            <Stat label="Hallazgos encontrados" value={numberFmt.format(data.totals.findings)}
              hint={`${numberFmt.format(data.totals.issues_fixed)} corregidos`} />
            <Stat label="Retos superados" value={numberFmt.format(data.totals.challenges_solved)}
              hint={`de ${numberFmt.format(data.totals.challenge_attempts)} intentos`} />
            <Stat label="Tiempo de escaneo (mediana)" value={segundos(data.totals.scan_seconds_median)}
              hint={`p95: ${segundos(data.totals.scan_seconds_p95)}`} />
            <Stat label="Proyectos" value={numberFmt.format(data.totals.projects)} />
          </dl>

          <section aria-labelledby="t-diario">
            <h2 id="t-diario" className="mb-2 font-medium">Actividad por día</h2>
            <DailyUsage data={data.daily} />
          </section>

          <div className="grid gap-8 md:grid-cols-2">
            <Desglose titulo="Escaneos por estado" datos={data.by_status} etiquetas={STATUS_LABEL} />
            <Desglose titulo="Escaneos por origen" datos={data.by_source} etiquetas={FUENTE} />
          </div>

          <div className="grid gap-8 md:grid-cols-2">
            <section aria-labelledby="t-reglas">
              <h2 id="t-reglas" className="mb-2 font-medium">Reglas que más saltan</h2>
              {data.top_rules.length === 0 ? (
                <p className="text-sm text-muted-foreground">Sin hallazgos en este periodo.</p>
              ) : (
                <Table>
                  <THead>
                    <TR><TH>Regla</TH><TH className="text-right">Hallazgos</TH></TR>
                  </THead>
                  <TBody>
                    {data.top_rules.map((r) => (
                      <TR key={r.rule_id}><TD className="font-mono text-sm">{r.rule_id}</TD><TD className="text-right tabular">{numberFmt.format(r.count)}</TD></TR>
                    ))}
                  </TBody>
                </Table>
              )}
            </section>
            <section aria-labelledby="t-retos">
              <h2 id="t-retos" className="mb-2 font-medium">Retos</h2>
              <Table>
                <THead>
                  <TR><TH>Reto</TH><TH className="text-right">Intentos</TH><TH className="text-right">Superados</TH></TR>
                </THead>
                <TBody>
                  {data.challenges.map((c) => (
                    <TR key={c.id}>
                      <TD>{c.title}</TD>
                      <TD className="text-right tabular">{numberFmt.format(c.attempts)}</TD>
                      <TD className="text-right tabular">{numberFmt.format(c.solved)}</TD>
                    </TR>
                  ))}
                </TBody>
              </Table>
            </section>
          </div>
        </div>
      )}
    </>
  );
}
