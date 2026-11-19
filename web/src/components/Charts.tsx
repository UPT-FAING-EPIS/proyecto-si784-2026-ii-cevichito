import { Bar, BarChart, CartesianGrid, Legend, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { SEVERITIES, type Metrics, type Usage } from "@/api/types";
import { SEVERITY_LABEL, formatShortDate } from "@/lib/format";
import { useTokens } from "@/lib/useTokens";

const TOKENS = [
  "sev-critical-bar",
  "sev-high-bar",
  "sev-medium-bar",
  "sev-low-bar",
  "sev-info-bar",
  "foreground",
  "muted-foreground",
  "border",
  "surface",
  "input",
] as const;

function useChartTheme() {
  const t = useTokens(TOKENS);
  return {
    t,
    axis: { stroke: t.border, tick: { fill: t["muted-foreground"], fontSize: 12 }, tickLine: false },
    tooltip: {
      contentStyle: { background: t.surface, border: `1px solid ${t.border}`, borderRadius: 6, fontSize: 13, color: t.foreground },
      labelStyle: { color: t["muted-foreground"] },
      cursor: { fill: t.border, opacity: 0.4 },
    },
  };
}

function label(i: number, date: string | null) {
  return `#${i + 1} · ${formatShortDate(date)}`;
}

/** Hallazgos por severidad en cada escaneo terminado (barras apiladas). */
export function SeverityOverTime({ data }: { data: Metrics["open_by_severity"] }) {
  const { t, axis, tooltip } = useChartTheme();
  const rows = data.map((d, i) => ({ ...d, name: label(i, d.date) }));
  return (
    <figure>
      <figcaption className="sr-only">
        Hallazgos por severidad en los últimos {rows.length} escaneos. Los valores exactos están en la tabla de escaneos.
      </figcaption>
      <div className="h-56" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid vertical={false} stroke={t.border} />
            <XAxis dataKey="name" {...axis} />
            <YAxis allowDecimals={false} {...axis} />
            <Tooltip {...tooltip} />
            <Legend wrapperStyle={{ fontSize: 12, color: t["muted-foreground"] }} iconType="square" iconSize={10} />
            {SEVERITIES.map((s) => (
              <Bar key={s} dataKey={s} name={SEVERITY_LABEL[s]} stackId="sev" fill={t[`sev-${s}-bar`]} isAnimationActive={false} maxBarSize={36} />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </figure>
  );
}

/** Nuevos frente a corregidos por escaneo. */
export function NewVsFixed({ data }: { data: Metrics["new_vs_fixed"] }) {
  const { t, axis, tooltip } = useChartTheme();
  const rows = data.map((d, i) => ({ ...d, name: label(i, d.date) }));
  return (
    <figure>
      <figcaption className="sr-only">Hallazgos nuevos y corregidos en cada escaneo.</figcaption>
      <div className="h-56" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid vertical={false} stroke={t.border} />
            <XAxis dataKey="name" {...axis} />
            <YAxis allowDecimals={false} {...axis} />
            <Tooltip {...tooltip} />
            <Legend wrapperStyle={{ fontSize: 12, color: t["muted-foreground"] }} iconType="square" iconSize={10} />
            <Bar dataKey="new" name="Nuevos" fill={t["sev-high-bar"]} isAnimationActive={false} maxBarSize={24} />
            <Bar dataKey="fixed" name="Corregidos" fill={t.input} isAnimationActive={false} maxBarSize={24} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </figure>
  );
}

/** Escaneos y usuarios activos por día (dashboard de uso). */
export function DailyUsage({ data }: { data: Usage["daily"] }) {
  const { t, axis, tooltip } = useChartTheme();
  const rows = data.map((d) => ({ ...d, name: formatShortDate(`${d.date}T12:00:00Z`) })); // mediodía: evita el día anterior en UTC-5
  return (
    <figure>
      <figcaption className="sr-only">Escaneos y usuarios activos por día.</figcaption>
      <div className="h-56" aria-hidden>
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={rows} margin={{ top: 8, right: 8, bottom: 0, left: -16 }}>
            <CartesianGrid vertical={false} stroke={t.border} />
            <XAxis dataKey="name" {...axis} minTickGap={16} />
            <YAxis allowDecimals={false} {...axis} />
            <Tooltip {...tooltip} />
            <Legend wrapperStyle={{ fontSize: 12, color: t["muted-foreground"] }} iconType="square" iconSize={10} />
            <Bar dataKey="scans" name="Escaneos" fill={t["sev-info-bar"]} isAnimationActive={false} maxBarSize={18} />
            <Bar dataKey="active_users" name="Usuarios activos" fill={t.input} isAnimationActive={false} maxBarSize={18} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </figure>
  );
}
