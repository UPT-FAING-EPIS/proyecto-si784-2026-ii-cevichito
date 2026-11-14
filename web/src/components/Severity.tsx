import { Circle, Diamond, Info, Octagon, Triangle } from "lucide-react";
import { SEVERITIES, type Severity, type SeverityCounts } from "@/api/types";
import { SEVERITY_LABEL, numberFmt } from "@/lib/format";
import { cn } from "@/lib/utils";

const ICON = { critical: Octagon, high: Triangle, medium: Diamond, low: Circle, info: Info } as const;

const CHIP: Record<Severity, string> = {
  critical: "bg-sev-critical-bg text-sev-critical-fg",
  high: "bg-sev-high-bg text-sev-high-fg",
  medium: "bg-sev-medium-bg text-sev-medium-fg",
  low: "bg-sev-low-bg text-sev-low-fg",
  info: "bg-sev-info-bg text-sev-info-fg",
};

const BAR: Record<Severity, string> = {
  critical: "bg-sev-critical-bar",
  high: "bg-sev-high-bar",
  medium: "bg-sev-medium-bar",
  low: "bg-sev-low-bar",
  info: "bg-sev-info-bar",
};

/** Chip de severidad: icono con forma propia + texto. El color nunca va solo. */
export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const Icon = ICON[severity];
  return (
    <span
      className={cn(
        "inline-flex h-5 items-center gap-1 whitespace-nowrap rounded-sm px-1.5 text-xs font-medium",
        CHIP[severity],
        className,
      )}
    >
      <Icon className="size-3 fill-current" aria-hidden />
      {SEVERITY_LABEL[severity]}
    </span>
  );
}

/** Barra apilada fina de abiertos por severidad, con el desglose en texto para lectores de pantalla. */
export function SeverityBar({ counts, className }: { counts: SeverityCounts | undefined; className?: string }) {
  const total = SEVERITIES.reduce((n, s) => n + (counts?.[s] ?? 0), 0);
  const description =
    total === 0
      ? "Sin hallazgos abiertos"
      : SEVERITIES.filter((s) => counts?.[s])
          .map((s) => `${numberFmt.format(counts![s]!)} ${SEVERITY_LABEL[s].toLowerCase()}`)
          .join(", ");
  return (
    <div className={cn("flex min-w-32 items-center gap-2", className)}>
      <div className="flex h-1.5 w-28 overflow-hidden rounded-full bg-muted" aria-hidden>
        {total > 0 &&
          SEVERITIES.map((s) =>
            counts?.[s] ? (
              // ancho calculado: única excepción a "sin estilos en línea" (DESIGN.md §9)
              <div key={s} className={BAR[s]} style={{ width: `${(counts[s]! / total) * 100}%` }} />
            ) : null,
          )}
      </div>
      <span className="tabular text-sm text-muted-foreground">
        <span className="sr-only">{description}. Total: </span>
        {numberFmt.format(total)}
      </span>
    </div>
  );
}

export function SeverityCountsInline({ counts }: { counts: SeverityCounts | undefined }) {
  const present = SEVERITIES.filter((s) => counts?.[s]);
  if (present.length === 0) return <span className="text-sm text-muted-foreground">Sin hallazgos</span>;
  return (
    <span className="flex flex-wrap items-center gap-1.5">
      {present.map((s) => {
        const Icon = ICON[s];
        return (
          <span key={s} className={cn("inline-flex h-5 items-center gap-1 rounded-sm px-1.5 text-xs font-medium", CHIP[s])}>
            <Icon className="size-3 fill-current" aria-hidden />
            <span className="tabular">{numberFmt.format(counts![s]!)}</span>
            <span className="sr-only">{SEVERITY_LABEL[s]}</span>
          </span>
        );
      })}
    </span>
  );
}
