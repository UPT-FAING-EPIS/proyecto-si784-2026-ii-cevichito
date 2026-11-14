import { useVirtualizer } from "@tanstack/react-virtual";
import { useEffect, useRef } from "react";
import type { Finding } from "@/api/types";
import { SeverityBadge } from "@/components/Severity";
import { CHANGE_LABEL, TRIAGE_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";
import { InlineCode } from "@/components/InlineCode";

const ROW = 36;
const VIRTUAL_FROM = 200; // DESIGN.md: virtualización a partir de 200 filas
const COLS = "grid grid-cols-[96px_minmax(140px,1fr)_minmax(160px,1.4fr)_minmax(200px,2fr)_88px_120px] items-center gap-x-3";
// En móvil cada fila es una tarjeta de tres líneas en vez de una tabla con scroll lateral.
const CARD =
  "max-md:grid-cols-[auto_minmax(0,1fr)_auto] max-md:gap-y-1 max-md:py-2.5 max-md:[grid-template-areas:'sev_loc_chg'_'msg_msg_msg'_'rule_rule_tri']";
const ROW_MOBILE = 92;

function Row({ f, active, onOpen, onFocusRow }: { f: Finding; active: boolean; onOpen: () => void; onFocusRow: () => void }) {
  return (
    <div
      role="row"
      aria-selected={active}
      tabIndex={active ? 0 : -1}
      data-row
      onClick={onOpen}
      onFocus={onFocusRow}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpen();
        }
      }}
      className={cn(COLS, CARD, "md:h-9 cursor-pointer border-b px-3 text-sm hover:bg-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring", active && "bg-muted", f.suppressed && "text-muted-foreground")}
    >
      <span role="gridcell" className="max-md:[grid-area:sev]">
        <SeverityBadge severity={f.severity} />
      </span>
      <span role="gridcell" className="truncate font-mono max-md:text-xs max-md:text-muted-foreground max-md:[grid-area:rule]" title={f.rule_id}>
        {f.rule_id}
      </span>
      <span role="gridcell" className="flex min-w-0 font-mono max-md:[grid-area:loc]" title={`${f.path}:${f.start_line}`}>
        {/* Si no cabe, se recorta la carpeta; el archivo y la línea se ven siempre. */}
        {f.path.includes("/") && (
          <span className="truncate text-muted-foreground">{f.path.slice(0, f.path.lastIndexOf("/") + 1)}</span>
        )}
        <span className="shrink-0">
          {f.path.slice(f.path.lastIndexOf("/") + 1)}:{f.start_line}
        </span>
      </span>
      <span role="gridcell" className="truncate max-md:line-clamp-2 max-md:whitespace-normal max-md:[grid-area:msg]" title={f.message}>
        <InlineCode text={f.message} />
        {f.suppressed && " (suprimido)"}
      </span>
      <span role="gridcell" className="max-md:text-xs max-md:[grid-area:chg]">
        {f.change ? CHANGE_LABEL[f.change] : "—"}
      </span>
      <span role="gridcell" className="truncate max-md:text-right max-md:text-xs max-md:text-muted-foreground max-md:[grid-area:tri]">
        {TRIAGE_LABEL[f.triage]}
      </span>
    </div>
  );
}

/**
 * Tabla de hallazgos con cabecera fija, navegación j/k y virtualización desde 200 filas.
 * `active` es el índice seleccionado; Enter abre el detalle.
 */
export function FindingsTable({
  items,
  active,
  onActiveChange,
  onOpen,
}: {
  items: Finding[];
  active: number;
  onActiveChange: (i: number) => void;
  onOpen: (f: Finding) => void;
}) {
  const scrollRef = useRef<HTMLDivElement>(null);
  const virtual = items.length >= VIRTUAL_FROM;
  const rv = useVirtualizer({
    count: items.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => (window.matchMedia("(max-width: 767px)").matches ? ROW_MOBILE : ROW),
    overscan: 12,
    enabled: virtual,
  });

  useEffect(() => {
    if (active < 0) return;
    if (virtual) rv.scrollToIndex(active, { align: "auto" });
    const el = scrollRef.current?.querySelector<HTMLElement>('[data-row][aria-selected="true"]');
    if (el && scrollRef.current?.contains(document.activeElement)) el.focus({ preventScroll: !virtual ? false : true });
  }, [active, virtual, rv]);

  const header = (
    <div role="row" className={cn(COLS, "sticky top-0 max-md:hidden z-10 h-8 border-b bg-muted px-3 text-xs font-medium text-muted-foreground")}>
      <span role="columnheader">Severidad</span>
      <span role="columnheader">Regla</span>
      <span role="columnheader">Ubicación</span>
      <span role="columnheader">Mensaje</span>
      <span role="columnheader">Cambio</span>
      <span role="columnheader">Revisión</span>
    </div>
  );

  return (
    <div
      ref={scrollRef}
      role="grid"
      aria-label="Hallazgos"
      aria-rowcount={items.length + 1}
      className="max-h-[calc(100dvh-280px)] min-h-48 overflow-auto rounded-lg border"
    >
      <div className="md:min-w-[860px]">
        {header}
        {virtual ? (
          // altura total y desplazamiento los calcula el virtualizador (excepción documentada en DESIGN.md §9)
          <div className="relative" style={{ height: rv.getTotalSize() }}>
            {rv.getVirtualItems().map((v) => (
              <div key={v.key} ref={rv.measureElement} data-index={v.index} className="absolute inset-x-0" style={{ transform: `translateY(${v.start}px)` }}>
                <Row f={items[v.index]} active={v.index === active} onOpen={() => onOpen(items[v.index])} onFocusRow={() => onActiveChange(v.index)} />
              </div>
            ))}
          </div>
        ) : (
          items.map((f, i) => (
            <Row key={f.occurrence_id} f={f} active={i === active} onOpen={() => onOpen(f)} onFocusRow={() => onActiveChange(i)} />
          ))
        )}
      </div>
    </div>
  );
}
