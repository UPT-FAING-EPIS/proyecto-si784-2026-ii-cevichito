import { cn } from "@/lib/utils";

/** Bloque de carga estático (sin pulso: el movimiento se reserva para lo funcional). */
export function Skeleton({ className }: { className?: string }) {
  return <div aria-hidden className={cn("rounded bg-muted", className)} />;
}
