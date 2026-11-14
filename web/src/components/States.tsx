import { AlertCircle, type LucideIcon } from "lucide-react";
import type { ReactNode } from "react";
import type { ApiError } from "@/api/client";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { cn } from "@/lib/utils";

export function ErrorState({ error, onRetry, className }: { error: ApiError | Error; onRetry?: () => void; className?: string }) {
  const requestId = "requestId" in error ? error.requestId : null;
  return (
    <div role="alert" className={cn("flex items-start gap-3 rounded-lg border p-4", className)}>
      <AlertCircle className="mt-0.5 size-4 shrink-0 text-destructive" aria-hidden />
      <div className="grid gap-1">
        <p className="font-medium">{error.message}</p>
        {requestId && (
          <p className="text-sm text-muted-foreground">
            Identificador de la petición: <code className="text-sm">{requestId}</code>
          </p>
        )}
        {onRetry && (
          <div className="pt-1">
            <Button variant="outline" size="sm" onClick={onRetry}>
              Reintentar
            </Button>
          </div>
        )}
      </div>
    </div>
  );
}

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
}: {
  icon?: LucideIcon;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-start gap-2 rounded-lg border border-dashed px-5 py-8">
      {Icon && <Icon className="size-5 text-muted-foreground" aria-hidden />}
      <p className="font-medium">{title}</p>
      {children && <div className="max-w-prose text-sm text-muted-foreground">{children}</div>}
      {action && <div className="pt-2">{action}</div>}
    </div>
  );
}

/** Esqueleto de tabla con la forma del contenido real. */
export function TableSkeleton({ rows = 6, cols = 4 }: { rows?: number; cols?: number }) {
  return (
    <div role="status" aria-label="Cargando" className="overflow-hidden rounded-lg border">
      <div className="h-8 bg-muted" />
      {Array.from({ length: rows }, (_, r) => (
        <div key={r} className="flex h-9 items-center gap-6 border-t px-3">
          {Array.from({ length: cols }, (_, c) => (
            <Skeleton key={c} className={cn("h-3", c === 0 ? "w-48" : "w-20")} />
          ))}
        </div>
      ))}
    </div>
  );
}

export function BlockSkeleton({ className }: { className?: string }) {
  return (
    <div role="status" aria-label="Cargando">
      <Skeleton className={cn("h-40 w-full", className)} />
    </div>
  );
}
