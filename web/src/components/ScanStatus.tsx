import { CheckCircle2, CircleDashed, CircleSlash, Loader2, XCircle } from "lucide-react";
import type { ScanStatus } from "@/api/types";
import { STATUS_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";

const ICON = { queued: CircleDashed, running: Loader2, done: CheckCircle2, failed: XCircle, canceled: CircleSlash } as const;

export function ScanStatusText({ status, className }: { status: ScanStatus; className?: string }) {
  const Icon = ICON[status];
  return (
    <span className={cn("inline-flex items-center gap-1.5", status === "failed" && "text-destructive", className)}>
      <Icon className={cn("size-4", status === "running" && "motion-safe:animate-spin")} aria-hidden />
      {STATUS_LABEL[status]}
    </span>
  );
}
