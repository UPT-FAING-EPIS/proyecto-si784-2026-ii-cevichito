import { CheckCircle2, Circle, CircleDot, Trophy } from "lucide-react";
import { Link } from "react-router-dom";
import type { ChallengeProgress, ChallengeSummary } from "@/api/types";
import { useApi } from "@/api/useApi";
import { PageHeader } from "@/components/PageHeader";
import { ErrorState, TableSkeleton } from "@/components/States";
import { cn } from "@/lib/utils";

const PROGRESS_LABEL: Record<ChallengeProgress, string> = {
  sin_empezar: "Sin empezar",
  en_curso: "En curso",
  superado: "Superado",
};

function ProgressIcon({ state }: { state: ChallengeProgress }) {
  const Icon = state === "superado" ? CheckCircle2 : state === "en_curso" ? CircleDot : Circle;
  return <Icon className={cn("size-4 shrink-0", state === "superado" ? "text-primary" : "text-muted-foreground")} aria-hidden />;
}

export default function Challenges() {
  const { data, error, loading, reload } = useApi<ChallengeSummary[]>("/challenges");
  const solved = (data ?? []).filter((c) => c.state === "superado").length;

  return (
    <>
      <PageHeader
        title="Retos de corrección"
        description="Cada reto trae código con una vulnerabilidad real. Corrígelo en el editor y SAST Studio comprueba si el fallo desapareció sin que aparezcan otros."
      />
      {loading && <TableSkeleton rows={4} cols={2} />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <div className="grid gap-4">
          <p className="flex items-center gap-2 text-sm text-muted-foreground" aria-live="polite">
            <Trophy className="size-4" aria-hidden />
            {`Superados ${solved} de ${data.length}`}
          </p>
          <ul className="grid gap-3 md:grid-cols-2" aria-label="Retos">
            {data.map((c) => (
              <li key={c.id}>
                <Link
                  to={`/retos/${c.id}`}
                  className="grid h-full gap-2 rounded-lg border bg-surface p-4 transition-colors hover:bg-muted focus-visible:outline focus-visible:outline-2 focus-visible:outline-ring"
                >
                  <span className="flex items-start gap-2">
                    <ProgressIcon state={c.state} />
                    <span className="font-medium leading-tight">
                      {c.order}. {c.title}
                    </span>
                  </span>
                  <span className="text-sm text-muted-foreground">{c.summary}</span>
                  <span className="mt-auto flex flex-wrap gap-x-3 gap-y-1 text-xs text-muted-foreground">
                    <span>Nivel {c.level}</span>
                    <span>{c.cwe}</span>
                    <span className={cn(c.state === "superado" && "font-medium text-primary")}>{PROGRESS_LABEL[c.state]}</span>
                  </span>
                </Link>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}
