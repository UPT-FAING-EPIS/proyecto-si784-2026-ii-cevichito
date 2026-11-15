import { AlertTriangle, CheckCircle2, Lightbulb, Loader2, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import { lazy, Suspense, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type ApiError } from "@/api/client";
import type { AttemptState, ChallengeAttempt, ChallengeDetail, Finding } from "@/api/types";
import { useApi } from "@/api/useApi";
import { InlineCode } from "@/components/InlineCode";
import { RuleLesson } from "@/components/Lesson";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { BlockSkeleton, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { readDraft, writeDraft } from "@/lib/drafts";
import { cn } from "@/lib/utils";

const CodeEditor = lazy(() => import("@/components/CodeEditor").then((m) => ({ default: m.CodeEditor })));

const RUNNING: AttemptState[] = ["analizando"];

function FindingLine({ f }: { f: Finding }) {
  return (
    <li className="flex flex-wrap items-baseline gap-2 text-sm">
      <SeverityBadge severity={f.severity} />
      <span className="font-mono text-muted-foreground">línea {f.start_line}</span>
      <span>
        <InlineCode text={f.message} />
      </span>
      <Link to={`/issues/${f.issue_id}`} className="underline hover:no-underline">
        Ver explicación
      </Link>
    </li>
  );
}

function Verdict({ attempt }: { attempt: ChallengeAttempt }) {
  const box = (tone: "ok" | "bad" | "info", icon: ReactNode, title: string, body: ReactNode) => (
    <section
      aria-live="polite"
      className={cn(
        "grid gap-2 rounded-lg border p-4",
        tone === "ok" && "border-primary",
        tone === "bad" && "border-sev-high-bar bg-sev-high-bg",
      )}
    >
      <h2 className="flex items-center gap-2 font-semibold">
        {icon}
        {title}
      </h2>
      {body}
    </section>
  );

  switch (attempt.state) {
    case "sin_empezar":
      return null;
    case "analizando":
      return box("info", <Loader2 className="size-4 animate-spin" aria-hidden />, "Comprobando tu corrección…",
        <p className="text-sm text-muted-foreground">El código está en la cola de análisis. Suele tardar unos segundos.</p>);
    case "error":
      return box("bad", <AlertTriangle className="size-4" aria-hidden />, "No se pudo comprobar",
        <p className="text-sm">El análisis falló o se canceló. Vuelve a pulsar «Comprobar».</p>);
    case "sigue":
      return box("bad", <XCircle className="size-4" aria-hidden />, "La vulnerabilidad sigue presente", (
        <>
          <p className="text-sm">El analizador todavía la encuentra aquí:</p>
          <ul className="grid gap-1">{attempt.remaining.map((f) => <FindingLine key={f.occurrence_id} f={f} />)}</ul>
        </>
      ));
    case "silenciado":
      return box("bad", <ShieldAlert className="size-4" aria-hidden />, "Silenciar no es corregir", (
        <>
          <p className="text-sm">
            Marcaste el hallazgo con un comentario de supresión, pero el código sigue siendo vulnerable. Quita la supresión y
            corrige la causa.
          </p>
          <ul className="grid gap-1">{attempt.silenced.map((f) => <FindingLine key={f.occurrence_id} f={f} />)}</ul>
        </>
      ));
    case "nuevo_fallo":
      return box("bad", <AlertTriangle className="size-4" aria-hidden />, "Corregiste el fallo, pero apareció otro", (
        <>
          <p className="text-sm">Tu cambio introdujo un hallazgo grave que el código original no tenía:</p>
          <ul className="grid gap-1">{attempt.new.map((f) => <FindingLine key={f.occurrence_id} f={f} />)}</ul>
        </>
      ));
    case "superado":
      return box("ok", <CheckCircle2 className="size-4 text-primary" aria-hidden />, "¡Reto superado!", (
        <p className="text-sm">
          El analizador ya no encuentra la vulnerabilidad y no apareció ningún fallo grave nuevo. Ojo: esto confirma que el
          patrón inseguro desapareció, no que el programa siga funcionando igual; pruébalo también.{" "}
          <Link to="/retos" className="underline hover:no-underline">
            Ir a otro reto
          </Link>
        </p>
      ));
  }
}

export default function ChallengePage() {
  const { challengeId = "" } = useParams();
  const detail = useApi<ChallengeDetail>(`/challenges/${challengeId}`);
  if (detail.loading) return <BlockSkeleton className="h-96" />;
  if (detail.error) return <ErrorState error={detail.error} onRetry={detail.reload} />;
  if (!detail.data) return null;
  return <Workspace key={detail.data.id} ch={detail.data} />;
}

function Workspace({ ch }: { ch: ChallengeDetail }) {
  const [code, setCode] = useState(() => readDraft(ch.id) ?? ch.starter);
  const [hints, setHints] = useState(0);
  const [sending, setSending] = useState(false);
  const [sendError, setSendError] = useState<ApiError | null>(null);
  // Cada envío cambia la clave y vuelve a consultar el veredicto hasta que el análisis termina.
  const [pollKey, setPollKey] = useState(RUNNING.includes(ch.attempt.state) ? 1 : 0);
  const poll = useApi<ChallengeAttempt>(pollKey ? `/challenges/${ch.id}/attempt` : null, {
    query: { envio: pollKey },
    pollMs: 1000,
    poll: (d) => RUNNING.includes((d as ChallengeAttempt).state),
  });
  const latest = poll.data ?? ch.attempt;
  const attempt: ChallengeAttempt = sending || poll.loading ? { ...latest, state: "analizando" } : latest;

  const change = (v: string) => {
    setCode(v);
    writeDraft(ch.id, v === ch.starter ? null : v);
  };
  const reset = () => {
    setCode(ch.starter);
    writeDraft(ch.id, null);
  };
  const check = async () => {
    setSending(true);
    setSendError(null);
    try {
      await api.post(`/challenges/${ch.id}/submissions`, { code });
      setPollKey((k) => k + 1);
    } catch (err) {
      setSendError(err as ApiError);
    } finally {
      setSending(false);
    }
  };
  const busy = attempt.state === "analizando";

  return (
    <>
      <PageHeader
        title={ch.title}
        crumbs={[{ label: "Retos", to: "/retos" }, { label: `Reto ${ch.order}` }]}
        description={`Nivel ${ch.level} · ${ch.cwe}${attempt.submissions > 0 ? ` · ${attempt.submissions} ${attempt.submissions === 1 ? "envío" : "envíos"}` : ""}`}
      />
      <div className="grid items-start gap-6 lg:grid-cols-[minmax(0,1fr)_380px]">
        <div className="grid min-w-0 gap-4">
          <section aria-labelledby="enunciado" className="grid gap-2">
            <h2 id="enunciado" className="font-semibold">
              Qué tienes que hacer
            </h2>
            <p className="max-w-prose">
              <InlineCode text={ch.statement} />
            </p>
            <p className="text-sm text-muted-foreground">
              Mantén {ch.keep.length === 1 ? "la función" : "las funciones"}{" "}
              {ch.keep.map((k, i) => (
                <span key={k}>
                  {i > 0 && ", "}
                  <code className="font-mono">{k}</code>
                </span>
              ))}
              : borrar el código no cuenta como corregirlo.
            </p>
          </section>

          <section aria-labelledby="editor-titulo" className="grid gap-2">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <h2 id="editor-titulo" className="font-mono text-sm">
                {ch.filename}
              </h2>
              <Button variant="ghost" size="sm" onClick={reset} disabled={busy || code === ch.starter}>
                <RotateCcw className="size-4" aria-hidden />
                Reiniciar código
              </Button>
            </div>
            <Suspense fallback={<BlockSkeleton className="h-[420px]" />}>
              <CodeEditor value={code} onChange={change} python labelledBy="editor-titulo" height="420px" placeholder="" />
            </Suspense>
            <div className="flex flex-wrap items-center gap-3">
              <Button onClick={check} disabled={busy || !code.trim()}>
                {busy && <Loader2 className="size-4 animate-spin" aria-hidden />}
                Comprobar
              </Button>
              <span className="text-sm text-muted-foreground">Tu borrador se guarda en este navegador.</span>
            </div>
            {sendError && <ErrorState error={sendError} />}
          </section>

          <Verdict attempt={attempt} />
        </div>

        <aside className="grid gap-4 lg:sticky lg:top-5">
          <section aria-labelledby="pistas" className="grid gap-2 rounded-lg border p-4">
            <h2 id="pistas" className="flex items-center gap-2 font-semibold">
              <Lightbulb className="size-4" aria-hidden />
              Pistas
            </h2>
            {hints === 0 && <p className="text-sm text-muted-foreground">Inténtalo primero sin ayuda.</p>}
            <ol className="grid list-decimal gap-2 pl-5 text-sm">
              {ch.hints.slice(0, hints).map((h, i) => (
                <li key={i}>
                  <InlineCode text={h} />
                </li>
              ))}
            </ol>
            {hints < ch.hints.length && (
              <Button variant="outline" size="sm" className="justify-self-start" onClick={() => setHints((n) => n + 1)}>
                {hints === 0 ? "Ver una pista" : "Ver otra pista"} ({hints}/{ch.hints.length})
              </Button>
            )}
          </section>
          {ch.rule_details.map((r) => (
            <details key={r.id} className="rounded-lg border">
              <summary className="cursor-pointer select-none px-4 py-3 font-semibold">Aprende sobre: {r.name}</summary>
              <div className="border-t p-4">
                <RuleLesson rule={r} compact />
              </div>
            </details>
          ))}
        </aside>
      </div>
    </>
  );
}
