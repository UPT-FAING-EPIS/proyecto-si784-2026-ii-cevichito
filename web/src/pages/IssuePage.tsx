import { useState, type FormEvent } from "react";
import { Link, useParams } from "react-router-dom";
import { api, type ApiError } from "@/api/client";
import { TRIAGES, type Issue, type IssueEvent, type Project, type Triage } from "@/api/types";
import { useApi } from "@/api/useApi";
import { CodeView, RuleLesson, TaintTrace } from "@/components/Lesson";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { BlockSkeleton, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { NativeSelect, Textarea } from "@/components/ui/input";
import { InlineCode } from "@/components/InlineCode";
import {
  LIFECYCLE_LABEL,
  TRIAGE_LABEL,
  TRIAGE_NEEDS_JUSTIFICATION,
  formatDate,
  formatRelative,
} from "@/lib/format";

const MAX_TEXT = 2000;

function eventText(e: IssueEvent) {
  const label = (v: string | null) => (v && v in TRIAGE_LABEL ? TRIAGE_LABEL[v as Triage] : v && v in LIFECYCLE_LABEL ? LIFECYCLE_LABEL[v as keyof typeof LIFECYCLE_LABEL] : v ?? "—");
  switch (e.kind) {
    case "triage":
      return `cambió la revisión de «${label(e.from)}» a «${label(e.to)}»`;
    case "comment":
      return "comentó";
    case "lifecycle":
      if (e.to === "fixed") return "dejó de aparecer (corregido)";
      if (e.to === "reopened") return "volvió a aparecer (reabierto)";
      if (e.from === "fixed") return "volvió a aparecer";
      return "apareció por primera vez";
    default:
      return e.to ? `${e.kind}: ${label(e.from)} → ${label(e.to)}` : e.kind;
  }
}

function TriageForm({ issue, onSaved }: { issue: Issue; onSaved: (i: Issue) => void }) {
  const [triage, setTriage] = useState<Triage>(issue.triage);
  const [text, setText] = useState(issue.triage_justification ?? "");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const needs = TRIAGE_NEEDS_JUSTIFICATION.includes(triage);
  const invalid = needs && !text.trim();

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (invalid) return;
    setBusy(true);
    setError(null);
    try {
      onSaved(await api.patch<Issue>(`/issues/${issue.id}`, { triage, justification: text.trim() || null }));
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="grid gap-3" aria-labelledby="triage-title">
      <h2 id="triage-title" className="font-semibold">
        Revisión
      </h2>
      <div className="grid gap-1.5">
        <Label htmlFor="triage">Estado</Label>
        <NativeSelect id="triage" value={triage} onChange={(e) => setTriage(e.target.value as Triage)}>
          {TRIAGES.map((t) => (
            <option key={t} value={t}>
              {TRIAGE_LABEL[t]}
            </option>
          ))}
        </NativeSelect>
      </div>
      <div className="grid gap-1.5">
        <Label htmlFor="justification">Justificación{needs ? " (obligatoria)" : " (opcional)"}</Label>
        <Textarea
          id="justification"
          value={text}
          maxLength={MAX_TEXT}
          onChange={(e) => setText(e.target.value)}
          aria-invalid={invalid || undefined}
          aria-describedby="justification-help"
          rows={4}
        />
        <p id="justification-help" className="text-sm text-muted-foreground">
          {needs
            ? "Explica por qué no es un problema o por qué se acepta el riesgo. Queda en el historial."
            : "Por ejemplo, qué cambio lo corrige."}{" "}
          <span className="tabular">
            {text.length}/{MAX_TEXT}
          </span>
        </p>
      </div>
      {error && <p className="text-sm text-destructive">{error.message}</p>}
      <div>
        <Button type="submit" disabled={busy || invalid || (triage === issue.triage && text === (issue.triage_justification ?? ""))}>
          {busy ? "Guardando…" : "Guardar revisión"}
        </Button>
      </div>
    </form>
  );
}

function CommentForm({ issueId, onSaved }: { issueId: string; onSaved: () => void }) {
  const [body, setBody] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.post(`/issues/${issueId}/comments`, { body: body.trim() });
      setBody("");
      onSaved();
    } catch (err) {
      setError(err as ApiError);
    }
  }
  return (
    <form onSubmit={submit} className="grid gap-2">
      <Label htmlFor="comment">Añadir comentario</Label>
      <Textarea id="comment" value={body} maxLength={MAX_TEXT} rows={3} onChange={(e) => setBody(e.target.value)} />
      {error && <p className="text-sm text-destructive">{error.message}</p>}
      <div>
        <Button type="submit" variant="outline" disabled={!body.trim()}>
          Comentar
        </Button>
      </div>
    </form>
  );
}

export default function IssuePage() {
  const { issueId = "" } = useParams();
  const issue = useApi<Issue>(`/issues/${issueId}`);
  const events = useApi<IssueEvent[]>(`/issues/${issueId}/events`);
  const project = useApi<Project>(issue.data ? `/projects/${issue.data.project_id}` : null);

  if (issue.error) return <ErrorState error={issue.error} onRetry={issue.reload} />;
  const i = issue.data;
  const occ = i?.last_occurrence;

  return (
    <>
      <PageHeader
        title={i?.rule?.name ?? i?.rule_id ?? "Hallazgo"}
        crumbs={[
          { label: "Proyectos", to: "/proyectos" },
          ...(i ? [{ label: project.data?.name ?? "…", to: `/proyectos/${i.project_id}` }] : []),
        ]}
        description={i && <InlineCode text={i.message} />}
      />
      {!i && <BlockSkeleton />}
      {i && (
        <div className="grid items-start gap-8 lg:grid-cols-[minmax(0,1fr)_320px]">
          <div className="grid min-w-0 gap-6">
            <dl className="flex flex-wrap gap-x-6 gap-y-2 text-sm">
              <div className="grid gap-0.5">
                <dt className="text-muted-foreground">Severidad</dt>
                <dd>
                  <SeverityBadge severity={i.severity} />
                </dd>
              </div>
              <div className="grid gap-0.5">
                <dt className="text-muted-foreground">Estado</dt>
                <dd className="font-medium">{LIFECYCLE_LABEL[i.lifecycle]}</dd>
              </div>
              <div className="grid gap-0.5">
                <dt className="text-muted-foreground">Ubicación actual</dt>
                <dd className="break-all font-mono">
                  {i.path}:{i.line}
                </dd>
              </div>
              <div className="grid gap-0.5">
                <dt className="text-muted-foreground">Primera vez</dt>
                <dd>
                  {i.first_seen_scan_id ? (
                    <Link to={`/escaneos/${i.first_seen_scan_id}`} className="underline">
                      {formatDate(i.first_seen_at)}
                    </Link>
                  ) : (
                    formatDate(i.first_seen_at)
                  )}
                </dd>
              </div>
              {i.fixed_at && (
                <div className="grid gap-0.5">
                  <dt className="text-muted-foreground">Corregido</dt>
                  <dd>{formatDate(i.fixed_at)}</dd>
                </div>
              )}
              {i.reopened_count > 0 && (
                <div className="grid gap-0.5">
                  <dt className="text-muted-foreground">Reabierto</dt>
                  <dd className="tabular">{i.reopened_count} veces</dd>
                </div>
              )}
            </dl>

            {occ?.snippet && (
              <CodeView code={occ.snippet} firstLine={occ.start_line} highlight={[occ.start_line]} label={`${occ.path} · última aparición`} />
            )}
            {occ && <TaintTrace steps={occ.trace} />}
            {i.rule && (
              <section aria-labelledby="leccion">
                <h2 id="leccion" className="mb-3 border-t pt-5 text-md font-semibold">
                  Qué significa y cómo corregirlo
                </h2>
                <RuleLesson rule={i.rule} />
              </section>
            )}
          </div>

          <aside className="grid gap-6 lg:sticky lg:top-5">
            <TriageForm issue={i} onSaved={(n) => (issue.setData(n), events.reload())} />
            <section className="grid gap-3 border-t pt-5" aria-labelledby="historial">
              <h2 id="historial" className="font-semibold">
                Historial
              </h2>
              {events.error && <ErrorState error={events.error} onRetry={events.reload} />}
              {events.data && events.data.length === 0 && <p className="text-sm text-muted-foreground">Sin eventos.</p>}
              {events.data && (
                <ol className="grid gap-3">
                  {events.data.map((e, idx) => (
                    <li key={idx} className="grid gap-0.5 text-sm">
                      <p>
                        <span className="font-medium">{e.user?.name ?? "El sistema"}</span> {eventText(e)}
                        {e.scan_id && (
                          <>
                            {" "}
                            en un{" "}
                            <Link to={`/escaneos/${e.scan_id}`} className="underline">
                              escaneo
                            </Link>
                          </>
                        )}
                      </p>
                      {e.comment && <p className="whitespace-pre-line rounded bg-muted px-2 py-1.5">{e.comment}</p>}
                      <time dateTime={e.created_at} title={formatDate(e.created_at)} className="text-muted-foreground">
                        {formatRelative(e.created_at)}
                      </time>
                    </li>
                  ))}
                </ol>
              )}
              <CommentForm issueId={i.id} onSaved={events.reload} />
            </section>
          </aside>
        </div>
      )}
    </>
  );
}
