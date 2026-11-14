import { Check, ExternalLink, X } from "lucide-react";
import type { Rule, TraceStep } from "@/api/types";
import { CONFIDENCE_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";
import { InlineCode } from "@/components/InlineCode";

/** Código con número de línea; resalta las líneas indicadas. */
export function CodeView({
  code,
  firstLine = 1,
  highlight = [],
  label,
  className,
}: {
  code: string;
  firstLine?: number;
  highlight?: number[];
  label?: string;
  className?: string;
}) {
  const lines = code.replace(/\n$/, "").split("\n");
  return (
    <figure className={cn("overflow-hidden rounded border", className)}>
      {label && <figcaption className="border-b bg-muted px-3 py-1 text-xs text-muted-foreground">{label}</figcaption>}
      <pre className="overflow-x-auto bg-muted py-2 text-sm leading-6">
        <code>
          {lines.map((text, i) => {
            const n = firstLine + i;
            const hit = highlight.includes(n);
            return (
              <span key={i} className={cn("flex", hit && "bg-sev-high-bg")}>
                <span className="w-12 shrink-0 select-none pr-3 text-right text-muted-foreground" aria-hidden>
                  {n}
                </span>
                <span className="whitespace-pre pr-4">{text || " "}</span>
              </span>
            );
          })}
        </code>
      </pre>
    </figure>
  );
}

/** Traza de taint paso a paso: de la fuente al sumidero. */
export function TaintTrace({ steps }: { steps: TraceStep[] }) {
  if (steps.length === 0) return null;
  return (
    <section aria-labelledby="traza">
      <h3 id="traza" className="mb-2 font-semibold">
        Recorrido del dato
      </h3>
      <ol className="grid gap-0">
        {steps.map((s, i) => {
          const last = i === steps.length - 1;
          return (
            <li key={i} className="grid grid-cols-[20px_1fr] gap-2">
              <span className="flex flex-col items-center" aria-hidden>
                <span className={cn("mt-1.5 size-2 rounded-full", last ? "bg-sev-critical-bar" : "bg-input")} />
                {!last && <span className="w-px flex-1 bg-border" />}
              </span>
              <p className="pb-3 text-sm">
                <span className="font-medium">
                  {i === 0 ? "Entrada" : last ? "Uso peligroso" : `Paso ${i}`} · línea {s.line}
                </span>
                <span className="block text-muted-foreground">
                  <InlineCode text={s.description ?? s.desc ?? ""} />
                </span>
              </p>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

/** Panel didáctico (RF-24): qué es, por qué importa, cómo se corrige, con ejemplos. */
export function RuleLesson({ rule, compact = false }: { rule: Rule; compact?: boolean }) {
  return (
    <div className="grid gap-4">
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted-foreground">
        {rule.cwe.length > 0 && (
          <span>
            {rule.cwe.map((c) => (
              <a
                key={c}
                href={`https://cwe.mitre.org/data/definitions/${c.replace(/\D/g, "")}.html`}
                target="_blank"
                rel="noreferrer"
                className="mr-2 underline hover:text-foreground"
              >
                {c}
              </a>
            ))}
          </span>
        )}
        {rule.owasp.length > 0 && <span>OWASP {rule.owasp.join(", ")}</span>}
        <span>{CONFIDENCE_LABEL[rule.confidence]}</span>
        {rule.engine === "heuristic" && <span>Heurística: búsqueda por texto, confianza baja</span>}
      </div>

      <section>
        <h3 className="mb-1 font-semibold">Qué ocurre</h3>
        <p className="max-w-prose whitespace-pre-line">
          <InlineCode text={rule.explanation_es} />
        </p>
      </section>
      <section>
        <h3 className="mb-1 font-semibold">Cómo corregirlo</h3>
        <p className="max-w-prose whitespace-pre-line">
          <InlineCode text={rule.remediation_es} />
        </p>
      </section>

      {(rule.example_bad || rule.example_good) && (
        <div className={cn("grid gap-3", !compact && "lg:grid-cols-2")}>
          {rule.example_bad && (
            <div>
              <p className="mb-1 flex items-center gap-1 text-sm font-medium text-sev-critical-fg">
                <X className="size-4" aria-hidden /> Vulnerable
              </p>
              <CodeView code={rule.example_bad} />
            </div>
          )}
          {rule.example_good && (
            <div>
              <p className="mb-1 flex items-center gap-1 text-sm font-medium">
                <Check className="size-4" aria-hidden /> Corregido
              </p>
              <CodeView code={rule.example_good} />
            </div>
          )}
        </div>
      )}

      {rule.references.length > 0 && (
        <section>
          <h3 className="mb-1 font-semibold">Para saber más</h3>
          <ul className="grid gap-1 text-sm">
            {rule.references.map((r) => (
              <li key={r}>
                <a href={r} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 break-all underline">
                  {r.replace(/^https?:\/\//, "")}
                  <ExternalLink className="size-3 shrink-0" aria-hidden />
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}
    </div>
  );
}
