import { Search } from "lucide-react";
import { useMemo } from "react";
import { useSearchParams } from "react-router-dom";
import { SEVERITIES, type Rule } from "@/api/types";
import { useApi } from "@/api/useApi";
import { RuleLesson } from "@/components/Lesson";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/States";
import { Input, NativeSelect } from "@/components/ui/input";
import { ENGINE_LABEL, SEVERITY_LABEL } from "@/lib/format";
import { cn } from "@/lib/utils";
import { InlineCode, ruleTemplate } from "@/components/InlineCode";

const LANG_LABEL: Record<string, string> = { python: "Python", javascript: "JavaScript", any: "Cualquier lenguaje" };

export default function Rules() {
  const { data, error, loading, reload } = useApi<Rule[]>("/rules");
  const [params, setParams] = useSearchParams();
  const q = params.get("q") ?? "";
  const lang = params.get("lenguaje") ?? "";
  const selectedId = params.get("regla");

  const set = (k: string, v: string) => {
    const next = new URLSearchParams(params);
    if (v) next.set(k, v);
    else next.delete(k);
    setParams(next, { replace: true });
  };

  const languages = useMemo(() => [...new Set((data ?? []).flatMap((r) => r.languages))].sort(), [data]);
  const rules = useMemo(() => {
    const needle = q.toLowerCase();
    return (data ?? [])
      .filter((r) => (!lang || r.languages.includes(lang)) && (!needle || `${r.id} ${r.name} ${r.cwe.join(" ")}`.toLowerCase().includes(needle)))
      .sort((a, b) => SEVERITIES.indexOf(a.severity) - SEVERITIES.indexOf(b.severity) || a.name.localeCompare(b.name, "es"));
  }, [data, q, lang]);
  const selected = rules.find((r) => r.id === selectedId) ?? (data ?? []).find((r) => r.id === selectedId) ?? rules[0];

  return (
    <>
      <PageHeader
        title="Catálogo de reglas"
        description="Qué comprueba el analizador, por qué importa y cómo se corrige cada caso. Las reglas heurísticas buscan texto y tienen confianza baja."
      />
      {loading && <TableSkeleton rows={8} cols={2} />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && (
        <div className="grid items-start gap-6 lg:grid-cols-[340px_minmax(0,1fr)]">
          <div className="grid gap-2 lg:sticky lg:top-5">
            <div className="flex gap-2" role="search">
              <div className="relative flex-1">
                <Search className="pointer-events-none absolute left-2.5 top-2 size-4 text-muted-foreground" aria-hidden />
                <Input value={q} onChange={(e) => set("q", e.target.value)} placeholder="Buscar regla o CWE" aria-label="Buscar regla o CWE" className="pl-8" />
              </div>
              <NativeSelect aria-label="Lenguaje" value={lang} onChange={(e) => set("lenguaje", e.target.value)} className="w-32">
                <option value="">Todos</option>
                {languages.map((l) => (
                  <option key={l} value={l}>
                    {LANG_LABEL[l] ?? l}
                  </option>
                ))}
              </NativeSelect>
            </div>
            {rules.length === 0 ? (
              <EmptyState title="Ninguna regla coincide" />
            ) : (
              <ul className="max-h-[calc(100dvh-220px)] overflow-y-auto rounded-lg border" aria-label="Reglas">
                {rules.map((r) => (
                  <li key={r.id} className="border-b last:border-b-0">
                    <button
                      type="button"
                      onClick={() => set("regla", r.id)}
                      aria-current={selected?.id === r.id ? "true" : undefined}
                      className={cn("grid w-full gap-1 px-3 py-2 text-left hover:bg-muted", selected?.id === r.id && "bg-muted")}
                    >
                      <span className="flex items-center gap-2">
                        <SeverityBadge severity={r.severity} />
                        <span className="truncate font-medium">{r.name}</span>
                      </span>
                      <span className="flex gap-2 text-sm text-muted-foreground">
                        <span className="truncate font-mono">{r.id}</span>
                        <span className="ml-auto shrink-0">{ENGINE_LABEL[r.engine] ?? r.engine}</span>
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {selected && (
            <article aria-labelledby="regla-titulo" className="min-w-0">
              <div className="mb-4 grid gap-1">
                <h2 id="regla-titulo" className="text-lg font-semibold">
                  {selected.name}
                </h2>
                <p className="flex flex-wrap items-center gap-x-3 gap-y-1 text-sm text-muted-foreground">
                  <span className="font-mono">{selected.id}</span>
                  <span>Severidad {SEVERITY_LABEL[selected.severity].toLowerCase()}</span>
                  <span>{ENGINE_LABEL[selected.engine] ?? selected.engine}</span>
                  <span>{selected.languages.map((l) => LANG_LABEL[l] ?? l).join(", ")}</span>
                </p>
                <p className="max-w-prose">
                  <InlineCode text={ruleTemplate(selected.message)} />
                </p>
              </div>
              <RuleLesson rule={selected} />
            </article>
          )}
        </div>
      )}
    </>
  );
}
