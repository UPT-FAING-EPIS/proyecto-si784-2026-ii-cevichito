import { Code2, FileArchive, Github, Upload } from "lucide-react";
import { lazy, Suspense, useMemo, useRef, useState, type FormEvent } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, type ApiError } from "@/api/client";
import type { Project, Rule } from "@/api/types";
import { useApi } from "@/api/useApi";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge } from "@/components/Severity";
import { BlockSkeleton, ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ENGINE_LABEL, numberFmt } from "@/lib/format";
import { cn } from "@/lib/utils";

const CodeEditor = lazy(() => import("@/components/CodeEditor").then((m) => ({ default: m.CodeEditor })));

type Source = "snippet" | "zip" | "github";
const REPO_RE = /^[A-Za-z0-9][A-Za-z0-9-]{0,38}\/[A-Za-z0-9._-]{1,100}$/;
/** Acepta también la URL que se copia de GitHub: https://github.com/dueño/repo(.git)(/...). */
function normalizeRepo(raw: string) {
  const m = raw.trim().match(/^(?:https?:\/\/)?(?:www\.)?github\.com\/([^/\s]+)\/([^/\s#?]+?)(?:\.git)?(?:[/#?].*)?$/i);
  return m ? `${m[1]}/${m[2]}` : raw.trim();
}

function RulePicker({ selected, onChange }: { selected: Set<string> | null; onChange: (s: Set<string> | null) => void }) {
  const rules = useApi<Rule[]>("/rules");
  if (rules.loading) return <BlockSkeleton className="h-24" />;
  if (rules.error) return <ErrorState error={rules.error} onRetry={rules.reload} />;
  const all = rules.data ?? [];
  const toggle = (id: string) => {
    const next = new Set(selected ?? all.map((r) => r.id));
    if (next.has(id)) next.delete(id);
    else next.add(id);
    onChange(next.size === all.length ? null : next);
  };
  return (
    <details className="rounded-lg border">
      <summary className="cursor-pointer select-none px-3 py-2 font-medium">
        Reglas:{" "}
        <span className="font-normal text-muted-foreground">
          {selected === null ? `todas (${all.length})` : `${selected.size} de ${all.length}`}
        </span>
      </summary>
      <div className="grid gap-2 border-t p-3">
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={() => onChange(null)}>
            Todas
          </Button>
          <Button size="sm" variant="outline" onClick={() => onChange(new Set())}>
            Ninguna
          </Button>
        </div>
        <fieldset className="grid gap-1 md:grid-cols-2">
          <legend className="sr-only">Reglas que se aplicarán</legend>
          {all.map((r) => (
            <label key={r.id} className="flex items-center gap-2 rounded px-1 py-1 hover:bg-muted">
              <input
                type="checkbox"
                className="size-4 accent-[var(--foreground)]"
                checked={selected === null || selected.has(r.id)}
                onChange={() => toggle(r.id)}
              />
              <SeverityBadge severity={r.severity} />
              <span className="truncate">{r.name}</span>
              <span className="ml-auto shrink-0 text-xs text-muted-foreground">{ENGINE_LABEL[r.engine] ?? r.engine}</span>
            </label>
          ))}
        </fieldset>
      </div>
    </details>
  );
}

export default function NewScan() {
  const { projectId = "" } = useParams();
  const navigate = useNavigate();
  const { config } = useAuth();
  const project = useApi<Project>(`/projects/${projectId}`);
  const limits = config?.limits;

  const [source, setSource] = useState<Source>("snippet");
  const [code, setCode] = useState("");
  const [filename, setFilename] = useState("app.py");
  const [file, setFile] = useState<File | null>(null);
  const [repo, setRepo] = useState("");
  const [ref, setRef] = useState("");
  const [rules, setRules] = useState<Set<string> | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement>(null);

  const problem = useMemo(() => {
    if (rules && rules.size === 0) return "Elige al menos una regla.";
    if (source === "snippet") {
      if (!code.trim()) return "Pega algo de código.";
      if (limits && new Blob([code]).size > limits.max_snippet_kb * 1024) return `El código supera ${limits.max_snippet_kb} KB.`;
      if (!/^[\w.\-/]{1,200}$/.test(filename)) return "El nombre de archivo solo admite letras, números, «.», «-», «_» y «/».";
    }
    if (source === "zip") {
      if (!file) return "Elige un archivo .zip.";
      if (!file.name.toLowerCase().endsWith(".zip")) return "El archivo debe ser un .zip.";
      if (limits && file.size > limits.max_upload_mb * 1024 * 1024) return `El ZIP supera ${limits.max_upload_mb} MB.`;
    }
    if (source === "github" && !REPO_RE.test(normalizeRepo(repo))) return "Escribe el repositorio como propietario/nombre.";
    return null;
  }, [source, code, filename, file, repo, rules, limits]);

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (problem) return;
    setBusy(true);
    setError(null);
    const ruleList = rules ? [...rules] : undefined;
    try {
      let res: { id: string };
      if (source === "zip") {
        const form = new FormData();
        form.append("file", file!);
        ruleList?.forEach((r) => form.append("rules", r));
        res = await api.upload(`/projects/${projectId}/scans`, form);
      } else if (source === "snippet") {
        res = await api.post(`/projects/${projectId}/scans`, { source, filename, code, rules: ruleList });
      } else {
        res = await api.post(`/projects/${projectId}/scans`, { source, repo: normalizeRepo(repo), ref: ref.trim() || undefined, rules: ruleList });
      }
      navigate(`/escaneos/${res.id}`);
    } catch (err) {
      setError(err as ApiError);
      setBusy(false);
    }
  }

  if (project.error) return <ErrorState error={project.error} onRetry={project.reload} />;

  return (
    <>
      <PageHeader
        title="Nuevo escaneo"
        crumbs={[
          { label: "Proyectos", to: "/proyectos" },
          { label: project.data?.name ?? "…", to: `/proyectos/${projectId}` },
        ]}
      />
      <form onSubmit={submit} className="grid max-w-4xl gap-5">
        <Tabs value={source} onValueChange={(v) => setSource(v as Source)}>
          <TabsList aria-label="Origen del código">
            <TabsTrigger value="snippet">
              <Code2 aria-hidden /> Pegar código
            </TabsTrigger>
            <TabsTrigger value="zip">
              <FileArchive aria-hidden /> Subir ZIP
            </TabsTrigger>
            <TabsTrigger value="github">
              <Github aria-hidden /> Repositorio de GitHub
            </TabsTrigger>
          </TabsList>

          <TabsContent value="snippet" className="grid gap-3">
            <div className="grid max-w-xs gap-1.5">
              <Label htmlFor="filename">Nombre del archivo</Label>
              <Input id="filename" value={filename} onChange={(e) => setFilename(e.target.value)} className="font-mono" />
            </div>
            <div className="grid gap-1.5">
              <span id="code-label" className="text-sm font-medium">
                Código
              </span>
              <Suspense fallback={<BlockSkeleton className="h-[360px]" />}>
                <CodeEditor value={code} onChange={setCode} python={filename.endsWith(".py")} labelledBy="code-label" />
              </Suspense>
              {limits && <p className="text-sm text-muted-foreground">Máximo {numberFmt.format(limits.max_snippet_kb)} KB.</p>}
            </div>
          </TabsContent>

          <TabsContent value="zip" className="grid gap-3">
            <div
              className={cn(
                "flex flex-col items-start gap-2 rounded-lg border border-dashed border-input p-5",
                dragging && "bg-muted",
              )}
              onDragOver={(e) => {
                e.preventDefault();
                setDragging(true);
              }}
              onDragLeave={() => setDragging(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragging(false);
                setFile(e.dataTransfer.files[0] ?? null);
              }}
            >
              <Upload className="size-5 text-muted-foreground" aria-hidden />
              <p>{file ? <span className="font-mono">{file.name}</span> : "Arrastra aquí un .zip o elígelo."}</p>
              {file && <p className="text-sm text-muted-foreground">{numberFmt.format(Math.round(file.size / 1024))} KB</p>}
              <input
                ref={fileInput}
                id="zip"
                type="file"
                accept=".zip,application/zip"
                className="sr-only"
                onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              />
              <Button variant="outline" size="sm" onClick={() => fileInput.current?.click()}>
                {file ? "Cambiar archivo" : "Elegir archivo"}
              </Button>
            </div>
            {limits && (
              <ul className="grid gap-0.5 text-sm text-muted-foreground">
                <li>Hasta {limits.max_upload_mb} MB comprimido y {limits.max_total_uncompressed_mb} MB descomprimido.</li>
                <li>Como mucho {numberFmt.format(limits.max_zip_entries)} archivos y una razón de compresión de {limits.max_compression_ratio}:1.</li>
                <li>Sin enlaces simbólicos ni rutas con «..». El ZIP no se descomprime en disco.</li>
              </ul>
            )}
          </TabsContent>

          <TabsContent value="github" className="grid gap-3">
            <div className="grid gap-3 sm:grid-cols-[1fr_200px]">
              <div className="grid gap-1.5">
                <Label htmlFor="repo">Repositorio</Label>
                <Input
                  id="repo"
                  value={repo}
                  onChange={(e) => setRepo(e.target.value)}
                  placeholder="propietario/nombre"
                  className="font-mono"
                  autoComplete="off"
                />
              </div>
              <div className="grid gap-1.5">
                <Label htmlFor="ref">Rama o etiqueta (opcional)</Label>
                <Input id="ref" value={ref} onChange={(e) => setRef(e.target.value)} placeholder="main" className="font-mono" />
              </div>
            </div>
            <p className="text-sm text-muted-foreground">
              Solo repositorios públicos{limits ? `, hasta ${limits.github_max_mb} MB` : ""}. Se descarga el ZIP de GitHub en el
              servidor; tu navegador no se conecta a GitHub.
            </p>
          </TabsContent>
        </Tabs>

        <RulePicker selected={rules} onChange={setRules} />

        {error && <ErrorState error={error} />}

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={busy || problem !== null}>
            {busy ? "Enviando…" : "Lanzar escaneo"}
          </Button>
          {problem && <p className="text-sm text-muted-foreground">{problem}</p>}
        </div>
      </form>
    </>
  );
}
