import { MoreHorizontal, Pencil, Play, ScanSearch, Trash2 } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { api, type ApiError } from "@/api/client";
import { SEVERITIES, type Issue, type Metrics, type Page, type Project, type Scan } from "@/api/types";
import { useApi } from "@/api/useApi";
import { NewVsFixed, SeverityOverTime } from "@/components/Charts";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBadge, SeverityBar, SeverityCountsInline } from "@/components/Severity";
import { BlockSkeleton, EmptyState, ErrorState, TableSkeleton } from "@/components/States";
import { ScanStatusText } from "@/components/ScanStatus";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { SEVERITY_LABEL, SOURCE_LABEL, TRIAGE_LABEL, formatDate, formatDuration, formatRelative, numberFmt } from "@/lib/format";

function Stat({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid gap-0.5">
      <dt className="text-sm text-muted-foreground">{label}</dt>
      <dd className="font-medium">{children}</dd>
    </div>
  );
}

function Mttr({ mttr }: { mttr: Metrics["mttr_days"] }) {
  const entries = SEVERITIES.filter((s) => mttr[s]);
  if (entries.length === 0) return <span className="font-normal text-muted-foreground">Aún no hay hallazgos corregidos</span>;
  return (
    <span className="flex flex-wrap gap-x-3 font-normal">
      {entries.map((s) => (
        <span key={s} className="tabular">
          {SEVERITY_LABEL[s]}: {numberFmt.format(mttr[s]!.median)} d
        </span>
      ))}
    </span>
  );
}

function ScansTable({ projectId }: { projectId: string }) {
  const { data, error, loading, reload } = useApi<Page<Scan>>(`/projects/${projectId}/scans`, {
    query: { limit: 100 },
    pollMs: 2000,
    poll: (d) => (d as Page<Scan>).items.some((s) => s.status === "queued" || s.status === "running"),
  });
  if (loading && !data) return <TableSkeleton cols={5} />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  if (!data || data.items.length === 0)
    return (
      <EmptyState
        icon={ScanSearch}
        title="Este proyecto no tiene escaneos"
        action={
          <Button asChild>
            <Link to={`/proyectos/${projectId}/nuevo-escaneo`}>Lanzar el primero</Link>
          </Button>
        }
      >
        Pega código, sube un ZIP o indica un repositorio público de GitHub.
      </EmptyState>
    );
  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <THead>
          <TR>
            <TH>Fecha</TH>
            <TH>Origen</TH>
            <TH>Estado</TH>
            <TH>Hallazgos</TH>
            <TH className="text-right">Nuevos</TH>
            <TH className="text-right">Corregidos</TH>
            <TH className="text-right">Duración</TH>
          </TR>
        </THead>
        <TBody>
          {data.items.map((s) => (
            <TR key={s.id} className="hover:bg-muted">
              <TD>
                <Link to={`/escaneos/${s.id}`} className="hover:underline" title={formatDate(s.queued_at)}>
                  {formatRelative(s.queued_at)}
                </Link>
              </TD>
              <TD className="max-w-64">
                <span className="block truncate">
                  {SOURCE_LABEL[s.source]}
                  {s.source_ref && <span className="text-muted-foreground"> · {s.source_ref}</span>}
                </span>
              </TD>
              <TD>
                <ScanStatusText status={s.status} />
              </TD>
              <TD>{s.status === "done" ? <SeverityBar counts={s.summary.by_severity} /> : "—"}</TD>
              <TD className="text-right tabular">{s.status === "done" ? numberFmt.format(s.summary.new ?? 0) : "—"}</TD>
              <TD className="text-right tabular">{s.status === "done" ? numberFmt.format(s.summary.fixed ?? 0) : "—"}</TD>
              <TD className="text-right tabular text-muted-foreground">{formatDuration(s.started_at, s.finished_at)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

function OpenIssues({ projectId }: { projectId: string }) {
  const { data, error, loading, reload } = useApi<Page<Issue>>(`/projects/${projectId}/issues`, { query: { limit: 200 } });
  if (loading && !data) return <TableSkeleton cols={4} />;
  if (error) return <ErrorState error={error} onRetry={reload} />;
  const open = (data?.items ?? []).filter((i) => i.lifecycle !== "fixed");
  if (open.length === 0)
    return <EmptyState title="No hay hallazgos abiertos">Cuando un escaneo encuentre problemas aparecerán aquí.</EmptyState>;
  return (
    <div className="overflow-x-auto rounded-lg border">
      <Table>
        <THead>
          <TR>
            <TH>Severidad</TH>
            <TH>Regla</TH>
            <TH>Ubicación</TH>
            <TH>Revisión</TH>
            <TH className="text-right">Visto por primera vez</TH>
          </TR>
        </THead>
        <TBody>
          {open.map((i) => (
            <TR key={i.id} className="hover:bg-muted">
              <TD>
                <SeverityBadge severity={i.severity} />
              </TD>
              <TD>
                <Link to={`/issues/${i.id}`} className="font-mono hover:underline">
                  {i.rule_id}
                </Link>
              </TD>
              <TD className="max-w-80">
                <span className="block truncate font-mono" title={`${i.path}:${i.line}`}>
                  {i.path}:{i.line}
                </span>
              </TD>
              <TD>{TRIAGE_LABEL[i.triage]}</TD>
              <TD className="text-right text-muted-foreground">{formatRelative(i.first_seen_at)}</TD>
            </TR>
          ))}
        </TBody>
      </Table>
    </div>
  );
}

function RenameDialog({ project, open, onOpenChange, onDone }: { project: Project; open: boolean; onOpenChange: (o: boolean) => void; onDone: (p: Project) => void }) {
  const [name, setName] = useState(project.name);
  const [error, setError] = useState<ApiError | null>(null);
  async function submit(e: FormEvent) {
    e.preventDefault();
    try {
      onDone(await api.patch<Project>(`/projects/${project.id}`, { name: name.trim() }));
      onOpenChange(false);
    } catch (err) {
      setError(err as ApiError);
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Renombrar proyecto</DialogTitle>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="rename">Nombre</Label>
            <Input id="rename" value={name} maxLength={120} required onChange={(e) => setName(e.target.value)} autoFocus />
            {error && <p className="text-sm text-destructive">{error.message}</p>}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={!name.trim()}>
              Guardar
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function DeleteDialog({ project, open, onOpenChange }: { project: Project; open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  async function remove() {
    try {
      await api.del(`/projects/${project.id}`);
      navigate("/proyectos");
    } catch (err) {
      setError(err as ApiError);
    }
  }
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Eliminar «{project.name}»</DialogTitle>
          <DialogDescription>
            Se borran todos sus escaneos, hallazgos, comentarios e historial. No se puede deshacer.
          </DialogDescription>
        </DialogHeader>
        <div className="grid gap-1.5">
          <Label htmlFor="confirm-delete">Escribe el nombre del proyecto para confirmar</Label>
          <Input id="confirm-delete" value={confirm} onChange={(e) => setConfirm(e.target.value)} autoComplete="off" />
          {error && <p className="text-sm text-destructive">{error.message}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancelar
          </Button>
          <Button variant="destructive" disabled={confirm !== project.name} onClick={remove}>
            <Trash2 aria-hidden /> Eliminar definitivamente
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ProjectOverview() {
  const { projectId = "" } = useParams();
  const project = useApi<Project>(`/projects/${projectId}`);
  const metrics = useApi<Metrics>(`/projects/${projectId}/metrics`);
  const [renaming, setRenaming] = useState(false);
  const [deleting, setDeleting] = useState(false);

  if (project.error) return <ErrorState error={project.error} onRetry={project.reload} />;
  const p = project.data;

  return (
    <>
      <PageHeader
        title={p?.name ?? "Proyecto"}
        crumbs={[{ label: "Proyectos", to: "/proyectos" }]}
        actions={
          p && (
            <>
              <Button asChild>
                <Link to={`/proyectos/${p.id}/nuevo-escaneo`}>
                  <Play aria-hidden /> Nuevo escaneo
                </Link>
              </Button>
              <DropdownMenu>
                <DropdownMenuTrigger asChild>
                  <Button variant="outline" size="icon" aria-label="Más acciones del proyecto">
                    <MoreHorizontal aria-hidden />
                  </Button>
                </DropdownMenuTrigger>
                <DropdownMenuContent align="end">
                  <DropdownMenuItem onSelect={() => setRenaming(true)}>
                    <Pencil aria-hidden /> Renombrar
                  </DropdownMenuItem>
                  <DropdownMenuItem onSelect={() => setDeleting(true)} className="text-destructive">
                    <Trash2 aria-hidden /> Eliminar proyecto
                  </DropdownMenuItem>
                </DropdownMenuContent>
              </DropdownMenu>
            </>
          )
        }
      />

      {metrics.loading && !metrics.data && <BlockSkeleton className="h-16" />}
      {metrics.error && <ErrorState error={metrics.error} onRetry={metrics.reload} />}
      {metrics.data && p && (
        <dl className="mb-6 grid grid-cols-2 gap-x-8 gap-y-3 border-b pb-5 lg:flex lg:flex-wrap">
          <Stat label="Abiertos">
            <span className="flex items-center gap-2">
              <span className="tabular">{numberFmt.format(metrics.data.open_issues)}</span>
              <SeverityCountsInline counts={p.open_by_severity} />
            </span>
          </Stat>
          <Stat label="Tiempo mediano hasta corregir">
            <Mttr mttr={metrics.data.mttr_days} />
          </Stat>
          <Stat label="Densidad">
            {metrics.data.density_per_kloc === null ? (
              <span className="font-normal text-muted-foreground">—</span>
            ) : (
              <span className="tabular">{numberFmt.format(metrics.data.density_per_kloc)} por cada 1000 líneas</span>
            )}
          </Stat>
          <Stat label="Riesgo aceptado o sin corregir">
            <span className="tabular">{numberFmt.format(metrics.data.accepted_issues)}</span>
          </Stat>
        </dl>
      )}

      {metrics.data && metrics.data.open_by_severity.length > 1 && (
        <div className="mb-6 grid gap-6 lg:grid-cols-2">
          <section aria-labelledby="g1">
            <h2 id="g1" className="mb-2 font-semibold">
              Hallazgos por severidad en cada escaneo
            </h2>
            <SeverityOverTime data={metrics.data.open_by_severity.slice(-20)} />
          </section>
          <section aria-labelledby="g2">
            <h2 id="g2" className="mb-2 font-semibold">
              Nuevos frente a corregidos
            </h2>
            <NewVsFixed data={metrics.data.new_vs_fixed.slice(-20)} />
          </section>
        </div>
      )}
      {metrics.data && metrics.data.open_by_severity.length === 1 && (
        <p className="mb-6 text-sm text-muted-foreground">
          Las gráficas de evolución aparecen a partir del segundo escaneo terminado.
        </p>
      )}

      <Tabs defaultValue="escaneos">
        <TabsList>
          <TabsTrigger value="escaneos">Escaneos</TabsTrigger>
          <TabsTrigger value="hallazgos">Hallazgos abiertos</TabsTrigger>
        </TabsList>
        <TabsContent value="escaneos">
          <ScansTable projectId={projectId} />
        </TabsContent>
        <TabsContent value="hallazgos">
          <OpenIssues projectId={projectId} />
        </TabsContent>
      </Tabs>

      {p && <RenameDialog project={p} open={renaming} onOpenChange={setRenaming} onDone={project.setData} />}
      {p && <DeleteDialog project={p} open={deleting} onOpenChange={setDeleting} />}
    </>
  );
}
