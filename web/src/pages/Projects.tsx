import { FolderPlus, Plus } from "lucide-react";
import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { api, type ApiError } from "@/api/client";
import type { Page, Project } from "@/api/types";
import { useApi } from "@/api/useApi";
import { PageHeader } from "@/components/PageHeader";
import { SeverityBar } from "@/components/Severity";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/States";
import { ScanStatusText } from "@/components/ScanStatus";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { formatRelative, formatDate } from "@/lib/format";

export function NewProjectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const [name, setName] = useState("");
  const [error, setError] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const p = await api.post<Project>("/projects", { name: name.trim() });
      onOpenChange(false);
      navigate(`/proyectos/${p.id}/nuevo-escaneo`);
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <form onSubmit={submit} className="grid gap-4">
          <DialogHeader>
            <DialogTitle>Nuevo proyecto</DialogTitle>
            <DialogDescription>Agrupa los escaneos de un mismo código para ver su evolución.</DialogDescription>
          </DialogHeader>
          <div className="grid gap-1.5">
            <Label htmlFor="project-name">Nombre</Label>
            <Input
              id="project-name"
              required
              maxLength={120}
              value={name}
              onChange={(e) => setName(e.target.value)}
              aria-invalid={error ? true : undefined}
              aria-describedby={error ? "project-error" : undefined}
              placeholder="practica-3-flask"
              autoFocus
            />
            {error && (
              <p id="project-error" className="text-sm text-destructive">
                {error.message}
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => onOpenChange(false)}>
              Cancelar
            </Button>
            <Button type="submit" disabled={busy || !name.trim()}>
              {busy ? "Creando…" : "Crear y escanear"}
            </Button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  );
}

export default function Projects() {
  const { data, error, loading, reload } = useApi<Page<Project>>("/projects", { query: { limit: 200 } });
  const [creating, setCreating] = useState(false);

  return (
    <>
      <PageHeader
        title="Proyectos"
        actions={
          <Button onClick={() => setCreating(true)}>
            <Plus aria-hidden /> Nuevo proyecto
          </Button>
        }
      />

      {loading && !data && <TableSkeleton cols={4} />}
      {error && <ErrorState error={error} onRetry={reload} />}
      {data && data.items.length === 0 && (
        <EmptyState
          icon={FolderPlus}
          title="Todavía no tienes proyectos"
          action={<Button onClick={() => setCreating(true)}>Crear el primero</Button>}
        >
          Un proyecto guarda los escaneos de un mismo código. Así puedes ver qué hallazgos son nuevos, cuáles corregiste y
          cuáles siguen ahí.
        </EmptyState>
      )}
      {data && data.items.length > 0 && (
        <div className="overflow-x-auto rounded-lg border">
          <Table>
            <THead>
              <TR>
                <TH>Nombre</TH>
                <TH>Último escaneo</TH>
                <TH>Hallazgos del último escaneo</TH>
                <TH className="text-right">Fecha</TH>
              </TR>
            </THead>
            <TBody>
              {data.items.map((p) => (
                <TR key={p.id} className="hover:bg-muted">
                  <TD className="font-medium">
                    <Link to={`/proyectos/${p.id}`} className="hover:underline">
                      {p.name}
                    </Link>
                  </TD>
                  <TD>
                    {p.last_scan ? <ScanStatusText status={p.last_scan.status} /> : <span className="text-muted-foreground">Sin escaneos</span>}
                  </TD>
                  <TD>
                    {p.last_scan?.status === "done" ? (
                      <SeverityBar counts={p.last_scan.summary.by_severity} />
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </TD>
                  <TD className="text-right text-muted-foreground">
                    <time dateTime={p.last_scan?.finished_at ?? p.created_at} title={formatDate(p.last_scan?.finished_at ?? p.created_at)}>
                      {formatRelative(p.last_scan?.finished_at ?? p.created_at)}
                    </time>
                  </TD>
                </TR>
              ))}
            </TBody>
          </Table>
        </div>
      )}

      <NewProjectDialog open={creating} onOpenChange={setCreating} />
    </>
  );
}
