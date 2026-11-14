import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthProvider";
import { PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/button";
import { applyTheme, readTheme, type ThemeChoice } from "@/lib/theme";
import { numberFmt } from "@/lib/format";

const THEMES: { value: ThemeChoice; label: string }[] = [
  { value: "system", label: "Como el sistema" },
  { value: "light", label: "Claro" },
  { value: "dark", label: "Oscuro" },
];

function Section({ id, title, children }: { id: string; title: string; children: React.ReactNode }) {
  return (
    <section aria-labelledby={id} className="grid gap-3 border-t py-5 first:border-t-0 first:pt-0">
      <h2 id={id} className="text-md font-semibold">
        {title}
      </h2>
      {children}
    </section>
  );
}

export default function Settings() {
  const { user, config, logout } = useAuth();
  const navigate = useNavigate();
  const [theme, setTheme] = useState<ThemeChoice>(readTheme);
  const l = config?.limits;

  return (
    <>
      <PageHeader title="Ajustes" />
      <div className="max-w-2xl">
        <Section id="sesion" title="Sesión">
          <dl className="grid grid-cols-[120px_1fr] gap-y-1">
            <dt className="text-muted-foreground">Nombre</dt>
            <dd>{user?.name}</dd>
            <dt className="text-muted-foreground">Correo</dt>
            <dd>{user?.email}</dd>
          </dl>
          <p className="text-sm text-muted-foreground">
            La sesión vive en una cookie que el navegador no deja leer a la página. Caduca tras 2 horas sin actividad y, como
            mucho, a las 12 horas.
          </p>
          <div>
            <Button
              variant="outline"
              onClick={async () => {
                await logout();
                navigate("/login");
              }}
            >
              Cerrar sesión
            </Button>
          </div>
        </Section>

        <Section id="tema" title="Apariencia">
          <fieldset className="flex flex-wrap gap-4">
            <legend className="sr-only">Tema</legend>
            {THEMES.map((t) => (
              <label key={t.value} className="flex items-center gap-2">
                <input
                  type="radio"
                  name="theme"
                  value={t.value}
                  checked={theme === t.value}
                  className="size-4 accent-[var(--foreground)]"
                  onChange={() => {
                    setTheme(t.value);
                    applyTheme(t.value);
                  }}
                />
                {t.label}
              </label>
            ))}
          </fieldset>
        </Section>

        <Section id="datos" title="Tus datos">
          <p>
            El código que subes se borra en cuanto termina el análisis. Cada hallazgo guarda un fragmento de unas líneas; esos
            fragmentos se eliminan a los {l ? numberFmt.format(l.retention_days) : "90"} días y se conserva el resumen y el
            historial de revisiones. Para borrarlo todo de un proyecto, ábrelo y usa «Eliminar proyecto» en el menú de
            acciones: el borrado es inmediato y en cascada.
          </p>
        </Section>

        {l && (
          <Section id="limites" title="Límites de este servidor">
            <dl className="grid grid-cols-[minmax(0,1fr)_auto] gap-x-6 gap-y-1">
              <dt className="text-muted-foreground">Tamaño de un ZIP</dt>
              <dd className="tabular">{l.max_upload_mb} MB</dd>
              <dt className="text-muted-foreground">Contenido descomprimido</dt>
              <dd className="tabular">{l.max_total_uncompressed_mb} MB</dd>
              <dt className="text-muted-foreground">Archivos por ZIP</dt>
              <dd className="tabular">{numberFmt.format(l.max_zip_entries)}</dd>
              <dt className="text-muted-foreground">Código pegado</dt>
              <dd className="tabular">{numberFmt.format(l.max_snippet_kb)} KB</dd>
              <dt className="text-muted-foreground">Repositorio de GitHub</dt>
              <dd className="tabular">{l.github_max_mb} MB</dd>
              <dt className="text-muted-foreground">Tiempo máximo de un análisis</dt>
              <dd className="tabular">{numberFmt.format(l.scan_timeout_s)} s</dd>
              <dt className="text-muted-foreground">Escaneos por hora</dt>
              <dd className="tabular">{l.scans_per_hour}</dd>
            </dl>
          </Section>
        )}
      </div>
    </>
  );
}
