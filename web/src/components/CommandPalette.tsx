import * as DialogPrimitive from "@radix-ui/react-dialog";
import { BookOpen, FolderGit2, Info, Moon, Settings } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useApi } from "@/api/useApi";
import type { Page, Project } from "@/api/types";
import { Command, CommandEmpty, CommandGroup, CommandInput, CommandItem, CommandList } from "@/components/ui/command";
import { applyTheme, readTheme } from "@/lib/theme";

/** Paleta de comandos (Ctrl+K): ir a una pantalla o a un proyecto. */
export function CommandPalette({ open, onOpenChange }: { open: boolean; onOpenChange: (o: boolean) => void }) {
  const navigate = useNavigate();
  const projects = useApi<Page<Project>>(open ? "/projects" : null, { query: { limit: 100 } });

  const go = (to: string) => {
    onOpenChange(false);
    navigate(to);
  };

  return (
    <DialogPrimitive.Root open={open} onOpenChange={onOpenChange}>
      <DialogPrimitive.Portal>
        <DialogPrimitive.Overlay className="fixed inset-0 z-40 bg-overlay" />
        <DialogPrimitive.Content
          className="fixed left-1/2 top-[15vh] z-50 w-[calc(100%-32px)] max-w-lg -translate-x-1/2 overflow-hidden rounded-lg border bg-surface shadow-1"
          aria-describedby={undefined}
        >
          <DialogPrimitive.Title className="sr-only">Paleta de comandos</DialogPrimitive.Title>
          <Command label="Paleta de comandos">
            <CommandInput placeholder="Escribe una pantalla o un proyecto…" />
            <CommandList>
              <CommandEmpty>Nada coincide.</CommandEmpty>
              <CommandGroup heading="Ir a">
                <CommandItem onSelect={() => go("/proyectos")}>
                  <FolderGit2 aria-hidden /> Proyectos
                </CommandItem>
                <CommandItem onSelect={() => go("/reglas")}>
                  <BookOpen aria-hidden /> Catálogo de reglas
                </CommandItem>
                <CommandItem onSelect={() => go("/ajustes")}>
                  <Settings aria-hidden /> Ajustes
                </CommandItem>
                <CommandItem onSelect={() => go("/acerca")}>
                  <Info aria-hidden /> Acerca de
                </CommandItem>
                <CommandItem
                  onSelect={() => {
                    const dark =
                      document.documentElement.getAttribute("data-theme") === "dark" ||
                      (readTheme() === "system" && window.matchMedia?.("(prefers-color-scheme: dark)").matches);
                    applyTheme(dark ? "light" : "dark");
                    onOpenChange(false);
                  }}
                >
                  <Moon aria-hidden /> Cambiar entre tema claro y oscuro
                </CommandItem>
              </CommandGroup>
              {projects.data && projects.data.items.length > 0 && (
                <CommandGroup heading="Proyectos">
                  {projects.data.items.map((p) => (
                    <CommandItem key={p.id} value={`proyecto ${p.name}`} onSelect={() => go(`/proyectos/${p.id}`)}>
                      <FolderGit2 aria-hidden /> {p.name}
                    </CommandItem>
                  ))}
                </CommandGroup>
              )}
            </CommandList>
          </Command>
        </DialogPrimitive.Content>
      </DialogPrimitive.Portal>
    </DialogPrimitive.Root>
  );
}
