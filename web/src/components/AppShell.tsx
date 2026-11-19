import { BarChart3, BookOpen, FolderGit2, GraduationCap, Info, LogOut, Menu, Search, Settings } from "lucide-react";
import { useEffect, useState, type ReactNode } from "react";
import { NavLink, Outlet, useLocation, useNavigate } from "react-router-dom";
import { useAuth } from "@/auth/AuthProvider";
import { CommandPalette } from "@/components/CommandPalette";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { cn } from "@/lib/utils";

const NAV = [
  { to: "/proyectos", label: "Proyectos", icon: FolderGit2 },
  { to: "/retos", label: "Retos", icon: GraduationCap },
  { to: "/reglas", label: "Reglas", icon: BookOpen },
  { to: "/ajustes", label: "Ajustes", icon: Settings },
  { to: "/acerca", label: "Acerca de", icon: Info },
];

function Logo() {
  return (
    <span className="flex items-center gap-2 font-semibold">
      <img src="/favicon.svg" alt="" className="size-6" />
      SAST Studio
    </span>
  );
}

// Solo para administradores (ADMIN_EMAILS en el servidor).
const NAV_ADMIN = { to: "/uso", label: "Uso", icon: BarChart3 };

function NavItems({ onNavigate }: { onNavigate?: () => void }) {
  const { user } = useAuth();
  const items = user?.is_admin ? [...NAV.slice(0, 3), NAV_ADMIN, ...NAV.slice(3)] : NAV;
  return (
    <ul className="grid gap-0.5">
      {items.map(({ to, label, icon: Icon }) => (
        <li key={to}>
          <NavLink
            to={to}
            onClick={onNavigate}
            className={({ isActive }) =>
              cn(
                "flex h-8 items-center gap-2 rounded px-2 text-muted-foreground transition-colors hover:bg-muted hover:text-foreground",
                isActive && "bg-muted font-medium text-foreground",
              )
            }
          >
            <Icon className="size-4" aria-hidden />
            {label}
          </NavLink>
        </li>
      ))}
    </ul>
  );
}

function UserMenu() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  if (!user) return null;
  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="w-full justify-start px-2" aria-label={`Cuenta de ${user.name}`}>
          <span className="flex size-6 items-center justify-center rounded-full bg-muted text-xs font-medium" aria-hidden>
            {user.name.slice(0, 1).toUpperCase()}
          </span>
          <span className="truncate">{user.name}</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start" side="top" className="w-56">
        <DropdownMenuLabel>{user.email}</DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => navigate("/ajustes")}>
          <Settings aria-hidden /> Ajustes
        </DropdownMenuItem>
        <DropdownMenuItem
          onSelect={async () => {
            await logout();
            navigate("/login");
          }}
        >
          <LogOut aria-hidden /> Cerrar sesión
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

function SearchButton({ onClick }: { onClick: () => void }) {
  return (
    <Button variant="outline" className="w-full justify-between px-2 text-muted-foreground" onClick={onClick}>
      <span className="flex items-center gap-2">
        <Search aria-hidden /> Ir a…
      </span>
      <kbd className="rounded-sm border px-1 text-xs">Ctrl K</kbd>
    </Button>
  );
}

export function AppShell({ children }: { children?: ReactNode }) {
  const [paletteOpen, setPaletteOpen] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const location = useLocation();

  useEffect(() => setMobileOpen(false), [location.pathname]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPaletteOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <div className="min-h-dvh md:grid md:grid-cols-[224px_1fr]">
      <a
        href="#contenido"
        className="sr-only z-50 rounded bg-primary px-3 py-2 text-primary-foreground focus:not-sr-only focus:fixed focus:left-2 focus:top-2"
      >
        Saltar al contenido
      </a>

      <aside className="sticky top-0 hidden h-dvh flex-col gap-4 border-r p-3 md:flex" aria-label="Navegación principal">
        <div className="px-2 pt-1">
          <Logo />
        </div>
        <SearchButton onClick={() => setPaletteOpen(true)} />
        <nav className="flex-1">
          <NavItems />
        </nav>
        <UserMenu />
      </aside>

      <div className="flex items-center justify-between border-b px-4 py-2 md:hidden">
        <Logo />
        <div className="flex gap-1">
          <Button variant="ghost" size="icon" onClick={() => setPaletteOpen(true)} aria-label="Buscar">
            <Search aria-hidden />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            onClick={() => setMobileOpen((o) => !o)}
            aria-expanded={mobileOpen}
            aria-controls="menu-movil"
            aria-label="Menú"
          >
            <Menu aria-hidden />
          </Button>
        </div>
      </div>
      {mobileOpen && (
        <nav id="menu-movil" className="grid gap-3 border-b p-3 md:hidden" aria-label="Navegación principal">
          <NavItems onNavigate={() => setMobileOpen(false)} />
          <UserMenu />
        </nav>
      )}

      <main id="contenido" tabIndex={-1} className="min-w-0 px-4 py-5 focus:outline-none md:px-6">
        {children ?? <Outlet />}
      </main>

      <CommandPalette open={paletteOpen} onOpenChange={setPaletteOpen} />
    </div>
  );
}
