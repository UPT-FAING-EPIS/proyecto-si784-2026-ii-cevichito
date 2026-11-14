import { lazy, Suspense, type ReactNode } from "react";
import { BrowserRouter, Link, Navigate, Route, Routes, useLocation } from "react-router-dom";
import { AuthProvider, useAuth } from "@/auth/AuthProvider";
import { AppShell } from "@/components/AppShell";
import { BlockSkeleton, ErrorState } from "@/components/States";
import { TooltipProvider } from "@/components/ui/tooltip";
import Login from "@/pages/Login";
import Projects from "@/pages/Projects";

// Las pantallas pesadas (gráficas, editor) se cargan bajo demanda.
const ProjectOverview = lazy(() => import("@/pages/ProjectOverview"));
const NewScan = lazy(() => import("@/pages/NewScan"));
const ScanPage = lazy(() => import("@/pages/ScanPage"));
const ScanDiff = lazy(() => import("@/pages/ScanDiff"));
const IssuePage = lazy(() => import("@/pages/IssuePage"));
const Rules = lazy(() => import("@/pages/Rules"));
const Settings = lazy(() => import("@/pages/Settings"));
const About = lazy(() => import("@/pages/About"));

function RequireAuth({ children }: { children: ReactNode }) {
  const { user, status, error, refresh } = useAuth();
  const location = useLocation();
  if (status === "loading" && !user)
    return (
      <div className="p-6" role="status">
        <p className="text-muted-foreground">Conectando con el servidor…</p>
      </div>
    );
  if (status === "error" && error)
    return (
      <div className="mx-auto max-w-lg p-6">
        <ErrorState error={error} onRetry={refresh} />
      </div>
    );
  if (!user) return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  return <>{children}</>;
}

function NotFound() {
  return (
    <div className="grid max-w-prose gap-2">
      <h1 className="text-lg font-semibold">Esta página no existe</h1>
      <p className="text-muted-foreground">
        Puede que el enlace esté mal o que el recurso se haya borrado.{" "}
        <Link to="/proyectos" className="underline">
          Volver a proyectos
        </Link>
      </p>
    </div>
  );
}

export function AppRoutes() {
  return (
    <Routes>
      <Route path="/login" element={<Login />} />
      <Route
        element={
          <RequireAuth>
            <AppShell />
          </RequireAuth>
        }
      >
        <Route index element={<Navigate to="/proyectos" replace />} />
        <Route path="/proyectos" element={<Projects />} />
        <Route path="/proyectos/:projectId" element={<Lazy><ProjectOverview /></Lazy>} />
        <Route path="/proyectos/:projectId/nuevo-escaneo" element={<Lazy><NewScan /></Lazy>} />
        <Route path="/escaneos/:scanId" element={<Lazy><ScanPage /></Lazy>} />
        <Route path="/escaneos/:scanId/comparar" element={<Lazy><ScanDiff /></Lazy>} />
        <Route path="/issues/:issueId" element={<Lazy><IssuePage /></Lazy>} />
        <Route path="/reglas" element={<Lazy><Rules /></Lazy>} />
        <Route path="/ajustes" element={<Lazy><Settings /></Lazy>} />
        <Route path="/acerca" element={<Lazy><About /></Lazy>} />
        <Route path="*" element={<NotFound />} />
      </Route>
    </Routes>
  );
}

function Lazy({ children }: { children: ReactNode }) {
  return <Suspense fallback={<BlockSkeleton />}>{children}</Suspense>;
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <TooltipProvider>
          <AppRoutes />
        </TooltipProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
