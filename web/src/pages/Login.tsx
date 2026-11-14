import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useSearchParams } from "react-router-dom";
import type { ApiError } from "@/api/client";
import { useAuth } from "@/auth/AuthProvider";
import { ErrorState } from "@/components/States";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

function GoogleMark() {
  return (
    <svg viewBox="0 0 18 18" className="size-4" aria-hidden>
      <path fill="#4285F4" d="M17.64 9.2c0-.64-.06-1.25-.16-1.84H9v3.48h4.84a4.14 4.14 0 0 1-1.8 2.72v2.26h2.92a8.78 8.78 0 0 0 2.68-6.62Z" />
      <path fill="#34A853" d="M9 18c2.43 0 4.47-.8 5.96-2.18l-2.92-2.26c-.8.54-1.84.86-3.04.86-2.34 0-4.33-1.58-5.04-3.7H.96v2.33A9 9 0 0 0 9 18Z" />
      <path fill="#FBBC05" d="M3.96 10.72A5.4 5.4 0 0 1 3.68 9c0-.6.1-1.18.28-1.72V4.95H.96A9 9 0 0 0 0 9c0 1.45.35 2.83.96 4.05l3-2.33Z" />
      <path fill="#EA4335" d="M9 3.58c1.32 0 2.5.45 3.44 1.35l2.58-2.58A9 9 0 0 0 .96 4.95l3 2.33C4.67 5.16 6.66 3.58 9 3.58Z" />
    </svg>
  );
}

/** Solo rutas internas como destino tras el login (el backend también lo valida). */
function safeNext(raw: string | null) {
  return raw && raw.startsWith("/") && !raw.startsWith("//") ? raw : "/proyectos";
}

export default function Login() {
  const { user, config, devLogin } = useAuth();
  const [params] = useSearchParams();
  const location = useLocation();
  const next = safeNext(params.get("next") ?? (location.state as { from?: string } | null)?.from ?? null);
  const [email, setEmail] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);

  if (user) return <Navigate to={next} replace />;

  const oidc = config?.auth.oidc ?? config?.auth.google ?? false;
  const provider = config?.auth.provider ?? "Google";
  const dev = config?.auth.dev_login ?? false;
  const loginError = params.get("error");

  async function onDev(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await devLogin(email.trim());
    } catch (err) {
      setError(err as ApiError);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-dvh items-center justify-center px-4">
      <div className="grid w-full max-w-sm gap-6">
        <div className="grid gap-1">
          <span className="flex items-center gap-2 text-md font-semibold">
            <img src="/favicon.svg" alt="" className="size-6" />
            SAST Studio
          </span>
          <h1 className="text-lg font-semibold">Inicia sesión</h1>
          <p className="text-muted-foreground">Tus proyectos y su historial de escaneos se guardan en este servidor.</p>
        </div>

        {loginError && (
          <ErrorState error={new Error(`No se pudo completar el inicio de sesión con ${provider}. Vuelve a intentarlo.`)} />
        )}

        {oidc && (
          <Button asChild variant="outline" className="h-10 w-full">
            <a href={`/api/v1/auth/login?next=${encodeURIComponent(next)}`}>
              {provider === "Google" && <GoogleMark />}
              Continuar con {provider}
            </a>
          </Button>
        )}

        {dev && (
          <form onSubmit={onDev} className="grid gap-3 rounded-lg border p-4" aria-labelledby="dev-title">
            <div>
              <h2 id="dev-title" className="font-semibold">
                Acceso de desarrollo
              </h2>
              <p className="text-sm text-muted-foreground">
                Solo existe con <code className="text-sm">DEV_LOGIN_ENABLED</code>. No pide contraseña.
              </p>
            </div>
            <div className="grid gap-1.5">
              <Label htmlFor="dev-email">Correo</Label>
              <Input
                id="dev-email"
                type="email"
                autoComplete="email"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                placeholder="tu@universidad.edu"
              />
            </div>
            {error && <p className="text-sm text-destructive">{error.message}</p>}
            <Button type="submit" disabled={busy || !email.includes("@")}>
              {busy ? "Entrando…" : "Entrar"}
            </Button>
          </form>
        )}

        {!oidc && !dev && config && (
          <ErrorState
            error={
              new Error(
                "No hay ningún método de acceso configurado. Define GOOGLE_CLIENT_ID y GOOGLE_CLIENT_SECRET (u OIDC_ISSUER, OIDC_CLIENT_ID y OIDC_CLIENT_SECRET) en el servidor.",
              )
            }
          />
        )}
      </div>
    </main>
  );
}
