import { createContext, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from "react";
import { ApiError, UNAUTHORIZED_EVENT, api, setCsrfToken } from "@/api/client";
import type { Me, PublicConfig } from "@/api/types";

interface AuthState {
  user: Me | null;
  config: PublicConfig | null;
  status: "loading" | "ready" | "error";
  error: ApiError | null;
  devLogin: (email: string) => Promise<void>;
  logout: () => Promise<void>;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<Me | null>(null);
  const [config, setConfig] = useState<PublicConfig | null>(null);
  const [status, setStatus] = useState<AuthState["status"]>("loading");
  const [error, setError] = useState<ApiError | null>(null);

  const applyUser = useCallback((me: Me | null) => {
    setUser(me);
    setCsrfToken(me?.csrf_token ?? null);
  }, []);

  const refresh = useCallback(async () => {
    setStatus("loading");
    setError(null);
    try {
      const cfg = await api.get<PublicConfig>("/config");
      setConfig(cfg);
      try {
        applyUser(await api.get<Me>("/auth/me"));
      } catch (err) {
        if (!(err instanceof ApiError) || err.status !== 401) throw err;
        applyUser(null);
      }
      setStatus("ready");
    } catch (err) {
      setError(err as ApiError);
      setStatus("error");
    }
  }, [applyUser]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  useEffect(() => {
    const onUnauthorized = () => applyUser(null);
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, [applyUser]);

  const devLogin = useCallback(
    async (email: string) => {
      applyUser(await api.post<Me>("/auth/dev-login", { email }));
    },
    [applyUser],
  );

  const logout = useCallback(async () => {
    try {
      await api.post("/auth/logout");
    } finally {
      applyUser(null);
    }
  }, [applyUser]);

  const value = useMemo(
    () => ({ user, config, status, error, devLogin, logout, refresh }),
    [user, config, status, error, devLogin, logout, refresh],
  );
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth fuera de AuthProvider");
  return ctx;
}
