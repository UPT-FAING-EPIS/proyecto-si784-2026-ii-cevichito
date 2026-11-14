import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { ApiError, api } from "./client";

type Query = Record<string, string | number | undefined | null | false>;

interface State<T> {
  data: T | undefined;
  error: ApiError | undefined;
  loading: boolean;
}

interface Options {
  query?: Query;
  /** Consulta periódica en ms mientras `poll` devuelva true (escaneos en curso). */
  pollMs?: number;
  poll?: (data: unknown) => boolean;
}

/**
 * Lectura de un recurso GET con estados de carga/error y recarga manual.
 * `path = null` desactiva la petición (p. ej. mientras falta un id).
 */
export function useApi<T>(path: string | null, opts: Options = {}) {
  const [state, setState] = useState<State<T>>({ data: undefined, error: undefined, loading: path !== null });
  const [tick, setTick] = useState(0);
  const queryKey = JSON.stringify(opts.query ?? {});
  const optsRef = useRef(opts);
  useLayoutEffect(() => {
    optsRef.current = opts;
  });

  const reload = useCallback(() => setTick((t) => t + 1), []);

  useEffect(() => {
    if (path === null) {
      setState({ data: undefined, error: undefined, loading: false });
      return;
    }
    const ctrl = new AbortController();
    let timer: ReturnType<typeof setTimeout> | undefined;
    let delay = optsRef.current.pollMs ?? 0;

    const run = async (first: boolean) => {
      if (first) setState((s) => ({ ...s, loading: true, error: undefined }));
      try {
        const data = await api.get<T>(path, JSON.parse(queryKey) as Query, ctrl.signal);
        setState({ data, error: undefined, loading: false });
        const { pollMs, poll } = optsRef.current;
        if (pollMs && poll?.(data)) {
          timer = setTimeout(() => run(false), delay);
          delay = Math.min(delay * 1.25, 5000); // backoff suave hasta 5 s
        }
      } catch (err) {
        if ((err as Error).name === "AbortError") return;
        setState((s) => ({ ...s, error: err as ApiError, loading: false }));
      }
    };
    run(true);
    return () => {
      ctrl.abort();
      if (timer) clearTimeout(timer);
    };
  }, [path, queryKey, tick]);

  return { ...state, reload, setData: (data: T) => setState((s) => ({ ...s, data })) };
}
