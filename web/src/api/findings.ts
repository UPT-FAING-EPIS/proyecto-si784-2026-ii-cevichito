import { useEffect, useState } from "react";
import { ApiError, api } from "./client";
import type { Finding, Page } from "./types";

const PAGE = 200; // MAX_LIMIT del backend
const CAP = 10_000; // tope de seguridad para no colgar el navegador

/** Carga todas las ocurrencias de un escaneo recorriendo el cursor; el filtrado se hace en cliente. */
export function useAllFindings(scanId: string | null) {
  const [items, setItems] = useState<Finding[] | undefined>();
  const [error, setError] = useState<ApiError | undefined>();
  const [truncated, setTruncated] = useState(false);
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (!scanId) return;
    const ctrl = new AbortController();
    setItems(undefined);
    setError(undefined);
    (async () => {
      const acc: Finding[] = [];
      let cursor: string | null = null;
      try {
        do {
          const page: Page<Finding> = await api.get(`/scans/${scanId}/findings`, { limit: PAGE, cursor }, ctrl.signal);
          acc.push(...page.items);
          cursor = page.next_cursor;
        } while (cursor && acc.length < CAP);
        setTruncated(Boolean(cursor));
        setItems(acc);
      } catch (err) {
        if ((err as Error).name !== "AbortError") setError(err as ApiError);
      }
    })();
    return () => ctrl.abort();
  }, [scanId, tick]);

  return { items, error, truncated, reload: () => setTick((t) => t + 1) };
}
