import { useEffect, useState } from "react";

/**
 * Lee tokens CSS ya resueltos. Recharts escribe los colores como atributos SVG, que no
 * resuelven var(--x); por eso se pasan valores calculados y se recalculan al cambiar el tema.
 */
export function useTokens<K extends string>(names: readonly K[]): Record<K, string> {
  const read = () => {
    const style = getComputedStyle(document.documentElement);
    return Object.fromEntries(names.map((n) => [n, style.getPropertyValue(`--${n}`).trim()])) as Record<K, string>;
  };
  const [values, setValues] = useState(read);
  const key = names.join(",");

  useEffect(() => {
    const update = () => setValues(read());
    const media = window.matchMedia?.("(prefers-color-scheme: dark)");
    media?.addEventListener?.("change", update);
    const obs = new MutationObserver(update);
    obs.observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    return () => {
      media?.removeEventListener?.("change", update);
      obs.disconnect();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key]);

  return values;
}
