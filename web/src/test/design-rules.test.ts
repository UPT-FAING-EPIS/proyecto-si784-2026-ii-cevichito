// Comprobaciones deterministas de web/DESIGN.md: contraste AA de los tokens y patrones prohibidos
// (secciones 9 y 10). Sustituyen al detector binario de impeccable (decisión D5: solo texto).
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

// vitest se ejecuta desde web/ (npm test); import.meta.url no es file:// bajo jsdom.
const ROOT = join(process.cwd(), "src");
const tokensCss = readFileSync(join(ROOT, "styles", "tokens.css"), "utf8");

function block(selectorStart: string) {
  const i = tokensCss.indexOf(selectorStart);
  const open = tokensCss.indexOf("{", i);
  let depth = 0;
  for (let j = open; j < tokensCss.length; j++) {
    if (tokensCss[j] === "{") depth++;
    if (tokensCss[j] === "}" && --depth === 0) return tokensCss.slice(open + 1, j);
  }
  throw new Error(`bloque no encontrado: ${selectorStart}`);
}

function vars(css: string) {
  const out: Record<string, string> = {};
  for (const m of css.matchAll(/--([\w-]+):\s*(#[0-9a-fA-F]{6})/g)) out[m[1]] = m[2];
  return out;
}

const light = vars(block(":root {"));
const dark = { ...light, ...vars(block(':root[data-theme="dark"]')) };

function luminance(hex: string) {
  const [r, g, b] = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const f = (c: number) => (c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4);
  return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b);
}
function contrast(a: string, b: string) {
  const [x, y] = [luminance(a), luminance(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}

const TEXT_PAIRS: [string, string][] = [
  ["foreground", "background"],
  ["foreground", "muted"],
  ["muted-foreground", "background"],
  ["muted-foreground", "muted"],
  ["primary-foreground", "primary"],
  ["destructive", "background"],
  ["code-keyword", "muted"],
  ["code-string", "muted"],
  ["code-number", "muted"],
  ["code-comment", "muted"],
  ["code-keyword", "surface"],
  ...(["critical", "high", "medium", "low", "info"] as const).flatMap(
    (s) =>
      [
        [`sev-${s}-fg`, `sev-${s}-bg`],
        [`sev-${s}-fg`, "background"],
      ] as [string, string][],
  ),
];
const GRAPHIC_PAIRS: [string, string][] = [
  ["input", "background"],
  ["ring", "background"],
  ...(["critical", "high", "medium", "low", "info"] as const).map((s) => [`sev-${s}-bar`, "background"] as [string, string]),
];

describe("contraste WCAG 2.1 AA de los tokens", () => {
  for (const [name, theme] of [
    ["claro", light],
    ["oscuro", dark],
  ] as const) {
    it.each(TEXT_PAIRS)(`${name}: texto %s sobre %s ≥ 4,5:1`, (fg, bg) => {
      expect(theme[fg], fg).toBeDefined();
      expect(contrast(theme[fg], theme[bg])).toBeGreaterThanOrEqual(4.5);
    });
    it.each(GRAPHIC_PAIRS)(`${name}: gráfico %s sobre %s ≥ 3:1`, (fg, bg) => {
      expect(contrast(theme[fg], theme[bg])).toBeGreaterThanOrEqual(3);
    });
  }

  it("el bloque oscuro por preferencia del sistema y el forzado son idénticos", () => {
    const media = vars(block(':root:not([data-theme="light"])'));
    expect(media).toEqual(vars(block(':root[data-theme="dark"]')));
  });
});

function sources(dir: string): string[] {
  return readdirSync(dir).flatMap((f: string) => {
    const p = join(dir, f);
    if (statSync(p).isDirectory()) return f === "test" ? [] : sources(p);
    return /\.(tsx?|css)$/.test(f) ? [p] : [];
  });
}

const FILES = sources(ROOT).map((p) => ({ path: relative(ROOT, p).replaceAll("\\", "/"), text: readFileSync(p, "utf8") }));

const BANNED: [string, RegExp][] = [
  ["degradados", /bg-gradient-|linear-gradient|radial-gradient|from-\w+-\d{2,3}\s+to-/],
  ["glassmorphism", /backdrop-blur|backdrop-filter/],
  ["mayúsculas con tracking (eyebrows)", /\buppercase\b|tracking-(wide|wider|widest)/],
  ["borde izquierdo grueso como estado", /border-l-(2|4|8)\b/],
  ["Inter o Space Grotesk", /["'](Inter|Space Grotesk)["']/],
  ["paleta crema/terracota", /#F4F1EA|#D97757/i],
  ["acentos lima/rosa del original de Sentry", /#c2ef4e|#fa7faa/i],
  ["animaciones de entrada o pulso", /animate-(pulse|bounce|ping|fade)|framer-motion/],
  ["emojis", /[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u],
  ["colores de la paleta por defecto de Tailwind", /\b(bg|text|border)-(slate|gray|zinc|red|blue|green|purple|violet|indigo|amber|emerald)-\d{2,3}\b/],
];

describe("patrones prohibidos en el código de la interfaz (DESIGN.md §9)", () => {
  it.each(BANNED)("sin %s", (_name, re) => {
    const hits = FILES.filter((f) => f.path !== "styles/tokens.css" && re.test(f.text)).map((f) => f.path);
    expect(hits).toEqual([]);
  });

  it("sin colores hexadecimales fuera de tokens.css (salvo el logotipo de Google)", () => {
    const hits = FILES.filter(
      (f) => f.path !== "styles/tokens.css" && f.path !== "pages/Login.tsx" && /#[0-9a-fA-F]{6}\b/.test(f.text),
    ).map((f) => f.path);
    expect(hits).toEqual([]);
  });

  it("estilos en línea solo donde DESIGN.md los permite (anchos y posiciones calculados)", () => {
    const allowed = new Set(["components/Severity.tsx", "components/FindingsTable.tsx"]);
    const hits = FILES.filter((f) => /style=\{\{/.test(f.text) && !allowed.has(f.path)).map((f) => f.path);
    expect(hits).toEqual([]);
  });

  it("solo la preferencia de tema usa localStorage; nada de sesión ni historial", () => {
    const hits = FILES.filter((f) => /localStorage|sessionStorage/.test(f.text)).map((f) => f.path);
    expect(hits).toEqual(["lib/theme.ts"]);
    expect(FILES.some((f) => /sast\.history|jwt|Bearer/i.test(f.text))).toBe(false);
  });

  it("la interfaz no llama a la API antigua", () => {
    const hits = FILES.filter((f) => /["'`]\/api\/(?!v1)/.test(f.text)).map((f) => f.path);
    expect(hits).toEqual([]);
  });
});
