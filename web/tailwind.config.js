/** Tailwind v3 mapeado a los tokens de src/styles/tokens.css (ver DESIGN.md). */
const sev = (level) => ({ bg: `var(--sev-${level}-bg)`, fg: `var(--sev-${level}-fg)`, bar: `var(--sev-${level}-bar)` });

/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: ["variant", ["@media (prefers-color-scheme: dark) { :root:not([data-theme=light]) & }", '[data-theme="dark"] &']],
  theme: {
    // Paleta cerrada: no hay colores de Tailwind por defecto, solo tokens.
    colors: {
      transparent: "transparent",
      current: "currentColor",
      background: "var(--background)",
      surface: "var(--surface)",
      muted: { DEFAULT: "var(--muted)", foreground: "var(--muted-foreground)" },
      foreground: "var(--foreground)",
      border: "var(--border)",
      input: "var(--input)",
      ring: "var(--ring)",
      overlay: "var(--overlay)",
      primary: { DEFAULT: "var(--primary)", foreground: "var(--primary-foreground)", hover: "var(--primary-hover)" },
      destructive: { DEFAULT: "var(--destructive)", foreground: "var(--destructive-foreground)" },
      sev: {
        critical: sev("critical"),
        high: sev("high"),
        medium: sev("medium"),
        low: sev("low"),
        info: sev("info"),
      },
    },
    fontFamily: {
      sans: ["var(--font-sans)"],
      mono: ["var(--font-mono)"],
    },
    fontSize: {
      xs: ["13px", { lineHeight: "1.4" }],
      sm: ["14px", { lineHeight: "1.45" }],
      base: ["16px", { lineHeight: "1.5" }],
      md: ["18px", { lineHeight: "1.4" }],
      lg: ["24px", { lineHeight: "1.25" }],
    },
    borderRadius: {
      none: "0",
      sm: "var(--radius-sm)",
      DEFAULT: "var(--radius)",
      md: "var(--radius)",
      lg: "var(--radius-lg)",
      full: "9999px",
    },
    boxShadow: {
      none: "none",
      1: "var(--shadow-1)",
    },
    extend: {
      transitionDuration: { DEFAULT: "120ms" },
    },
  },
  plugins: [],
};
