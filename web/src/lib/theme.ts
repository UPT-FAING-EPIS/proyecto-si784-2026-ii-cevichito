// Preferencia de tema del usuario. Es lo único que se guarda en el navegador: no es un dato
// de sesión ni del historial, y si el almacenamiento falla se sigue al sistema.

export type ThemeChoice = "system" | "light" | "dark";
const KEY = "sast.theme";

export function readTheme(): ThemeChoice {
  try {
    const v = window.localStorage.getItem(KEY);
    return v === "light" || v === "dark" ? v : "system";
  } catch {
    return "system";
  }
}

export function applyTheme(choice: ThemeChoice) {
  const root = document.documentElement;
  if (choice === "system") root.removeAttribute("data-theme");
  else root.setAttribute("data-theme", choice);
  try {
    if (choice === "system") window.localStorage.removeItem(KEY);
    else window.localStorage.setItem(KEY, choice);
  } catch {
    // almacenamiento bloqueado: el tema se aplica solo en esta visita
  }
}
