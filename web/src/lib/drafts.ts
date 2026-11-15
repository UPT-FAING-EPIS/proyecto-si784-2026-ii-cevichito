// Borrador del editor de retos. Es el código público del reto editado por el alumno, no datos de sesión
// ni resultados: vive solo en este navegador porque el servidor borra el código al terminar cada escaneo.
const key = (id: string) => `sast:reto:${id}`;

export function readDraft(id: string): string | null {
  try {
    return window.localStorage.getItem(key(id));
  } catch {
    return null;
  }
}

export function writeDraft(id: string, code: string | null) {
  try {
    if (code === null) window.localStorage.removeItem(key(id));
    else window.localStorage.setItem(key(id), code);
  } catch {
    // almacenamiento bloqueado (ventana privada): el borrador simplemente no se guarda
  }
}
