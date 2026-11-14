# Referencias de diseño (solo texto)

Material de terceros copiado como **texto**, sin instaladores ni binarios (decisiones D5 y D6 de
`docs/spec/especificacion.md`, sección 7). Nada de esta carpeta se ejecuta ni se importa desde el código.

| Carpeta | Origen | Licencia | Para qué se usa |
|---|---|---|---|
| `sentry/DESIGN.original.md` | [VoltAgent/awesome-design-md](https://github.com/VoltAgent/awesome-design-md), `design-md/sentry/DESIGN.md` (copiado el 2026-11-13) | MIT (`sentry/LICENSE`) | Base de tokens de `web/DESIGN.md`: lienzo violeta oscuro, tinta, líneas finas, radios, escala de espaciado y jerarquía del botón primario. |
| `impeccable/craft-floor.md`, `impeccable/operate.md` | [pbakaus/impeccable](https://github.com/pbakaus/impeccable), `.agent/skills/impeccable/reference/` (v4.9.0) | Apache 2.0 (`impeccable/LICENSE`) | Lista de comprobación y patrones que se rechazan. |

## Qué no se copió

- El `SKILL.md` de impeccable: arranca un ejecutable (`scripts/impeccable context`) y concede permiso a
  `npx impeccable`. La decisión D5 fue usar solo el texto.
- Las referencias `audit.md` y `critique.md`: dependen del detector binario.

## Qué se descartó del DESIGN.md de Sentry

El archivo describe la web de marketing, no el producto. Se descartó todo lo que la sección 4.4 de la
especificación prohíbe o que no encaja en una herramienta de trabajo: el acento lima `#c2ef4e` y el rosa
`#fa7faa` ("casi negro con un acento ácido"), las etiquetas en mayúsculas con tracking (botones y "eyebrows"),
las mascotas, el fondo estrellado, el halo del botón y la tipografía display. Ver `web/DESIGN.md`.
