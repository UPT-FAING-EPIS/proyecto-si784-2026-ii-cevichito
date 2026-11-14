# DESIGN.md · SAST Studio

Sistema visual de la interfaz web. Deriva del DESIGN.md de Sentry publicado en
[VoltAgent/awesome-design-md](https://github.com/VoltAgent/awesome-design-md) (MIT; copia en
`design/referencias/sentry/`), con el acento neutralizado y adaptado a una herramienta de trabajo
(decisión D6). Las reglas de rechazo vienen de la sección 4.4 de la especificación y del texto de
impeccable (`design/referencias/impeccable/`, decisión D5).

Los valores de este documento son la fuente de `src/styles/tokens.css`. Si cambias uno, cambia los dos;
`src/test/design-rules.test.ts` comprueba el contraste de los pares de color y busca los patrones prohibidos
en el código.

## 1. Tema

- **Modo:** operar. La gente viene a revisar hallazgos y corregirlos, no a que la convenzan. Prima la lectura
  rápida de tablas, la consistencia y los atajos.
- **Polaridad:** claro y oscuro completos. Por defecto se sigue `prefers-color-scheme`; el usuario puede fijarlo
  en Ajustes. El oscuro conserva el violeta medianoche de Sentry, pero desaturado.
- **Densidad:** media. Texto base de 16 px, celdas de tabla de 14 px y controles de 32 px. Se subió desde 14 px tras probarla en portátil y proyector: a 14 px costaba leerla en clase.

## 2. Color

### Lienzo y texto

| Token | Claro | Oscuro | Uso | Contraste (claro / oscuro) |
|---|---|---|---|---|
| `--background` | `#ffffff` | `#15121c` | Lienzo | — |
| `--surface` | `#ffffff` | `#1c1825` | Paneles, menús, diálogos | — |
| `--muted` | `#f4f4f7` | `#252030` | Cabecera de tabla, fila activa, código | — |
| `--foreground` | `#1f1633` | `#edecf1` | Texto principal (la "tinta" de Sentry) | 17,2 / 15,7 |
| `--muted-foreground` | `#5d576b` | `#a7a3b3` | Texto secundario | 6,9 / 7,5 |
| `--border` | `#e4e3ea` | `#342e43` | Líneas finas de 1 px (separadores, no controles) | — |
| `--input` | `#8e8a9c` | `#6a6380` | Borde de campos y casillas | 3,4 / 3,3 |
| `--primary` | `#150f23` | `#f1f0f5` | Botón primario (casi negro / invertido) | 18,7 / 16,3 |
| `--primary-foreground` | `#ffffff` | `#150f23` | Texto del botón primario | — |
| `--ring` | `#3b6fd9` | `#8fb5f2` | Anillo de foco; el único azul del sistema | 4,7 / 8,9 |
| `--destructive` | `#9a1b30` | `#ffa5b3` | Borrar, errores | 8,2 / 9,9 |

**Del original se conserva** el botón primario casi negro que se invierte en oscuro, la tinta violeta como color
de texto, las líneas finas y el azul reservado al foco.
**Se elimina** el lima `#c2ef4e`, el rosa `#fa7faa` y los violetas de acento (`#6a5fc1`, `#422082`,
`#79628c`). Los enlaces se distinguen por el subrayado, no por el color.

### Severidad

Siempre acompañada de texto ("Crítica", "Alta"...) y de un icono con forma distinta por nivel. Nunca solo color.

| Nivel | Fondo chip (claro / oscuro) | Texto (claro / oscuro) | Barra/gráfica (claro / oscuro) | Icono |
|---|---|---|---|---|
| Crítica | `#fce8eb` / `#3b1620` | `#9a1b30` / `#ffa5b3` | `#d32f4c` / `#f0566f` | octógono |
| Alta | `#fdede2` / `#3a2114` | `#94350f` / `#ffb07d` | `#dd6a22` / `#f08a45` | triángulo |
| Media | `#fbf3d5` / `#352a10` | `#7a4a06` / `#f0cd6a` | `#b8870b` / `#d6aa2c` | rombo |
| Baja | `#e7effb` / `#152541` | `#1d4b98` / `#a2c5ff` | `#3a76d0` / `#5b95eb` | círculo |
| Informativa | `#efeef3` / `#27232f` | `#4a4558` / `#c7c3d1` | `#878296` / `#8f8a9e` | info |

Contraste mínimo medido: texto sobre chip 6,6:1; barra sobre lienzo 3,2:1 (AA para gráficos, 1.4.11).

## 3. Tipografía

| Rol | Familia | Tamaño / peso / interlineado |
|---|---|---|
| Título de página | Rubik | 24 px / 600 / 1,25 |
| Título de sección | Rubik | 18 px / 600 / 1,4 |
| Texto | Rubik | 16 px / 400 / 1,5 |
| Celda de tabla, ayuda | Rubik | 14 px / 400 / 1,45 |
| Etiqueta pequeña | Rubik | 13 px / 500 / 1,4 |
| Código, rutas, IDs de regla | Monaco, Menlo, "Ubuntu Mono", ui-monospace | 14 px / 400 / 1,5 |

- Rubik es la familia de interfaz del DESIGN.md de Sentry. Se sirve desde el propio contenedor
  (`@fontsource-variable/rubik`), sin Google Fonts, porque la CSP solo permite `font-src 'self'`.
- Sin tipografía display: es una aplicación, no una portada.
- Números en tablas con `font-variant-numeric: tabular-nums`.
- Texto en frase normal ("Nuevo escaneo"), nunca en mayúsculas sostenidas.

## 4. Componentes

Base: shadcn/ui (Radix + Tailwind v3), copiados en `src/components/ui/`.

| Componente | Regla |
|---|---|
| Botón primario | `--primary` con texto `--primary-foreground`, radio 6 px, alto 32 px (36 px en móvil). Uno por vista. |
| Botón secundario | Borde `--input`, fondo transparente. |
| Botón fantasma | Sin borde; para acciones de fila y barra de herramientas. |
| Campo de texto | Borde 1 px `--input`, radio 6 px, alto 32 px. Foco: anillo 2 px `--ring`. |
| Chip de severidad | Radio 4 px, 12 px / 500, icono + texto. |
| Tabla | Cabecera fija sobre `--muted`, filas de 36 px separadas por `--border`, sin bandas alternas. Virtualizada desde 200 filas. |
| Panel lateral | Hoja a la derecha (Radix Dialog) para el detalle de un hallazgo sin perder la tabla. |
| Bloque de código | Fondo `--muted`, monoespaciada, línea resaltada con `--sev-*-bg` de su severidad. |
| Diálogo | Solo para confirmar acciones destructivas o pedir una justificación obligatoria. |

## 5. Espaciado y retícula

Escala de Sentry, base 4 px: 2 · 4 · 8 · 12 · 16 · 24 · 32. Sin bandas de 96 px.
Barra lateral fija de 224 px en escritorio; menú desplegable bajo 768 px. Contenido a todo el ancho
disponible, con 24 px de margen (16 px en móvil).

## 6. Elevación

Plano por defecto. Solo dos niveles:

| Nivel | Sombra | Uso |
|---|---|---|
| 0 | ninguna | Todo lo que está en el lienzo |
| 1 | `0 4px 12px -2px rgb(0 0 0 / 0.12), 0 2px 4px -2px rgb(0 0 0 / 0.08)` | Menús, diálogos, panel lateral |

## 7. Radios

4 px (chips) · 6 px (botones, campos) · 8 px (paneles y diálogos). Nada más redondeado salvo avatares.

## 8. Movimiento

Solo transiciones funcionales de 150 ms o menos (color de hover, apertura de menús y del panel). Todas se
desactivan con `prefers-reduced-motion: reduce`. Sin animaciones de entrada.

## 9. Prohibido

Comprobado a mano en cada pantalla y, donde se puede, por `src/test/design-rules.test.ts`.

- Degradados en fondos, botones, texto o números (`bg-gradient-*`, `linear-gradient`).
- Rejillas de tarjetas idénticas con sombra suave ("kit de tarjetas SaaS") y tarjetas dentro de tarjetas.
- Borde izquierdo de color como único indicador de estado (`border-l-2` o más en tarjetas y avisos).
- Etiquetas sobre los títulos ("eyebrows"), mayúsculas con tracking amplio, marcadores 01/02/03 y palabras
  del título resaltadas en color.
- La paleta crema/terracota (`#F4F1EA` / `#D97757`), "casi negro con acento ácido" y degradados morado-azul.
- Inter y Space Grotesk.
- Glassmorphism (`backdrop-blur`), emojis en títulos o como iconos, y portadas centradas en pantallas de la
  aplicación.
- Animaciones de hover o de entrada repartidas por la página.
- Estilos en línea (`style={{…}}`) y colores escritos a mano fuera de los tokens. Única excepción: el ancho de
  los segmentos de la barra de severidad y las dimensiones que calcula el virtualizador.
- Monoespaciada como adorno "técnico": solo para código, rutas, IDs de regla y huellas.
- Hero de número grande con degradado o "métricas destacadas" en tarjetas.

## 10. Siempre

- Estados de carga (esqueleto con la forma del contenido), vacío (qué falta y qué hacer) y error (qué pasó, el
  `request_id` y cómo reintentar) en cada vista.
- Foco visible en todos los controles, orden de tabulación lógico y "Saltar al contenido".
- Atajos: `/` busca, `j`/`k` recorren hallazgos, `Enter` abre el detalle, `Ctrl+K` abre la paleta de comandos.
- Selección de texto, cursor, barras de desplazamiento y anillo de foco tomados de los tokens.
- Textos en español, con verbos en los botones ("Lanzar escaneo", "Marcar como falso positivo").
