# Despliegue gratis paso a paso: Neon + Google + Render

Resultado final: la app en `https://<servicio>.onrender.com`, con login de Google, la base de
datos en Neon y el worker de escaneos dentro del mismo contenedor. Todo lo de Render está en
[`render.yaml`](../render.yaml).

**Orden:** Neon → Google → Render → comprobar. Tiempo aproximado: 30–45 min la primera vez.

> **Secretos.** La cadena de conexión de Neon y el secreto de Google van **solo** en los
> paneles de Render. No los pegues en el repositorio, en issues ni en chats.

Las etiquetas de los botones se tomaron de la documentación oficial (fuentes al final, consultadas
el 14 de noviembre de 2026). Si una pantalla ha cambiado, el nombre del botón puede variar.

---

## 0. Qué implica el plan gratis

| Servicio | Límite | Qué notarás |
|---|---|---|
| Render web free | 512 MB de RAM, 0,1 CPU, 750 h/mes por workspace [R1][R2] | Escaneos más lentos. Probado en local con esos límites: ~350 archivos en ~2 min, con un pico de 387 MB. |
| | Se duerme tras **15 min** sin peticiones y tarda ~1 min en despertar [R1] | La primera visita tras dormir tarda 1–2 min: despierta Render y luego arranca la app (~50 s con 0,1 CPU). |
| | Sin workers de fondo gratis [R1] | Por eso web y worker comparten contenedor (`docker/start-embedded.sh`). |
| | Puede reiniciarse en cualquier momento [R1] | Un escaneo cortado vuelve a la cola a los 2 min (reaper) y se repite solo. |
| Render Key Value free | Solo en memoria, se pierde al reiniciar; uno por workspace [R1] | Solo guarda los contadores del limitador de peticiones. |
| Neon free | 1 GB por proyecto; 100 CU-hora/mes; se suspende tras **5 min** sin uso (no se puede desactivar) [N1] | La primera consulta tras suspenderse tarda un poco más. |

Límites de escaneo en Render (en `render.yaml`), medidos con 512 MB y 0,1 CPU:

| Límite | Valor | Notas |
|---|---|---|
| ZIP subido | 25 MB | |
| Repositorio de GitHub | 40 MB descargados | |
| Total descomprimido | 150 MB | |
| Archivos de código | 5000 | Solo cuenta el código analizable: imágenes, documentación, pruebas, dependencias y minificados no cuentan y se descartan al descomprimir. |
| Tiempo de análisis | 300 s | Si se agota, el escaneo termina con un **resultado parcial** («se analizaron X de Y archivos»). |

Medición (contenedor con `--memory=512m --cpus=0.1`, igual que Render free):

| Repositorio | Archivos analizados | Tiempo | Pico de RAM |
|---|---:|---:|---:|
| En reposo | — | — | 218 MB |
| sqlalchemy/sqlalchemy | 344 | 125 s | 350 MB |
| django/django | 1143 | 107 s | 353 MB |
| Mismo commit de sqlalchemy, otro usuario | 344 (caché) | 9 s | 353 MB |

Con muchos usuarios a la vez, la cola atiende primero el código pegado y los ZIP pequeños, da
turnos por usuario y muestra cuántos escaneos hay delante. Si varios escanean el mismo commit, el
análisis se hace una sola vez y el resto reutiliza el resultado.

---

## Antes de empezar

- [ ] **La CI está en verde** en la rama que vas a desplegar: en GitHub, pestaña **Actions**,
      el último run del workflow `ci-quality.yml` con todos los trabajos en verde (backend en SQLite y en
      PostgreSQL, web, autoanálisis e «Imagen Docker arranca»). Ese último trabajo arranca la
      imagen igual que Render: si falla ahí, fallará en Render.
- [ ] **Rama:** lo recomendable es fusionar `refactor/fases` en `main` con un pull request y
      desplegar `main`. Render vuelve a desplegar en cada push a la rama enlazada
      (`autoDeployTrigger: commit`), así que conviene que sea una rama estable.
- [ ] Tienes a mano un **gestor de contraseñas** para guardar la cadena de Neon y el secreto de
      Google mientras los copias de un panel a otro.

---

## 1. Base de datos en Neon

1. Entra en <https://console.neon.tech> y crea una cuenta (puedes usar tu cuenta de GitHub o
   de Google).
2. Crea un proyecto:
   - **Nombre:** `sast-studio`.
   - **Proveedor y región:** AWS, **US East (N. Virginia)**. Es la más cercana a la región
     `virginia` de Render que usa `render.yaml`; así cada consulta no cruza el continente.
   - **Versión de Postgres:** la que proponga por defecto (la app funciona con 16 o superior).
   - Neon crea la base de datos `neondb` y la rama por defecto `production` [N2].
3. Pulsa **Connect** en la barra de navegación. Se abre **Connect to your branch** [N3].
4. Deja la rama, la base de datos (`neondb`) y el rol que vienen seleccionados.
5. **Desactiva el interruptor "Connection pooling"** para obtener la conexión **directa** [N3].
   Comprueba que el host **no** lleva `-pooler`.
6. Copia la cadena. Tiene esta forma [N3]:

   ```text
   postgresql://usuario:contraseña@ep-xxxx-xxxx.us-east-1.aws.neon.tech/neondb?sslmode=require&channel_binding=require
   ```

   Guárdala en un gestor de contraseñas: la usarás en el paso 3.

> **Por qué la directa y no la "pooled":** la app ya mantiene un pool pequeño propio y la cola
> de escaneos usa transacciones con `SELECT … FOR UPDATE SKIP LOCKED`. Un pooler en modo
> transacción no aporta nada aquí y puede dar problemas con sentencias preparadas.

---

## 2. Credenciales de Google (OAuth)

### 2.1 Proyecto y pantalla de consentimiento

1. Ve a <https://console.cloud.google.com> y crea un proyecto (por ejemplo `sast-studio`).
2. Abre **Google Auth Platform**: <https://console.developers.google.com/auth/clients>. Si la
   app aún no está registrada, Google te pide hacerlo antes de crear un cliente [G1].
3. **Branding** [G3]:
   - **App name:** `SAST Studio`.
   - **User support email:** tu correo (o un Grupo de Google que administres).
   - **Developer contact information:** tu correo; ahí llegan los avisos del proyecto.
   - Logo, página de inicio, privacidad y condiciones: déjalos vacíos de momento. Solo son
     obligatorios si pides la verificación de la app [G3].
4. **Audience** [G2]:
   - **User type:** **External** (cualquier cuenta de Google). Usa **Internal** solo si tu
     universidad tiene Google Workspace y el proyecto pertenece a esa organización.
   - **Publishing status:** al crear queda en **Testing**.

> **¿Hace falta publicar o verificar la app?** SAST Studio solo pide los scopes `openid`,
> `email` y `profile`. Según Google, con solo esos scopes no aplican ni la lista de 100 usuarios
> de prueba, ni el aviso, ni la caducidad de 7 días del modo Testing [G2]. Si aun así Google
> bloquea a alguien, añade su correo como usuario de prueba o pulsa **Publish app** [G2].
> Para restringir el acceso a tu universidad, usa `GOOGLE_HOSTED_DOMAIN` (paso 3.4).

### 2.2 Cliente OAuth

1. En **Clients**, pulsa **CREATE CLIENT** [G1].
2. **Application type:** *Web application*.
3. **Name:** `sast-studio-render`.
4. **Authorized JavaScript origins:** déjalo vacío. La app no llama a Google desde el
   navegador; el login lo hace el servidor.
5. **Authorized redirect URIs:** añade exactamente:

   ```text
   https://sast-studio.onrender.com/api/v1/auth/callback
   ```

   Debe ser HTTPS y no puede llevar comodines [G1]. Si en el paso 3 Render te da otra URL
   (cuando el nombre `sast-studio` ya está ocupado, añade un sufijo), vuelve aquí y cámbiala.
6. Pulsa **CREATE**.
7. Copia el **Client ID** y el **Client secret** en tu gestor de contraseñas. **El secreto solo
   se muestra completo ahora**; después la consola enseña solo los 4 últimos caracteres. Si lo
   pierdes, en el detalle del cliente usa **Add Secret** para generar uno nuevo [G1].

> Los cambios en un cliente OAuth pueden tardar **de 5 minutos a varias horas** en aplicarse
> [G1]. Si justo después falla con `redirect_uri_mismatch`, espera un poco antes de cambiar nada.

---

## 3. Render

### 3.1 Conectar GitHub

1. Crea una cuenta en <https://render.com>.
2. Conecta GitHub: **Account Settings → Account Security → Git Deployment Credentials →
   Add credential → GitHub** y autoriza [R5].
3. El repositorio **NestorSnIbz/sast-studio** es privado: Render solo lo ve si la app de Render
   en GitHub tiene acceso. Si no aparece, abre
   <https://github.com/apps/render/installations/new>, elige tu cuenta y, en
   **Repository access**, incluye `sast-studio` [R5].

### 3.2 Crear todo desde el Blueprint

1. En el Dashboard de Render: **New → Blueprint** [R3].
2. Pulsa **Connect** junto a `NestorSnIbz/sast-studio` [R3].
3. Rellena el formulario:
   - **Nombre del Blueprint:** `sast-studio`.
   - **Rama:** `main` (tras fusionar `refactor/fases`; ver «Antes de empezar»).
   - **Blueprint Path:** déjalo vacío (`render.yaml` está en la raíz) [R3].
4. Render muestra los cambios que va a aplicar: un **web service** `sast-studio` (Docker,
   plan free, región virginia) y un **Key Value** `sast-ratelimit` (free).
5. Te pedirá los valores marcados con `sync: false` en `render.yaml` [R4]:

   | Variable | Valor |
   |---|---|
   | `DATABASE_URL` | La cadena **directa** de Neon (paso 1.6). |
   | `GOOGLE_CLIENT_ID` | El Client ID (paso 2.2). |
   | `GOOGLE_CLIENT_SECRET` | El Client secret (paso 2.2). |

   `SECRET_KEY` y `SESSION_HMAC_KEY` los genera Render solo (`generateValue: true`) [R4].
   `PUBLIC_ORIGIN` no hace falta: la app usa `RENDER_EXTERNAL_URL`, que Render define con la
   URL `https://….onrender.com` del servicio [R6].
6. Pulsa **Deploy Blueprint** [R3].

La primera construcción tarda varios minutos: compila la web y las dependencias de Python
dentro de la imagen. Al arrancar, `docker/start-embedded.sh` aplica las migraciones
(`RUN_MIGRATIONS=1`) y luego lanza Gunicorn y el worker. En el log verás
`start-embedded: aplicando migraciones`, después las líneas de Alembic y `worker listo`.

### 3.3 Revisar la URL

Abre el servicio `sast-studio` y copia su URL. Si no es exactamente
`https://sast-studio.onrender.com`, vuelve al paso 2.2.5 y pon la URL real en la URI de
redirección de Google.

### 3.4 Variables opcionales

En el servicio: **Environment → + Add Environment Variable** y, al guardar, elige
**Save and deploy** [R7].

| Variable | Para qué |
|---|---|
| `GOOGLE_HOSTED_DOMAIN=universidad.edu` | Solo admite cuentas de ese dominio de Google Workspace. |
| `GITHUB_TOKEN` | Solo si GitHub empieza a limitar las descargas: con un token se usa la API autenticada (5000 por hora). Crea un *fine-grained token* sin permisos sobre ningún repositorio; para repos públicos basta. |
| `PUBLIC_ORIGIN=https://tu-dominio` | Si añades un dominio propio (y su URI en Google). |

Cada `git push` a la rama enlazada vuelve a desplegar solo (`autoDeployTrigger: commit`).

---

## 4. Comprobar que funciona

1. **Salud:** `https://<servicio>.onrender.com/readyz` debe devolver
   `{"db":"ok","migrations":"head"}`.
2. **Login:** abre la URL, pulsa **Continuar con Google** y entra. Debes acabar en «Proyectos».
3. **Escaneo:** crea un proyecto y, en «Nuevo escaneo → Repositorio de GitHub», escanea
   `stamparm/DSVW`. Debe terminar con hallazgos (en local, con los mismos límites, tarda ~20 s).
4. **Logs:** en Render, pestaña **Logs**. Al arrancar verás `worker listo`, y después una línea
   JSON por petición. No debe aparecer ningún `Traceback`.
5. **Demo:** con todo en verde, el guion de 5 minutos de [`docs/demo.md`](demo.md) funciona igual
   sobre la URL pública. Despierta el servicio unos minutos antes de presentarlo.

---

## 5. Copias de seguridad

Neon free guarda **6 horas** de historial y permite **1 snapshot manual** [N1]. Para tener tus
propias copias, desde tu equipo (necesitas el cliente de PostgreSQL instalado):

```bash
pg_dump "<cadena directa de Neon>" --format=custom --file=sast-$(date +%F).dump
```

Para restaurar en una base vacía:

```bash
pg_restore --no-owner --dbname "<cadena de la base destino>" sast-AAAA-MM-DD.dump
```

---

## 6. Si algo falla

| Síntoma | Causa probable y solución |
|---|---|
| El deploy no arranca y el log habla de configuración | Falta `DATABASE_URL`, `GOOGLE_CLIENT_ID` o `GOOGLE_CLIENT_SECRET`: en producción son obligatorios. Revísalos en **Environment**. |
| El log muestra `relation "rules" does not exist` y el servicio se reinicia | No se aplicaron las migraciones. Desde el commit que corrige este fallo, `start-embedded.sh` migra solo al arrancar; si lo ves, comprueba que el despliegue usa un commit posterior y que `RUN_MIGRATIONS` no está en `0`. |
| `/readyz` da error de base de datos | La cadena de Neon está mal copiada o es la *pooled* (`-pooler`). Usa la directa. |
| Google dice `redirect_uri_mismatch` | La URI de Google no coincide **exactamente** con `https://<servicio>.onrender.com/api/v1/auth/callback`, o el cambio aún no se aplicó (puede tardar) [G1]. |
| Google bloquea el acceso o dice que la app no está verificada | Añade el correo como usuario de prueba o pulsa **Publish app** en **Audience** [G2]. |
| Tras el login vuelves a la pantalla de acceso con un error | El motivo real está en **Logs** (`login rechazado: …`): por ejemplo, un dominio distinto de `GOOGLE_HOSTED_DOMAIN`. |
| La web tarda 1–2 min en abrir | Estaba dormida: es normal en el plan gratis [R1]. |
| Un escaneo se queda «En curso» | Render reinició el contenedor: a los 2 min vuelve a la cola solo. |
| Un escaneo de GitHub falla con «GitHub limitó las descargas» | Con versiones anteriores al arreglo, la app usaba la API de GitHub sin autenticar: 60 descargas por hora y por IP, y en Render esa IP se comparte con otros servicios. Ahora descarga como el botón «Download ZIP», sin gastar esa cuota. Si aun así ocurre, añade `GITHUB_TOKEN` (paso 3.4). |
| Un repo grande falla por tamaño | Supera los límites de `render.yaml` (40 MB descargados, 150 MB descomprimidos o 5000 archivos de código): están medidos para los 512 MB de RAM. Si se agota el tiempo no falla: queda como resultado parcial. |

---

## Fuentes

- [R1] Render, *Deploy for Free*: <https://render.com/docs/free>
- [R2] Render, *Compute plans*: <https://render.com/docs/compute-plans>
- [R3] Render, *Blueprints (Infrastructure as Code)*: <https://render.com/docs/infrastructure-as-code>
- [R4] Render, *Blueprint YAML Reference*: <https://render.com/docs/blueprint-spec>
- [R5] Render, *Connect GitHub*: <https://render.com/docs/github>
- [R6] Render, *Default Environment Variables*: <https://render.com/docs/environment-variables>
- [R7] Render, *Environment Variables and Secrets*: <https://render.com/docs/configure-environment-variables>
- [N1] Neon, *Pricing*: <https://neon.com/pricing>
- [N2] Neon, *Getting started*: <https://neon.com/docs/get-started/signing-up>
- [N3] Neon, *Connect from any application*: <https://neon.com/docs/connect/connect-from-any-app>
- [G1] Google Cloud, *Manage OAuth Clients*: <https://support.google.com/cloud/answer/15549257>
- [G2] Google Cloud, *Manage App Audience*: <https://support.google.com/cloud/answer/15549945>
- [G3] Google Cloud, *Manage OAuth App Branding*: <https://support.google.com/cloud/answer/15549049>
