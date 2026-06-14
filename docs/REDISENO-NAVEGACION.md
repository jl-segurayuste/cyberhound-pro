# Rediseño de navegación — UI responsive sin scroll lateral

> Fecha: **2026-06-14** · Alcance: `cyberhound/ui/static/{index.html,style.css}`
> Estado: **implementado, QA superado y revisado a nivel de seguridad (CISO)**.

## 1. Problema

La barra superior listaba **19 funciones** como pestañas en una sola fila
horizontal (`.top-nav`). Consecuencias:

- En monitor (escritorio) las pestañas **desbordaban** el ancho → aparecía
  **scroll horizontal a nivel de página**.
- El "responsive" previo resolvía el desbordamiento con `overflow-x: auto` en la
  propia barra → **scroll lateral dentro de la nav** (peor experiencia).

## 2. Solución (sencilla y elegante)

Las 19 funciones se reorganizan en **5 entradas** con menús desplegables, de modo
que la navegación cabe en cualquier pantalla sin scroll:

| Entrada | Funciones |
|---|---|
| **Inicio** | Dashboard |
| **Red** ▾ | Mi Red · Subdominios · DNS Security · Intel |
| **Sistema** ▾ | Seguridad · Malware · Docker · Código · Servicios |
| **Web** ▾ | TLS/SSL · Cabeceras Web · Exposición Web · API / CORS · Nuclei |
| **Gestión** ▾ | Historial · Monitor · Informes · Configuración |

Detalles de diseño:

- Desplegables con `<details>/<summary>` **nativo**: accesible (teclado y táctil)
  y sin dependencias frágiles de JS.
- Estética depurada (línea Apple): **sin iconos** en la navegación, tipografía
  limpia, píldora translúcida para el estado activo, caret fino animado,
  desplegable con esquinas redondeadas y sombra suave.
- **Acordeón**: abrir un grupo cierra los demás; se cierra al elegir una función,
  al pulsar fuera o con `Escape`.
- El grupo que contiene el panel activo se **resalta** (azul + negrita). Se marca
  envolviendo `showPanel` (cubre nav, acciones rápidas y enlaces internos);
  `:has()` queda como mejora progresiva.
- **Móvil**: botón **hamburguesa** (`☰`) que despliega la navegación en vertical;
  los submenús se muestran en línea.
- Garantía dura anti-desbordamiento: `html, body { overflow-x: hidden }`.
- Se conserva intacto el contrato con `app.js`: cada función mantiene su
  `data-panel` y `onclick="showPanel('…')"`.

## 3. QA (navegador headless, Chrome)

**Sin scroll lateral** en todos los anchos probados (`scrollWidth ≤ innerWidth`):

| Viewport | Resultado |
|---|---|
| 1920×1080 | overflow=no |
| 1600×900 | overflow=no |
| 1366×768 | overflow=no |
| 1024×768 | overflow=no |
| 820×1180 (tablet) | overflow=no |
| 390×844 (móvil) | overflow=no |

Funcional verificado:

- Click en una función → cambia de panel (`panel-*.active`) y marca el botón. ✓
- El desplegable se cierra tras seleccionar. ✓
- El grupo activo se resalta en azul (al seleccionar un sub-elemento). ✓
- Desktop: 5 grupos visibles; móvil: hamburguesa. ✓

> Nota técnica: en el resaltado del grupo activo, `color: var(--blue)` no se
> aplicaba sobre `<summary>` en el motor de pruebas (sí el `font-weight`); se usa
> el color **literal** `#58a6ff` para garantizar el render.

## 4. Revisión de seguridad (CISO)

- El cambio es **solo frontend** (HTML/CSS/JS); no toca autenticación, API ni
  manejo de datos.
- El `<script>` inline añadido **solo manipula clases del DOM** (sin `eval`, sin
  `innerHTML`, sin datos de usuario, sin nuevas peticiones de red ni orígenes
  externos) → **no introduce vector XSS**.
- Consistente con la **CSP** vigente (`script-src 'self' 'unsafe-inline'`) y con
  los 186 manejadores `onclick` ya presentes; no amplía la superficie de ataque.
- **Pendiente (pre-existente, no introducido aquí):** la CSP permite
  `'unsafe-inline'` en `script-src`, lo que debilita la defensa anti-XSS. Mejora
  futura: migrar a CSP basada en `nonce`/hash y eliminar los `onclick` inline.

## 5. Archivos

- `cyberhound/ui/static/index.html` — nav reagrupada + script de comportamiento.
- `cyberhound/ui/static/style.css` — estilos de la nav (grupos, desplegables,
  hamburguesa), guard `overflow-x`, ajustes responsive.

---

## 6. Limpieza visual (estilo Apple, menos iconos) — 2026-06-14

A petición de "interfaz sencilla y elegante, sin sobrecarga de iconos":

- **Sin emojis decorativos** en toda la UI (`index.html` y `app.js`): cabeceras,
  títulos de tarjetas, etiquetas, botones, estados vacíos, toasts y logs.
- **Se conservan** glifos monocromos funcionales (✓ ✗ ✕ ⚠ ↻ ⬇) y el **formato
  de informes** (`─ ═`), que no son decoración.
- El indicador de auto-fix (antes `⚡`) pasa a una etiqueta de texto sutil
  `Auto-fix` (`.fix-tag`).
- Botones de "Acciones rápidas": se elimina el hueco del icono vacío (rejilla a
  2 columnas + ocultar `span:empty`).
- Verificación: `node --check app.js` OK; ningún emoji decorativo se usa en
  lógica (solo en cadenas de presentación), así que no se altera el
  comportamiento.

## 7. Fix — la cabecera de Historial tapaba información

**Síntoma:** en la pestaña **Historial**, con datos, la cabecera sticky de la
tabla (`thead`) **solapaba la primera fila** y aparecía una caja vacía.

**Causa:** el panel tenía **dos `<div style="overflow-y:auto;flex:1">` anidados**
(sin altura definida, en un contenedor no-flex). Esos `overflow:auto` creaban un
contexto de scroll roto al que se anclaba el `thead position:sticky; top:0`, en
vez de a `#main`.

**Corrección:** se convierten esos wrappers en `<div>` planos. Ahora el `thead`
sticky se fija correctamente bajo la barra superior (`#main` como contenedor de
scroll), sin solapar filas ni dejar huecos. Verificado con datos inyectados y
scroll en navegador headless.

> Nota: el panel arrastra un `id="history-trend-wrap"` **duplicado** (dos
> elementos ocultos). No afecta al render; pendiente de limpieza menor futura.
