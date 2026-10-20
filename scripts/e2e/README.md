# Batería E2E (navegador real)

Complementa a `pytest`: levanta dos instancias de demo con **datos ficticios** (una normal y otra
multi-tenant) y las recorre con Chromium vía Playwright. Nada sale de la máquina salvo los análisis
DNS/subdominios de `example.com`.

| Script | Qué comprueba |
|---|---|
| `ui.py` | Los 19 paneles en escritorio, tablet y móvil (scroll y desbordamiento horizontal), el menú y el botón ☰, y un clic en **cada** botón, selector y fila de cada panel y de cada pestaña de Configuración (con un WebSocket simulado: no lanza análisis reales). Falla con cualquier error JS, error de consola, 5xx o petición fallida que no esté en la lista de esperados |
| `roles.py` | Lector y operador: ningún 403 al navegar y pulsar, lo no permitido aparece bloqueado y la pestaña Usuarios oculta |
| `multitenant.py` | El superadmin crea una organización desde la UI, cambia a ella y la da de baja; su admin entra con el campo Organización, no ve nada de la plataforma y puede pulsar todo sin errores |
| `functional.py` | ~120 pruebas contra el backend real: cabeceras, CSRF, login, cookies, RBAC, validación WS, análisis reales (hardening, malware con webshell plantada, código con secretos plantados, TLS, cabeceras y exposición web contra una web local con `.git`/`.env`, DNS, red…), toda la API, informe PDF real, cuarentena y restauración, agentes, organizaciones, 2FA de principio a fin y rate limit |

## Ejecutar

```bash
python3 -m venv /tmp/pw && /tmp/pw/bin/pip install playwright && /tmp/pw/bin/playwright install chromium
CH_PYTHON=.venv/bin/python E2E_PYTHON=/tmp/pw/bin/python scripts/e2e/run.sh
```

- `CH_PYTHON`: Python con CyberHound instalado (`pip install -e .`).
- `E2E_PYTHON`: Python con Playwright.
- `CH_E2E_CHROME`: ruta a un Chrome/Chromium propio (opcional).
- Puertos: `CH_E2E_PORT` (18443; la instancia multi-tenant usa el siguiente) y `CH_E2E_WEB_PORT` (18080).

Termina con código 0 si todo pasa. Los objetivos controlados los genera `targets.py` en un directorio
temporal (una webshell, secretos falsos y una web con `.git`/`.env`), y `seed.py` siembra el historial
de demo. Todo se borra al acabar.
