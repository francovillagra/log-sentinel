# log-sentinel

**Dashboard de monitoreo de seguridad en tiempo real**

Sistema SIEM liviano de Blue Team que ingiere logs, detecta patrones de ataque en tiempo real mediante reglas personalizadas y transmite alertas a un dashboard live vía WebSocket.

> Parte de una dupla ofensiva/defensiva en mi portfolio junto a [recon-scope](https://github.com/francovillagra/recon-scope).

**🔴 Demo en vivo:** https://log-sentinel-eta.vercel.app

![demo](docs/demo.gif)

---

## Arquitectura

```
POST /api/v1/ingest
(raw log line)
        │
        ▼
┌─────────────────────┐
│  Detection Engine   │
│  (Python)           │
│                     │
│  • brute_force      │
│  • sqli / xss       │
│  • path_traversal   │
│  • suspicious_ua    │
│  • rate_anomaly     │
└──────────┬──────────┘
           │ Alert
           ▼
┌──────────────────────┐
│   Redis Stream       │
│  log_sentinel:alerts │
└──────────┬───────────┘
           │ XREAD BLOCK
           ▼
┌──────────────────────┐
│   broadcast_loop     │
│   (FastAPI async)    │
└──────────┬───────────┘
           │ WebSocket push
           ▼
┌──────────────────────┐
│  Dashboard Next.js   │
│  (Vercel)            │
└──────────────────────┘
```

---

## Reglas de detección

| Rule ID | Tipo | Dispara cuando | Severidad |
|---|---|---|---|
| `brute_force` | Stateful | 5 fallos de auth (401/403) desde la misma IP en 60s | HIGH |
| `sqli` | Stateless | Patrones SQLi en path/query (`UNION SELECT`, `OR 1=1`, `--`) | HIGH |
| `xss` | Stateless | Patrones XSS (`<script`, `onerror=`, `javascript:`) | MEDIUM |
| `path_traversal` | Stateless | Secuencias `../`, variantes encodeadas, rutas sensibles (`.env`, `.git`, `/etc/passwd`) | HIGH |
| `suspicious_ua` | Stateless | User-agents de scanners conocidos (sqlmap, nikto, nuclei, gobuster, masscan) | MEDIUM |
| `rate_anomaly` | Stateful | ≥100 requests desde la misma IP en 10s | MEDIUM |

---

## Stack tecnológico

| Capa | Tecnología |
|---|---|
| Motor de detección | Python 3.11 (stdlib only) |
| API + WebSocket | FastAPI + Uvicorn |
| Autenticación | JWT (PyJWT) |
| Stream de eventos | Redis Streams |
| Persistencia | Supabase (PostgreSQL) |
| Dashboard | Next.js 15 + TypeScript + Tailwind CSS |
| Visualización | Recharts |
| Backend hosting | Railway |
| Frontend hosting | Vercel |

---

## Estructura del proyecto

```
log-sentinel/
├── engine/                  # Motor de detección (Phase 1)
│   ├── models.py            # LogEvent, Alert, Severity
│   ├── rules.py             # Umbrales y patrones regex configurables
│   ├── parsers/             # Nginx/Apache combined + JSON-lines
│   └── detectors/           # brute_force, injection, path_traversal, ua, rate_anomaly
├── api/                     # FastAPI (Phase 2)
│   ├── main.py              # App con lifespan: engine + redis + broadcast_loop
│   ├── dependencies.py      # Validación de API key
│   ├── routes/              # /api/v1/ingest, /ws/alerts, /health
│   └── services/            # redis_client, stream, broadcaster
├── web/                     # Dashboard Next.js (Phase 3)
│   └── src/
│       ├── hooks/           # useAlertStream — WebSocket con exponential backoff
│       └── components/      # ConnectionStatus, SeverityCounters, AlertFeed,
│                            # TimelineChart, TopAttackers
├── cli.py                   # CLI para correr el motor standalone
├── samples/                 # Logs de prueba con ataques embebidos
├── tests/                   # engine/ (motor) y api/ (API contra PostgreSQL real)
├── Dockerfile
├── requirements.txt         # dependencias de producción, versiones fijas
└── requirements-dev.txt     # + pytest
```

---

## Correr localmente

### Motor de detección — sin dependencias externas

```bash
python cli.py samples/access.log

# O vía stdin
cat /var/log/nginx/access.log | python cli.py -
```

### API completa — requiere Redis y PostgreSQL

```bash
pip install -r requirements.txt
psql "$DATABASE_URL" -f schema.sql            # tablas users y alerts
export DATABASE_URL=postgresql://usuario:clave@localhost:5432/logsentinel
export UPSTASH_REDIS_URL=redis://localhost:6379
# La API se niega a arrancar con secretos cortos, repetitivos o de ejemplo. Generá uno distinto para cada variable:
export JWT_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
export INGEST_API_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
export ADMIN_EMAIL=vos@ejemplo.com            # el administrador se crea solo si la tabla users está vacía
export ADMIN_PASSWORD='una-contraseña-larga-y-única'   # 12+ caracteres
uvicorn api.main:app --reload
```

El `.env.example` lista todas las variables (obligatorias, recomendadas y opcionales).

### Dashboard

```bash
cd web
npm install
# Crear web/.env.local:
# NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/alerts
npm run dev
```

### Simulador de tráfico

```bash
INGEST_API_KEY=<your-key> python simulator/run.py

# Genera tráfico continuo (normal + 6 escenarios de ataque) para demos en vivo.
# Variables opcionales:
#   RATE=2.0          requests por segundo (default: 2)
#   ATTACK_RATIO=0.3  proporción de tráfico malicioso (default: 0.3)
```

### Pruebas

```bash
pip install -r requirements-dev.txt
python -m pytest -q                      # el motor y lo que no necesita base de datos
# Las de la API usan PostgreSQL de verdad: una base descartable (el nombre debe incluir "test") con schema.sql aplicado.
TEST_DATABASE_URL=postgresql://usuario:clave@localhost:5432/logsentinel_test python -m pytest -q
```

### Test rápido end-to-end

Con la API corriendo, enviá una línea de log con ataque:

```bash
curl -X POST http://localhost:8000/api/v1/ingest \
  -H "X-API-Key: your-secret-key" \
  -H "Content-Type: application/json" \
  -d '{"line": "10.0.0.1 - - [01/Jan/2026:12:00:00 +0000] \"GET /../../../etc/passwd HTTP/1.1\" 403 0 \"-\" \"sqlmap/1.7\""}'
```

Resultado esperado: `alerts_fired: 2` (`path_traversal` HIGH + `suspicious_ua` MEDIUM) aparecen en el dashboard en tiempo real.

---

## Deploy en producción

| Servicio | Plataforma | URL |
|---|---|---|
| API + WebSocket | Railway | https://log-sentinel-production.up.railway.app |
| Dashboard | Vercel | https://log-sentinel-eta.vercel.app |

**Variables requeridas en Railway:**

```
INGEST_API_KEY=<64 caracteres aleatorios>
JWT_SECRET=<64 caracteres aleatorios, distinto del anterior>
CORS_ORIGINS=https://log-sentinel-eta.vercel.app
DATABASE_URL=<supabase-postgres-connection-string>
ADMIN_EMAIL=<email-del-admin>
ADMIN_PASSWORD=<12+ caracteres; solo hace falta para crear el primer administrador, después se puede sacar>
TRUSTED_PROXY_COUNT=1
```

`INGEST_API_KEY` y `JWT_SECRET` se validan al arrancar: si son cortos, repetitivos o parecen un valor de ejemplo
(`change-me…`), la API no inicia y el log dice cuál es el problema. `TRUSTED_PROXY_COUNT=1` hace que los límites de
intentos cuenten por la IP real del cliente (Railway es un proxy) y no por la del proxy.

Opcional pero recomendado: verificar el certificado de la base de datos. Bajá la CA de Supabase (Database → Settings →
SSL Configuration) y configurá `DATABASE_SSL_CA` (el texto PEM o la ruta al archivo) y `DATABASE_SSL_MODE=verify-full`.
Sin eso la conexión va cifrada pero no se verifica a quién se le habla (`require`, el valor por defecto, que avisa en el log).

Redis corre como servicio interno en el mismo proyecto de Railway — no requiere configuración adicional.

**Variables requeridas en Vercel:**

```
NEXT_PUBLIC_WS_URL=wss://log-sentinel-production.up.railway.app/ws/alerts
NEXT_PUBLIC_API_URL=https://log-sentinel-production.up.railway.app
```

---

## Seguridad

La API y el panel se revisaron como lo haría un atacante y se corrigió lo encontrado. Las correcciones están cubiertas
por pruebas (`tests/api/`: 86, las de login e historial contra PostgreSQL real) que se comprobaron rompiendo cada
protección a propósito, y por el CI (`.github/workflows/`), que además construye la imagen y la levanta.

| Superficie | Qué hace |
|---|---|
| Login | Límite de intentos fallidos por dirección y por dirección + cuenta (429 con `Retry-After`); el hash de bcrypt corre fuera del hilo principal con tope de trabajos y de espera (503 si se satura); un correo inexistente tarda igual que uno real; tope de tamaño de los campos |
| Sesión | JWT HS256 con `exp`, `iat`, `sub`, emisor y audiencia obligatorios; 24 h; el panel cierra la sesión solo si la API la rechaza |
| Ingesta | Clave en `X-API-Key` comparada en tiempo constante; tope de líneas (1000) y de bytes (2 MB) por pedido |
| HTTP | Tope de cuerpo (413) también para cuerpos sin `Content-Length`; cabeceras de seguridad en todas las respuestas, incluidos los errores; CORS solo con los orígenes configurados y sin credenciales; `/docs` y `/openapi.json` solo con `DEBUG=true`; los errores de validación no repiten lo recibido y los 500 son genéricos |
| WebSocket | Token válido + `Origin` permitido; tope de conexiones; un cliente lento no frena a los demás; el token no se escribe en los logs |
| Base de datos | Conexión TLS con verificación opcional (`verify-full`); guardado de alertas en segundo plano acotado |
| Contenedor | Corre sin root, con dependencias fijadas, sin cabecera `Server` |
| Panel (Next.js) | Content-Security-Policy con nonce por pedido (`src/proxy.ts`), cabeceras fijas, `poweredByHeader` apagado; `npm audit` de producción sin vulnerabilidades |

**Límites que quedan, a propósito:** el token de sesión vive en `localStorage` (la CSP estricta reduce el riesgo de XSS
que lo robaría, pero no lo elimina) y viaja en la URL del WebSocket porque el navegador no puede mandar encabezados
ahí (por eso se tacha de los logs). Las alertas no tienen retención: la tabla crece sin límite. Un único usuario
administrador; no hay roles.

---

## Roadmap

- [x] Phase 1 — Motor de detección en Python (CLI, stdlib only)
- [x] Phase 2 — API REST + Redis Streams + WebSocket en Railway
- [x] Phase 3 — Dashboard en tiempo real (Next.js + Recharts) en Vercel
- [x] Phase 4 — Autenticación JWT + persistencia en Supabase + simulador de tráfico
- [x] Phase 5 — README con demo GIF + integración en portfolio

---

## Portfolio

Este proyecto forma parte de una dupla de seguridad:

| Proyecto | Tipo | Descripción |
|---|---|---|
| [recon-scope](https://github.com/francovillagra/recon-scope) | 🔴 Ofensiva | Reconocimiento automatizado para assessments autorizados |
| **log-sentinel** | 🔵 Defensiva | Detección y monitoreo de ataques en tiempo real |

La combinación ilustra el ciclo completo: identificar vectores de ataque (red team) y detectarlos en producción (blue team).

---

## Autor

**Franco Villagra** — Desarrollador Ciberseguridad

- Portfolio: https://francoverse.fvillagra-dev.workers.dev/
- GitHub: [@francovillagra](https://github.com/francovillagra)

## Licencia

Licencia MIT — libre para usar, modificar y distribuir.
