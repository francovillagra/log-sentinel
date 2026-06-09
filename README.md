# log-sentinel

**Dashboard de monitoreo de seguridad en tiempo real**

Sistema SIEM liviano de Blue Team que ingiere logs, detecta patrones de ataque en tiempo real mediante reglas personalizadas y transmite alertas a un dashboard live vía WebSocket.

> Parte de una dupla ofensiva/defensiva en mi portfolio junto a [recon-scope](https://github.com/francovillagra/recon-scope).

**🔴 Demo en vivo:** https://log-sentinel-eta.vercel.app

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
| Stream de eventos | Redis Streams |
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
├── Dockerfile
└── requirements.txt
```

---

## Correr localmente

### Motor de detección — sin dependencias externas

```bash
python cli.py samples/access.log

# O vía stdin
cat /var/log/nginx/access.log | python cli.py -
```

### API completa — requiere Redis

```bash
pip install -r requirements.txt
export UPSTASH_REDIS_URL=redis://localhost:6379
export INGEST_API_KEY=your-secret-key
uvicorn api.main:app --reload
```

### Dashboard

```bash
cd web
npm install
# Crear web/.env.local:
# NEXT_PUBLIC_WS_URL=ws://localhost:8000/ws/alerts
npm run dev
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
INGEST_API_KEY=<clave-secreta>
CORS_ORIGINS=https://log-sentinel-eta.vercel.app
```

Redis corre como servicio interno en el mismo proyecto de Railway — no requiere configuración adicional.

---

## Roadmap

- [x] Phase 1 — Motor de detección en Python (CLI, stdlib only)
- [x] Phase 2 — API REST + Redis Streams + WebSocket en Railway
- [x] Phase 3 — Dashboard en tiempo real (Next.js + Recharts) en Vercel
- [ ] Phase 4 — Autenticación JWT + persistencia en Supabase + simulador de tráfico
- [ ] Phase 5 — README con demo GIF + integración en portfolio

---

## Portfolio

Este proyecto forma parte de una dupla de seguridad:

| Proyecto | Tipo | Descripción |
|---|---|---|
| [recon-scope](https://github.com/francovillagra/recon-scope) | 🔴 Ofensiva | Reconocimiento automatizado para assessments autorizados |
| **log-sentinel** | 🔵 Defensiva | Detección y monitoreo de ataques en tiempo real |

La combinación ilustra el ciclo completo: identificar vectores de ataque (red team) y detectarlos en producción (blue team).
