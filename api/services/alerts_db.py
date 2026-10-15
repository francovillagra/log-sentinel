import asyncio
import logging

import asyncpg

from engine.models import Alert

log = logging.getLogger(__name__)


def _row_to_dict(row: asyncpg.Record) -> dict:
    """Shape a DB row like the WebSocket payload so the frontend can merge both."""
    return {
        "rule_id": row["rule_id"],
        "severity": row["severity"],
        "src_ip": row["src_ip"],
        "title": row["title"],
        "description": row["description"],
        "evidence": row["evidence"],
        "ts": row["ts"].isoformat(),
        "stream_id": row["stream_id"],
    }


async def save_alert(pool: asyncpg.Pool, alert: Alert) -> None:
    """
    Persist one alert to Postgres.

    Designed to run fire-and-forget: it never raises — any failure is logged
    so a DB hiccup can't break ingestion.
    """
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO alerts
                    (rule_id, severity, src_ip, title, description, evidence, ts, raw_event)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                """,
                alert.rule_id,
                alert.severity.value,
                alert.src_ip,
                alert.title,
                alert.description,
                alert.evidence,
                alert.ts,
                alert.raw_event,
            )
    except Exception as exc:  # noqa: BLE001 — fire-and-forget, must not propagate
        log.error("save_alert failed: %s", exc)


# Guardados en segundo plano: se guarda una referencia a cada tarea (Python puede descartar una tarea que nadie
# referencia antes de que termine) y hay un tope de pendientes. Con el tope, un flujo de ataques no hace crecer la
# memoria sin límite mientras la base no da abasto: las alertas que no entran en la cola se cuentan y se avisan en el
# log (siguen yendo al stream de Redis, al WebSocket y a la respuesta de /ingest).
MAX_PENDING_SAVES = 500
_pending_saves: set[asyncio.Task] = set()
dropped_saves = 0


def schedule_save(pool: asyncpg.Pool, alert: Alert) -> bool:
    """Programa el guardado de una alerta sin esperar. Devuelve False si se descartó por el tope de pendientes."""
    global dropped_saves
    if len(_pending_saves) >= MAX_PENDING_SAVES:
        dropped_saves += 1
        if dropped_saves == 1 or dropped_saves % 1000 == 0:
            log.warning("save_alert: %d alertas sin guardar en la base (cola llena, %d pendientes)",
                        dropped_saves, len(_pending_saves))
        return False
    task = asyncio.create_task(save_alert(pool, alert))
    _pending_saves.add(task)
    task.add_done_callback(_pending_saves.discard)
    return True


async def get_recent_alerts(pool: asyncpg.Pool, limit: int = 200) -> list[dict]:
    """Return the most recent alerts ordered newest-first. Caps limit at 500."""
    limit = max(1, min(limit, 500))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT rule_id, severity, src_ip, title, description, evidence,
                   ts, raw_event, stream_id, created_at
            FROM alerts
            ORDER BY created_at DESC
            LIMIT $1
            """,
            limit,
        )
    return [_row_to_dict(row) for row in rows]
