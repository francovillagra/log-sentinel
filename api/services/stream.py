import redis.asyncio as aioredis

from engine.models import Alert

STREAM_KEY = "log_sentinel:alerts"
_MAX_LEN = 10_000


def _alert_to_fields(alert: Alert) -> dict[str, str]:
    return {
        "rule_id": alert.rule_id,
        "severity": alert.severity.value,
        "src_ip": alert.src_ip,
        "title": alert.title,
        "description": alert.description,
        "evidence": alert.evidence,
        "ts": alert.ts.isoformat(),
    }


async def write_alert(redis: aioredis.Redis, alert: Alert) -> str:
    """Publish one alert to the Redis Stream with a capped length."""
    fields = _alert_to_fields(alert)
    return await redis.xadd(STREAM_KEY, fields, maxlen=_MAX_LEN, approximate=True)


async def read_new_alerts(
    redis: aioredis.Redis,
    last_id: str,
) -> list[tuple[str, dict]]:
    """
    Read alerts newer than last_id (use '$' on first call to receive only future messages).
    Returns list of (stream_id, alert_dict) tuples.
    """
    entries = await redis.xread({STREAM_KEY: last_id}, count=100, block=500)
    if not entries:
        return []
    _stream_name, messages = entries[0]
    return [(msg_id, fields) for msg_id, fields in messages]
