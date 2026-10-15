from typing import Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field, model_validator

from api.config import max_ingest_lines
from api.dependencies import verify_api_key
from api.services.alerts_db import schedule_save
from api.services.stream import write_alert
from engine.models import Alert

router = APIRouter(prefix="/api/v1", dependencies=[Depends(verify_api_key)])


class IngestRequest(BaseModel):
    line: Optional[str] = None
    # Tope de líneas por pedido (MAX_INGEST_LINES): el motor las procesa una tras otra dentro del pedido. El tamaño
    # de cada línea lo acota el tope del cuerpo (MAX_REQUEST_BYTES) y el motor salta y cuenta las demasiado largas.
    lines: Optional[list[str]] = Field(default=None, max_length=max_ingest_lines())

    @model_validator(mode="after")
    def _at_least_one(self) -> "IngestRequest":
        if self.line is None and not self.lines:
            raise ValueError("provide 'line' or 'lines'")
        return self

    def get_lines(self) -> list[str]:
        if self.lines:
            return self.lines
        return [self.line]  # type: ignore[list-item]


class AlertOut(BaseModel):
    rule_id: str
    severity: str
    src_ip: str
    title: str
    description: str
    evidence: str
    ts: str


class IngestResponse(BaseModel):
    processed: int
    alerts_fired: int
    alerts: list[AlertOut]


def _alert_to_dict(a: Alert) -> dict:
    return {
        "rule_id": a.rule_id,
        "severity": a.severity.value,
        "src_ip": a.src_ip,
        "title": a.title,
        "description": a.description,
        "evidence": a.evidence,
        "ts": a.ts.isoformat(),
    }


@router.post("/ingest", response_model=IngestResponse)
async def ingest(body: IngestRequest, request: Request) -> IngestResponse:
    engine = request.app.state.engine
    redis = request.app.state.redis
    processed = 0
    alerts_out: list[AlertOut] = []

    for raw in body.get_lines():
        if not raw.strip():
            continue
        processed += 1
        _event, alerts = engine.process_line(raw)
        for alert in alerts:
            await write_alert(redis, alert)
            # Persist to Postgres fire-and-forget: a DB write must never block
            # the HTTP response nor fail ingestion. Acotado: ver schedule_save.
            schedule_save(request.app.state.db_pool, alert)
            alerts_out.append(AlertOut(**_alert_to_dict(alert)))

    return IngestResponse(
        processed=processed,
        alerts_fired=len(alerts_out),
        alerts=alerts_out,
    )
