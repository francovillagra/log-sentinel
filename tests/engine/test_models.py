from datetime import datetime

from engine.models import MAX_ALERT_FIELD_CHARS, Alert, LogEvent, Severity, clean_text


def test_clean_text_neutraliza_control_y_sustitutos():
    assert clean_text("a\x00b", 50) == "a\\x00b"  # un NUL rompe el INSERT en Postgres
    assert clean_text("l1\nl2\r", 50) == "l1\\x0al2\\x0d"
    assert "\udcc0" not in clean_text("x\udcc0y", 50)  # un sustituto suelto rompe la codificación a UTF-8
    clean_text("x\udcc0y", 50).encode("utf-8")  # no lanza


def test_clean_text_corta_y_acepta_cualquier_tipo():
    assert clean_text("a" * 100, 10) == "a" * 9 + "…"
    assert clean_text(12345, 10) == "12345"
    assert clean_text("corto", 10) == "corto"


def test_alert_acota_todos_los_campos():
    gigante = "A" * 1_000_000
    a = Alert(ts=datetime(2026, 1, 1), src_ip=gigante, rule_id="x", severity=Severity.HIGH, title=gigante,
              description=gigante, evidence=gigante, raw_event=gigante)
    for campo, limite in MAX_ALERT_FIELD_CHARS.items():
        assert len(getattr(a, campo)) <= limite, campo


def test_target_se_calcula_una_sola_vez():
    ev = LogEvent(ts=datetime(2026, 1, 1), src_ip="1.1.1.1", method="GET", path="/a", query="q=%20", status=200,
                  user_agent="-", bytes_sent=0, referer=None, raw="x")
    assert ev.target is ev.target
