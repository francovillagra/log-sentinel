import json

from engine.detectors.base import Detector
from engine.engine import Engine
from engine.parsers.base import Parser
from engine.parsers.nginx import NginxCombinedParser
from tests.engine.helpers import new_engine, nginx_line


class Roto(Detector):
    def inspect(self, event):
        raise RuntimeError("falla siempre")


class ParserRoto(Parser):
    def parse_line(self, raw):
        raise ValueError("falla siempre")


def test_un_detector_roto_no_deja_ciego_al_resto():
    eng = new_engine()
    eng._detectors.insert(0, Roto())
    _ev, alerts = eng.process_line(nginx_line("/?id=1+UNION+SELECT+1"))
    assert [a.rule_id for a in alerts] == ["sqli"]
    assert eng.stats["detector_errors"] == 1


def test_un_parser_roto_pasa_al_siguiente():
    eng = Engine([ParserRoto(), NginxCombinedParser()], [])
    ev, _ = eng.process_line(nginx_line("/"))
    assert ev is not None and eng.stats["parser_errors"] == 1


def test_lineas_que_no_se_entienden_se_cuentan_y_no_fallan():
    eng = new_engine()
    for raw in ["", "basura", "{", "[]", "1.2.3.4"]:
        assert eng.process_line(raw) == (None, [])
    assert eng.stats["skipped"] == 5


def test_una_linea_mas_larga_que_el_tope_se_omite_y_se_cuenta():
    eng = Engine([NginxCombinedParser()], [], max_line_chars=200)
    assert eng.process_line(nginx_line("/", ua="x" * 1000)) == (None, [])
    assert eng.stats["truncated"] == 1 and eng.stats["skipped"] == 1 and eng.stats["parsed"] == 0
    ev, _ = eng.process_line(nginx_line("/", ua="x"))  # una corta sí se analiza
    assert ev is not None and eng.stats["parsed"] == 1


def test_el_relleno_con_bytes_altos_no_saca_el_payload_del_analisis():
    # nginx escribe cada byte no ASCII como `\xHH` (4 caracteres): una URL de 8 KB de bytes altos ocupa ~32 KB en el log.
    # Un tope de línea más chico que eso dejaría a un atacante esconder su ataque detrás de relleno; con el tope por defecto no.
    eng = new_engine()
    relleno = r"\xc3\xa9" * 12_000  # 96 000 caracteres de log
    ev, alerts = eng.process_line(nginx_line(f"/{relleno}?id=1+UNION+SELECT+1"))
    assert ev is not None and eng.stats["truncated"] == 0
    assert "sqli" in [a.rule_id for a in alerts]


def test_una_entidad_html_gigante_no_ciega_a_los_detectores():
    eng = new_engine()
    _ev, alerts = eng.process_line(nginx_line("/?a=&#" + "1" * 5_000 + "&id=1+UNION+SELECT+1"))
    assert "sqli" in [a.rule_id for a in alerts]
    assert eng.stats["detector_errors"] == 0


def test_json_ok():
    ev, alerts = new_engine().process_line(json.dumps({"remote_addr": "9.9.9.9", "request": "GET /?a=<script> HTTP/1.1", "status": 200}))
    assert ev is not None and [a.rule_id for a in alerts] == ["xss"]
