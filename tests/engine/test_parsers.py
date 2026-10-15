import json
from datetime import datetime

import pytest

from engine.parsers.jsonl import JsonLinesParser
from engine.parsers.nginx import NginxCombinedParser, split_request_line
from tests.engine.helpers import nginx_line

nginx = NginxCombinedParser()
jsonl = JsonLinesParser()


def test_nginx_linea_normal():
    ev = nginx.parse_line(nginx_line("/a/b?x=1&y=2", status=404, ua="curl/8", ip="198.51.100.7", time="02/Feb/2026:10:30:00 +0200"))
    assert (ev.src_ip, ev.method, ev.path, ev.query, ev.status, ev.user_agent) == ("198.51.100.7", "GET", "/a/b", "x=1&y=2", 404, "curl/8")
    assert ev.ts == datetime(2026, 2, 2, 8, 30, 0)  # pasada a UTC


def test_nginx_peticion_con_espacios_no_pierde_nada():
    # nginx registra tal cual las peticiones mal formadas (las que responde con 400): lo que hay entre método y protocolo es la ruta
    ev = nginx.parse_line(nginx_line("/?id=1 UNION SELECT 1", status=400))
    assert ev.path == "/" and ev.query == "id=1 UNION SELECT 1"


def test_nginx_peticion_sin_protocolo_y_basura_binaria():
    assert nginx.parse_line(nginx_line("/viejo", proto="")).path == "/viejo"
    ev = nginx.parse_line('1.2.3.4 - - [01/Jan/2026:12:00:00 +0000] "\\x16\\x03\\x01\\x02\\x00" 400 150 "-" "-"')
    assert ev is not None and ev.status == 400 and ev.path == ""


def test_nginx_lineas_que_no_son_nginx():
    for raw in ["", "hola", "1.2.3.4 - - [mala fecha] \"GET / HTTP/1.1\" 200 1 \"-\" \"x\"", "{}", "1.2.3.4 - -"]:
        assert nginx.parse_line(raw) is None


@pytest.mark.parametrize("request_line, esperado", [
    ("GET / HTTP/1.1", ("GET", "/")),
    ("GET /a?b=1 HTTP/2.0", ("GET", "/a?b=1")),
    ("POST /x y z HTTP/1.0", ("POST", "/x y z")),
    ("GET /", ("GET", "/")),
    ("GET HTTP/1.1", ("GET", "")),
    ("", ("-", "")),
    ("A" * 100 + " /x", ("A" * 16, "/x")),
])
def test_split_request_line(request_line, esperado):
    assert split_request_line(request_line) == esperado


def test_jsonl_linea_normal():
    ev = jsonl.parse_line(json.dumps({"time": "2026-01-01T12:00:00Z", "remote_addr": "10.0.0.1", "request": "GET /x?y=1 HTTP/1.1",
                                      "status": 403, "http_user_agent": "sqlmap", "body_bytes_sent": 12, "referer": "-"}))
    assert (ev.src_ip, ev.method, ev.path, ev.query, ev.status, ev.user_agent, ev.bytes_sent, ev.referer) == \
           ("10.0.0.1", "GET", "/x", "y=1", 403, "sqlmap", 12, None)


POISON = [
    {"request": 123},
    {"request": ["GET", "/"]},
    {"request": None},
    {"remote_addr": ["1.1.1.1"], "request": "GET /../../etc/passwd HTTP/1.1"},
    {"remote_addr": {"a": 1}, "request": "GET /?q=<script> HTTP/1.1"},
    {"http_user_agent": 5},
    {"http_user_agent": {"x": 1}},
    {"status": "abc"},
    {"status": None},
    {"status": [1]},
    {"time": 1700000000},
    {"time": {"a": 1}},
    {"referer": 7},
    {"body_bytes_sent": "x"},
    {"body_bytes_sent": 10 ** 400},
    {"status": True},
]


@pytest.mark.parametrize("obj", POISON, ids=lambda o: json.dumps(o)[:50])
def test_jsonl_con_tipos_raros_nunca_lanza(obj):
    ev = jsonl.parse_line(json.dumps(obj))
    assert ev is None or isinstance(ev.src_ip, str) and isinstance(ev.user_agent, str) and isinstance(ev.status, int)


def test_jsonl_anidado_hasta_desbordar_no_lanza():
    assert jsonl.parse_line("{" + '"a":' * 5000 + "1" + "}" * 5000) is None


def test_jsonl_no_objeto_o_roto():
    for raw in ["{", "{'a': 1}", '{"a": 1', "[1, 2]", "texto", ""]:
        assert jsonl.parse_line(raw) is None
