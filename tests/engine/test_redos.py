"""Ningún patrón ni parser del motor puede volverse cuadrático con texto hostil.

Los patrones corren sobre texto que controla el atacante (su URL y su user-agent). Un patrón con retroceso cuadrático convierte
una sola línea de 64 KB en segundos de CPU y deja al servidor entero sin responder (medido en el código anterior: 64 KB de
espacios en una petición = 6 s; 32 KB de `<img` sin cerrar = 0,85 s con el XSS_PATTERN viejo).

Cómo se mide sin que dependa de la velocidad de la máquina: cada entrada se prueba con un tamaño n y con 8n. Si el costo es lineal
la segunda medición tarda ~8 veces más; si es cuadrático, ~64 veces. Se toma el mejor de 3 intentos (descarta pausas del
sistema) y se exige que 8n cueste menos de 20 veces n (más una pequeña holgura para tiempos de microsegundos), además de un
techo absoluto generoso para el tamaño máximo de línea.
"""
import json
import re
import time
from typing import Callable

import pytest

from engine.rules import (
    BRUTE_FORCE_CONFIG,
    MAX_LINE_CHARS,
    PATH_TRAVERSAL_PATTERN,
    SQLI_PATTERN,
    SUSPICIOUS_UA_PATTERN,
    XSS_PATTERN,
)
from tests.engine.helpers import new_engine, nginx_line

CHICO = 8_000
GRANDE = 8 * CHICO  # 64 000 caracteres
FACTOR_LINEAL = 20  # lineal = 8; cuadrático = 64
HOLGURA = 0.02  # segundos: por debajo de esto las diferencias son ruido
TECHO_ABSOLUTO = 1.0  # segundos para procesar una línea del tamaño máximo (en la práctica: decenas de milisegundos)

# Entradas que arman el peor caso de cada familia de patrones: el mismo inicio repetido sin llegar a completar el ataque, tiras
# largas de lo que un cuantificador se come (espacios, dígitos, `/`) y comienzos de construcciones que nunca se cierran.
HOSTILES: dict[str, Callable[[int], str]] = {
    "espacios": lambda n: " " * n + "x",
    "tabuladores": lambda n: "\t" * n + "x",
    "img_sin_cerrar": lambda n: "<img" * (n // 4),
    "svg_sin_cerrar": lambda n: "<svg " * (n // 5),
    "menor_y_espacios": lambda n: "<" + " " * n + "x",
    "menor_espacio_repetido": lambda n: "< " * (n // 2),
    "evento_sin_igual": lambda n: "onerror " * (n // 8),
    "evento_y_espacios": lambda n: "onerror" + " " * n + "x",
    "javascript_y_espacios": lambda n: "javascript" + " " * n + "x",
    "javascript_repetido": lambda n: "javascript " * (n // 11),
    "data_y_espacios": lambda n: "data:" + " " * n + "x",
    "union_y_espacios": lambda n: "union" + " " * n + "x",
    "union_repetido": lambda n: "union " * (n // 6),
    "union_all_repetido": lambda n: "union all " * (n // 10),
    "or_y_espacios": lambda n: "or" + " " * n + "x",
    "or_y_digitos": lambda n: "or " + "1" * n,
    "or_digito_repetido": lambda n: "or 1 " * (n // 5),
    "and_digito_igual_repetido": lambda n: "and 1=" * (n // 6),
    "comilla_y_espacios": lambda n: "'" + " " * n + "x",
    "comilla_espacio_repetido": lambda n: "' " * (n // 2),
    "comilla_or_repetido": lambda n: "' or " * (n // 5),
    "guiones_y_espacios": lambda n: "--" + " " * n + "x",
    "guiones_repetidos": lambda n: "-- x" * (n // 4),
    "punto_y_coma_drop": lambda n: ";" + " " * n + "drop x",
    "punto_y_coma_repetido": lambda n: "; drop " * (n // 7),
    "cast_y_espacios": lambda n: "cast" + " " * n + "x",
    "cast_repetido": lambda n: "cast " * (n // 5),
    "exec_y_espacios": lambda n: "exec" + " " * n + "x",
    "sleep_repetido": lambda n: "sleep " * (n // 6),
    "into_repetido": lambda n: "into " * (n // 5),
    "into_y_espacios": lambda n: "into" + " " * n + "x",
    "barras": lambda n: "/" * n,
    "puntos": lambda n: "." * n,
    "punto_punto_sin_barra": lambda n: ".." * (n // 2),
    "punto_punto_barra": lambda n: "../" * (n // 3),
    "etc_repetido": lambda n: "/etc/" * (n // 5),
    "env_repetido": lambda n: "/.env" * (n // 5) + "x",
    "porcentajes": lambda n: "%25" * (n // 3),
    "porcentaje_invalido": lambda n: "%" * n,
    "porcentajes_hex": lambda n: "%2e%2e%2f" * (n // 9),
    "entidades_numericas": lambda n: "&#" * (n // 2),
    "entidades_con_digitos": lambda n: "&#1" * (n // 3),
    "entidades_con_ceros": lambda n: "&#" + "0" * n + "1",
    "entidades_largas": lambda n: "&" + "a" * n,
    "entidades_amp": lambda n: "&amp;" * (n // 5),
    "comentarios_sql_abiertos": lambda n: "/*" * (n // 2),
    "comentarios_sql_cerrados": lambda n: "/**/" * (n // 4),
    "comentarios_sql_asteriscos": lambda n: "/*" + "*/*" * (n // 3),
    "comentarios_version": lambda n: "/*!50000 " * (n // 9),
    "nul": lambda n: "\x00" * n,
    "letras": lambda n: "a" * n,
    "ua_sospechoso_repetido": lambda n: "sqlmap " * (n // 7),
    "ua_prefijos": lambda n: "sqlma nikt nma nucle gobust " * (n // 28),
    "comillas_escapadas": lambda n: r"\x22" * (n // 4),
    "bytes_altos_escapados": lambda n: r"\xc3\xa9" * (n // 8),
}

PATRONES = {
    "sqli": SQLI_PATTERN,
    "xss": XSS_PATTERN,
    "path_traversal": PATH_TRAVERSAL_PATTERN,
    "user_agent": SUSPICIOUS_UA_PATTERN,
    "ruta_de_login": BRUTE_FORCE_CONFIG.auth_path_pattern,
}


def mejor_tiempo(fn: Callable[[], object], intentos: int = 3) -> float:
    mejor = float("inf")
    for _ in range(intentos):
        t = time.perf_counter()
        fn()
        mejor = min(mejor, time.perf_counter() - t)
    return mejor


def comprobar_lineal(medir: Callable[[int], float], nombre: str) -> None:
    chico = medir(CHICO)
    # Si el tamaño chico ya es lento no se sigue: una regresión cuadrática tardaría minutos en el grande.
    assert chico < TECHO_ABSOLUTO, f"{nombre}: {CHICO} caracteres tardaron {chico:.3f} s"
    grande = medir(GRANDE)
    assert grande < TECHO_ABSOLUTO, f"{nombre}: {GRANDE} caracteres tardaron {grande:.3f} s"
    assert grande <= chico * FACTOR_LINEAL + HOLGURA, (
        f"{nombre}: {CHICO} -> {chico:.4f} s, {GRANDE} -> {grande:.4f} s (x{grande / max(chico, 1e-9):.0f}; lineal es x8, cuadrático x64)"
    )


# --- cada patrón por separado ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize("hostil", HOSTILES)
@pytest.mark.parametrize("patron", PATRONES)
def test_el_patron_es_de_tiempo_lineal(patron: str, hostil: str) -> None:
    regex: re.Pattern[str] = PATRONES[patron]
    generar = HOSTILES[hostil]

    def medir(n: int) -> float:
        texto = generar(n)
        return mejor_tiempo(lambda: regex.search(texto))

    comprobar_lineal(medir, f"{patron} x {hostil}")


# --- el recorrido completo de una línea (parser + normalización + todos los detectores) -----------------------------------

def _linea_nginx_en_la_ruta(texto: str) -> str:
    return nginx_line("/" + texto)


def _linea_nginx_en_la_query(texto: str) -> str:
    return nginx_line("/p?q=" + texto)


def _linea_nginx_en_el_user_agent(texto: str) -> str:
    return nginx_line("/", ua=texto)


def _linea_json(texto: str) -> str:
    return json.dumps({"remote_addr": "203.0.113.5", "request": "GET /p?q=" + texto + " HTTP/1.1", "status": 200,
                       "http_user_agent": texto})


ARMADORES = {
    "nginx-ruta": _linea_nginx_en_la_ruta,
    "nginx-query": _linea_nginx_en_la_query,
    "nginx-user-agent": _linea_nginx_en_el_user_agent,
    "json": _linea_json,
}

# Los hostiles que contienen comillas dobles o saltos de línea rompen el formato de la línea (nginx los escapa), así que acá solo
# van los que son válidos tal cual en una línea.
HOSTILES_DE_LINEA = {k: v for k, v in HOSTILES.items() if k not in {"nul", "tabuladores"}}


@pytest.mark.parametrize("hostil", HOSTILES_DE_LINEA)
@pytest.mark.parametrize("armador", ARMADORES)
def test_procesar_una_linea_hostil_es_de_tiempo_lineal(armador: str, hostil: str) -> None:
    armar = ARMADORES[armador]
    generar = HOSTILES_DE_LINEA[hostil]

    def medir(n: int) -> float:
        # un motor nuevo por intento: el de brute_force/rate_anomaly guarda estado por IP
        linea = armar(generar(n))

        def una_vez() -> None:
            new_engine().process_line(linea)

        return mejor_tiempo(una_vez)

    comprobar_lineal(medir, f"{armador} x {hostil}")


@pytest.mark.parametrize("armador", ARMADORES)
def test_una_linea_del_tamano_maximo_se_procesa_en_milisegundos(armador: str) -> None:
    # Lo peor que puede mandar un servidor web real: una línea que casi llega al tope, con el patrón más caro de cada familia.
    armar = ARMADORES[armador]
    peor = 0.0
    for generar in HOSTILES_DE_LINEA.values():
        n = MAX_LINE_CHARS - 400
        linea = armar(generar(n))
        while len(linea) > MAX_LINE_CHARS:  # el json repite el texto (petición y user-agent) y escapa las barras invertidas
            n //= 2
            linea = armar(generar(n))
        eng = new_engine()
        t = time.perf_counter()
        eng.process_line(linea)
        peor = max(peor, time.perf_counter() - t)
        assert eng.stats["truncated"] == 0
        assert eng.stats["detector_errors"] == 0 and eng.stats["parser_errors"] == 0
    assert peor < TECHO_ABSOLUTO, f"{armador}: la línea más lenta tardó {peor:.3f} s"
