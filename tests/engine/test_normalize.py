import time

import pytest

from engine.normalize import MAX_TARGET_CHARS, normalize_target, strip_sql_comments


def decoded(path: str, query: str = "") -> str:
    return normalize_target(path, query).decoded


def test_decodifica_porcentaje_y_mas_solo_en_la_query():
    # `+` es un espacio en una query (formularios) pero un `+` literal en la ruta
    assert decoded("/a+b", "q=x+y%20z") == "/a+b?q=x y z"


@pytest.mark.parametrize("vueltas", [1, 2, 3])
def test_decodifica_codificacion_repetida(vueltas):
    payload = "<script>"
    for _ in range(vueltas):
        payload = "".join(f"%{ord(c):02x}" for c in payload)
    assert decoded("/", f"q={payload}") == "/?q=<script>"


def test_no_decodifica_indefinidamente():
    # cuatro capas de codificación: se pelan tres, el resto queda como texto (el costo por evento tiene un techo)
    payload = "A"
    for _ in range(4):
        payload = "".join(f"%{ord(c):02x}" for c in payload)
    assert decoded("/", payload) != "/?A"


def test_entidades_html_y_nul_y_barra_invertida():
    assert decoded("/", "u=%26%23106%3Bavascript%3A1") == "/?u=javascript:1"
    assert decoded("/", "q=<%00script>") == "/?q=<script>"
    assert decoded("/..\\..\\app") == "/../../app"


@pytest.mark.parametrize(
    "referencia",
    [
        "&#" + "1" * 5_000,  # más de 4300 dígitos: int() lanzaba ValueError y la petición quedaba sin analizar
        "&#" + "0" * 5_000 + "65;",  # los ceros a la izquierda también cuentan para ese límite
        "&#" + "9" * 100_000 + ";",
        "&#" + "0" * 40,  # NUL: U+FFFD, no una excepción
    ],
    ids=["unos", "ceros-y-65", "cien-mil-nueves", "solo-ceros"],
)
def test_una_entidad_numerica_enorme_no_rompe_la_normalizacion(referencia):
    resultado = decoded("/", f"a={referencia}&id=1+UNION+SELECT+1")
    assert resultado.endswith("&id=1 UNION SELECT 1")


def test_las_entidades_numericas_largas_pero_validas_se_siguen_resolviendo():
    # ceros de relleno delante de un número válido: un navegador lo lee igual (`&#0000000106;` es `j`)
    assert decoded("/", "u=&#0000000106;avascript:1") == "/?u=javascript:1"
    assert decoded("/", "u=&#000000000000106avascript:1") == "/?u=javascript:1"


def test_bytes_invalidos_quedan_reconocibles():
    # %c0%ae (el `.` en UTF-8 "largo") no es UTF-8 válido: queda como sustitutos que PATH_TRAVERSAL_PATTERN sabe reconocer
    assert "\udcc0" in decoded("/", "f=%c0%ae%c0%ae/")


def test_ruta_sola_decodificada():
    assert normalize_target("/%6cogin", "next=/x").path == "/login"


def test_el_largo_esta_acotado():
    t = normalize_target("/" + "a" * (MAX_TARGET_CHARS * 4), "")
    assert len(t.decoded) <= MAX_TARGET_CHARS


@pytest.mark.parametrize(
    "entrada, esperado",
    [
        ("UNION/**/SELECT", "UNION SELECT"),
        ("UNION/*comentario largo*/SELECT", "UNION SELECT"),
        ("1/*!50000UNION*/ /*!50000SELECT*/1", "1 UNION   SELECT 1"),
        ("sin comentarios", "sin comentarios"),
        ("abierto /* sin cerrar UNION SELECT", "abierto /* sin cerrar UNION SELECT"),  # sin cierre: se deja tal cual
        ("a/**/b/**/c", "a b c"),
    ],
)
def test_comentarios_sql(entrada, esperado):
    assert strip_sql_comments(entrada) == esperado


def test_comentarios_sql_en_tiempo_lineal():
    # muchos `/*` sin cierre: una regex perezosa sería cuadrática; el recorrido con find() no
    def medir(n: int) -> float:
        texto = "/*a" * n
        t = time.perf_counter()
        strip_sql_comments(texto)
        return time.perf_counter() - t

    chico, grande = min(medir(5_000) for _ in range(3)), min(medir(40_000) for _ in range(3))
    assert grande < 0.25
    assert grande <= chico * 20 + 0.01  # lineal = 8x; cuadrático = 64x
