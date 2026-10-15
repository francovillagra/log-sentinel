"""Normalización de la ruta/query antes de buscar patrones de ataque.

Un atacante no escribe `UNION SELECT` tal cual: lo codifica (`%20`, `+`, `%2520`), lo parte con comentarios (`/**/`) o lo escribe
con entidades HTML. Para que una regla no se evada con un simple cambio de codificación, los detectores no miran el texto
crudo sino esta versión, que sale de aplicar (todo en tiempo lineal, sin expresiones regulares con retroceso):

  1. decodificación porcentual repetida (hasta MAX_DECODE_PASSES veces, hasta que el texto deja de cambiar), con `+` = espacio
     solo en la query (como un formulario);
  2. entidades HTML (`&#106;`, `&lt;`);
  3. NUL fuera (`<scr%00ipt`) y `\\` convertida en `/` (rutas de Windows);
  4. para SQL, además, los comentarios `/* ... */` reemplazados por un espacio (MySQL los trata como espacio) y el contenido
     de los comentarios de versión `/*!50000 ... */` conservado (MySQL lo ejecuta).
"""
import html
import re
import urllib.parse
from dataclasses import dataclass

from engine.rules import MAX_LINE_CHARS

# Tres vueltas cubren la doble y la triple codificación; más no se usa en la práctica y el costo crece con cada una.
MAX_DECODE_PASSES = 3
# La vista normalizada nunca es más larga que una línea (el techo del trabajo por evento). No puede ser menos: un atacante
# rellenaría la URL para dejar su payload más allá del corte.
MAX_TARGET_CHARS = MAX_LINE_CHARS

# `&#` + 8 o más dígitos decimales. html.unescape() los convierte con int(), que lanza ValueError a partir de 4300 dígitos (límite
# de Python, ceros a la izquierda incluidos): sin este paso, `&#` + 5000 dígitos en la query hacía fallar la normalización y dejaba
# ciegos a todos los detectores para esa petición. Se resuelve como lo haría un navegador: ceros a la izquierda fuera y, si el
# número pasa de 0x10FFFF (o es 0), U+FFFD. Con menos de 8 dígitos html.unescape() no puede fallar.
_LONG_DECIMAL_REF = re.compile(r"&#([0-9]{8,});?")


def _resolve_long_ref(match: "re.Match[str]") -> str:
    digits = match.group(1).lstrip("0")
    return f"&#{digits};" if 0 < len(digits) < 8 else "�"


@dataclass(frozen=True)
class Target:
    path: str  # solo la ruta, decodificada (para reconocer rutas de autenticación aunque vengan codificadas)
    decoded: str  # ruta + query decodificadas (para path traversal y XSS)
    sql: str  # lo mismo, con los comentarios SQL resueltos (para SQLi)


def strip_sql_comments(text: str) -> str:
    """Reemplaza cada `/* ... */` por un espacio; en `/*!NNNNN ... */` conserva el contenido (sin la versión)."""
    if "/*" not in text:
        return text
    parts: list[str] = []
    i = 0
    while True:
        start = text.find("/*", i)
        if start < 0:
            parts.append(text[i:])
            break
        end = text.find("*/", start + 2)
        if end < 0:  # comentario sin cerrar: no se toca el resto
            parts.append(text[i:])
            break
        parts.append(text[i:start])
        body = text[start + 2 : end]
        if body.startswith("!"):
            parts.append(" " + body[1:].lstrip("0123456789") + " ")
        else:
            parts.append(" ")
        i = end + 2
    return "".join(parts)


def normalize_target(path: str, query: str) -> Target:
    # surrogateescape: un byte inválido (%c0%ae, el `.` en UTF-8 "largo") queda como un sustituto reconocible por las reglas
    # en vez de convertirse en un carácter de reemplazo que se confunde con cualquier otra cosa.
    for _ in range(MAX_DECODE_PASSES):
        new_path = urllib.parse.unquote(path, errors="surrogateescape")
        new_query = urllib.parse.unquote_plus(query, errors="surrogateescape")
        if new_path == path and new_query == query:
            break
        path, query = new_path, new_query
    clean_path = path[:MAX_TARGET_CHARS].replace("\x00", "").replace("\\", "/")
    text = path + ("?" + query if query else "")
    text = text[:MAX_TARGET_CHARS]
    text = html.unescape(_LONG_DECIMAL_REF.sub(_resolve_long_ref, text))
    text = text.replace("\x00", "").replace("\\", "/")
    return Target(path=clean_path, decoded=text, sql=strip_sql_comments(text))
