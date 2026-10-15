"""Umbrales y patrones de detección.

Regla de oro para tocar este archivo: los patrones corren sobre texto que controla el atacante (la URL y el user-agent de sus
propias peticiones), así que ninguno puede tener un cuantificador anidado ni un `[^>]*` sin límite: el tiempo de búsqueda tiene
que crecer de forma lineal con el largo del texto. tests/engine/test_redos.py lo verifica midiendo.
"""
import re
from dataclasses import dataclass, field

# Largo máximo de una línea. Una petición de nginx no pasa de 8 KB y cada cabecera tampoco, pero nginx escribe cada byte no ASCII
# como `\xHH` (4 caracteres), así que una línea real puede llegar a ~100 KB: el tope tiene que quedar por encima de eso, o un
# atacante rellenaría la URL con bytes altos para que su línea no se analice. Con patrones de tiempo lineal, 128 KB cuestan unos
# milisegundos. Una línea más larga no es de un servidor web: se omite y se cuenta (`Engine.stats["truncated"]`).
MAX_LINE_CHARS = 131_072

# Cuántas IPs distintas recuerdan, como máximo, los detectores con estado. Pasado el tope se olvidan las menos recientes.
MAX_TRACKED_IPS = 50_000


@dataclass
class BruteForceConfig:
    # Segmentos que suelen autenticar: /login, /signin, /api/v1/auth/login, /wp-login.php, /oauth/token, /xmlrpc.php, /session...
    auth_path_pattern: "re.Pattern[str]" = field(
        default_factory=lambda: re.compile(
            r"(?:^|/)(?:wp-)?(?:login|signin|sign-in|auth|oauth|session|token|xmlrpc)", re.IGNORECASE
        )
    )
    auth_statuses: frozenset[int] = field(default_factory=lambda: frozenset({401, 403}))
    threshold: int = 5
    window_seconds: int = 60
    max_tracked_ips: int = MAX_TRACKED_IPS


@dataclass
class RateAnomalyConfig:
    threshold: int = 100
    window_seconds: int = 10
    max_tracked_ips: int = MAX_TRACKED_IPS


SQLI_PATTERN = re.compile(
    r"""
    \bunion\b (?:\s+(?:all|distinct))? \s+ select\b |
    \b(?:or|and) \s+ \d+ \s* (?:=|<>|!=|<=|>=|<|>) \s* \d+ \b |
    '\s*(?:or|and)\s+' |
    --\s*(?:$|\s) |
    ;\s*drop\s+(?:table|database) |
    ;\s*delete\s+from |
    ;\s*truncate\s+table |
    xp_cmdshell |
    \bcast\s*\( |
    \bconvert\s*\( |
    \bexec(?:ute)?\s*\( |
    \bwaitfor\s+delay |
    \b(?:sleep|benchmark|pg_sleep)\s*\( |
    \b(?:information_schema|sqlite_master|pg_catalog)\b |
    \b(?:extractvalue|updatexml)\s*\( |
    \bload_file\s*\( |
    \binto\s+(?:out|dump)file\b
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Manejadores de eventos que se usan en payloads XSS. A propósito no hay un `on\w+=` genérico: `online=1`, `once=true` o
# `onboarding=...` son parámetros legítimos.
_EVENT_HANDLERS = (
    "error|load|unload|click|dblclick|mouseover|mouseout|mouseenter|mouseleave|mousemove|mousedown|mouseup|focus|blur|"
    "focusin|focusout|toggle|pointerenter|pointerover|pointerdown|pointermove|animationstart|animationend|"
    "animationiteration|transitionend|begin|wheel|keydown|keyup|keypress|auxclick|contextmenu|pageshow|hashchange|"
    "beforeunload|readystatechange|loadstart|loadeddata|canplay|play|drag|dragstart|drop|copy|cut|paste|submit|input|"
    "change|resize|scroll|search|invalid"
)

# `<img[^>]*onerror` y `<svg[^>]*onload` ya no están: el `[^>]*` sin límite hacía cuadrático el costo con muchos `<img` sin
# cerrar, y `onerror=` / `onload=` ya los cubren los manejadores de arriba.
XSS_PATTERN = re.compile(
    rf"""
    <\s*script |
    \bon(?:{_EVENT_HANDLERS})\s*= |
    \b(?:javascript|vbscript)\s*: |
    \bdata\s*:\s*text/html |
    <\s*(?:iframe|object|embed|svg|img|body|video|audio|details|marquee|math|form|input|style|link|meta|base)\b |
    \beval\s*\( |
    \bdocument\.(?:cookie|location|write|domain) |
    \b(?:alert|confirm|prompt)\s*\( |
    \bexpression\s*\( |
    \bsrcdoc\s*=
    """,
    re.IGNORECASE | re.VERBOSE,
)

# Corre sobre la ruta ya decodificada (engine/normalize.py): `\` ya es `/`, `%2e%2e%2f` ya es `../`, el NUL ya no está.
# Los `\udcXX` son bytes inválidos que dejó la decodificación (%c0%ae, el `.` en UTF-8 "largo": nunca válido).
PATH_TRAVERSAL_PATTERN = re.compile(
    r"""
    \.\./ |
    /etc/(?:passwd|shadow|hosts|group) |
    (?<![^/=&?])\.env(?:[./]|$) |
    (?<![^/=&?])\.git(?:/|$) |
    /proc/self |
    /windows/system32 | \bwin\.ini | \bboot\.ini |
    \.aws/ | \.ssh/ | \bid_rsa | \bwp-config | /web-inf/ | \.ht(?:passwd|access) |
    \b(?:php|file|expect|phar|zip|data|glob)://  |
    [\udcc0\udcc1][\udc80-\udcbf] | \udce0\udc80[\udc80-\udcbf]
    """,
    re.IGNORECASE | re.VERBOSE,
)

SUSPICIOUS_UA_PATTERN = re.compile(
    r"sqlmap|nikto|nmap|nuclei|gobuster|dirbuster|\bdirb\b|masscan|acunetix|zgrab|wfuzz|burpsuite|metasploit|openvas|"
    r"\bffuf\b|fuzz faster u fool|feroxbuster|wpscan|hydra|havij|w3af|skipfish|arachni|jaeles|nessus|netsparker|appscan|"
    r"whatweb|commix|xsstrike|dalfox",
    re.IGNORECASE,
)

BRUTE_FORCE_CONFIG = BruteForceConfig()
RATE_ANOMALY_CONFIG = RateAnomalyConfig()
