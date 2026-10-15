"""Corpus de ataques (con las evasiones habituales) y de tráfico legítimo para probar los detectores.

Los objetivos están como los registraría nginx: ya codificados (`%20`, `+`...). El corpus no es exhaustivo ni pretende serlo:
fija lo que el motor tiene que seguir detectando y lo que no tiene que marcar jamás. Una técnica de evasión nueva es una prueba
nueva acá, primero fallando.
"""

# (nombre, objetivo de la petición, regla que debe saltar)
ATTACKS = [
    ("sqli clásico (%20)", "/p?id=1%20UNION%20SELECT%201,2--%20-", "sqli"),
    ("sqli con '+' (formularios, sqlmap)", "/p?id=1+UNION+SELECT+1,2", "sqli"),
    ("sqli UNION ALL SELECT", "/p?id=1%20UNION%20ALL%20SELECT%20NULL,NULL", "sqli"),
    ("sqli comentario /**/", "/p?id=1/**/UNION/**/SELECT/**/1", "sqli"),
    ("sqli comentario de versión /*!50000*/", "/p?id=1/*!50000UNION*//*!50000SELECT*/1", "sqli"),
    ("sqli doble codificación", "/p?id=1%2520UNION%2520SELECT%25201", "sqli"),
    ("sqli ' OR '1'='1", "/login?u=a%27%20OR%20%271%27=%271", "sqli"),
    ("sqli OR 1=1", "/p?id=1%20OR%201=1", "sqli"),
    ("sqli OR 2>1", "/p?id=1%20OR%202%3E1", "sqli"),
    ("sqli AND 1234=5678 (ciego)", "/p?id=1%20AND%201234=5678", "sqli"),
    ("sqli comentario --+", "/login?u=admin%27--+", "sqli"),
    ("sqli ; DROP TABLE", "/p?id=1;DROP%20TABLE%20users", "sqli"),
    ("sqli SLEEP()", "/p?id=1%20AND%20SLEEP(5)", "sqli"),
    ("sqli pg_sleep()", "/p?id=1;SELECT%20pg_sleep(5)", "sqli"),
    ("sqli information_schema", "/p?id=1%20and%20(select%20count(*)%20from%20information_schema.tables)%3E0", "sqli"),
    ("sqli extractvalue()", "/p?id=extractvalue(1,concat(0x7e,version()))", "sqli"),
    ("sqli xp_cmdshell", "/p?id=1;exec%20xp_cmdshell%20%27dir%27", "sqli"),
    ("sqli mayúsculas mezcladas", "/p?id=1%20uNiOn%20SeLeCt%201", "sqli"),
    ("sqli salto de línea", "/p?id=1%0aUNION%0aSELECT%0a1", "sqli"),
    ("xss <script>", "/s?q=%3Cscript%3Ealert(1)%3C/script%3E", "xss"),
    ("xss <img onerror>", "/s?q=%3Cimg%20src=x%20onerror=alert(1)%3E", "xss"),
    ("xss <svg/onload>", "/s?q=%3Csvg/onload=alert(1)%3E", "xss"),
    ("xss javascript:", "/r?url=javascript:alert(1)", "xss"),
    ("xss onpointerenter", "/s?q=%22%20onpointerenter=confirm(1)%20x=%22", "xss"),
    ("xss ontoggle (<details>)", "/s?q=%3Cdetails%20open%20ontoggle=confirm(1)%3E", "xss"),
    ("xss <iframe>", "/s?q=%22%3E%3Ciframe%20src=//evil.test%3E", "xss"),
    ("xss doble codificación", "/s?q=%253Cscript%253Econfirm(1)%253C/script%253E", "xss"),
    ("xss triple codificación", "/s?q=%25253Cscript%25253Econfirm(1)", "xss"),
    ("xss entidad HTML (&#106;avascript)", "/r?url=%26%23106%3Bavascript%3Aconfirm(1)", "xss"),
    ("xss <script con NUL (%00)", "/s?q=%3C%00script%3Econfirm(1)", "xss"),
    ("xss document.cookie", "/s?q=document.cookie", "xss"),
    ("traversal ../", "/download?f=../../../../etc/passwd", "path_traversal"),
    ("traversal ..%2f", "/download?f=..%2f..%2f..%2fetc%2fpasswd", "path_traversal"),
    ("traversal %2e%2e%2f", "/download?f=%2e%2e%2f%2e%2e%2fetc%2fpasswd", "path_traversal"),
    ("traversal ....// (filtro ingenuo)", "/download?f=....//....//etc/passwd", "path_traversal"),
    ("traversal ..\\ (Windows, %5c)", "/download?f=..%5c..%5capp%5cconfig.yml", "path_traversal"),
    ("traversal doble codificación", "/download?f=%252e%252e%252f%252e%252e%252fapp%252fconfig.yml", "path_traversal"),
    ("traversal triple codificación", "/download?f=%25252e%25252e%25252fapp%25252fconfig.yml", "path_traversal"),
    ("traversal UTF-8 largo (%c0%ae)", "/download?f=%c0%ae%c0%ae/%c0%ae%c0%ae/app/config.yml", "path_traversal"),
    ("traversal /etc/passwd%00", "/download?f=/etc/passwd%00.jpg", "path_traversal"),
    ("archivo .env", "/.env", "path_traversal"),
    ("archivo .env.production", "/.env.production", "path_traversal"),
    ("archivo .git/config", "/.git/config", "path_traversal"),
    ("archivo .aws/credentials", "/.aws/credentials", "path_traversal"),
    ("archivo wp-config", "/wp-config.php.bak", "path_traversal"),
    ("archivo .ssh/id_rsa", "/.ssh/id_rsa", "path_traversal"),
    ("LFI php://filter", "/index.php?page=php://filter/convert.base64-encode/resource=config", "path_traversal"),
]

# (nombre, user-agent, regla esperada o None si no debe saltar nada)
USER_AGENTS = [
    ("ua sqlmap", "sqlmap/1.7#stable (https://sqlmap.org)", "suspicious_ua"),
    ("ua Nikto", "Mozilla/5.00 (Nikto/2.1.6)", "suspicious_ua"),
    ("ua nuclei", "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)", "suspicious_ua"),
    ("ua ffuf", "Fuzz Faster U Fool v2.1.0", "suspicious_ua"),
    ("ua feroxbuster", "feroxbuster/2.10.0", "suspicious_ua"),
    ("ua WPScan", "WPScan v3.8.25 (https://wpscan.com/wordpress-security-scanner)", "suspicious_ua"),
    ("ua python-requests (no es un escáner)", "python-requests/2.31", None),
    ("ua curl (no es un escáner)", "curl/8.4.0", None),
    ("ua navegador", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36", None),
]

# Rutas donde un 401/403 repetido es un intento de adivinar credenciales.
LOGIN_PATHS = [
    "/login", "/api/login", "/api/v1/auth/login", "/wp-login.php", "/user/login", "/admin/login", "/xmlrpc.php",
    "/oauth/token", "/Login", "/%6cogin",
]

# Tráfico legítimo que se parece a un ataque. Ninguno debe generar una alerta.
BENIGN = [
    "/", "/index.html", "/static/js/scripts.bundle.js", "/static/css/main.css", "/img/logo--dark.png", "/favicon.ico", "/robots.txt",
    "/search?q=trade+union+members", "/search?q=how%20to%20select%20a%20union", "/search?q=select+union", "/blog/union-select-lessons",
    "/products?category=shoes&sort=price&order=asc", "/api/v1/orders?filter=status%3Dopen&page=2", "/api/v1/users/42/profile",
    "/docs/sql-injection-prevention", "/docs/xss-cheatsheet", "/search?q=O%27Reilly%20or%20Smith", "/search?q=rock+%27n%27+roll",
    "/app?next=/profile%3Ftab%3Don&online=1&once=true&only=me&onboarding=1", "/.well-known/acme-challenge/abcdef",
    "/.github/workflows/ci.yml", "/environment/settings", "/api/envelope/1", "/download/report-2026.pdf", "/files/a..b/c.txt",
    "/uploads/2026/10/photo.jpg", "/search?q=1+or+1+items", "/search?q=me+and+you", "/p?id=10&and=5",
    "/forum/post?title=To+be+or+not+to+be", "/p?q=exec+summary", "/p?q=convert+units", "/p?q=cast+iron+pan",
    "/blog/why-alert-fatigue-matters", "/p?q=document+cookies+policy", "/p?lang=es&theme=dark&utm_source=newsletter",
    "/wp-content/themes/x/style.css?ver=6.4", "/api/v2/search?q=select&type=union", "/shop?color=red&size=10&and=true",
    "/img/photo.png?width=800&height=600", "/data/export.csv?from=2026-01-01&to=2026-02-01", "/ruta/con/guion--medio/pagina",
]
