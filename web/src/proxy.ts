import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";

// Next 16 llama "proxy" a lo que antes se llamaba "middleware". Corre en cada pedido de página y le pone una
// Content-Security-Policy con un nonce nuevo: solo se ejecutan los scripts que el servidor marcó con ese nonce, así
// que un script inyectado en la página (XSS) no corre. Importa porque el token de sesión vive en localStorage.
//
// NEXT_PUBLIC_* se reemplaza al construir la app: acá valen lo mismo que en el navegador.
const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
const WS_URL = process.env.NEXT_PUBLIC_WS_URL ?? "ws://localhost:8000/ws/alerts";

function originOf(url: string): string | null {
  try {
    return new URL(url).origin;
  } catch {
    return null;
  }
}

export function buildCsp(nonce: string, isDev: boolean): string {
  const connect = ["'self'", originOf(API_URL), originOf(WS_URL)].filter((o): o is string => Boolean(o));
  const directives = [
    "default-src 'self'",
    // 'strict-dynamic': los scripts que cargan los autorizados también corren; sin nonce no corre nada más.
    // En desarrollo React necesita eval para reconstruir las pilas de error; en producción no.
    `script-src 'self' 'nonce-${nonce}' 'strict-dynamic'${isDev ? " 'unsafe-eval'" : ""}`,
    `style-src 'self' 'nonce-${nonce}'`,
    "img-src 'self' data: blob:",
    "font-src 'self'",
    // El panel solo habla con la API (HTTP y WebSocket) y con sí mismo.
    `connect-src ${connect.join(" ")}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ];
  // Solo si la API va por https: con una API en http://localhost (desarrollo) obligaría a https y la rompería.
  if (API_URL.startsWith("https://")) directives.push("upgrade-insecure-requests");
  return directives.join("; ");
}

export function proxy(request: NextRequest) {
  const nonce = Buffer.from(crypto.randomUUID()).toString("base64");
  const csp = buildCsp(nonce, process.env.NODE_ENV === "development");

  // Next.js lee el nonce de la CSP del pedido y se lo pone a sus scripts y estilos al renderizar.
  const requestHeaders = new Headers(request.headers);
  requestHeaders.set("x-nonce", nonce);
  requestHeaders.set("Content-Security-Policy", csp);

  const response = NextResponse.next({ request: { headers: requestHeaders } });
  response.headers.set("Content-Security-Policy", csp);
  return response;
}

export const config = {
  matcher: [
    {
      // Páginas y datos de Next; no los archivos estáticos ni las precargas de enlaces.
      source: "/((?!_next/static|_next/image|favicon.ico).*)",
      missing: [
        { type: "header", key: "next-router-prefetch" },
        { type: "header", key: "purpose", value: "prefetch" },
      ],
    },
  ],
};
