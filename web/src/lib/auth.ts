const TOKEN_KEY = 'log_sentinel_token';

export function getToken(): string | null {
  if (typeof window === 'undefined') return null;
  return window.localStorage.getItem(TOKEN_KEY);
}

const listeners = new Set<() => void>();
const notify = () => listeners.forEach((listener) => listener());

export function setToken(token: string): void {
  if (typeof window === 'undefined') return;
  window.localStorage.setItem(TOKEN_KEY, token);
  notify();
}

export function removeToken(): void {
  if (typeof window === 'undefined') return;
  window.localStorage.removeItem(TOKEN_KEY);
  notify();
}

/** Para useSyncExternalStore: avisa cuando el token cambia en esta pestaña o en otra (evento `storage`). */
export function subscribeToken(listener: () => void): () => void {
  listeners.add(listener);
  window.addEventListener('storage', listener);
  return () => {
    listeners.delete(listener);
    window.removeEventListener('storage', listener);
  };
}

interface JwtPayload {
  exp?: number;
  sub?: string;
}

/** Decode a JWT payload (base64url) WITHOUT verifying the signature — client-side only. */
function decodeJwtPayload(token: string): JwtPayload | null {
  const parts = token.split('.');
  if (parts.length < 2) return null;
  try {
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    const padding = (4 - (base64.length % 4)) % 4;
    const json = atob(base64 + '='.repeat(padding));
    return JSON.parse(json) as JwtPayload;
  } catch {
    return null;
  }
}

/** True only if a token exists and its `exp` claim has not passed. */
export function isAuthenticated(): boolean {
  const token = getToken();
  if (!token) return false;
  const payload = decodeJwtPayload(token);
  if (!payload || typeof payload.exp !== 'number') return false;
  return payload.exp * 1000 > Date.now();
}

/** El token si hay uno vigente; null si no hay o ya venció. Devuelve el mismo valor mientras nada cambie. */
export function getValidToken(): string | null {
  return isAuthenticated() ? getToken() : null;
}
