'use client';

import { useState } from 'react';
import { useRouter } from 'next/navigation';
import { setToken } from '@/lib/auth';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      const res = await fetch(`${API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (res.status === 401) {
        setError('Credenciales inválidas');
        return;
      }
      if (!res.ok) {
        setError('Error del servidor. Intentá de nuevo.');
        return;
      }

      const data = (await res.json()) as { access_token: string };
      setToken(data.access_token);
      router.push('/');
    } catch {
      setError('No se pudo conectar con el servidor.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <main className="min-h-screen bg-[#0d1117] text-[#c9d1d9] flex items-center justify-center p-4">
      <div className="w-full max-w-sm">
        <div className="mb-6 text-center">
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
            log-sentinel
          </h1>
          <p className="text-sm text-[#8b949e] mt-0.5">
            real-time security log monitoring
          </p>
        </div>

        <form
          onSubmit={handleSubmit}
          className="bg-[#161b22] border border-[#30363d] rounded-lg p-6 flex flex-col gap-4"
        >
          <div className="flex flex-col gap-1.5">
            <label htmlFor="email" className="text-xs text-[#8b949e]">
              Email
            </label>
            <input
              id="email"
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoComplete="username"
              className="bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="password" className="text-xs text-[#8b949e]">
              Password
            </label>
            <input
              id="password"
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              className="bg-[#0d1117] border border-[#30363d] rounded px-3 py-2 text-sm text-[#c9d1d9] focus:outline-none focus:border-[#58a6ff]"
            />
          </div>

          {error && <p className="text-sm text-red-400">{error}</p>}

          <button
            type="submit"
            disabled={submitting}
            className="mt-1 bg-[#238636] hover:bg-[#2ea043] disabled:opacity-60 text-white text-sm font-medium rounded px-3 py-2 transition-colors"
          >
            {submitting ? 'Ingresando…' : 'Ingresar'}
          </button>
        </form>
      </div>
    </main>
  );
}
