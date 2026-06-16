'use client';

import { useMemo, useEffect, useState, useCallback } from 'react';
import { useRouter } from 'next/navigation';
import { useAlertStream } from '@/hooks/useAlertStream';
import { SEVERITIES } from '@/lib/severity';
import type { Severity, Alert } from '@/lib/types';
import { isAuthenticated, getToken } from '@/lib/auth';
import ConnectionStatus from '@/components/ConnectionStatus';
import SeverityCounters from '@/components/SeverityCounters';
import AlertFeed from '@/components/AlertFeed';
import TimelineChart from '@/components/TimelineChart';
import TopAttackers from '@/components/TopAttackers';
import LogoutButton from '@/components/LogoutButton';

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000';
const WS_BASE = process.env.NEXT_PUBLIC_WS_URL ?? 'ws://localhost:8000/ws/alerts';
const WINDOW_MS = 120_000;
const BUCKET_MS = 5_000;

function Dashboard({ token }: { token: string }) {
  const wsUrl = `${WS_BASE}?token=${token}`;
  const [history, setHistory] = useState<Alert[]>([]);
  const { alerts: streaming, status, clear: clearStreaming } = useAlertStream(wsUrl);

  useEffect(() => {
    fetch(`${API_URL}/api/v1/alerts`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((r) => (r.ok ? r.json() : []))
      .then((data: Alert[]) => setHistory(data))
      .catch(() => {});
  }, [token]);

  const clear = useCallback(() => {
    clearStreaming();
    setHistory([]);
  }, [clearStreaming]);

  const allAlerts = useMemo(() => {
    const seen = new Set<string>();
    const result: Alert[] = [];
    for (const a of [...streaming, ...history]) {
      if (!seen.has(a.id)) {
        seen.add(a.id);
        result.push(a);
      }
    }
    return result;
  }, [streaming, history]);

  const countsBySeverity = useMemo(() => {
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
    for (const a of allAlerts) counts[a.severity] = (counts[a.severity] ?? 0) + 1;
    return counts;
  }, [allAlerts]);

  const topAttackers = useMemo(() => {
    const map = new Map<string, number>();
    for (const a of allAlerts) map.set(a.src_ip, (map.get(a.src_ip) ?? 0) + 1);
    return Array.from(map.entries())
      .sort((x, y) => y[1] - x[1])
      .slice(0, 10)
      .map(([ip, count]) => ({ ip, count }));
  }, [allAlerts]);

  const timeline = useMemo(() => {
    const now = Date.now();
    const numBuckets = Math.floor(WINDOW_MS / BUCKET_MS);
    const buckets = Array.from({ length: numBuckets }, (_, i) => {
      const bucketStart = now - WINDOW_MS + i * BUCKET_MS;
      const d = new Date(bucketStart);
      const hh = String(d.getHours()).padStart(2, '0');
      const mm = String(d.getMinutes()).padStart(2, '0');
      const ss = String(d.getSeconds()).padStart(2, '0');
      return {
        time: `${hh}:${mm}:${ss}`,
        CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
      };
    });

    for (const a of allAlerts) {
      const t = new Date(a.ts).getTime();
      const age = now - t;
      if (age < 0 || age >= WINDOW_MS) continue;
      const idx = Math.floor((WINDOW_MS - age) / BUCKET_MS);
      if (idx >= 0 && idx < numBuckets) {
        buckets[idx][a.severity]++;
      }
    }
    return buckets;
  }, [allAlerts]);

  return (
    <main className="min-h-screen bg-[#0d1117] text-[#c9d1d9] p-4 md:p-6">
      {status === 'disconnected' && (
        <div className="mb-4 px-4 py-2 rounded-md bg-red-900/30 border border-red-800 text-red-400 text-sm font-mono">
          Reconnecting…
        </div>
      )}

      <header className="mb-6 flex items-start justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-white font-mono">
            log-sentinel
          </h1>
          <p className="text-sm text-[#8b949e] mt-0.5">
            real-time security log monitoring
          </p>
        </div>
        <LogoutButton />
      </header>

      <div className="flex flex-wrap items-center gap-4 mb-6">
        <ConnectionStatus status={status} totalAlerts={allAlerts.length} />
        <SeverityCounters counts={countsBySeverity} />
        <button
          onClick={clear}
          className="ml-auto text-xs text-[#8b949e] hover:text-[#c9d1d9] border border-[#30363d] rounded px-3 py-1.5 transition-colors"
        >
          Clear
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2 flex flex-col">
          <AlertFeed alerts={allAlerts} />
        </div>
        <div className="flex flex-col gap-4">
          <TimelineChart timeline={timeline} />
          <TopAttackers attackers={topAttackers} />
        </div>
      </div>
    </main>
  );
}

export default function DashboardPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);

  useEffect(() => {
    const t = getToken();
    if (!isAuthenticated() || !t) {
      router.replace('/login');
      return;
    }
    setToken(t);
  }, [router]);

  if (!token) return null;

  return <Dashboard token={token} />;
}
