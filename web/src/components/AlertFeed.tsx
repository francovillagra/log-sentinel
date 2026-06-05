'use client';

import type { Alert } from '@/lib/types';
import { SEVERITY_META } from '@/lib/severity';

interface Props {
  alerts: Alert[];
}

function relativeTime(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  return `${Math.floor(diff / 3600)}h ago`;
}

export default function AlertFeed({ alerts }: Props) {
  return (
    <div className="rounded-md border border-[#30363d] bg-[#161b22] flex flex-col h-full">
      <div className="px-4 py-2 border-b border-[#30363d]">
        <span className="text-xs uppercase tracking-widest text-[#8b949e]">Alert Feed</span>
      </div>
      <div className="overflow-y-auto flex-1" style={{ maxHeight: '520px' }}>
        {alerts.length === 0 ? (
          <div className="flex items-center justify-center h-32 gap-2 text-[#8b949e] text-sm">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-green-400" />
            </span>
            Listening for events…
          </div>
        ) : (
          alerts.map((alert) => {
            const meta = SEVERITY_META[alert.severity];
            return (
              <div
                key={alert.id}
                className="flex items-center gap-3 px-4 py-2 border-b border-[#21262d] animate-fadein hover:bg-[#1c2128] transition-colors"
              >
                <span
                  className="text-[10px] font-bold px-1.5 py-0.5 rounded uppercase tracking-wide shrink-0"
                  style={{ color: meta.color, border: `1px solid ${meta.color}` }}
                >
                  {alert.severity}
                </span>
                <span className="text-xs text-[#c9d1d9] shrink-0 w-40 truncate">
                  {alert.rule_id}
                </span>
                <span className="font-mono text-xs text-[#58a6ff] shrink-0 w-32">
                  {alert.src_ip}
                </span>
                <span className="font-mono text-xs text-[#8b949e] flex-1 truncate">
                  {alert.evidence}
                </span>
                <span className="text-xs text-[#484f58] shrink-0">
                  {relativeTime(alert.ts)}
                </span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
