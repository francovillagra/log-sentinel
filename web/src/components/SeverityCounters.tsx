'use client';

import { SEVERITIES, SEVERITY_META } from '@/lib/severity';
import type { Severity } from '@/lib/types';

interface Props {
  counts: Record<Severity, number>;
}

export default function SeverityCounters({ counts }: Props) {
  return (
    <div className="flex gap-3 flex-wrap">
      {SEVERITIES.map((sev) => {
        const meta = SEVERITY_META[sev];
        return (
          <div
            key={sev}
            className="flex flex-col px-4 py-3 rounded-md border border-[#30363d] bg-[#161b22] min-w-[90px]"
            style={{ borderLeftColor: meta.color, borderLeftWidth: '3px' }}
          >
            <span
              className="font-mono text-2xl font-bold leading-none"
              style={{ color: meta.color }}
            >
              {counts[sev]}
            </span>
            <span className="text-xs text-[#8b949e] mt-1 uppercase tracking-wide">
              {meta.label}
            </span>
          </div>
        );
      })}
    </div>
  );
}
