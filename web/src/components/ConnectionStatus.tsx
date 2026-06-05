'use client';

import type { Status } from '@/hooks/useAlertStream';

interface Props {
  status: Status;
  totalAlerts: number;
}

const DOT: Record<Status, string> = {
  connected:    'bg-green-400',
  connecting:   'bg-amber-400',
  disconnected: 'bg-red-500',
};

const LABEL: Record<Status, string> = {
  connected:    'Live',
  connecting:   'Connecting…',
  disconnected: 'Disconnected',
};

export default function ConnectionStatus({ status, totalAlerts }: Props) {
  return (
    <div className="flex items-center gap-3 px-4 py-2 rounded-md border border-[#30363d] bg-[#161b22] w-fit">
      <span className="relative flex h-2.5 w-2.5">
        <span
          className={`${DOT[status]} absolute inline-flex h-full w-full rounded-full ${
            status === 'connected' ? 'animate-ping opacity-75' : ''
          }`}
        />
        <span className={`${DOT[status]} relative inline-flex h-2.5 w-2.5 rounded-full`} />
      </span>
      <span className="text-sm text-[#c9d1d9]">{LABEL[status]}</span>
      <span className="text-sm font-mono text-[#8b949e]">
        {totalAlerts.toLocaleString()} events
      </span>
    </div>
  );
}
