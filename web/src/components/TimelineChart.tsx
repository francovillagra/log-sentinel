'use client';

import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { SEVERITIES, SEVERITY_META } from '@/lib/severity';

interface Bucket {
  time: string;
  CRITICAL: number;
  HIGH: number;
  MEDIUM: number;
  LOW: number;
  INFO: number;
}

interface Props {
  timeline: Bucket[];
}

export default function TimelineChart({ timeline }: Props) {
  return (
    <div className="rounded-md border border-[#30363d] bg-[#161b22] p-4">
      <span className="text-xs uppercase tracking-widest text-[#8b949e] block mb-3">
        Alert Timeline (2 min)
      </span>
      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={timeline} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
          <CartesianGrid strokeDasharray="3 3" stroke="#21262d" />
          <XAxis
            dataKey="time"
            tick={{ fontSize: 10, fill: '#484f58', fontFamily: 'ui-monospace, monospace' }}
            interval="preserveStartEnd"
            tickLine={false}
            axisLine={false}
          />
          <YAxis
            tick={{ fontSize: 10, fill: '#484f58' }}
            tickLine={false}
            axisLine={false}
            allowDecimals={false}
          />
          <Tooltip
            contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 6, fontSize: 12 }}
            labelStyle={{ color: '#8b949e', fontFamily: 'ui-monospace, monospace' }}
            itemStyle={{ fontFamily: 'ui-monospace, monospace' }}
          />
          {SEVERITIES.map((sev) => (
            <Area
              key={sev}
              type="monotone"
              dataKey={sev}
              stackId="1"
              stroke={SEVERITY_META[sev].color}
              fill={SEVERITY_META[sev].color}
              fillOpacity={0.3}
              strokeWidth={1.5}
              dot={false}
              activeDot={{ r: 3 }}
            />
          ))}
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
