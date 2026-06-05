import type { Severity } from './types';

interface SeverityMeta {
  color: string;
  label: string;
  order: number;
}

export const SEVERITY_META: Record<Severity, SeverityMeta> = {
  CRITICAL: { color: '#f85149', label: 'Critical', order: 0 },
  HIGH:     { color: '#fb8500', label: 'High',     order: 1 },
  MEDIUM:   { color: '#d29922', label: 'Medium',   order: 2 },
  LOW:      { color: '#58a6ff', label: 'Low',      order: 3 },
  INFO:     { color: '#8b949e', label: 'Info',     order: 4 },
};

export const SEVERITIES: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];
