export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export interface Alert {
  id: string;
  rule_id: string;
  severity: Severity;
  src_ip: string;
  title: string;
  description: string;
  evidence: string;
  ts: string;
  stream_id: string;
}
