'use client';

import { useState, useEffect, useRef, useCallback } from 'react';
import type { Alert } from '@/lib/types';

export type Status = 'connecting' | 'connected' | 'disconnected';

const MAX_ALERTS = 500;
const BACKOFF_START = 1000;
const BACKOFF_MAX = 30000;

interface UseAlertStreamResult {
  alerts: Alert[];
  status: Status;
  clear: () => void;
}

export function useAlertStream(wsUrl: string): UseAlertStreamResult {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [status, setStatus] = useState<Status>('connecting');

  const wsRef = useRef<WebSocket | null>(null);
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const backoffRef = useRef<number>(BACKOFF_START);
  const mountedRef = useRef<boolean>(true);

  const clearTimer = () => {
    if (timerRef.current !== null) {
      clearTimeout(timerRef.current);
      timerRef.current = null;
    }
  };

  const connect = useCallback(() => {
    if (!mountedRef.current) return;
    if (wsRef.current && wsRef.current.readyState < WebSocket.CLOSING) return;

    setStatus('connecting');
    const ws = new WebSocket(wsUrl);
    wsRef.current = ws;

    ws.onopen = () => {
      if (!mountedRef.current) { ws.close(); return; }
      backoffRef.current = BACKOFF_START;
      setStatus('connected');
    };

    ws.onmessage = (event: MessageEvent<string>) => {
      if (!mountedRef.current) return;
      try {
        const raw = JSON.parse(event.data) as Omit<Alert, 'id'>;
        const alert: Alert = {
          ...raw,
          id: raw.stream_id ?? crypto.randomUUID(),
        };
        setAlerts((prev) => [alert, ...prev].slice(0, MAX_ALERTS));
      } catch {
        // malformed message — ignore
      }
    };

    ws.onerror = () => {
      // onclose fires right after and handles reconnect
    };

    ws.onclose = () => {
      if (!mountedRef.current) return;
      setStatus('disconnected');
      wsRef.current = null;
      clearTimer();
      timerRef.current = setTimeout(() => {
        backoffRef.current = Math.min(backoffRef.current * 2, BACKOFF_MAX);
        connect();
      }, backoffRef.current);
    };
  }, [wsUrl]);

  useEffect(() => {
    mountedRef.current = true;
    connect();

    return () => {
      mountedRef.current = false;
      clearTimer();
      if (wsRef.current) {
        wsRef.current.onclose = null;
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  const clear = useCallback(() => setAlerts([]), []);

  return { alerts, status, clear };
}
