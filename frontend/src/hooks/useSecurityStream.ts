"use client";

import { useEffect, useRef, useState, useCallback } from "react";

export interface LiveSecurityEvent {
  id?: string;
  request_id?: string;
  timestamp?: string;
  source_ip?: string;
  action?: string;
  risk_score?: number;
  risk_level?: string;
  method?: string;
  path?: string;
  threats?: string[] | { name?: string; category?: string; rule_id?: string }[];
  [key: string]: unknown;
}

interface UseSecurityStreamOptions {
  onEvent?: (event: LiveSecurityEvent) => void;
  token?: string;
}

export function useSecurityStream({ onEvent, token }: UseSecurityStreamOptions = {}) {
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<LiveSecurityEvent | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const pingIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const reconnectAttemptsRef = useRef(0);

  // Store onEvent in a ref to decouple WebSocket lifecycle from caller component re-renders
  const onEventRef = useRef(onEvent);
  useEffect(() => {
    onEventRef.current = onEvent;
  }, [onEvent]);

  const connect = useCallback(() => {
    if (typeof window === "undefined") return;

    // Clean up any pending reconnect
    if (reconnectTimeoutRef.current) {
      clearTimeout(reconnectTimeoutRef.current);
      reconnectTimeoutRef.current = null;
    }

    try {
      const host = window.location.hostname || "127.0.0.1";
      const wsUrl = `ws://${host}:8000/ws/security-events${token ? `?token=${encodeURIComponent(token)}` : ""}`;
      
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        reconnectAttemptsRef.current = 0;

        // Keep-alive heartbeat ping every 20 seconds
        if (pingIntervalRef.current) clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, 20000);
      };

      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data);
          if (payload.type === "security_event" && payload.event) {
            setLastEvent(payload.event);
            if (onEventRef.current) {
              onEventRef.current(payload.event);
            }
          } else if (payload.type === "connection_established") {
            setIsConnected(true);
          }
        } catch {
          // ignore malformed packets
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        if (pingIntervalRef.current) {
          clearInterval(pingIntervalRef.current);
          pingIntervalRef.current = null;
        }

        // Reconnect with exponential backoff capped at 5s
        const delay = Math.min(1000 * 1.5 ** reconnectAttemptsRef.current, 5000);
        reconnectAttemptsRef.current += 1;
        reconnectTimeoutRef.current = setTimeout(() => {
          connect();
        }, delay);
      };

      ws.onerror = () => {
        // Trigger onclose for reconnect
        try {
          ws.close();
        } catch {
          // ignore
        }
      };
    } catch {
      // Retry in 3s on immediate failure
      reconnectTimeoutRef.current = setTimeout(() => {
        connect();
      }, 3000);
    }
  }, [token]);

  useEffect(() => {
    connect();

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
        reconnectTimeoutRef.current = null;
      }
      if (pingIntervalRef.current) {
        clearInterval(pingIntervalRef.current);
        pingIntervalRef.current = null;
      }
      if (wsRef.current) {
        wsRef.current.onclose = null; // Prevent reconnect on unmount
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { isConnected, lastEvent };
}
