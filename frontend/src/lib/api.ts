/**
 * SentinelGate / Zentry — Unified Typed API Client
 * Connects frontend tabs directly to real live backend endpoints.
 */

const getApiBase = () => {
  if (typeof window !== "undefined") {
    const host = window.location.hostname || "localhost";
    return `http://${host}:8000`;
  }
  return process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";
};

export class ApiError extends Error {
  constructor(
    public status: number,
    message: string
  ) {
    super(message);
    this.name = "ApiError";
  }
}

async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${getApiBase()}${path}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string>),
  };

  const response = await fetch(url, {
    ...options,
    headers,
    credentials: "include",
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({ message: response.statusText }));
    throw new ApiError(response.status, body?.detail || body?.message || response.statusText);
  }

  return response.json() as Promise<T>;
}

export interface SecurityEventData {
  id: string;
  request_id: string;
  timestamp: string;
  source_ip: string;
  client_ipv6: boolean;
  method: string;
  path: string;
  query_string: string | null;
  user_agent: string | null;
  user_id: string | null;
  threats: any[];
  risk_score: number;
  risk_level: string;
  action: string;
  response_code: number | null;
  duration_ms: number | null;
  hmac_chain: string | null;
}

export interface SecurityEventsResponse {
  total: number;
  events: SecurityEventData[];
}

export interface SecurityStatsResponse {
  total_requests: number;
  allowed_requests: number;
  blocked_requests: number;
  challenged_requests: number;
  active_threats: number;
  global_threat_level: string;
  average_risk_score: number;
  threat_distribution: { name: string; category: string; count: number; color: string }[];
  traffic_timeline: { time: string; allowed: number; blocked: number }[];
  recent_events: SecurityEventData[];
}

export interface WAFRuleData {
  rule_id: string;
  name: string;
  category: string;
  severity: string;
  risk_delta: number;
  enabled: boolean;
  blocks_directly: boolean;
  status_code: number;
}

export interface DeviceData {
  id: string;
  user: string;
  os: string;
  browser: string;
  trustScore: number;
  lastSeen: string;
  status: string;
  ip: string;
  requestCount: number;
}

export interface IdentityData {
  id: string;
  email: string;
  name: string;
  role: string;
  roles: string[];
  type: string;
  trustScore: number;
  lastActive: string;
  authMethod: string;
  status: string;
  location?: string | null;
  deviceCount?: number | null;
}

export interface GatewayTelemetryData {
  status: string;
  version: string;
  uptime_seconds: number;
  total_requests: number;
  allowed_requests: number;
  blocked_requests: number;
  active_threats: number;
  db_connected: boolean;
  db_latency_ms: number;
  redis_connected: boolean;
  redis_latency_ms: number;
  cpu_percent: number;
  memory_mb: number;
  pipeline_overhead_ms: number;
  p95_latency_ms: number;
  error_rate_pct: number;
}

export interface IntegrityVerifyData {
  verified: boolean;
  total_events: number;
  tampered_events: any[];
}

export const api = {
  health: {
    check: () => apiFetch<{ status: string; version: string; timestamp: string }>("/health"),
    telemetry: () => apiFetch<GatewayTelemetryData>("/security/health/telemetry"),
  },
  security: {
    getStats: () => apiFetch<SecurityStatsResponse>("/security/stats"),
    getEvents: (params?: { limit?: number; offset?: number; risk_level?: string; action?: string }) => {
      const q = new URLSearchParams();
      if (params?.limit) q.set("limit", String(params.limit));
      if (params?.offset) q.set("offset", String(params.offset));
      if (params?.risk_level) q.set("risk_level", params.risk_level);
      if (params?.action) q.set("action", params.action);
      const queryStr = q.toString() ? `?${q.toString()}` : "";
      return apiFetch<SecurityEventsResponse>(`/security/events${queryStr}`);
    },
    getIdentities: () => apiFetch<{ total: number; identities: IdentityData[] }>("/security/identities"),
    getDevices: () => apiFetch<DeviceData[]>("/security/devices"),
    getRules: () => apiFetch<WAFRuleData[]>("/security/rules"),
    toggleRule: (ruleId: string) => apiFetch<{ status: string; rule_id: string; enabled: boolean }>(`/security/rules/${ruleId}/toggle`, { method: "POST" }),
    verifyIntegrity: () => apiFetch<IntegrityVerifyData>("/security/integrity/verify"),
  },
  auth: {
    login: (credentials: { username: string; password: string }) =>
      apiFetch<{ access_token: string; refresh_token: string; role: string; username: string }>("/auth/login", {
        method: "POST",
        body: JSON.stringify(credentials),
      }),
    me: () => apiFetch<{ id: string; username: string; role: string }>("/auth/me"),
  },
};

export default api;
