export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Decision = "ALLOWED" | "BLOCKED" | "CHALLENGED";
export type ThreatCategory =
  | "SQL_INJECTION"
  | "XSS"
  | "PATH_TRAVERSAL"
  | "COMMAND_INJECTION"
  | "SSRF"
  | "CREDENTIAL_STUFFING"
  | "BOT_ACTIVITY"
  | "ANOMALOUS_BEHAVIOR";

export interface SecurityRequest {
  id: string;
  timestamp: string;
  timeDisplay: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  sourceIp: string;
  location: string;
  identity: string;
  identityTrust: number;
  endpoint: string;
  riskScore: number;
  riskLevel: RiskLevel;
  decision: Decision;
  statusCode: number;
  device: {
    id: string;
    os: string;
    browser: string;
    fingerprint: string;
    trustScore: number;
    status: "Verified" | "Unverified" | "Suspicious";
  };
  network: {
    ip: string;
    reputation: "Trusted" | "Neutral" | "Suspicious" | "Malicious";
    asn: string;
  };
  riskBreakdown: {
    identity: number;
    device: number;
    network: number;
    behavior: number;
  };
  threats: {
    category: ThreatCategory;
    name: string;
    confidence: number;
    ruleId: string;
  }[];
  appliedPolicy: string;
  policyReason: string;
}

export interface SecurityEventItem {
  id: string;
  timestamp: string;
  timeAgo: string;
  type: string;
  endpoint: string;
  decision: Decision;
  severity: RiskLevel;
  sourceIp: string;
}

export interface ThreatIntelligenceItem {
  id: string;
  name: string;
  category: ThreatCategory;
  severity: RiskLevel;
  confidence: number;
  target: string;
  sourceIp: string;
  ruleId: string;
  detectionMethod: string;
  action: Decision;
  timestamp: string;
}

export interface SecurityPolicyItem {
  id: string;
  code: string;
  name: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";
  rulesCount: number;
  status: "ACTIVE" | "DISABLED" | "EVALUATING";
  lastModified: string;
  description: string;
  conditions: {
    field: string;
    operator: string;
    value: string;
  }[];
  actions: string[];
}

export interface IdentityItem {
  id: string;
  email: string;
  type: "Human" | "Service" | "Unknown" | "Bot" | string;
  trustScore: number;
  lastActive: string;
  authMethod: "MFA" | "Token" | "SSO" | "Password" | "None" | string;
  status: "TRUSTED" | "EVALUATING" | "BLOCKED" | "WARNING" | "UNTRUSTED" | string;
  roles: string[];
  role?: string;
  name?: string;
  location?: string;
  deviceCount?: number;
}

export interface DeviceItem {
  id: string;
  user: string;
  os: string;
  browser: string;
  trustScore: number;
  lastSeen: string;
  status: "Known" | "Unverified" | "Suspicious" | "Compromised";
  fingerprint: string;
}

export interface IncidentItem {
  id: string;
  title: string;
  severity: RiskLevel;
  status: "INVESTIGATING" | "CONTAINED" | "RESOLVED";
  createdAt: string;
  affectedEndpoints: string[];
  sourceIps: string[];
  identities: string[];
  timeline: {
    time: string;
    event: string;
    detail: string;
  }[];
}
