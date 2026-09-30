"use client";

import React, { useState, useEffect, useCallback, useRef } from "react";
import {
  Activity,
  AlertOctagon,
  AlertTriangle,
  CheckCircle2,
  Radio,
  ShieldAlert,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { useSecurityStream, LiveSecurityEvent } from "../../hooks/useSecurityStream";
import { api } from "../../lib/api";

/** Formats a UTC ISO string or Date to IST display */
function toIST(ts?: string | Date): string {
  try {
    const d = ts ? new Date(ts) : new Date();
    return d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      day: "2-digit",
      month: "short",
    });
  } catch {
    return "—";
  }
}

interface ThreatDistItem {
  name: string;
  category?: string;
  count: number;
  percentage: number;
  color: string;
}

interface LiveThreatDetail {
  category: string;
  severity: string;
  confidence: string;
  targetEndpoint: string;
  sourceIp: string;
  ruleId: string;
  action: string;
  responseCode: number;
  timestamp: string;
}

const DEFAULT_THREAT_DISTRIBUTION: ThreatDistItem[] = [
  { name: "SQL Injection", count: 0, percentage: 0, color: "#EF4444" },
  { name: "XSS", count: 0, percentage: 0, color: "#F59E0B" },
  { name: "Path Traversal", count: 0, percentage: 0, color: "#EC4899" },
  { name: "Cmd Injection", count: 0, percentage: 0, color: "#8B5CF6" },
  { name: "SSRF", count: 0, percentage: 0, color: "#38BDF8" },
  { name: "Credential Abuse", count: 0, percentage: 0, color: "#3B82F6" },
];

export const ThreatDetectionView: React.FC = () => {
  const [threatDistribution, setThreatDistribution] = useState<ThreatDistItem[]>(DEFAULT_THREAT_DISTRIBUTION);
  const [activeThreats, setActiveThreats] = useState<number>(0);
  const [blockedAttacks, setBlockedAttacks] = useState<number>(0);
  const [criticalEvents, setCriticalEvents] = useState<number>(0);
  const [attackRate, setAttackRate] = useState<string>("0.0");
  const [totalDetections, setTotalDetections] = useState<number>(0);
  const [lastUpdated, setLastUpdated] = useState<string>(toIST());
  const [liveThreat, setLiveThreat] = useState<LiveThreatDetail | null>(null);
  const attackWindowRef = useRef<number[]>([]);

  /** Fetch stats from REST endpoint */
  const loadStats = useCallback(async () => {
    try {
      const data = await api.security.getStats();

      setBlockedAttacks(data.blocked_requests ?? 0);
      setActiveThreats(data.active_threats ?? 0);
      setLastUpdated(toIST());

      // Count criticals from recent events
      if (data.recent_events?.length) {
        const crits = data.recent_events.filter((e: any) =>
          e.risk_level === "CRITICAL" || e.risk_score >= 80
        ).length;
        setCriticalEvents(crits);

        // Get latest blocked event for threat detail card
        const latestBlocked = data.recent_events.find((e: any) => e.action === "BLOCK");
        if (latestBlocked) {
          const threat = Array.isArray(latestBlocked.threats) && latestBlocked.threats.length > 0
            ? latestBlocked.threats[0]
            : null;
          const cat = typeof threat === "object" && threat
            ? (threat.category || threat.name || "UNKNOWN")
            : typeof threat === "string" ? threat : "UNKNOWN";
          setLiveThreat({
            category: cat.replace(/_/g, " "),
            severity: latestBlocked.risk_level || "HIGH",
            confidence: `${Math.min(99, latestBlocked.risk_score || 75)}%`,
            targetEndpoint: latestBlocked.path || "/api/unknown",
            sourceIp: latestBlocked.source_ip || "0.0.0.0",
            ruleId: typeof threat === "object" && threat ? (threat.rule_id || threat.ruleId || "—") : "—",
            action: `BLOCKED (${latestBlocked.response_code || 403})`,
            responseCode: latestBlocked.response_code || 403,
            timestamp: toIST(latestBlocked.timestamp),
          });
        }
      }

      // Update threat distribution chart
      if (data.threat_distribution?.length > 0) {
        const totalThreats = data.threat_distribution.reduce((acc: number, d: any) => acc + d.count, 0) || 1;
        setTotalDetections(totalThreats);
        const updated: ThreatDistItem[] = data.threat_distribution.map((d: any) => ({
          name: d.name || d.category || "Unknown",
          category: d.category,
          count: d.count,
          percentage: Math.round((d.count / totalThreats) * 100),
          color: d.color || "#6B7280",
        }));
        setThreatDistribution(updated);
      }
    } catch {
      // Backend not available, keep defaults
    }
  }, []);

  // Initial fetch + polling every 10s
  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 10000);
    return () => clearInterval(interval);
  }, [loadStats]);

  // WebSocket live event handler for real-time updates
  const handleLiveEvent = useCallback((evt: LiveSecurityEvent) => {
    const action = ((evt.action as string) || "ALLOW").toUpperCase();
    const isBlock = action === "BLOCK";
    const score = Number(evt.risk_score ?? 0);

    if (isBlock) {
      setBlockedAttacks((prev) => prev + 1);
      setActiveThreats((prev) => prev + 1);

      // Update attack rate (attacks per minute, rolling 60s window)
      const now = Date.now();
      attackWindowRef.current.push(now);
      attackWindowRef.current = attackWindowRef.current.filter((t) => now - t < 60000);
      setAttackRate(attackWindowRef.current.length.toFixed(1));

      // Update threat distribution
      if (evt.threats && Array.isArray(evt.threats) && evt.threats.length > 0) {
        const firstThreat = evt.threats[0];
        const cat = typeof firstThreat === "object" && firstThreat
          ? ((firstThreat as any).category || (firstThreat as any).name || "UNKNOWN")
          : typeof firstThreat === "string" ? firstThreat : "UNKNOWN";

        setThreatDistribution((prev) => {
          const updated = [...prev];
          const idx = updated.findIndex(
            (d) => d.category === cat || d.name.toUpperCase().replace(/\s+/g, "_") === cat
          );
          if (idx >= 0) {
            updated[idx] = { ...updated[idx], count: updated[idx].count + 1 };
          }
          const total = updated.reduce((acc, d) => acc + d.count, 0) || 1;
          setTotalDetections(total);
          return updated.map((d) => ({
            ...d,
            percentage: Math.round((d.count / total) * 100),
          }));
        });

        // Update live threat detail card
        setLiveThreat({
          category: cat.replace(/_/g, " "),
          severity: score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : "MEDIUM",
          confidence: `${Math.min(99, score)}%`,
          targetEndpoint: (evt.path as string) || "/api/unknown",
          sourceIp: (evt.source_ip as string) || "0.0.0.0",
          ruleId: typeof firstThreat === "object" && firstThreat
            ? ((firstThreat as any).rule_id || (firstThreat as any).ruleId || "—")
            : "—",
          action: `BLOCKED (${evt.response_code || 403})`,
          responseCode: Number(evt.response_code) || 403,
          timestamp: toIST(evt.timestamp as string),
        });
      }
    }

    if (score >= 80) {
      setCriticalEvents((prev) => prev + 1);
    }

    setLastUpdated(toIST());
  }, []);

  const { isConnected } = useSecurityStream({ onEvent: handleLiveEvent });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Threat Detection & Intelligence
            </h2>
            {isConnected && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE
              </span>
            )}
          </div>
          <p className="text-xs text-[#9CA3AF]">
            Multi-layered detection matching OWASP Top 10 vulnerabilities, behavioral anomalies, and zero-day probes.
          </p>
        </div>
        <span className="text-[10px] font-mono-tech text-[#6B7280]">
          Last updated: {lastUpdated} IST
        </span>
      </div>

      {/* Top Threat Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "ACTIVE THREATS", value: activeThreats.toString(), change: "Live detection count", color: "text-red-400", icon: AlertOctagon },
          { label: "BLOCKED ATTACKS", value: blockedAttacks.toLocaleString(), change: "Audit database total", color: "text-red-400", icon: ShieldAlert },
          { label: "CRITICAL EVENTS", value: criticalEvents.toString(), change: "Risk ≥ 80 incidents", color: "text-amber-400", icon: AlertTriangle },
          { label: "ATTACK RATE", value: `${attackRate} / min`, change: "Rolling 60s window", color: "text-blue-400", icon: Activity },
        ].map((m) => {
          const Icon = m.icon;
          return (
            <div key={m.label} className="glass-panel p-4 rounded-lg flex flex-col justify-between">
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech uppercase">
                  {m.label}
                </span>
                <Icon className={`w-4 h-4 ${m.color}`} />
              </div>
              <div className="text-2xl font-bold font-mono-tech text-[#F3F4F6]">
                {m.value}
              </div>
              <span className="text-[10px] text-[#6B7280] font-mono-tech mt-1">
                {m.change}
              </span>
            </div>
          );
        })}
      </div>

      {/* Attack Distribution Chart & Threat Detail View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Attack Type Distribution */}
        <div className="lg:col-span-2 glass-panel p-5 rounded-lg space-y-4">
          <div className="flex items-center justify-between border-b border-[#202832] pb-3">
            <div>
              <h3 className="text-sm font-bold font-mono-tech text-[#F3F4F6]">
                Attack Vector Breakdown (Live)
              </h3>
              <p className="text-[11px] text-[#6B7280]">
                Proportional distribution of blocked application-layer attack categories.
              </p>
            </div>
            <span className="text-[10px] font-mono-tech text-blue-400">
              {totalDetections.toLocaleString()} Total Detections
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={threatDistribution} layout="vertical" margin={{ left: 20 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#202832" horizontal={false} />
                <XAxis type="number" stroke="#6B7280" fontSize={10} />
                <YAxis dataKey="name" type="category" stroke="#6B7280" fontSize={11} width={110} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: "#10151C",
                    borderColor: "#202832",
                    borderRadius: "6px",
                    fontSize: "11px",
                    fontFamily: "JetBrains Mono",
                  }}
                />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {threatDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Real-time Threat Detail Card */}
        <div className="glass-panel p-5 rounded-lg space-y-4 font-mono-tech text-xs">
          <div className="border-b border-[#202832] pb-3">
            <span className="text-[10px] font-bold text-red-400 tracking-wider uppercase block mb-1">
              {liveThreat ? "LATEST BLOCKED THREAT" : "ACTIVE THREAT SIGNATURE"}
            </span>
            <h3 className="text-base font-bold text-[#F3F4F6]">
              {liveThreat?.category || "Awaiting Data…"}
            </h3>
            <span className="text-[11px] text-[#9CA3AF]">
              Severity: {liveThreat?.severity || "—"} · Confidence: {liveThreat?.confidence || "—"}
            </span>
          </div>

          <div className="space-y-2 text-[11px]">
            <div className="flex justify-between">
              <span className="text-[#6B7280]">Target Endpoint:</span>
              <span className="text-[#F3F4F6] font-bold">{liveThreat?.targetEndpoint || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#6B7280]">Source IP:</span>
              <span className="text-red-400 font-bold">{liveThreat?.sourceIp || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#6B7280]">Triggered Rule:</span>
              <span className="text-blue-400">{liveThreat?.ruleId || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#6B7280]">Action Taken:</span>
              <span className="text-red-400 font-bold">{liveThreat?.action || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#6B7280]">Detected At:</span>
              <span className="text-[#9CA3AF]">{liveThreat?.timestamp || "—"} IST</span>
            </div>
          </div>

          <div className="pt-3 border-t border-[#202832]">
            <span className="text-[10px] text-[#6B7280] uppercase tracking-wider block mb-2">
              Mitigation Pipeline:
            </span>
            <div className="space-y-1.5 text-[10px] text-[#9CA3AF]">
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                <span>01. Request received & IP reputation checked</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
                <span>02. Device fingerprint evaluated</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${liveThreat ? "bg-red-500" : "bg-blue-500"}`} />
                <span>03. {liveThreat ? `${liveThreat.category} payload detected` : "WAF analysis complete"}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-1.5 h-1.5 rounded-full ${liveThreat ? "bg-red-500" : "bg-blue-500"}`} />
                <span>04. Risk score calculated ({liveThreat?.confidence || "—"})</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" />
                <span>05. Policy enforced ({liveThreat?.action || "—"})</span>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
