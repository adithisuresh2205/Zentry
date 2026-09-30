"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import {
  Download,
  Filter,
  RefreshCw,
  Search,
  Shield,
  SlidersHorizontal,
} from "lucide-react";
import { MOCK_REQUESTS } from "../../lib/mockData";
import { Decision, RiskLevel, SecurityRequest, ThreatCategory } from "../../types";
import { useSecurityStream, LiveSecurityEvent } from "../../hooks/useSecurityStream";
import { api } from "../../lib/api";
import { extractThreatString } from "./OverviewView";

interface RequestExplorerViewProps {
  onSelectRequest: (req: SecurityRequest) => void;
}

export function mapBackendEventToSecurityRequest(e: any): SecurityRequest {
  const isBlock = (e.action || "").toUpperCase() === "BLOCK";
  const isChallenge = (e.action || "").toUpperCase() === "CHALLENGE";
  const decision: Decision = isBlock ? "BLOCKED" : isChallenge ? "CHALLENGED" : "ALLOWED";
  const riskScore = Number(e.risk_score ?? (isBlock ? 85 : isChallenge ? 55 : 12));
  const riskLevel: RiskLevel =
    (e.risk_level as RiskLevel) ||
    (riskScore >= 80 ? "CRITICAL" : riskScore >= 60 ? "HIGH" : riskScore >= 30 ? "MEDIUM" : "LOW");

  const threatItems: SecurityRequest["threats"] = [];
  if (e.threats && Array.isArray(e.threats)) {
    e.threats.forEach((t: any) => {
      if (!t) return;
      if (typeof t === "string") {
        if (t !== "[object Object]") {
          threatItems.push({
            category: (t as ThreatCategory) || "SQL_INJECTION",
            name: t,
            confidence: 95,
            ruleId: "RULE_AUTO",
          });
        }
      } else if (typeof t === "object") {
        threatItems.push({
          category: (t.category as ThreatCategory) || "SQL_INJECTION",
          name: t.name || t.category || t.rule_id || "THREAT",
          confidence: Math.round(Number(t.confidence ?? 0.95) <= 1 ? Number(t.confidence ?? 0.95) * 100 : Number(t.confidence ?? 95)),
          ruleId: t.ruleId || t.rule_id || "RULE_INSPECT",
        });
      }
    });
  }

  const timeStr = (() => {
    try {
      const d = e.timestamp ? new Date(e.timestamp) : new Date();
      return d.toLocaleTimeString("en-IN", {
        timeZone: "Asia/Kolkata",
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        hour12: false,
      }) + " IST";
    } catch {
      return "—";
    }
  })();

  return {
    id: e.request_id || e.id || `req-${Math.random().toString(36).substring(2, 9)}`,
    timestamp: e.timestamp || new Date().toISOString(),
    timeDisplay: timeStr,
    method: (e.method || "GET").toUpperCase() as SecurityRequest["method"],
    sourceIp: e.source_ip || "127.0.0.1",
    location: e.source_ip === "127.0.0.1" ? "Localhost" : "External / Wan",
    identity: e.user_id || (isBlock ? "unauthenticated_attacker" : "auth_user_01"),
    identityTrust: isBlock ? 15 : 94,
    endpoint: e.path || "/api/v1/resource",
    riskScore,
    riskLevel,
    decision,
    statusCode: Number(e.response_code ?? (isBlock ? 403 : 200)),
    device: {
      id: "DEV-GATEWAY-AUTO",
      os: "Linux / Windows Host",
      browser: e.user_agent ? e.user_agent.split(" ")[0] : "curl/7.88.1",
      fingerprint: "fp_sha256_" + Math.random().toString(36).substring(2, 8),
      trustScore: isBlock ? 20 : 92,
      status: isBlock ? "Suspicious" : "Verified",
    },
    network: {
      ip: e.source_ip || "127.0.0.1",
      reputation: isBlock ? "Malicious" : "Trusted",
      asn: "AS15169 Google LLC",
    },
    riskBreakdown: {
      identity: isBlock ? 80 : 10,
      device: isBlock ? 65 : 12,
      network: isBlock ? 70 : 8,
      behavior: isBlock ? 90 : 15,
    },
    threats: threatItems,
    appliedPolicy: isBlock ? "POL-001: WAF Strict Enforcement" : "POL-004: Standard Verified Access",
    policyReason: isBlock
      ? "Payload contained prohibited signatures matching WAF detection rules."
      : "Zero-Trust evaluation satisfied all gate criteria.",
  };
}

export const RequestExplorerView: React.FC<RequestExplorerViewProps> = ({
  onSelectRequest,
}) => {
  const [requests, setRequests] = useState<SecurityRequest[]>([]);
  const [searchQuery, setSearchQuery] = useState("");
  const [methodFilter, setMethodFilter] = useState<string>("ALL");
  const [decisionFilter, setDecisionFilter] = useState<string>("ALL");
  const [selectedRequestId, setSelectedRequestId] = useState<string | null>(null);

  const loadRequests = useCallback(async () => {
    try {
      const res = await api.security.getEvents({ limit: 100 });
      if (res && res.events && res.events.length > 0) {
        const mapped = res.events.map(mapBackendEventToSecurityRequest);
        setRequests(mapped);
      }
    } catch {
      // Keep existing requests on fetch failure
    }
  }, []);

  useEffect(() => {
    loadRequests();
    const interval = setInterval(loadRequests, 10000);
    return () => clearInterval(interval);
  }, [loadRequests]);

  const handleLiveEvent = useCallback((liveEvt: LiveSecurityEvent) => {
    const newReq = mapBackendEventToSecurityRequest(liveEvt);
    setRequests((prev) => [newReq, ...prev.filter((r) => r.id !== newReq.id).slice(0, 99)]);
  }, []);

  const { isConnected } = useSecurityStream({
    onEvent: handleLiveEvent,
  });

  const filteredRequests = requests.filter((r) => {
    const matchesSearch =
      searchQuery === "" ||
      r.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.endpoint.toLowerCase().includes(searchQuery.toLowerCase()) ||
      r.sourceIp.includes(searchQuery) ||
      r.identity.toLowerCase().includes(searchQuery.toLowerCase());

    const matchesMethod =
      methodFilter === "ALL" || r.method === methodFilter;

    const matchesDecision =
      decisionFilter === "ALL" || r.decision === decisionFilter;

    return matchesSearch && matchesMethod && matchesDecision;
  });

  return (
    <div className="space-y-4">
      {/* View Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-blue-500 animate-pulse" />
            <h2 className="text-base font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Request Explorer
            </h2>
          </div>
          <p className="text-xs text-[#9CA3AF] mt-0.5">
            Forensic inspection and telemetry for all intercepted inbound requests.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <div className="flex items-center gap-2 text-[10px] font-mono-tech text-blue-400 bg-blue-500/10 px-3 py-1 rounded-full border border-blue-500/20">
            <span
              className={`w-2 h-2 rounded-full ${
                isConnected ? "bg-emerald-400 animate-pulse shadow-[0_0_8px_rgba(16,185,129,0.8)]" : "bg-amber-400"
              }`}
            />
            <span>{isConnected ? "Live Stream" : "Connecting..."}</span>
          </div>

          <button
            onClick={() => loadRequests()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#10151C]/90 hover:bg-[#171D26] text-xs font-mono-tech text-[#F3F4F6] border border-white/10 transition-all shadow-sm"
            title="Refresh requests from database"
          >
            <RefreshCw className="w-3.5 h-3.5 text-cyan-400" />
            Reload
          </button>

          <button
            onClick={() => {
              const blob = new Blob([JSON.stringify(filteredRequests, null, 2)], {
                type: "application/json",
              });
              const url = URL.createObjectURL(blob);
              const a = document.createElement("a");
              a.href = url;
              a.download = "zentry-forensic-telemetry.json";
              a.click();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#10151C]/90 hover:bg-[#171D26] text-xs font-mono-tech text-[#F3F4F6] border border-white/10 transition-all shadow-sm"
          >
            <Download className="w-3.5 h-3.5 text-blue-400" />
            Export Telemetry
          </button>
        </div>
      </div>

      {/* Filter Toolbar with Specular Glass Panel */}
      <div className="glass-panel tactical-corner p-3.5 rounded-xl flex flex-wrap items-center gap-3">
        {/* Search */}
        <div className="relative flex-1 min-w-[220px]">
          <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-[#6B7280]" />
          <input
            type="text"
            placeholder="Filter by ID, IP, endpoint, or identity..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-[#080B10]/80 border border-white/10 rounded-lg pl-8 pr-3 py-1.5 text-xs text-[#F3F4F6] placeholder-[#6B7280] focus:outline-none focus:border-blue-500/60 font-mono-tech transition-colors shadow-inner"
          />
        </div>

        {/* Method Filter */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-[#6B7280] font-mono-tech uppercase mr-1">
            Method:
          </span>
          {["ALL", "GET", "POST"].map((m) => (
            <button
              key={m}
              onClick={() => setMethodFilter(m)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono-tech transition-all ${
                methodFilter === m
                  ? "bg-blue-600 text-white font-bold shadow-[0_0_12px_rgba(59,130,246,0.5)]"
                  : "bg-[#080B10]/60 text-[#9CA3AF] border border-white/5 hover:text-[#F3F4F6] hover:bg-white/[0.04]"
              }`}
            >
              {m}
            </button>
          ))}
        </div>

        {/* Decision Filter */}
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-[#6B7280] font-mono-tech uppercase mr-1">
            Decision:
          </span>
          {["ALL", "ALLOWED", "BLOCKED", "CHALLENGED"].map((d) => (
            <button
              key={d}
              onClick={() => setDecisionFilter(d)}
              className={`px-2.5 py-1 rounded-lg text-[11px] font-mono-tech transition-all ${
                decisionFilter === d
                  ? "bg-blue-600 text-white font-bold shadow-[0_0_12px_rgba(59,130,246,0.5)]"
                  : "bg-[#080B10]/60 text-[#9CA3AF] border border-white/5 hover:text-[#F3F4F6] hover:bg-white/[0.04]"
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {/* Main Request Forensic Table */}
      <div className="glass-panel tactical-corner rounded-xl overflow-hidden border border-white/5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono-tech">
            <thead className="bg-[#0B0F14]/90 border-b border-white/5 text-[10px] font-bold text-[#6B7280] tracking-wider uppercase">
              <tr>
                <th className="py-3 px-4">TIME</th>
                <th className="py-3 px-4">REQUEST ID</th>
                <th className="py-3 px-4">METHOD</th>
                <th className="py-3 px-4">SOURCE IP</th>
                <th className="py-3 px-4">IDENTITY</th>
                <th className="py-3 px-4">ENDPOINT</th>
                <th className="py-3 px-4 text-center">RISK</th>
                <th className="py-3 px-4">DECISION</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-white/5">
              {filteredRequests.map((req, idx) => {
                const isBlocked = req.decision === "BLOCKED";
                const isChallenged = req.decision === "CHALLENGED";
                const isSelected = selectedRequestId === req.id;

                return (
                  <motion.tr
                    key={req.id}
                    initial={{ opacity: 0, y: 4 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.02, duration: 0.2 }}
                    onClick={() => {
                      setSelectedRequestId(req.id);
                      onSelectRequest(req);
                    }}
                    className={`cursor-pointer transition-all group ${
                      isSelected
                        ? "bg-blue-500/10 border-l-2 border-l-blue-500"
                        : "hover:bg-white/[0.03]"
                    }`}
                  >
                    <td className="py-3 px-4 text-[#6B7280]">{req.timeDisplay}</td>
                    <td className="py-3 px-4 text-blue-400 font-semibold group-hover:text-blue-300">
                      {req.id}
                    </td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded bg-[#10151C] text-[#F3F4F6] border border-white/5 text-[10px]">
                        {req.method}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-[#F3F4F6]">{req.sourceIp}</td>
                    <td className="py-3 px-4 text-[#9CA3AF]">{req.identity}</td>
                    <td className="py-3 px-4 text-[#F3F4F6] truncate max-w-xs">{req.endpoint}</td>
                    <td className="py-3 px-4 text-center">
                      <span
                        className={`font-bold px-2 py-0.5 rounded ${
                          req.riskScore >= 80
                            ? "text-red-400 bg-red-500/10"
                            : req.riskScore >= 60
                            ? "text-amber-400 bg-amber-500/10"
                            : req.riskScore >= 30
                            ? "text-yellow-400 bg-yellow-500/10"
                            : "text-emerald-400 bg-emerald-500/10"
                        }`}
                      >
                        {req.riskScore}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2.5 py-0.5 rounded text-[10px] font-bold ${
                          isBlocked
                            ? "bg-red-500/15 text-red-300 border border-red-500/30 glow-red"
                            : isChallenged
                            ? "bg-amber-500/15 text-amber-300 border border-amber-500/30 glow-amber"
                            : "bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 glow-emerald"
                        }`}
                      >
                        {req.decision}
                      </span>
                    </td>
                  </motion.tr>
                );
              })}
            </tbody>
          </table>
        </div>

        <div className="p-3.5 bg-[#0B0F14]/95 border-t border-white/5 flex items-center justify-between text-[11px] text-[#6B7280] font-mono-tech">
          <span>Showing {filteredRequests.length} recorded gateway requests</span>
          <span className="text-blue-400/80">Click any row to open Request Investigation Drawer</span>
        </div>
      </div>
    </div>
  );
};
