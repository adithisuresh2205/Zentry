"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  AlertOctagon,
  AlertTriangle,
  Clock,
  Radio,
  ShieldAlert,
} from "lucide-react";
import { useSecurityStream, LiveSecurityEvent } from "../../hooks/useSecurityStream";
import { api } from "../../lib/api";

/** Formats a UTC ISO string to IST display */
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

interface IncidentEvent {
  id: string;
  timestamp: string;
  sourceIp: string;
  path: string;
  action: string;
  riskScore: number;
  riskLevel: string;
  threatCategory: string;
  method: string;
}

interface IncidentGroup {
  id: string;
  title: string;
  severity: string;
  status: string;
  createdAt: string;
  sourceIps: string[];
  affectedEndpoints: string[];
  events: IncidentEvent[];
  eventCount: number;
}

function extractCategory(threats: any): string {
  if (!threats) return "Unknown";
  if (Array.isArray(threats) && threats.length > 0) {
    const t = threats[0];
    if (typeof t === "object" && t) return t.category || t.name || "Unknown";
    if (typeof t === "string") return t;
  }
  return "Unknown";
}

export const IncidentsView: React.FC = () => {
  const [incidents, setIncidents] = useState<IncidentGroup[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentGroup | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [totalBlocked, setTotalBlocked] = useState(0);
  const [totalCritical, setTotalCritical] = useState(0);

  /** Build incident groups from raw blocked events */
  const buildIncidents = useCallback((events: any[]): IncidentGroup[] => {
    // Group blocked events by source IP to form incident groups
    const ipGroups = new Map<string, any[]>();
    for (const evt of events) {
      if (evt.action !== "BLOCK") continue;
      const ip = evt.source_ip || "unknown";
      if (!ipGroups.has(ip)) ipGroups.set(ip, []);
      ipGroups.get(ip)!.push(evt);
    }

    const groups: IncidentGroup[] = [];
    let idx = 0;
    for (const [ip, evts] of ipGroups.entries()) {
      idx++;
      const categories = [...new Set(evts.map((e: any) => extractCategory(e.threats)))];
      const endpoints = [...new Set(evts.map((e: any) => e.path || "/unknown"))];
      const maxRisk = Math.max(...evts.map((e: any) => e.risk_score ?? 0));
      const severity = maxRisk >= 80 ? "CRITICAL" : maxRisk >= 60 ? "HIGH" : maxRisk >= 30 ? "MEDIUM" : "LOW";
      const firstTs = evts[evts.length - 1]?.timestamp || new Date().toISOString();

      groups.push({
        id: `INC-${String(idx).padStart(3, "0")}`,
        title: `${categories.join(", ")} Attack from ${ip}`,
        severity,
        status: severity === "CRITICAL" ? "INVESTIGATING" : "CONTAINED",
        createdAt: toIST(firstTs),
        sourceIps: [ip],
        affectedEndpoints: endpoints.slice(0, 5),
        events: evts.map((e: any) => ({
          id: e.id || e.request_id || `evt-${Math.random()}`,
          timestamp: toIST(e.timestamp),
          sourceIp: e.source_ip || ip,
          path: e.path || "/unknown",
          action: e.action || "BLOCK",
          riskScore: e.risk_score ?? 0,
          riskLevel: e.risk_level || "HIGH",
          threatCategory: extractCategory(e.threats),
          method: e.method || "GET",
        })),
        eventCount: evts.length,
      });
    }

    return groups.sort((a, b) => b.events.length - a.events.length);
  }, []);

  /** Fetch incidents from backend */
  const loadIncidents = useCallback(async () => {
    try {
      const data = await api.security.getStats();

      setTotalBlocked(data.blocked_requests ?? 0);

      if (data.recent_events?.length) {
        const crits = data.recent_events.filter((e: any) =>
          e.risk_level === "CRITICAL" || e.risk_score >= 80
        ).length;
        setTotalCritical(crits);

        const groups = buildIncidents(data.recent_events);
        setIncidents(groups);
        if (groups.length > 0 && !selectedIncident) {
          setSelectedIncident(groups[0]);
        }
      }
    } catch {
      // Backend not available
    } finally {
      setIsLoading(false);
    }
  }, [buildIncidents, selectedIncident]);

  useEffect(() => {
    loadIncidents();
    const interval = setInterval(loadIncidents, 10000);
    return () => clearInterval(interval);
  }, [loadIncidents]);

  // Live WebSocket updates
  const handleLiveEvent = useCallback((evt: LiveSecurityEvent) => {
    const action = ((evt.action as string) || "ALLOW").toUpperCase();
    if (action !== "BLOCK") return;

    setTotalBlocked((prev) => prev + 1);
    const score = Number(evt.risk_score ?? 0);
    if (score >= 80) setTotalCritical((prev) => prev + 1);

    const newEvent: IncidentEvent = {
      id: (evt.id as string) || (evt.request_id as string) || `live-${Date.now()}`,
      timestamp: toIST(evt.timestamp as string),
      sourceIp: (evt.source_ip as string) || "0.0.0.0",
      path: (evt.path as string) || "/unknown",
      action: "BLOCK",
      riskScore: score,
      riskLevel: (evt.risk_level as string) || "HIGH",
      threatCategory: extractCategory(evt.threats),
      method: (evt.method as string) || "GET",
    };

    setIncidents((prev) => {
      const existing = prev.find((g) => g.sourceIps.includes(newEvent.sourceIp));
      if (existing) {
        return prev.map((g) =>
          g.id === existing.id
            ? {
                ...g,
                events: [newEvent, ...g.events.slice(0, 19)],
                eventCount: g.eventCount + 1,
                status: score >= 80 ? "INVESTIGATING" : g.status,
              }
            : g
        );
      } else {
        const newGroup: IncidentGroup = {
          id: `INC-LIVE-${Date.now()}`,
          title: `${newEvent.threatCategory} Attack from ${newEvent.sourceIp}`,
          severity: score >= 80 ? "CRITICAL" : score >= 60 ? "HIGH" : "MEDIUM",
          status: "INVESTIGATING",
          createdAt: newEvent.timestamp,
          sourceIps: [newEvent.sourceIp],
          affectedEndpoints: [newEvent.path],
          events: [newEvent],
          eventCount: 1,
        };
        return [newGroup, ...prev.slice(0, 19)];
      }
    });
  }, []);

  const { isConnected } = useSecurityStream({ onEvent: handleLiveEvent });

  const hasNoData = !isLoading && incidents.length === 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <h2 className="text-lg font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Incidents
            </h2>
            {isConnected && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE
              </span>
            )}
          </div>
          <p className="text-xs text-[#9CA3AF]">
            Security incidents correlated from blocked events. Grouped by source IP and attack vector.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <div className="text-right">
            <div className="text-[10px] text-[#6B7280] font-mono-tech">TOTAL BLOCKED</div>
            <div className="text-sm font-bold text-red-400 font-mono-tech">{totalBlocked.toLocaleString()}</div>
          </div>
          <div className="text-right">
            <div className="text-[10px] text-[#6B7280] font-mono-tech">CRITICAL</div>
            <div className="text-sm font-bold text-amber-400 font-mono-tech">{totalCritical}</div>
          </div>
        </div>
      </div>

      {/* No data state */}
      {hasNoData && (
        <div className="glass-panel p-8 rounded-lg text-center">
          <ShieldAlert className="w-8 h-8 text-[#6B7280] mx-auto mb-3" />
          <h3 className="text-sm font-bold text-[#F3F4F6] font-mono-tech">No Incidents Recorded</h3>
          <p className="text-xs text-[#9CA3AF] mt-1">
            Run attack simulations against the gateway to generate incident data.
          </p>
        </div>
      )}

      {/* Incidents Grid */}
      {incidents.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Incident List */}
          <div className="lg:col-span-2 space-y-3">
            {incidents.map((inc) => {
              const isSelected = selectedIncident?.id === inc.id;
              const severityColor =
                inc.severity === "CRITICAL"
                  ? "bg-red-500/20 text-red-400 border-red-500/40"
                  : inc.severity === "HIGH"
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                  : "bg-blue-500/20 text-blue-400 border-blue-500/40";
              const statusColor =
                inc.status === "INVESTIGATING"
                  ? "bg-amber-500/20 text-amber-400 border-amber-500/40"
                  : "bg-emerald-500/20 text-emerald-400 border-emerald-500/40";

              return (
                <div
                  key={inc.id}
                  onClick={() => setSelectedIncident(inc)}
                  className={`glass-panel p-4 rounded-lg cursor-pointer transition-all border ${
                    isSelected
                      ? "border-blue-500/50 bg-[#171D26]"
                      : "border-transparent hover:border-white/10 hover:bg-[#131922]"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono-tech border ${severityColor}`}>
                        {inc.severity}
                      </span>
                      <span className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono-tech border ${statusColor}`}>
                        {inc.status}
                      </span>
                      <span className="text-[10px] text-[#6B7280] font-mono-tech">{inc.id}</span>
                    </div>
                    <span className="text-[10px] text-[#6B7280] font-mono-tech">
                      {inc.eventCount} event{inc.eventCount !== 1 ? "s" : ""}
                    </span>
                  </div>
                  <h3 className="text-xs font-bold text-[#F3F4F6] font-mono-tech">{inc.title}</h3>
                  <p className="text-[10px] text-[#9CA3AF] mt-1">
                    First seen: {inc.createdAt} IST · Endpoints: {inc.affectedEndpoints.join(", ")}
                  </p>
                </div>
              );
            })}
          </div>

          {/* Selected Incident Detail */}
          {selectedIncident && (
            <div className="glass-panel p-5 rounded-lg space-y-4 font-mono-tech text-xs">
              <div className="border-b border-[#202832] pb-3">
                <div className="flex items-center gap-2 mb-1">
                  <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-mono-tech text-[10px] font-bold border border-red-500/40">
                    {selectedIncident.id}
                  </span>
                </div>
                <h3 className="font-bold text-[#F3F4F6] text-sm">{selectedIncident.title}</h3>
              </div>

              {/* Attack Timeline */}
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <Clock className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-[10px] text-[#6B7280] uppercase tracking-wider font-bold">
                    Event Timeline (IST)
                  </span>
                </div>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {selectedIncident.events.slice(0, 10).map((ev, idx) => (
                    <div key={ev.id} className="flex items-start gap-3">
                      <span className="px-2 py-0.5 rounded bg-[#10151C] text-blue-400 border border-[#202832] font-bold text-[10px] shrink-0">
                        {ev.timestamp}
                      </span>
                      <div className="flex-1 pb-2 border-b border-[#202832]/60">
                        <div className="text-[#F3F4F6] font-bold text-[11px]">
                          {ev.method} {ev.path}
                        </div>
                        <div className="text-[#9CA3AF] text-[10px] mt-0.5">
                          {ev.threatCategory} · Risk: {ev.riskScore} · {ev.action}
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* IOC & Scope */}
              <div className="space-y-3 pt-2 border-t border-[#202832]">
                <div>
                  <span className="text-[10px] text-[#6B7280] uppercase tracking-wider block mb-1">
                    Attacker IP Addresses:
                  </span>
                  <div className="space-y-1">
                    {selectedIncident.sourceIps.map((ip) => (
                      <div key={ip} className="p-1.5 rounded bg-[#10151C] text-red-400 font-bold text-[11px] border border-red-500/20">
                        {ip}
                      </div>
                    ))}
                  </div>
                </div>
                <div>
                  <span className="text-[10px] text-[#6B7280] uppercase tracking-wider block mb-1">
                    Targeted Endpoints:
                  </span>
                  <div className="space-y-1">
                    {selectedIncident.affectedEndpoints.map((ep) => (
                      <div key={ep} className="p-1.5 rounded bg-[#10151C] text-[#F3F4F6] text-[11px] border border-[#202832]">
                        {ep}
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <button
                onClick={() => alert(`Incident ${selectedIncident.id} marked as contained.`)}
                className="w-full py-2 rounded bg-blue-600 hover:bg-blue-500 text-xs font-mono-tech text-white font-semibold transition-colors"
              >
                Contain Incident
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
