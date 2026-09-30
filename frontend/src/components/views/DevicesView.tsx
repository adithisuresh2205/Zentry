"use client";

import React, { useState, useEffect, useCallback } from "react";
import { HardDrive, Radio, Search, Filter, ShieldCheck, ShieldAlert, AlertTriangle } from "lucide-react";
import { api, DeviceData } from "../../lib/api";
import { useSecurityStream, LiveSecurityEvent } from "../../hooks/useSecurityStream";

export const DevicesView: React.FC = () => {
  const [devices, setDevices] = useState<DeviceData[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [isLoading, setIsLoading] = useState(true);

  const loadDevices = useCallback(async () => {
    try {
      const data = await api.security.getDevices();
      if (data && data.length > 0) {
        setDevices(data);
      }
    } catch {
      // offline fallback
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDevices();
    const interval = setInterval(loadDevices, 10000);
    return () => clearInterval(interval);
  }, [loadDevices]);

  // Live WebSocket device update
  const handleLiveEvent = useCallback((evt: LiveSecurityEvent) => {
    const ip = (evt.source_ip as string) || "127.0.0.1";
    const isBlock = ((evt.action as string) || "").toUpperCase() === "BLOCK";
    const risk = Number(evt.risk_score ?? (isBlock ? 85 : 10));

    setDevices((prev) => {
      const matchIdx = prev.findIndex((d) => d.ip === ip);
      if (matchIdx >= 0) {
        const updated = [...prev];
        const current = updated[matchIdx];
        const newTrust = isBlock ? Math.max(10, current.trustScore - 12) : Math.min(99, current.trustScore + 1);
        const newStatus = newTrust >= 80 ? "Known" : newTrust >= 40 ? "Suspicious" : "Quarantined";
        updated[matchIdx] = {
          ...current,
          trustScore: newTrust,
          status: newStatus,
          requestCount: current.requestCount + 1,
          lastSeen: "Just now (Live)",
        };
        return updated;
      } else {
        const newTrust = isBlock ? 15 : 95;
        const newDevice: DeviceData = {
          id: `DEV-${ip.replace(/\./g, "-")}-NEW`,
          user: (evt.user_id as string) || (isBlock ? "Anonymous" : "admin"),
          os: "Observed Client Host",
          browser: typeof evt.user_agent === "string" ? evt.user_agent.split(" ")[0] : "HTTP Client",
          trustScore: newTrust,
          lastSeen: "Just now (Live)",
          status: newTrust >= 80 ? "Known" : newTrust >= 40 ? "Suspicious" : "Quarantined",
          ip,
          requestCount: 1,
        };
        return [newDevice, ...prev];
      }
    });
  }, []);

  const { isConnected } = useSecurityStream({ onEvent: handleLiveEvent });

  const filteredDevices = devices.filter((d) => {
    const matchSearch =
      search === "" ||
      d.id.toLowerCase().includes(search.toLowerCase()) ||
      d.user.toLowerCase().includes(search.toLowerCase()) ||
      d.os.toLowerCase().includes(search.toLowerCase()) ||
      d.browser.toLowerCase().includes(search.toLowerCase()) ||
      d.ip.includes(search);

    const matchStatus = statusFilter === "ALL" || d.status.toUpperCase() === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Device Fleet Posture
            </h2>
            {isConnected && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE SYNC
              </span>
            )}
          </div>
          <p className="text-xs text-[#9CA3AF]">
            Continuous real-time device posture derived from intercepted network traffic, client headers, and trust attestation.
          </p>
        </div>

        {/* Search & Filter Controls */}
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-[#6B7280]" />
            <input
              type="text"
              placeholder="Filter by IP, OS, or Device ID..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-[#0D1219] border border-[#202832] rounded text-xs text-[#F3F4F6] placeholder-[#6B7280] font-mono-tech focus:outline-none focus:border-blue-500 w-56 sm:w-64"
            />
          </div>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="px-2.5 py-1.5 bg-[#0D1219] border border-[#202832] rounded text-xs text-[#F3F4F6] font-mono-tech focus:outline-none focus:border-blue-500"
          >
            <option value="ALL">All Postures</option>
            <option value="KNOWN">Known / Healthy</option>
            <option value="SUSPICIOUS">Suspicious</option>
            <option value="QUARANTINED">Quarantined</option>
          </select>
        </div>
      </div>

      {/* Real Devices Table */}
      <div className="glass-panel rounded-lg overflow-hidden">
        <table className="w-full text-left text-xs font-mono-tech">
          <thead className="bg-[#0B0F14] border-b border-[#202832] text-[10px] font-bold text-[#6B7280] tracking-wider uppercase">
            <tr>
              <th className="py-2.5 px-3">DEVICE ID</th>
              <th className="py-2.5 px-3">SOURCE IP</th>
              <th className="py-2.5 px-3">IDENTITY</th>
              <th className="py-2.5 px-3">OPERATING SYSTEM</th>
              <th className="py-2.5 px-3">BROWSER / CLIENT</th>
              <th className="py-2.5 px-3 text-center">REQUESTS</th>
              <th className="py-2.5 px-3 text-center">TRUST SCORE</th>
              <th className="py-2.5 px-3">LAST SEEN</th>
              <th className="py-2.5 px-3">STATUS</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#202832]">
            {filteredDevices.length === 0 ? (
              <tr>
                <td colSpan={9} className="py-8 text-center text-xs text-[#6B7280] font-mono-tech">
                  {isLoading ? "Loading real-time device telemetry from gateway..." : "No client devices match the current filter."}
                </td>
              </tr>
            ) : (
              filteredDevices.map((d) => (
                <tr key={d.id} className="hover:bg-[#131922] transition-colors">
                  <td className="py-2.5 px-3 font-semibold text-blue-400">{d.id}</td>
                  <td className="py-2.5 px-3 text-[#9CA3AF]">{d.ip}</td>
                  <td className="py-2.5 px-3 text-[#F3F4F6]">{d.user}</td>
                  <td className="py-2.5 px-3 text-[#9CA3AF]">{d.os}</td>
                  <td className="py-2.5 px-3 text-[#9CA3AF] max-w-[160px] truncate" title={d.browser}>
                    {d.browser}
                  </td>
                  <td className="py-2.5 px-3 text-center text-[#9CA3AF] font-bold">
                    {d.requestCount}
                  </td>
                  <td className="py-2.5 px-3 text-center font-bold">
                    <span
                      className={
                        d.trustScore >= 80
                          ? "text-emerald-400"
                          : d.trustScore >= 50
                          ? "text-amber-400"
                          : "text-red-400"
                      }
                    >
                      {d.trustScore}
                    </span>
                  </td>
                  <td className="py-2.5 px-3 text-[#6B7280]">{d.lastSeen}</td>
                  <td className="py-2.5 px-3">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                        d.status === "Known"
                          ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                          : d.status === "Suspicious"
                          ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                          : "bg-red-500/20 text-red-400 border border-red-500/30"
                      }`}
                    >
                      {d.status}
                    </span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
};
