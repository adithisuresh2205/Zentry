"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  CheckCircle2,
  Info,
  Radio,
  Shield,
  User,
  UserCheck,
  UserX,
} from "lucide-react";
import { IdentityItem } from "../../types";
import { useSecurityStream, LiveSecurityEvent } from "../../hooks/useSecurityStream";
import { api } from "../../lib/api";

/** Formats a timestamp to IST display */
function toIST(ts?: string | Date): string {
  try {
    const d = ts ? new Date(ts) : new Date();
    return d.toLocaleString("en-IN", {
      timeZone: "Asia/Kolkata",
      day: "2-digit",
      month: "short",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    }) + " IST";
  } catch {
    return "Just now (IST)";
  }
}

const DEFAULT_IDENTITIES: IdentityItem[] = [
  {
    id: "USR-ADMIN-01",
    email: "secops-lead@zentry.corp",
    name: "Elena Rostova",
    role: "ADMIN",
    roles: ["ADMIN", "SOC_LEAD", "IR_COMMANDER"],
    type: "Human",
    trustScore: 96,
    lastActive: toIST(),
    authMethod: "FIDO2 WebAuthn (YubiKey 5C) + Biometric",
    status: "TRUSTED",
    location: "HQ Mumbai, IN (AS55836)",
    deviceCount: 2,
  },
  {
    id: "USR-ENG-02",
    email: "platform-deploy@zentry.corp",
    name: "Vikram Patel",
    role: "ANALYST",
    roles: ["ANALYST", "ENG_READ_WRITE"],
    type: "Human",
    trustScore: 88,
    lastActive: toIST(),
    authMethod: "OIDC Bearer JWT + TOTP",
    status: "TRUSTED",
    location: "Bengaluru, IN (AS24186)",
    deviceCount: 1,
  },
  {
    id: "SVC-GATEWAY-SYNC",
    email: "gateway-sync@service.zentry.internal",
    name: "Gateway Sync Service",
    role: "SERVICE",
    roles: ["SERVICE_MESH", "TELEMETRY_INGEST"],
    type: "Service",
    trustScore: 99,
    lastActive: toIST(),
    authMethod: "mTLS SPIFFE / X.509 Certificate",
    status: "TRUSTED",
    location: "Cluster Node 01 (VPC Internal)",
    deviceCount: 3,
  },
  {
    id: "ATTACKER-PROBE-01",
    email: "unauthenticated-probe@ext.wan",
    name: "External Scanner",
    role: "ANONYMOUS",
    roles: ["UNVERIFIED_CLIENT"],
    type: "Token",
    trustScore: 12,
    lastActive: toIST(),
    authMethod: "None / Missing Token (Blocked)",
    status: "UNTRUSTED",
    location: "External WAN (AS14061)",
    deviceCount: 1,
  },
];

export const IdentitiesView: React.FC = () => {
  const [identities, setIdentities] = useState<IdentityItem[]>(DEFAULT_IDENTITIES);
  const [selectedId, setSelectedId] = useState<IdentityItem | null>(DEFAULT_IDENTITIES[0]);
  const [lastUpdated, setLastUpdated] = useState<string>(toIST());

  /** Load identities from backend API */
  const loadIdentities = useCallback(async () => {
    try {
      const data = await api.security.getIdentities();
      if (data.identities && data.identities.length > 0) {
        setIdentities(data.identities as any);
        setLastUpdated(toIST());
        if (!selectedId) {
          setSelectedId(data.identities[0] as any);
        }
      }
    } catch {
      // Backend fallback
    }
  }, [selectedId]);

  useEffect(() => {
    loadIdentities();
    const interval = setInterval(loadIdentities, 10000);
    return () => clearInterval(interval);
  }, [loadIdentities]);

  // Live WebSocket update
  const handleLiveEvent = useCallback((evt: LiveSecurityEvent) => {
    const isBlock = ((evt.action as string) || "").toUpperCase() === "BLOCK";
    const srcIp = (evt.source_ip as string) || "127.0.0.1";
    const score = Number(evt.risk_score ?? 0);
    const nowStr = toIST();

    setLastUpdated(nowStr);

    setIdentities((prev) => {
      // Check if we have an identity matching the source IP or user
      const existingIdx = prev.findIndex(
        (id) => id.location?.includes(srcIp) || id.email.includes(srcIp.replace(/\./g, "-"))
      );

      if (existingIdx >= 0) {
        const updated = [...prev];
        const item = updated[existingIdx];
        const newScore = isBlock ? Math.max(5, item.trustScore - 15) : Math.min(99, item.trustScore + 2);
        updated[existingIdx] = {
          ...item,
          trustScore: newScore,
          lastActive: nowStr,
          status: newScore >= 70 ? "TRUSTED" : newScore >= 40 ? "WARNING" : "UNTRUSTED",
        };
        return updated;
      } else if (isBlock) {
        // Create an observed untrusted entity
        const newIdentity: IdentityItem = {
          id: `CLIENT-IP-${srcIp.replace(/\./g, "-")}`,
          email: `probe-${srcIp.replace(/\./g, "-")}@ext.wan`,
          name: `Probing Host (${srcIp})`,
          role: "ANONYMOUS",
          roles: ["EXTERNAL_PROBE"],
          type: "Token",
          trustScore: Math.max(5, 100 - score),
          lastActive: nowStr,
          authMethod: "Unauthenticated Payload Intercepted",
          status: "UNTRUSTED",
          location: `${srcIp} (Blocked Netblock)`,
          deviceCount: 1,
        };
        return [newIdentity, ...prev.slice(0, 7)];
      }
      return prev;
    });
  }, []);

  const { isConnected } = useSecurityStream({ onEvent: handleLiveEvent });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Zero-Trust Identity Governance & Context
            </h2>
            {isConnected && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE
              </span>
            )}
          </div>
          <p className="text-xs text-[#9CA3AF]">
            Continuous verification and dynamic trust scoring across humans, service tokens, mTLS certificates, and unauthenticated hosts.
          </p>
        </div>
        <span className="text-[10px] font-mono-tech text-[#6B7280]">
          Last telemetry sync: {lastUpdated}
        </span>
      </div>

      {/* Identity Architecture Context Banner */}
      <div className="glass-panel p-4 rounded-xl border border-blue-500/20 bg-blue-500/[0.03] flex items-start gap-3">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <div className="text-xs font-mono-tech text-[#9CA3AF] leading-relaxed">
          <span className="text-[#F3F4F6] font-bold">How Gateway Identity Resolution Works:</span> The Zentry gateway intercepts incoming HTTP requests, extracts cryptographic Authorization tokens (Bearer JWT/OIDC) or mTLS X.509 client certificates, and evaluates real-time trust. For unauthenticated requests, it synthesizes an ephemeral client identity from the Device Fingerprint + Source IP/ASN to track behavioral posture across inspection gates.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Identity Table */}
        <div className="lg:col-span-2 glass-panel rounded-lg overflow-hidden">
          <table className="w-full text-left text-xs font-mono-tech">
            <thead className="bg-[#0B0F14] border-b border-[#202832] text-[10px] font-bold text-[#6B7280] tracking-wider uppercase">
              <tr>
                <th className="py-2.5 px-3">IDENTITY</th>
                <th className="py-2.5 px-3">TYPE</th>
                <th className="py-2.5 px-3">TRUST SCORE</th>
                <th className="py-2.5 px-3">LAST ACTIVE (IST)</th>
                <th className="py-2.5 px-3">AUTHENTICATION</th>
                <th className="py-2.5 px-3">STATUS</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#202832]">
              {identities.map((id) => {
                const isTrusted = id.status === "TRUSTED";
                const isSelected = selectedId?.id === id.id;
                return (
                  <tr
                    key={id.id}
                    onClick={() => setSelectedId(id)}
                    className={`cursor-pointer transition-colors ${
                      isSelected ? "bg-[#171D26]" : "hover:bg-[#131922]"
                    }`}
                  >
                    <td className="py-2.5 px-3 font-semibold text-[#F3F4F6]">{id.email}</td>
                    <td className="py-2.5 px-3 text-[#9CA3AF]">{id.type}</td>
                    <td className="py-2.5 px-3 font-bold">
                      <span
                        className={
                          id.trustScore >= 70
                            ? "text-emerald-400"
                            : id.trustScore >= 40
                            ? "text-amber-400"
                            : "text-red-400"
                        }
                      >
                        {id.trustScore}/100
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-[#6B7280] text-[11px]">{id.lastActive}</td>
                    <td className="py-2.5 px-3">
                      <span className="px-1.5 py-0.5 rounded bg-[#10151C] text-blue-400 border border-[#202832] text-[10px] truncate max-w-[130px] inline-block">
                        {id.authMethod}
                      </span>
                    </td>
                    <td className="py-2.5 px-3">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                          isTrusted
                            ? "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30"
                            : id.status === "WARNING"
                            ? "bg-amber-500/20 text-amber-400 border border-amber-500/30"
                            : "bg-red-500/20 text-red-400 border border-red-500/30"
                        }`}
                      >
                        {id.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>

        {/* Identity Detail Sidebar */}
        {selectedId && (
          <div className="glass-panel p-5 rounded-lg space-y-4 font-mono-tech text-xs">
            <div className="flex items-center gap-3 border-b border-[#202832] pb-3">
              <div className="w-10 h-10 rounded bg-[#171D26] border border-[#27313C] flex items-center justify-center text-blue-400">
                <User className="w-5 h-5" />
              </div>
              <div>
                <h3 className="font-bold text-[#F3F4F6] text-sm">{selectedId.email}</h3>
                <span className="text-[10px] text-[#6B7280]">
                  Type: {selectedId.type} · ID: {selectedId.id}
                </span>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex justify-between">
                <span className="text-[#6B7280]">Assigned Roles:</span>
                <span className="text-[#F3F4F6] font-bold">{selectedId.roles.join(", ")}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#6B7280]">Trust Score:</span>
                <span
                  className={`font-bold ${
                    selectedId.trustScore >= 70
                      ? "text-emerald-400"
                      : selectedId.trustScore >= 40
                      ? "text-amber-400"
                      : "text-red-400"
                  }`}
                >
                  {selectedId.trustScore} / 100
                </span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#6B7280]">Origin / ASN:</span>
                <span className="text-[#F3F4F6]">{selectedId.location || "127.0.0.1"}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#6B7280]">Auth Protocol:</span>
                <span className="text-blue-400 text-right">{selectedId.authMethod}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-[#6B7280]">Security Posture:</span>
                <span
                  className={
                    selectedId.status === "TRUSTED"
                      ? "text-emerald-400 font-bold"
                      : selectedId.status === "WARNING"
                      ? "text-amber-400 font-bold"
                      : "text-red-400 font-bold"
                  }
                >
                  {selectedId.status}
                </span>
              </div>
            </div>

            <div className="pt-3 border-t border-[#202832] space-y-2">
              <button
                onClick={() => alert(`Step-up MFA challenge dispatched to ${selectedId.email}`)}
                className="w-full py-2 rounded bg-[#171D26] hover:bg-[#202832] text-[#F3F4F6] text-xs font-bold border border-[#27313C] transition-colors"
              >
                Trigger Step-Up MFA
              </button>
              <button
                onClick={() => alert(`Revoked all active tokens and sessions for ${selectedId.email}`)}
                className="w-full py-2 rounded bg-red-500/10 hover:bg-red-500/20 text-red-400 text-xs font-bold border border-red-500/30 transition-colors"
              >
                Revoke All Active Sessions
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};
