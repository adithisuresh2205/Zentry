"use client";

import React, { useState, useEffect, useCallback } from "react";
import {
  Check,
  Code,
  FileCode,
  Fingerprint,
  Layers,
  Plus,
  Radio,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Sliders,
  ToggleLeft,
  ToggleRight,
} from "lucide-react";
import { api, WAFRuleData } from "../../lib/api";

interface PolicyItem {
  id: string;
  code: string;
  name: string;
  description: string;
  priority: "CRITICAL" | "HIGH" | "MEDIUM";
  rulesCount: number;
  status: string;
  lastModified: string;
  conditions: { field: string; operator: string; value: string }[];
  actions: string[];
}

const LIVE_GATEWAY_POLICIES: PolicyItem[] = [
  {
    id: "POL-001",
    code: "ZT-WAF-INSPECT",
    name: "Zero-Trust Deep Threat Inspection Policy",
    description: "Multi-stage normalization & OWASP signature evaluation across URI paths, headers, and request body.",
    priority: "CRITICAL",
    rulesCount: 7,
    status: "ENFORCING",
    lastModified: "Live Dynamic",
    conditions: [
      { field: "request.waf_threat_count", operator: ">", value: "0" },
      { field: "threat.blocks_directly", operator: "==", value: "true" },
    ],
    actions: ["INTERCEPT_AND_TERMINATE (HTTP 403)", "GENERATE_SECURITY_AUDIT_RECORD", "HMAC_SEAL_LOG_CHAIN"],
  },
  {
    id: "POL-002",
    code: "ZT-AUTH-BRUTEFORCE",
    name: "Credential Brute-Force & Rate Shield",
    description: "Sliding-window Redis rate limiting and automatic IP quarantine after repeated authentication failures.",
    priority: "HIGH",
    rulesCount: 2,
    status: "ENFORCING",
    lastModified: "Live Dynamic",
    conditions: [
      { field: "client.login_failures", operator: ">=", value: "10" },
      { field: "client.window_seconds", operator: "<=", value: "60" },
    ],
    actions: ["AUTOMATED_IP_BLOCKLIST_INJECTION", "QUARANTINE_IP_900S", "REJECT_WITH_HTTP_403"],
  },
  {
    id: "POL-003",
    code: "ZT-CIPHER-SEAL",
    name: "Tamper-Evident Cryptographic Audit Policy",
    description: "Continuous HMAC-SHA256 integrity sealing across all recorded request transitions.",
    priority: "CRITICAL",
    rulesCount: 3,
    status: "ENFORCING",
    lastModified: "Live Dynamic",
    conditions: [
      { field: "gateway.decision", operator: "IN", value: "['ALLOW', 'BLOCK', 'CHALLENGE']" },
    ],
    actions: ["COMPUTE_HMAC_SHA256_SEAL", "CHAIN_PREVIOUS_RECORD_HASH", "PERSIST_TO_POSTGRES_STORE"],
  },
];

export const PoliciesView: React.FC = () => {
  const [policies, setPolicies] = useState<PolicyItem[]>(LIVE_GATEWAY_POLICIES);
  const [wafRules, setWafRules] = useState<WAFRuleData[]>([]);
  const [selectedPolicy, setSelectedPolicy] = useState<PolicyItem>(LIVE_GATEWAY_POLICIES[0]);
  const [isUpdating, setIsUpdating] = useState<string | null>(null);

  const loadRules = useCallback(async () => {
    try {
      const rules = await api.security.getRules();
      if (rules && rules.length > 0) {
        setWafRules(rules);
      }
    } catch {
      // offline fallback
    }
  }, []);

  useEffect(() => {
    loadRules();
  }, [loadRules]);

  const toggleWafRule = async (ruleId: string) => {
    setIsUpdating(ruleId);
    try {
      const res = await api.security.toggleRule(ruleId);
      setWafRules((prev) =>
        prev.map((r) => (r.rule_id === ruleId ? { ...r, enabled: res.enabled } : r))
      );
    } catch (err: any) {
      alert(`Failed to toggle rule: ${err.message}`);
    } finally {
      setIsUpdating(null);
    }
  };

  const activeRulesCount = wafRules.filter((r) => r.enabled).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-lg font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Security Policies & Live WAF Rule Engine
            </h2>
            <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
              <Radio className="w-3 h-3 animate-pulse" />
              HOT-RELOAD ENGINE
            </span>
          </div>
          <p className="text-xs text-[#9CA3AF]">
            Zero-Trust access control policies, declarative rule definitions, and live WAF protection guards synced directly to the gateway engine.
          </p>
        </div>
      </div>

      {/* Policy Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {policies.map((p) => {
          const isSelected = selectedPolicy.id === p.id;
          return (
            <div
              key={p.id}
              onClick={() => setSelectedPolicy(p)}
              className={`glass-panel p-4 rounded-lg cursor-pointer transition-all ${
                isSelected
                  ? "border-blue-500 ring-1 ring-blue-500/40 bg-[#171D26]"
                  : "hover:border-[#27313C]"
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="px-2 py-0.5 rounded bg-[#10151C] text-blue-400 font-mono-tech text-[10px] font-bold border border-[#202832]">
                  {p.code}
                </span>
                <span
                  className={`text-[10px] font-mono-tech font-bold ${
                    p.priority === "CRITICAL"
                      ? "text-red-400"
                      : p.priority === "HIGH"
                      ? "text-amber-400"
                      : "text-blue-400"
                  }`}
                >
                  {p.priority} PRIORITY
                </span>
              </div>
              <h3 className="text-xs font-bold text-[#F3F4F6] mb-1">{p.name}</h3>
              <p className="text-[11px] text-[#9CA3AF] line-clamp-2 mb-3">
                {p.description}
              </p>
              <div className="flex items-center justify-between text-[10px] font-mono-tech text-[#6B7280] pt-2 border-t border-[#202832]">
                <span>{p.rulesCount} active rules</span>
                <span className="text-emerald-400 font-bold">{p.status}</span>
              </div>
            </div>
          );
        })}
      </div>

      {/* Visual Policy Builder (Developer Tool UI) */}
      <div className="glass-panel p-5 rounded-lg space-y-4">
        <div className="flex items-center justify-between border-b border-[#202832] pb-3">
          <div className="flex items-center gap-2">
            <Code className="w-4 h-4 text-blue-400" />
            <h3 className="text-sm font-bold font-mono-tech text-[#F3F4F6]">
              Visual Policy Logic ({selectedPolicy.code})
            </h3>
          </div>
          <span className="text-[10px] font-mono-tech text-emerald-400">
            Status: {selectedPolicy.status}
          </span>
        </div>

        {/* Declarative IF ... THEN construct */}
        <div className="bg-[#080B10] p-4 rounded-lg border border-[#202832] font-mono-tech text-xs space-y-3">
          <div className="text-blue-400 font-bold uppercase text-[11px]">
            IF (Matching Conditions)
          </div>
          <div className="space-y-1.5 pl-4 border-l-2 border-blue-500/40">
            {selectedPolicy.conditions.map((c, i) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                {i > 0 && <span className="text-amber-400 font-bold">AND</span>}
                <span className="text-[#F3F4F6] bg-[#10151C] px-2 py-0.5 rounded border border-[#202832]">
                  {c.field}
                </span>
                <span className="text-blue-400 font-bold">{c.operator}</span>
                <span className="text-emerald-400 bg-[#10151C] px-2 py-0.5 rounded border border-[#202832]">
                  {c.value}
                </span>
              </div>
            ))}
          </div>

          <div className="text-red-400 font-bold uppercase text-[11px] pt-2">
            THEN (Authoritative Action)
          </div>
          <div className="space-y-1.5 pl-4 border-l-2 border-red-500/40">
            {selectedPolicy.actions.map((act, i) => (
              <div key={i} className="flex items-center gap-2 text-xs text-red-300 font-bold">
                <Check className="w-3.5 h-3.5 text-red-400" />
                <span>{act}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Real Core WAF Rule Toggles */}
      <div className="glass-panel p-5 rounded-lg space-y-4">
        <div className="flex items-center justify-between border-b border-[#202832] pb-3">
          <div>
            <h3 className="text-sm font-bold font-mono-tech text-[#F3F4F6]">
              Core WAF Detection Engine (Live Gateway Rules)
            </h3>
            <p className="text-[11px] text-[#6B7280]">
              Toggle active pattern inspection modules live on the gateway. Toggled state takes effect immediately for incoming traffic.
            </p>
          </div>
          <span className="text-[10px] font-mono-tech text-emerald-400 font-bold">
            {activeRulesCount} / {wafRules.length} Active
          </span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
          {wafRules.map((r) => (
            <div
              key={r.rule_id}
              className="p-3.5 rounded-lg bg-[#10151C] border border-[#202832] flex items-center justify-between font-mono-tech text-xs"
            >
              <div className="space-y-1">
                <span className="font-bold text-[#F3F4F6] block">{r.name}</span>
                <span className="text-[10px] text-[#6B7280] block">
                  {r.rule_id} · Severity: <span className={r.severity === "CRITICAL" ? "text-red-400" : r.severity === "HIGH" ? "text-amber-400" : "text-blue-400"}>{r.severity}</span>
                </span>
                <span className="text-[10px] text-[#6B7280] block">
                  Risk Delta: +{r.risk_delta} · Action: {r.blocks_directly ? `BLOCK (${r.status_code})` : "FLAG"}
                </span>
              </div>
              <button
                disabled={isUpdating === r.rule_id}
                onClick={() => toggleWafRule(r.rule_id)}
                className={`text-xs px-3 py-1.5 rounded font-bold transition-all ${
                  r.enabled
                    ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 hover:bg-emerald-500/20"
                    : "bg-[#171D26] text-[#6B7280] border border-[#202832] hover:text-[#9CA3AF]"
                }`}
              >
                {isUpdating === r.rule_id ? "SYNCING..." : r.enabled ? "ENABLED" : "DISABLED"}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
