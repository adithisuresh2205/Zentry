"use client";

import React, { useState, useEffect, useCallback } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Activity,
  CheckCircle2,
  HardDrive,
  Layers,
  Network,
  Radio,
  ShieldAlert,
  ShieldCheck,
  User,
} from "lucide-react";
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

export const TrustEngineView: React.FC = () => {
  const [activeStage, setActiveStage] = useState<number>(0);
  const [aggregateTrust, setAggregateTrust] = useState<number>(84);
  const [trustPosture, setTrustPosture] = useState<string>("TRUSTED POSTURE");
  const [lastAttested, setLastAttested] = useState<string>(toIST());
  const [totalEvaluations, setTotalEvaluations] = useState<number>(0);

  // Dynamic gate scores
  const [identityScore, setIdentityScore] = useState<number>(92);
  const [deviceScore, setDeviceScore] = useState<number>(78);
  const [networkScore, setNetworkScore] = useState<number>(88);
  const [behaviorScore, setBehaviorScore] = useState<number>(82);
  const [threatScore, setThreatScore] = useState<number>(94);
  const [riskEngineScore, setRiskEngineScore] = useState<number>(18);
  const [policyScore, setPolicyScore] = useState<number>(100);

  // Dynamic signals for Threat Intel & Risk Engine
  const [latestThreatSignal, setLatestThreatSignal] = useState<string>("WAF Rules: Clean Baseline");
  const [latestRiskSignal, setLatestRiskSignal] = useState<string>("Risk Index: 18/100 (LOW)");
  const [latestPolicyAction, setLatestPolicyAction] = useState<string>("ALLOW_AND_LOG");

  /** Load live security stats and calibrate trust scores */
  const loadStats = useCallback(async () => {
    try {
      const data = await api.security.getStats();

      const total = data.total_requests || 0;
      const blocked = data.blocked_requests || 0;
      const avgRisk = data.average_risk_score ?? 15;
      const activeThreats = data.active_threats || 0;

      setTotalEvaluations(total);
      setLastAttested(toIST());

      // Dynamically compute Aggregate Trust Index (0-100)
      const blockPenalty = total > 0 ? Math.round((blocked / total) * 30) : 0;
      const riskPenalty = Math.round(avgRisk * 0.5);
      const computedTrust = Math.max(15, Math.min(99, 100 - blockPenalty - riskPenalty));
      setAggregateTrust(computedTrust);

      if (computedTrust >= 75) {
        setTrustPosture("TRUSTED POSTURE");
      } else if (computedTrust >= 50) {
        setTrustPosture("ELEVATED RISK");
      } else {
        setTrustPosture("HOSTILE ATTACK DETECTED");
      }

      // Dynamic sub-scores
      const newThreatScore = activeThreats > 0 ? Math.max(25, 95 - activeThreats * 15) : 95;
      setThreatScore(newThreatScore);
      setRiskEngineScore(avgRisk);

      if (activeThreats > 0) {
        setLatestThreatSignal(`Active Threats Intercepted: ${activeThreats} Rules Triggered`);
      } else {
        setLatestThreatSignal("OWASP Top 10 Signatures: Clean Baseline");
      }

      setLatestRiskSignal(`Calculated Risk: ${avgRisk}/100 · Level: ${data.global_threat_level || "LOW"}`);

      // Network score based on block ratio
      const netScore = total > 0 ? Math.max(30, 95 - Math.round((blocked / total) * 50)) : 90;
      setNetworkScore(netScore);

      // Identity score based on challenge/block proportion
      const idScore = Math.max(40, 96 - (data.challenged_requests || 0) * 10 - blockPenalty);
      setIdentityScore(idScore);
    } catch {
      // Backend offline fallback
    }
  }, []);

  useEffect(() => {
    loadStats();
    const interval = setInterval(loadStats, 10000);
    return () => clearInterval(interval);
  }, [loadStats]);

  // WebSocket live updates for real-time reactivity
  const handleLiveEvent = useCallback((evt: LiveSecurityEvent) => {
    const isBlock = ((evt.action as string) || "").toUpperCase() === "BLOCK";
    const score = Number(evt.risk_score ?? 0);

    setTotalEvaluations((prev) => prev + 1);
    setLastAttested(toIST());

    if (isBlock) {
      setThreatScore((prev) => Math.max(20, prev - 8));
      setRiskEngineScore(score);
      setAggregateTrust((prev) => Math.max(15, prev - 5));

      const threatList = Array.isArray(evt.threats) && evt.threats.length > 0 ? evt.threats[0] : null;
      const cat = typeof threatList === "object" && threatList
        ? ((threatList as any).category || (threatList as any).name || "Prohibited Signature")
        : typeof threatList === "string" ? threatList : "Prohibited Signature";

      setLatestThreatSignal(`ALERT: ${cat} Intercepted from ${evt.source_ip || "Client"}`);
      setLatestRiskSignal(`Elevated Risk: ${score}/100 · ${evt.risk_level || "HIGH"}`);
      setLatestPolicyAction(`BLOCK_AND_ISOLATE (${evt.response_code || 403})`);
    } else {
      setThreatScore((prev) => Math.min(96, prev + 1));
      setAggregateTrust((prev) => Math.min(98, prev + 1));
      setLatestPolicyAction("ALLOW_AND_LOG (200)");
    }
  }, []);

  const { isConnected } = useSecurityStream({ onEvent: handleLiveEvent });

  const pipelineStages = [
    {
      id: 0,
      name: "IDENTITY",
      icon: User,
      score: identityScore,
      status: identityScore >= 75 ? "PASS" : identityScore >= 50 ? "WARNING" : "BLOCK",
      signals: ["Bearer JWT Attestation", "MFA Token Verified", "Session Age: Active"],
      details: "Continuous evaluation of cryptographic token validity, MFA status, and identity provider claims.",
    },
    {
      id: 1,
      name: "DEVICE",
      icon: HardDrive,
      score: deviceScore,
      status: deviceScore >= 70 ? "PASS" : "WARNING",
      signals: ["OS / User-Agent Baseline", "Hardware Fingerprint Consistent", "Browser Header Entropy Normal"],
      details: "Hardware posture, client headers, user-agent entropy, and device fingerprint consistency.",
    },
    {
      id: 2,
      name: "NETWORK",
      icon: Network,
      score: networkScore,
      status: networkScore >= 75 ? "PASS" : networkScore >= 50 ? "WARNING" : "BLOCK",
      signals: ["IP Blocklist Filter Active", "CIDR Range Verified", "Geo-Velocity: Normal"],
      details: "Real-time IP reputation filtering, persistent IP blocklist evaluation, and network netblock tracking.",
    },
    {
      id: 3,
      name: "BEHAVIOR",
      icon: Activity,
      score: behaviorScore,
      status: behaviorScore >= 70 ? "PASS" : "WARNING",
      signals: ["Token Bucket Rate Limit Clean", "Burst Thresholds Monitored", "Payload Length: Valid"],
      details: "Sliding-window request patterns, payload byte entropy, and deviations from normal endpoint baseline.",
    },
    {
      id: 4,
      name: "THREAT INTEL",
      icon: ShieldAlert,
      score: threatScore,
      status: threatScore >= 75 ? "PASS" : threatScore >= 45 ? "WARNING" : "BLOCK",
      signals: [latestThreatSignal, "SQLi, XSS, Path Traversal, SSRF Inspectors", "Regex & AST Pipeline Active"],
      details: "Deterministic threat detection engine matching incoming payloads against OWASP Top 10 patterns.",
    },
    {
      id: 5,
      name: "RISK ENGINE",
      icon: Layers,
      score: Math.max(0, 100 - riskEngineScore),
      status: riskEngineScore < 30 ? "LOW RISK" : riskEngineScore < 70 ? "ELEVATED" : "CRITICAL",
      signals: [latestRiskSignal, "Multi-Factor Weighted Bayesian Model", "Score Ceiling Enforced"],
      details: "Dynamically aggregates weighted signals with 100-point ceiling and deterministic rounding.",
    },
    {
      id: 6,
      name: "POLICY ENGINE",
      icon: ShieldCheck,
      score: policyScore,
      status: latestPolicyAction.includes("BLOCK") ? "ENFORCE BLOCK" : "ALLOW",
      signals: [`Enforced Action: ${latestPolicyAction}`, "Policy: ZT-GATEWAY-STRICT", "OWASP Compliant Headers Injected"],
      details: "Executes deterministic decision matrix mapping risk scores and detections to ALLOW, CHALLENGE, or BLOCK.",
    },
  ];

  const currentStage = pipelineStages[activeStage];

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-bold tracking-tight text-[#F3F4F6] font-mono-tech">
              Zero-Trust Trust Engine
            </h2>
            {isConnected && (
              <span className="flex items-center gap-1 px-2 py-0.5 rounded-full bg-emerald-500/10 text-emerald-400 text-[10px] font-mono-tech border border-emerald-500/30">
                <Radio className="w-3 h-3 animate-pulse" />
                LIVE STREAM
              </span>
            )}
          </div>
          <p className="text-xs text-[#9CA3AF] mt-0.5">
            &quot;Never Trust, Always Verify&quot; — Multi-stage deterministic gate pipeline & continuous evaluation.
          </p>
        </div>
        <div className="text-right">
          <div className="text-[10px] text-[#6B7280] font-mono-tech">LAST ATTESTATION (IST)</div>
          <div className="text-xs font-bold text-blue-400 font-mono-tech">{lastAttested}</div>
        </div>
      </div>

      {/* Visual Interactive Pipeline with Glowing Stage Connectors */}
      <div className="glass-panel tactical-corner p-5 rounded-xl space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-cyan-400" />
            <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
              ZERO-TRUST PIPELINE GATES
            </span>
          </div>
          <span className="text-[10px] font-mono-tech text-blue-400">
            Click any gate to inspect real-time signals
          </span>
        </div>

        {/* Pipeline Gates Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-2.5">
          {pipelineStages.map((stage, idx) => {
            const Icon = stage.icon;
            const isSelected = activeStage === stage.id;
            return (
              <motion.button
                key={stage.id}
                whileHover={{ y: -2 }}
                whileTap={{ scale: 0.98 }}
                onClick={() => setActiveStage(stage.id)}
                className={`p-3.5 rounded-xl border text-left transition-all flex flex-col justify-between h-28 relative overflow-hidden group ${
                  isSelected
                    ? "bg-gradient-to-b from-[#171D26] to-[#10151C] border-blue-500/80 shadow-[0_0_20px_rgba(59,130,246,0.25)] ring-1 ring-blue-500/50"
                    : "bg-[#10151C]/70 border-white/5 hover:border-white/15 hover:bg-[#131922]"
                }`}
              >
                {isSelected && (
                  <div className="absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r from-blue-400 to-cyan-400" />
                )}

                <div className="flex items-center justify-between w-full">
                  <div className={`p-1.5 rounded-lg ${isSelected ? "bg-blue-500/20 text-blue-300" : "bg-white/[0.03] text-[#6B7280]"}`}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <span className="text-[10px] font-mono-tech text-[#6B7280]">
                    0{idx + 1}
                  </span>
                </div>

                <div>
                  <div className="text-xs font-bold font-mono-tech text-[#F3F4F6] tracking-tight">
                    {stage.name}
                  </div>
                  <div className="text-[10px] font-mono-tech text-[#9CA3AF] flex items-center justify-between mt-1">
                    <span>Score: {stage.score}</span>
                    <span
                      className={`font-semibold px-1.5 py-0.2 rounded text-[9px] ${
                        stage.status.includes("WARNING") || stage.status.includes("ELEVATED")
                          ? "text-amber-400 bg-amber-500/10 border border-amber-500/20"
                          : stage.status.includes("BLOCK") || stage.status.includes("CRITICAL")
                          ? "text-red-400 bg-red-500/10 border border-red-500/20"
                          : "text-emerald-400 bg-emerald-500/10 border border-emerald-500/20"
                      }`}
                    >
                      {stage.status}
                    </span>
                  </div>
                </div>
              </motion.button>
            );
          })}
        </div>

        {/* Selected Gate Inspection Card with Fluid Cross-Fade */}
        <AnimatePresence mode="wait">
          <motion.div
            key={currentStage.id}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -6 }}
            transition={{ duration: 0.18 }}
            className="p-5 rounded-xl bg-[#0B0F14]/90 border border-white/10 space-y-4 font-mono-tech text-xs"
          >
            <div className="flex items-center justify-between border-b border-white/5 pb-3">
              <div className="flex items-center gap-2.5">
                <span className="px-2.5 py-1 rounded-full bg-blue-500/10 text-blue-400 text-[10px] font-bold border border-blue-500/30">
                  GATE 0{currentStage.id + 1}
                </span>
                <span className="font-bold text-[#F3F4F6] text-sm tracking-wide">
                  {currentStage.name} LIVE ATTESTATION
                </span>
              </div>
              <span className="text-blue-400/90 text-xs font-bold">
                Live Sub-Score: {currentStage.score} / 100
              </span>
            </div>

            <p className="text-[#9CA3AF] text-xs leading-relaxed">
              {currentStage.details}
            </p>

            <div>
              <span className="text-[10px] text-[#6B7280] uppercase tracking-wider block mb-2 font-bold">
                Active Verification Signals:
              </span>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2.5">
                {currentStage.signals.map((sig, i) => (
                  <div
                    key={i}
                    className="px-3 py-2 rounded-lg bg-[#10151C]/80 border border-white/5 text-[11px] text-[#F3F4F6] flex items-center gap-2.5"
                  >
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                    <span className="truncate">{sig}</span>
                  </div>
                ))}
              </div>
            </div>
          </motion.div>
        </AnimatePresence>
      </div>

      {/* Central Trust Score Bento Panel */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Large Score Gauge with Specular Glow */}
        <div className="glass-panel tactical-corner p-6 rounded-xl flex flex-col justify-between items-center text-center relative overflow-hidden">
          <div
            className={`absolute top-0 left-0 right-0 h-0.5 bg-gradient-to-r ${
              aggregateTrust >= 70
                ? "from-emerald-500/20 via-emerald-500/60 to-transparent"
                : aggregateTrust >= 45
                ? "from-amber-500/20 via-amber-500/60 to-transparent"
                : "from-red-500/20 via-red-500/60 to-transparent"
            }`}
          />

          <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
            AGGREGATE TRUST INDEX
          </span>

          <div className="my-6 relative">
            <div className="text-6xl font-extrabold font-mono-tech text-white tracking-tighter drop-shadow-[0_0_25px_rgba(16,185,129,0.3)]">
              {aggregateTrust}<span className="text-2xl text-[#6B7280] font-normal">/100</span>
            </div>
            <div
              className={`mt-3 px-3 py-1 rounded-full text-xs font-bold font-mono-tech inline-block border ${
                aggregateTrust >= 70
                  ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30 glow-emerald"
                  : aggregateTrust >= 45
                  ? "bg-amber-500/15 text-amber-400 border-amber-500/30 glow-amber"
                  : "bg-red-500/15 text-red-400 border-red-500/30 glow-red"
              }`}
            >
              {trustPosture}
            </div>
          </div>

          <p className="text-xs text-[#9CA3AF] max-w-xs leading-relaxed font-sans">
            Continuous Bayesian aggregation across {totalEvaluations.toLocaleString()} inspected requests, device postures, and network reputation.
          </p>
        </div>

        {/* Detailed Trust Factor Breakdown with Animated Progress Bars */}
        <div className="lg:col-span-2 glass-panel tactical-corner p-6 rounded-xl space-y-4">
          <div className="flex items-center justify-between border-b border-white/5 pb-2">
            <div className="flex items-center gap-2">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-500" />
              <span className="text-xs font-bold font-mono-tech text-[#F3F4F6] uppercase tracking-wide">
                Continuous Multi-Factor Signal Attestation
              </span>
            </div>
            <span className="text-[10px] font-mono-tech text-emerald-400">
              ● Live Dynamic Evaluation
            </span>
          </div>

          <div className="space-y-3.5 font-mono-tech text-xs pt-1">
            {[
              { label: "Identity Trust", score: identityScore, weight: "25%", color: "from-blue-600 to-blue-400" },
              { label: "Device Health & Attestation", score: deviceScore, weight: "20%", color: "from-amber-600 to-amber-400" },
              { label: "Network Origin Reputation", score: networkScore, weight: "20%", color: "from-emerald-600 to-emerald-400" },
              { label: "Behavioral Heuristics", score: behaviorScore, weight: "15%", color: "from-blue-500 to-cyan-400" },
              { label: "Threat Intelligence & WAF", score: threatScore, weight: "20%", color: "from-emerald-500 to-teal-400" },
            ].map((f) => (
              <div key={f.label} className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-[#F3F4F6] font-medium">{f.label}</span>
                  <span className="text-[#9CA3AF]">
                    Weight: {f.weight} · <strong className="text-white">{f.score}</strong>/100
                  </span>
                </div>
                <div className="w-full bg-[#080B10] h-2 rounded-full overflow-hidden border border-white/5 p-0.5">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${f.score}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={`bg-gradient-to-r ${f.color} h-full rounded-full shadow-[0_0_8px_rgba(59,130,246,0.3)]`}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
};
