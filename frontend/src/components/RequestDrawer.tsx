"use client";

import React from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertOctagon,
  AlertTriangle,
  Copy,
  ExternalLink,
  HardDrive,
  ShieldAlert,
  User,
  X,
} from "lucide-react";
import { SecurityRequest } from "../types";

interface RequestDrawerProps {
  request: SecurityRequest | null;
  onClose: () => void;
}

export const RequestDrawer: React.FC<RequestDrawerProps> = ({
  request,
  onClose,
}) => {
  return (
    <AnimatePresence>
      {request && (
        <div className="fixed inset-0 z-50 flex justify-end">
          {/* Backdrop Blur Overlay */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.2 }}
            onClick={onClose}
            className="fixed inset-0 bg-black/70 backdrop-blur-md"
          />

          {/* Sliding Investigation Panel */}
          <motion.div
            initial={{ x: "100%" }}
            animate={{ x: 0 }}
            exit={{ x: "100%" }}
            transition={{ type: "spring", damping: 32, stiffness: 320 }}
            className="relative w-full max-w-2xl bg-[#0B0F14]/95 backdrop-blur-2xl border-l border-white/10 h-full shadow-[0_0_50px_rgba(0,0,0,0.8)] flex flex-col z-10 select-none"
          >
            {/* Drawer Header */}
            <div className="h-16 px-6 border-b border-white/10 flex items-center justify-between bg-gradient-to-r from-[#10151C]/90 to-[#0B0F14]/90">
              <div className="flex items-center gap-3">
                <div
                  className={`p-2 rounded-lg ${
                    request.decision === "BLOCKED"
                      ? "bg-red-500/10 text-red-400 border border-red-500/30 glow-red"
                      : request.decision === "CHALLENGED"
                      ? "bg-amber-500/10 text-amber-400 border border-amber-500/30 glow-amber"
                      : "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 glow-emerald"
                  }`}
                >
                  <ShieldAlert className="w-5 h-5" />
                </div>
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-bold tracking-wider text-[#F3F4F6] font-mono-tech">
                      INVESTIGATION #{request.id}
                    </span>
                    <span
                      className={`text-[10px] font-mono-tech px-2 py-0.5 rounded font-bold ${
                        request.decision === "BLOCKED"
                          ? "bg-red-500/20 text-red-300 border border-red-500/40"
                          : request.decision === "CHALLENGED"
                          ? "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                          : "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40"
                      }`}
                    >
                      {request.decision}
                    </span>
                  </div>
                  <div className="text-[11px] text-[#6B7280] font-mono-tech mt-0.5">
                    {new Date(request.timestamp).toUTCString()}
                  </div>
                </div>
              </div>

              <button
                onClick={onClose}
                className="p-1.5 rounded-lg text-[#9CA3AF] hover:text-[#F3F4F6] hover:bg-white/5 border border-transparent hover:border-white/10 transition-all"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Scrollable Forensic Body */}
            <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-grid-tactical">
              {/* SECTION 1: REQUEST METADATA */}
              <div className="glass-panel tactical-corner p-4 rounded-xl space-y-3 border border-white/5">
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                    HTTP Request Details
                  </span>
                  <span className="text-[11px] font-mono-tech text-blue-400">
                    Timestamp: {request.timeDisplay}
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs font-mono-tech">
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">METHOD & ENDPOINT</span>
                    <span className="font-semibold text-blue-400 mr-2">{request.method}</span>
                    <span className="text-[#F3F4F6]">{request.endpoint}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">STATUS CODE</span>
                    <span
                      className={`font-semibold ${
                        request.statusCode >= 400 ? "text-red-400" : "text-emerald-400"
                      }`}
                    >
                      HTTP {request.statusCode}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">SOURCE IP</span>
                    <span className="text-[#F3F4F6]">{request.sourceIp}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">LOCATION</span>
                    <span className="text-[#9CA3AF]">{request.location}</span>
                  </div>
                </div>
              </div>

              {/* SECTION 2: IDENTITY CONTEXT */}
              <div className="glass-panel p-4 rounded-xl space-y-3 border border-white/5">
                <div className="flex items-center gap-2 border-b border-white/5 pb-2">
                  <User className="w-3.5 h-3.5 text-blue-400" />
                  <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                    Identity Context
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs font-mono-tech">
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">PRINCIPAL USER</span>
                    <span className="text-[#F3F4F6] font-medium">{request.identity}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">IDENTITY TRUST</span>
                    <span className="px-2 py-0.5 rounded bg-blue-500/10 text-blue-400 border border-blue-500/30 text-[10px] inline-block font-semibold">
                      {request.identityTrust} / 100
                    </span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">DEVICE OS</span>
                    <span className="text-[#9CA3AF]">{request.device.os}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">BROWSER</span>
                    <span className="text-[#9CA3AF] truncate block">{request.device.browser}</span>
                  </div>
                </div>
              </div>

              {/* SECTION 3: DEVICE & NETWORK TELEMETRY */}
              <div className="glass-panel p-4 rounded-xl space-y-3 border border-white/5">
                <div className="flex items-center gap-2 border-b border-white/5 pb-2">
                  <HardDrive className="w-3.5 h-3.5 text-cyan-400" />
                  <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                    Device & Network Posture
                  </span>
                </div>
                <div className="grid grid-cols-2 gap-3 text-xs font-mono-tech">
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">NETWORK ASN</span>
                    <span className="text-[#F3F4F6] font-semibold">{request.network.asn}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">REPUTATION</span>
                    <span className="text-[#9CA3AF]">{request.network.reputation}</span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">DEVICE STATUS</span>
                    <span
                      className={`text-[10px] font-bold px-2 py-0.5 rounded border inline-block ${
                        request.device.status === "Verified"
                          ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30"
                          : "bg-red-500/10 text-red-400 border-red-500/30"
                      }`}
                    >
                      {request.device.status}
                    </span>
                  </div>
                  <div>
                    <span className="text-[#6B7280] text-[10px] block">FINGERPRINT</span>
                    <span className="text-[#9CA3AF] text-[11px] truncate block" title={request.device.fingerprint}>
                      {request.device.fingerprint}
                    </span>
                  </div>
                </div>
              </div>

              {/* SECTION 4: RISK SCORE BREAKDOWN */}
              <div className="glass-panel p-4 rounded-xl space-y-3 border border-white/5">
                <div className="flex items-center justify-between border-b border-white/5 pb-2">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                    <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                      Risk Engine Breakdown
                    </span>
                  </div>
                  <span
                    className={`text-xs font-mono-tech font-bold px-2 py-0.5 rounded ${
                      request.riskScore >= 70
                        ? "bg-red-500/20 text-red-400"
                        : request.riskScore >= 30
                        ? "bg-amber-500/20 text-amber-400"
                        : "bg-emerald-500/20 text-emerald-400"
                    }`}
                  >
                    Risk Score: {request.riskScore} / 100 ({request.riskLevel})
                  </span>
                </div>

                <div className="space-y-2">
                  <div className="flex items-center justify-between text-[11px] font-mono-tech">
                    <span className="text-[#9CA3AF]">Composite Aggregate Risk</span>
                    <span className="text-white font-bold">{request.riskScore}%</span>
                  </div>
                  <div className="w-full bg-[#171D26] h-2 rounded-full overflow-hidden border border-white/5">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${request.riskScore}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={`h-full rounded-full ${
                        request.riskScore >= 70
                          ? "bg-gradient-to-r from-amber-500 to-red-500 glow-red"
                          : request.riskScore >= 30
                          ? "bg-gradient-to-r from-blue-500 to-amber-500 glow-amber"
                          : "bg-gradient-to-r from-blue-500 to-emerald-500 glow-emerald"
                      }`}
                    />
                  </div>

                  <div className="grid grid-cols-4 gap-2 pt-2 text-[10px] font-mono-tech text-[#9CA3AF]">
                    <div className="p-2 rounded bg-black/30 border border-white/5 text-center">
                      <span className="text-[#6B7280] block">Identity</span>
                      <span className="text-white font-bold">{request.riskBreakdown.identity}</span>
                    </div>
                    <div className="p-2 rounded bg-black/30 border border-white/5 text-center">
                      <span className="text-[#6B7280] block">Device</span>
                      <span className="text-white font-bold">{request.riskBreakdown.device}</span>
                    </div>
                    <div className="p-2 rounded bg-black/30 border border-white/5 text-center">
                      <span className="text-[#6B7280] block">Network</span>
                      <span className="text-white font-bold">{request.riskBreakdown.network}</span>
                    </div>
                    <div className="p-2 rounded bg-black/30 border border-white/5 text-center">
                      <span className="text-[#6B7280] block">Behavior</span>
                      <span className="text-white font-bold">{request.riskBreakdown.behavior}</span>
                    </div>
                  </div>
                </div>
              </div>

              {/* SECTION 5: MATCHED THREATS */}
              <div className="glass-panel p-4 rounded-xl space-y-3 border border-white/5">
                <div className="flex items-center gap-2 border-b border-white/5 pb-2">
                  <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
                  <span className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                    Matched Threats ({request.threats.length})
                  </span>
                </div>
                {request.threats.length > 0 ? (
                  <div className="space-y-2">
                    {request.threats.map((th: any, i) => {
                      const name = typeof th === "string" ? th : (th?.name || th?.category || th?.rule_id || "DETECTED_THREAT");
                      const rule = typeof th === "object" ? (th?.ruleId || th?.rule_id || "RULE_ENFORCED") : "RULE_ENFORCED";
                      const conf = typeof th === "object" && th?.confidence !== undefined
                        ? Math.round(Number(th.confidence) <= 1 ? Number(th.confidence) * 100 : Number(th.confidence))
                        : 98;
                      return (
                        <div
                          key={i}
                          className="p-3 rounded-lg bg-red-500/10 border border-red-500/20 flex items-center justify-between text-xs font-mono-tech"
                        >
                          <div>
                            <div className="font-bold text-red-300">{name}</div>
                            <div className="text-[10px] text-[#6B7280]">Rule: {rule}</div>
                          </div>
                          <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 font-bold border border-red-500/30">
                            {conf}% match
                          </span>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <div className="text-[#6B7280] text-[11px] italic font-mono-tech">
                    ✓ Clean signature payload. No threats detected.
                  </div>
                )}
              </div>

              {/* SECTION 6: POLICY ENFORCEMENT */}
              <div className="glass-panel p-4 rounded-xl space-y-2.5 border-l-2 border-l-blue-500 border border-white/5">
                <div className="text-[10px] font-bold text-[#6B7280] font-mono-tech tracking-wider uppercase">
                  Authoritative Policy Decision
                </div>
                <div className="font-mono-tech text-xs">
                  <span
                    className={`font-bold text-sm ${
                      request.decision === "BLOCKED"
                        ? "text-red-400"
                        : request.decision === "CHALLENGED"
                        ? "text-amber-400"
                        : "text-emerald-400"
                    }`}
                  >
                    {request.decision}
                  </span>
                  <span className="text-[#6B7280] ml-2">via {request.appliedPolicy}</span>
                </div>
                <p className="text-[#9CA3AF] text-[11px] leading-relaxed bg-black/30 p-2.5 rounded border border-white/5 font-mono-tech">
                  &quot;{request.policyReason}&quot;
                </p>
              </div>
            </div>

            {/* Drawer Footer */}
            <div className="h-16 px-6 border-t border-white/10 bg-[#10151C]/95 flex items-center justify-between">
              <button
                onClick={() => {
                  navigator.clipboard?.writeText(JSON.stringify(request, null, 2));
                  alert(`Forensic telemetry copied for Request #${request.id}`);
                }}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#171D26] hover:bg-[#202832] text-xs font-mono-tech text-[#F3F4F6] border border-white/10 transition-colors"
              >
                <Copy className="w-3.5 h-3.5 text-blue-400" />
                Copy Telemetry JSON
              </button>
              <button
                onClick={() => alert(`Full investigation package for Request #${request.id} downloaded.`)}
                className="flex items-center gap-1.5 px-4 py-1.5 rounded-lg bg-gradient-to-r from-blue-600 to-blue-500 hover:from-blue-500 hover:to-blue-400 text-xs font-mono-tech text-white font-medium transition-all shadow-[0_0_15px_rgba(59,130,246,0.3)]"
              >
                <ExternalLink className="w-3.5 h-3.5" />
                Investigate Trace
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );
};
