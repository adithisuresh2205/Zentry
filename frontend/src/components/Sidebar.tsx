"use client";

import React from "react";
import { motion } from "framer-motion";
import {
  Activity,
  AlertTriangle,
  Cpu,
  FileText,
  Fingerprint,
  HardDrive,
  Layers,
  Radio,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Users,
  Zap,
} from "lucide-react";
import { ZentryLogo } from "./ZentryLogo";

export type NavItemKey =
  | "overview"
  | "requests"
  | "trust-engine"
  | "identities"
  | "devices"
  | "threats"
  | "incidents"
  | "policies"
  | "audit-logs"
  | "health";

interface SidebarProps {
  currentTab: NavItemKey;
  onSelectTab: (_tab: NavItemKey) => void;
}

export const Sidebar: React.FC<SidebarProps> = ({ currentTab, onSelectTab }) => {
  const navSections = [
    {
      title: "TELEMETRY",
      items: [
        { key: "overview", label: "Overview", icon: Shield },
        { key: "requests", label: "Request Explorer", icon: Search },
      ],
    },
    {
      title: "ZERO TRUST",
      items: [
        { key: "trust-engine", label: "Trust Engine", icon: Zap },
        { key: "identities", label: "Identities", icon: Users },
        { key: "devices", label: "Devices", icon: HardDrive },
      ],
    },
    {
      title: "SECURITY",
      items: [
        { key: "threats", label: "Threat Detection", icon: ShieldAlert },
        { key: "incidents", label: "Incidents", icon: AlertTriangle },
      ],
    },
    {
      title: "GOVERNANCE",
      items: [
        { key: "policies", label: "Security Policies", icon: ShieldCheck },
        { key: "audit-logs", label: "Audit Logs", icon: FileText },
      ],
    },
    {
      title: "SYSTEM",
      items: [
        { key: "health", label: "Gateway Health", icon: Cpu },
      ],
    },
  ];

  return (
    <aside className="w-64 min-w-[256px] my-3 ml-3 h-[calc(100vh-1.5rem)] rounded-2xl glass-panel border border-white/10 flex flex-col select-none shrink-0 z-20 shadow-[0_12px_40px_rgba(0,0,0,0.6)] overflow-hidden">
      {/* Brand Header with Custom Zentry Logo */}
      <div className="h-16 px-5 border-b border-white/5 flex items-center justify-between bg-gradient-to-r from-[#10151C]/90 via-[#10151C]/50 to-transparent">
        <div className="flex items-center gap-3">
          <div className="relative flex items-center justify-center filter drop-shadow-[0_0_12px_rgba(56,189,248,0.35)]">
            <ZentryLogo size={32} />
          </div>
          <div>
            <div className="text-sm font-extrabold tracking-widest text-white font-mono-tech flex items-center gap-1.5">
              ZENTRY
            </div>
            <div className="text-[9px] text-cyan-400 font-mono-tech tracking-wider uppercase font-semibold">
              Zero-Trust Gateway
            </div>
          </div>
        </div>
      </div>

      {/* Navigation Sections */}
      <div className="flex-1 overflow-y-auto px-3 py-4 space-y-4">
        {navSections.map((sec) => (
          <div key={sec.title}>
            <div className="px-2.5 mb-1 text-[9px] font-bold text-[#6B7280] tracking-widest uppercase font-mono-tech flex items-center justify-between">
              <span>{sec.title}</span>
              <span className="w-1 h-1 rounded-full bg-white/10" />
            </div>
            <div className="space-y-0.5">
              {sec.items.map((item) => {
                const Icon = item.icon;
                const isActive = currentTab === item.key;
                return (
                  <button
                    key={item.key}
                    onClick={() => onSelectTab(item.key as NavItemKey)}
                    className={`relative w-full flex items-center gap-2.5 px-3 py-2 rounded-xl text-xs font-medium transition-all group ${
                      isActive
                        ? "text-white font-semibold"
                        : "text-[#9CA3AF] hover:text-[#F3F4F6] hover:bg-white/[0.04]"
                    }`}
                  >
                    {/* Animated Sliding Pill on Active Item */}
                    {isActive && (
                      <motion.div
                        layoutId="activeSidebarIndicator"
                        className="absolute inset-0 rounded-xl bg-gradient-to-r from-blue-600/30 via-cyan-500/15 to-transparent border border-cyan-400/40 shadow-[inset_0_1px_0_0_rgba(255,255,255,0.15),0_0_20px_rgba(56,189,248,0.2)]"
                        transition={{ type: "spring", stiffness: 400, damping: 33 }}
                      />
                    )}

                    <Icon
                      className={`w-4 h-4 z-10 transition-transform duration-200 group-hover:scale-110 ${
                        isActive
                          ? "text-cyan-400 drop-shadow-[0_0_8px_rgba(56,189,248,0.7)]"
                          : "text-[#6B7280]"
                      }`}
                    />
                    <span className="z-10 tracking-tight">{item.label}</span>
                    {isActive && (
                      <motion.span
                        initial={{ scale: 0 }}
                        animate={{ scale: 1 }}
                        className="ml-auto z-10 w-1.5 h-1.5 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(56,189,248,1)]"
                      />
                    )}
                  </button>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Cluster Node Summary Footer */}
      <div className="p-3.5 border-t border-white/5 bg-gradient-to-b from-transparent to-[#0B0F14]/80">
        <div className="flex items-center justify-between text-[11px] mb-1.5 font-mono-tech">
          <span className="text-[#6B7280] text-[10px] tracking-wider uppercase">Cluster Mesh</span>
          <span className="text-emerald-400 text-[10px] font-semibold flex items-center gap-1.5">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
            3/3 Active
          </span>
        </div>
        <div className="w-full bg-[#171D26] h-1.5 rounded-full overflow-hidden p-0.5 border border-white/5">
          <div className="bg-gradient-to-r from-cyan-500 via-blue-500 to-emerald-400 h-full w-full rounded-full shadow-[0_0_10px_rgba(56,189,248,0.5)]" />
        </div>
      </div>
    </aside>
  );
};
