"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Bell,
  Globe,
  Search,
  ShieldAlert,
} from "lucide-react";

interface TopNavProps {
  title: string;
  subtitle?: string;
  onSearch?: (_query: string) => void;
}

export const TopNav: React.FC<TopNavProps> = ({ title, subtitle, onSearch }) => {
  const [env] = useState<"production" | "staging" | "dev">("production");
  const [showNotifications, setShowNotifications] = useState(false);
  const [isSearchFocused, setIsSearchFocused] = useState(false);

  return (
    <header className="mx-4 mt-3 mb-2 px-5 h-14 rounded-full glass-panel border border-white/10 shadow-[0_12px_36px_rgba(0,0,0,0.5)] flex items-center justify-between backdrop-blur-2xl sticky top-3 z-30 select-none">
      {/* Page Title & Tactical Breadcrumb */}
      <div className="flex items-center gap-3 pl-1">
        <div className="flex items-center gap-2.5">
          <span className="w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(56,189,248,0.9)] animate-pulse" />
          <h1 className="text-xs font-bold tracking-wider text-[#F3F4F6] uppercase font-mono-tech">
            {title}
          </h1>
          {subtitle && (
            <span className="text-[11px] text-[#9CA3AF] hidden lg:inline font-sans border-l border-white/10 pl-2.5">
              {subtitle}
            </span>
          )}
        </div>
      </div>

      {/* Center/Right Controls */}
      <div className="flex items-center gap-2.5">
        {/* Global Forensic Search with Smooth Expand */}
        <motion.div
          animate={{ width: isSearchFocused ? 280 : 200 }}
          transition={{ duration: 0.2, ease: "easeInOut" }}
          className="relative hidden md:block"
        >
          <Search className="w-3.5 h-3.5 absolute left-3.5 top-1/2 -translate-y-1/2 text-[#6B7280]" />
          <input
            type="text"
            placeholder="Search forensic trace..."
            onFocus={() => setIsSearchFocused(true)}
            onBlur={() => setIsSearchFocused(false)}
            onChange={(e) => onSearch && onSearch(e.target.value)}
            className="w-full bg-black/40 border border-white/10 focus:border-cyan-500/60 rounded-full pl-9 pr-3.5 py-1 text-xs text-[#F3F4F6] placeholder-[#6B7280] focus:outline-none focus:ring-1 focus:ring-cyan-500/30 font-mono-tech transition-all shadow-inner"
          />
        </motion.div>

        {/* Gateway Status Beacon with Ping Ring */}
        <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/30 shadow-[0_0_12px_rgba(16,185,129,0.15)]">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          </span>
          <span className="text-[10px] font-mono-tech tracking-wider text-emerald-400 font-bold">
            GATEWAY OPERATIONAL
          </span>
        </div>

        {/* Environment Badge */}
        <div className="relative hidden xl:flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs text-[#9CA3AF]">
          <Globe className="w-3.5 h-3.5 text-cyan-400" />
          <span className="capitalize text-[#F3F4F6] font-mono-tech text-[10px] font-medium">
            {env}
          </span>
        </div>

        {/* Notifications Button */}
        <div className="relative">
          <button
            onClick={() => setShowNotifications(!showNotifications)}
            className="relative p-2 rounded-full bg-white/[0.04] hover:bg-white/[0.08] text-[#9CA3AF] hover:text-[#F3F4F6] transition-all border border-white/10 hover:border-cyan-500/40"
          >
            <Bell className="w-3.5 h-3.5" />
            <span className="absolute top-1 right-1 w-2 h-2 rounded-full bg-cyan-400 shadow-[0_0_8px_rgba(56,189,248,1)]" />
          </button>

          {/* Notifications Dropdown */}
          <AnimatePresence>
            {showNotifications && (
              <motion.div
                initial={{ opacity: 0, y: 8, scale: 0.96 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: 8, scale: 0.96 }}
                transition={{ duration: 0.15 }}
                className="absolute right-0 mt-3 w-80 rounded-2xl glass-panel p-3.5 shadow-2xl z-50 border border-white/10"
              >
                <div className="flex items-center justify-between pb-2 mb-2 border-b border-white/5 font-mono-tech text-xs">
                  <span className="font-bold text-white">Live Alert Stream</span>
                  <span className="text-[10px] text-cyan-400">2 New</span>
                </div>
                <div className="space-y-2 text-xs">
                  <div className="p-2 rounded-xl bg-red-500/10 border border-red-500/20 text-red-300">
                    <div className="font-semibold text-[11px] flex items-center gap-1.5">
                      <ShieldAlert className="w-3.5 h-3.5 text-red-400" />
                      SQLi Infiltration Attempt
                    </div>
                    <div className="text-[10px] text-gray-400 mt-0.5 font-mono-tech">
                      IP 194.26.29.112 blocked via Rule WAF-001
                    </div>
                  </div>
                  <div className="p-2 rounded-xl bg-amber-500/10 border border-amber-500/20 text-amber-300">
                    <div className="font-semibold text-[11px]">Anomalous Geo Spike</div>
                    <div className="text-[10px] text-gray-400 mt-0.5 font-mono-tech">
                      New ASN AS4837 detected on admin portal
                    </div>
                  </div>
                </div>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* User Profile Pill */}
        <div className="flex items-center gap-2 pl-1 pr-3 py-1 rounded-full bg-white/[0.04] border border-white/10">
          <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-blue-600 to-cyan-500 flex items-center justify-center text-[10px] font-mono-tech text-white font-bold shadow-[0_0_8px_rgba(56,189,248,0.4)]">
            ER
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-semibold text-[#F3F4F6] tracking-tight leading-tight">Elena Rostova</div>
            <div className="text-[9px] text-cyan-400/80 font-mono-tech leading-tight">SecOps Lead</div>
          </div>
        </div>
      </div>
    </header>
  );
};
