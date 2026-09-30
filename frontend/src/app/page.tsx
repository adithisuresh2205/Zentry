"use client";

import React, { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { RequestDrawer } from "../components/RequestDrawer";
import { NavItemKey, Sidebar } from "../components/Sidebar";
import { TopNav } from "../components/TopNav";
import { AuditLogsView } from "../components/views/AuditLogsView";
import { DevicesView } from "../components/views/DevicesView";
import { GatewayHealthView } from "../components/views/GatewayHealthView";
import { IdentitiesView } from "../components/views/IdentitiesView";
import { IncidentsView } from "../components/views/IncidentsView";
import { OverviewView } from "../components/views/OverviewView";
import { PoliciesView } from "../components/views/PoliciesView";
import { RequestExplorerView } from "../components/views/RequestExplorerView";
import { ThreatDetectionView } from "../components/views/ThreatDetectionView";
import { TrustEngineView } from "../components/views/TrustEngineView";
import { SecurityRequest } from "../types";

export default function DashboardPage() {
  const [currentTab, setCurrentTab] = useState<NavItemKey>("overview");
  const [selectedRequest, setSelectedRequest] = useState<SecurityRequest | null>(null);

  const getPageInfo = (): { title: string; subtitle: string } => {
    switch (currentTab) {
      case "overview":
        return {
          title: "Security Overview",
          subtitle: "Real-time visibility into gateway traffic, trust decisions, and detected threats.",
        };
      case "requests":
        return {
          title: "Request Explorer",
          subtitle: "Forensic inspection and telemetry for all intercepted inbound requests.",
        };
      case "trust-engine":
        return {
          title: "Zero-Trust Trust Engine",
          subtitle: "Multi-stage gate pipeline and multi-factor attestation.",
        };
      case "identities":
        return {
          title: "Identities & Credentials",
          subtitle: "Directory of active authenticated identities and trust scores.",
        };
      case "devices":
        return {
          title: "Device Fleet Posture",
          subtitle: "Hardware security, attestation status, and fingerprint records.",
        };
      case "threats":
        return {
          title: "Threat Detection & Intelligence",
          subtitle: "Real-time attack vector telemetry and mitigation signatures.",
        };
      case "incidents":
        return {
          title: "Incident Investigation",
          subtitle: "Forensic root-cause analysis and threat containment.",
        };
      case "policies":
        return {
          title: "Security Policies & WAF Rules",
          subtitle: "Declarative zero-trust access control rules and inspection gates.",
        };
      case "audit-logs":
        return {
          title: "Cryptographic Audit Logs",
          subtitle: "HMAC-SHA256 sealed security event records.",
        };
      case "health":
        return {
          title: "Gateway Health & Infrastructure",
          subtitle: "Cluster operational status, latency, and system telemetry.",
        };
      default:
        return { title: "Zentry Security Console", subtitle: "Zero-Trust Web Application Security Gateway" };
    }
  };

  const pageInfo = getPageInfo();

  return (
    <div className="flex h-screen bg-[#080B10] text-[#F3F4F6] overflow-hidden bg-grid-tactical">
      {/* Tactical Sidebar with Framer Motion animated active state */}
      <Sidebar currentTab={currentTab} onSelectTab={setCurrentTab} />

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden relative">
        <TopNav
          title={pageInfo.title}
          subtitle={pageInfo.subtitle}
          onSearch={(q) => {
            if (q) {
              setCurrentTab("requests");
            }
          }}
        />

        {/* Scrollable View Container */}
        <main className="flex-1 overflow-y-auto px-5 py-3 relative z-10">
          <div className="max-w-7xl mx-auto pb-12">
            <AnimatePresence mode="wait">
              <motion.div
                key={currentTab}
                initial={{ opacity: 0, y: 6 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -4 }}
                transition={{ duration: 0.15, ease: "easeOut" }}
              >
                {currentTab === "overview" && (
                  <OverviewView onRequestSelect={(r) => setSelectedRequest(r)} />
                )}

                {currentTab === "requests" && (
                  <RequestExplorerView onSelectRequest={(r) => setSelectedRequest(r)} />
                )}

                {currentTab === "trust-engine" && <TrustEngineView />}

                {currentTab === "identities" && <IdentitiesView />}

                {currentTab === "devices" && <DevicesView />}

                {currentTab === "threats" && <ThreatDetectionView />}

                {currentTab === "policies" && <PoliciesView />}

                {currentTab === "incidents" && <IncidentsView />}

                {currentTab === "audit-logs" && <AuditLogsView />}

                {currentTab === "health" && <GatewayHealthView />}
              </motion.div>
            </AnimatePresence>
          </div>
        </main>
      </div>

      {/* Forensic Request Investigation Drawer with spring physics */}
      <RequestDrawer
        request={selectedRequest}
        onClose={() => setSelectedRequest(null)}
      />
    </div>
  );
}
