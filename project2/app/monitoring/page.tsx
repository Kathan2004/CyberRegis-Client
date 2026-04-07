"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { Shield, Activity, RefreshCw } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  loadStoredScans,
  StoredScan,
  upsertStoredScan,
  SCHEDULE_STORAGE_KEY,
} from "@/lib/cache";

type ScheduledScanType = "domain" | "ip" | "port" | "vuln" | "headers" | "email";

interface ScheduledScan {
  input: string;
  type: ScheduledScanType;
  intervalMinutes: number;
  nextCheck: string;
  lastChecked?: string;
  status?: "idle" | "running" | "error";
  errorMessage?: string;
}

const intervalOptions = [
  { label: "Disabled", value: "off" },
  { label: "Every minute", value: "1" },
  { label: "Every 5 minutes", value: "5" },
  { label: "Every 15 minutes", value: "15" },
  { label: "Every 30 minutes", value: "30" },
  { label: "Every hour", value: "60" },
];

const formatTimestamp = (iso?: string) => {
  if (!iso) return "—";
  const date = new Date(iso);
  return Number.isNaN(date.getTime()) ? "—" : date.toLocaleString();
};

const getScheduleFor = (
  input: string,
  type: ScheduledScanType,
  schedules: ScheduledScan[]
) => schedules.find((item) => item.input === input && item.type === type);

const persistSchedules = (items: ScheduledScan[]) => {
  if (typeof window === "undefined") return;
  try {
    const payload = items.map(({ status, errorMessage, ...rest }) => rest);
    localStorage.setItem(SCHEDULE_STORAGE_KEY, JSON.stringify(payload));
  } catch (error) {
    console.error("Failed to persist monitoring schedules", error);
  }
};

const loadSchedules = (): ScheduledScan[] => {
  if (typeof window === "undefined") return [];
  try {
    const raw = localStorage.getItem(SCHEDULE_STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as Array<
      Omit<ScheduledScan, "status" | "errorMessage">
    >;
    return parsed.map((item) => ({
      ...item,
      type: item.type ?? "ip",
      status: "idle",
    }));
  } catch (error) {
    console.error("Failed to load monitoring schedules", error);
    return [];
  }
};

export default function MonitoringPage() {
  const [cachedIntegrated, setCachedIntegrated] = useState<StoredScan[]>([]);
  const [cachedIps, setCachedIps] = useState<StoredScan[]>([]);
  const [cachedLogs, setCachedLogs] = useState<StoredScan[]>([]);
  const [cachedPorts, setCachedPorts] = useState<StoredScan[]>([]);
  const [cachedVulns, setCachedVulns] = useState<StoredScan[]>([]);
  const [cachedHeaders, setCachedHeaders] = useState<StoredScan[]>([]);
  const [cachedEmails, setCachedEmails] = useState<StoredScan[]>([]);
  const [scheduledScans, setScheduledScans] = useState<ScheduledScan[]>([]);
  const scheduledScansRef = useRef<ScheduledScan[]>([]);

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000";

  const reloadCaches = () => {
    setCachedIntegrated(loadStoredScans("cyberregis_integrated"));
    setCachedIps(loadStoredScans("cyberregis_ips"));
    setCachedLogs(loadStoredScans("cyberregis_logs"));
    setCachedPorts(loadStoredScans("cyberregis_ports"));
    setCachedVulns(loadStoredScans("cyberregis_vuln"));
    setCachedHeaders(loadStoredScans("cyberregis_headers"));
    setCachedEmails(loadStoredScans("cyberregis_email"));
  };

  useEffect(() => {
    reloadCaches();
    setScheduledScans(loadSchedules());
  }, []);

  useEffect(() => {
    scheduledScansRef.current = scheduledScans;
  }, [scheduledScans]);

  useEffect(() => {
    const timer = setInterval(() => {
      const now = Date.now();
      scheduledScansRef.current.forEach((item) => {
        if (
          item.status !== "running" &&
          item.intervalMinutes > 0 &&
          new Date(item.nextCheck).getTime() <= now
        ) {
          recheckScheduledScan(item);
        }
      });
    }, 15000);

    return () => clearInterval(timer);
  }, []);

  const handleScheduleChange = (
    input: string,
    type: ScheduledScanType,
    value: string
  ) => {
    if (value === "off") {
      setScheduledScans((prev) => {
        const updated = prev.filter(
          (item) => !(item.input === input && item.type === type)
        );
        persistSchedules(updated);
        return updated;
      });
      return;
    }

    const intervalMinutes = parseInt(value, 10);
    const nextCheck = new Date(
      Date.now() + intervalMinutes * 60 * 1000
    ).toISOString();

    setScheduledScans((prev) => {
      const existing = prev.find(
        (item) => item.input === input && item.type === type
      );
      let updated: ScheduledScan[];
      if (existing) {
        updated = prev.map((item) =>
          item.input === input && item.type === type
            ? {
                ...item,
                intervalMinutes,
                nextCheck,
                status: "idle",
                errorMessage: undefined,
              }
            : item
        );
      } else {
        updated = [
          ...prev,
          {
            input,
            type,
            intervalMinutes,
            nextCheck,
            status: "idle",
          },
        ];
      }
      persistSchedules(updated);
      return updated;
    });
  };

  const recheckScheduledScan = async (item: ScheduledScan) => {
    setScheduledScans((prev) =>
      prev.map((entry) =>
        entry.input === item.input && entry.type === item.type
          ? { ...entry, status: "running", errorMessage: undefined }
          : entry
      )
    );

    try {
      const nowIso = new Date().toISOString();
      switch (item.type) {
        case "domain": {
          const isUrl =
            item.input.startsWith("http://") || item.input.startsWith("https://");
          const url = isUrl ? item.input : `https://${item.input}`;
          const domain = isUrl ? new URL(item.input).hostname : item.input;
          const [urlResponse, domainResponse] = await Promise.all([
            fetch(`${API_URL}/api/check-url`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ url }),
            }),
            fetch(`${API_URL}/api/analyze-domain`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ domain }),
            }),
          ]);
          if (!urlResponse.ok || !domainResponse.ok) {
            throw new Error(
              `Domain refresh failed (${urlResponse.status}/${domainResponse.status})`
            );
          }
          const urlData = await urlResponse.json();
          const domainData = await domainResponse.json();
          const updated = upsertStoredScan("cyberregis_integrated", {
            input: item.input,
            result: { urlResults: urlData, domainResults: domainData },
            timestamp: nowIso,
          });
          setCachedIntegrated(updated);
          break;
        }
        case "ip": {
          const response = await fetch(`${API_URL}/api/check-ip`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ ip: item.input }),
          });
          if (!response.ok) {
            throw new Error(`IP refresh failed (${response.status})`);
          }
          const data = await response.json();
          const updated = upsertStoredScan("cyberregis_ips", {
            input: item.input,
            result: data,
            timestamp: nowIso,
          });
          setCachedIps(updated);
          break;
        }
        case "port": {
          const response = await fetch(`${API_URL}/api/scan-ports`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: item.input }),
          });
          if (!response.ok) {
            throw new Error(`Port refresh failed (${response.status})`);
          }
          const data = await response.json();
          const updated = upsertStoredScan("cyberregis_ports", {
            input: item.input,
            result: data,
            timestamp: nowIso,
          });
          setCachedPorts(updated);
          break;
        }
        case "vuln": {
          const response = await fetch(`${API_URL}/api/vulnerability-scan`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ target: item.input }),
          });
          if (!response.ok) {
            throw new Error(`Vulnerability refresh failed (${response.status})`);
          }
          const data = await response.json();
          const updated = upsertStoredScan("cyberregis_vuln", {
            input: item.input,
            result: data,
            timestamp: nowIso,
          });
          setCachedVulns(updated);
          break;
        }
        case "headers": {
          const response = await fetch(`${API_URL}/api/security-headers`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: item.input }),
          });
          if (!response.ok) {
            throw new Error(`Security headers refresh failed (${response.status})`);
          }
          const data = await response.json();
          const updated = upsertStoredScan("cyberregis_headers", {
            input: item.input,
            result: data,
            timestamp: nowIso,
          });
          setCachedHeaders(updated);
          break;
        }
        case "email": {
          const response = await fetch(`${API_URL}/api/email-security`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ domain: item.input }),
          });
          if (!response.ok) {
            throw new Error(`Email security refresh failed (${response.status})`);
          }
          const data = await response.json();
          const updated = upsertStoredScan("cyberregis_email", {
            input: item.input,
            result: data,
            timestamp: nowIso,
          });
          setCachedEmails(updated);
          break;
        }
        default:
          throw new Error("Unsupported artefact type");
      }

      const nextCheck = new Date(
        Date.now() + item.intervalMinutes * 60 * 1000
      ).toISOString();
      setScheduledScans((prev) =>
        prev.map((entry) =>
          entry.input === item.input && entry.type === item.type
            ? {
                ...entry,
                status: "idle",
                errorMessage: undefined,
                lastChecked: nowIso,
                nextCheck,
              }
            : entry
        )
      );
    } catch (error) {
      console.error("Error refreshing scheduled scan", error);
      const errorMessage =
        error instanceof Error ? error.message : "Unexpected error";
      const nextCheck = new Date(
        Date.now() + item.intervalMinutes * 60 * 1000
      ).toISOString();
      setScheduledScans((prev) =>
        prev.map((entry) =>
          entry.input === item.input && entry.type === item.type
            ? {
                ...entry,
                status: "error",
                errorMessage,
                lastChecked: new Date().toISOString(),
                nextCheck,
              }
            : entry
        )
      );
    }
  };

  const handleManualRefresh = (item: ScheduledScan) => {
    recheckScheduledScan(item);
  };

  const renderScheduleControls = (
    input: string,
    type: ScheduledScanType,
    schedule?: ScheduledScan
  ) => (
    <div className="flex flex-col gap-2 md:items-end w-full md:w-auto">
      <div className="space-y-1">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
          Auto-refresh interval
        </span>
        <Select
          value={schedule ? String(schedule.intervalMinutes) : "off"}
          onValueChange={(value) => handleScheduleChange(input, type, value)}
        >
          <SelectTrigger className="bg-background/50 w-44">
            <SelectValue placeholder="Choose interval" />
          </SelectTrigger>
          <SelectContent>
            {intervalOptions.map((option) => (
              <SelectItem key={`${type}-${option.value}`} value={option.value}>
                {option.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      {schedule && (
        <Button
          variant="outline"
          size="sm"
          className="w-44"
          onClick={() => handleManualRefresh(schedule)}
          disabled={schedule.status === "running"}
        >
          {schedule.status === "running" ? "Refreshing..." : "Refresh now"}
        </Button>
      )}
    </div>
  );

  const renderScheduleMeta = (schedule?: ScheduledScan) =>
    schedule ? (
      <div className="space-y-1 text-xs text-muted-foreground">
        <div>Last refresh: {formatTimestamp(schedule.lastChecked)}</div>
        <div>Next refresh: {formatTimestamp(schedule.nextCheck)}</div>
        {schedule.status === "error" && schedule.errorMessage && (
          <div className="text-destructive">
            Last error: {schedule.errorMessage}
          </div>
        )}
      </div>
    ) : (
      <div className="text-xs text-muted-foreground">Not scheduled</div>
    );

  return (
    <div
      className="min-h-screen bg-background"
      style={{
        backgroundImage:
          "radial-gradient(circle at 50% 50%, hsl(var(--background)) 0%, hsl(var(--card)) 100%)",
      }}
    >
      <header className="border-b border-border/40 backdrop-blur-sm sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between h-16">
            <div className="flex items-center space-x-4">
              <div className="relative">
                <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full"></div>
                <Shield className="w-8 h-8 text-primary relative z-10" />
              </div>
              <span className="text-xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
                CyberRegis
              </span>
            </div>
            <nav className="flex items-center space-x-6">
              <Link href="/" className="text-foreground hover:text-primary transition-colors">
                Dashboard
              </Link>
              <Link href="/resources" className="text-foreground hover:text-primary transition-colors">
                Resources
              </Link>
              <Link href="/monitoring" className="text-primary transition-colors">
                Monitoring
              </Link>
              <div className="flex items-center space-x-1">
                <Activity className="w-4 h-4 text-green-500 animate-pulse" />
                <span className="text-sm text-muted-foreground">Active</span>
              </div>
            </nav>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto p-8 space-y-8">
        <div className="flex items-center justify-between flex-wrap gap-4">
          <div>
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
              Monitoring Console
            </h1>
            <p className="text-muted-foreground">
              Review cached artefacts, schedule periodic refreshes, and verify stored intelligence.
            </p>
          </div>
          <Button variant="outline" onClick={reloadCaches} className="gap-2">
            <RefreshCw className="w-4 h-4" />
            Refresh caches
          </Button>
        </div>

        <Card className="border-primary/20 bg-card/60 backdrop-blur-sm">
          <div className="p-6 space-y-8">
            {/* Domain Recon */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Domain Recon Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedIntegrated.length} cached {cachedIntegrated.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedIntegrated.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Run a domain or URL scan to populate this cache. Saved entries appear here for monitoring and scheduled refresh.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedIntegrated.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "domain", scheduledScans);
                    const threat = entry.result?.urlResults?.data?.threat_analysis;
                    const riskLevel =
                      entry.result?.domainResults?.data?.additional_checks?.domain_analysis?.risk_level;
                    const insights: string[] = [];
                    if (typeof threat?.is_malicious === "boolean") {
                      insights.push(
                        `Threat verdict: ${threat.is_malicious ? "malicious" : "clean"}`
                      );
                    }
                    if (typeof threat?.threats_found === "number") {
                      insights.push(`Threat matches: ${threat.threats_found}`);
                    }
                    if (riskLevel) {
                      insights.push(`Risk level: ${riskLevel}`);
                    }

                    return (
                      <div
                        key={`domain-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold">{entry.input}</span>
                              {typeof threat?.is_malicious === "boolean" && (
                                <Badge
                                  variant={threat.is_malicious ? "destructive" : "outline"}
                                  className={`text-xs ${
                                    threat.is_malicious ? "" : "text-green-600 border-green-600"
                                  }`}
                                >
                                  {threat.is_malicious ? "Malicious" : "Clean"}
                                </Badge>
                              )}
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            {insights.length > 0 && (
                              <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                                {insights.map((item) => (
                                  <li key={item}>{item}</li>
                                ))}
                              </ul>
                            )}
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "domain", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <Separator />

            {/* IP reputation */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">IP Reputation Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedIps.length} cached {cachedIps.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedIps.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Execute an IP scan to populate the cache. Cached entries can be refreshed to keep verdicts current.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedIps.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "ip", scheduledScans);
                    const risk =
                      entry.result?.data?.risk_assessment?.risk_level ||
                      entry.result?.risk_assessment?.risk_level;
                    const verdict =
                      entry.result?.data?.threat_analysis?.is_malicious ??
                      entry.result?.threat_analysis?.is_malicious;
                    const insights: string[] = [];
                    if (typeof verdict === "boolean") {
                      insights.push(`Threat verdict: ${verdict ? "malicious" : "clean"}`);
                    }
                    if (risk) {
                      insights.push(`Risk level: ${risk}`);
                    }
                    const reports =
                      entry.result?.data?.risk_assessment?.total_reports ??
                      entry.result?.risk_assessment?.total_reports;
                    if (typeof reports === "number") {
                      insights.push(`Reports: ${reports}`);
                    }

                    return (
                      <div
                        key={`ip-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold font-mono">{entry.input}</span>
                              {typeof verdict === "boolean" && (
                                <Badge
                                  variant={verdict ? "destructive" : "outline"}
                                  className={`text-xs ${
                                    verdict ? "" : "text-green-600 border-green-600"
                                  }`}
                                >
                                  {verdict ? "Malicious" : "Clean"}
                                </Badge>
                              )}
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            {insights.length > 0 && (
                              <ul className="text-xs text-muted-foreground space-y-1 list-disc list-inside">
                                {insights.map((item) => (
                                  <li key={item}>{item}</li>
                                ))}
                              </ul>
                            )}
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "ip", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <Separator />

            {/* Network logs */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Network Log Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedLogs.length} cached {cachedLogs.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedLogs.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Upload a PCAP file in the dashboard to store its analysis for later reference.
                </p>
              ) : (
                <div className="space-y-3">
                  {cachedLogs.map((entry) => (
                    <div
                      key={`log-${entry.input}-${entry.timestamp}`}
                      className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-2"
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-semibold">{entry.input}</span>
                        <Badge variant="outline" className="text-xs text-muted-foreground">
                          Manual refresh only
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Cached: {formatTimestamp(entry.timestamp)}
                      </p>
                      <p className="text-xs text-muted-foreground">
                        Offline refresh is unavailable because the original artefact must be re-uploaded.
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </section>

            <Separator />

            {/* Port scans */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Port Scan Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedPorts.length} cached {cachedPorts.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedPorts.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Run a port scan to populate this cache. Scheduled refreshes help detect newly exposed services.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedPorts.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "port", scheduledScans);
                    const portCount =
                      entry.result?.ports?.length ??
                      entry.result?.data?.ports?.length ??
                      entry.result?.open_ports?.length ??
                      0;
                    return (
                      <div
                        key={`port-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold">{entry.input}</span>
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Detected open services: {portCount}
                            </p>
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "port", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <Separator />

            {/* Vulnerability scans */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Vulnerability Scan Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedVulns.length} cached {cachedVulns.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedVulns.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Execute a vulnerability scan to store results. Scheduling periodic refreshes helps catch new CVE disclosures.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedVulns.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "vuln", scheduledScans);
                    const vulnCount =
                      entry.result?.vulnerabilities?.length ??
                      entry.result?.data?.vulnerabilities?.length ??
                      0;
                    return (
                      <div
                        key={`vuln-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold">{entry.input}</span>
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            <p className="text-xs text-muted-foreground">
                              Vulnerabilities found: {vulnCount}
                            </p>
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "vuln", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <Separator />

            {/* Security headers */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Security Headers Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedHeaders.length} cached {cachedHeaders.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedHeaders.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Run a security headers scan to populate this cache. Refresh schedules make it easy to track regressions.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedHeaders.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "headers", scheduledScans);
                    const grade = entry.result?.grade ?? entry.result?.data?.grade;
                    return (
                      <div
                        key={`headers-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold">{entry.input}</span>
                              {grade && (
                                <Badge variant="outline" className="text-xs">
                                  Grade: {grade}
                                </Badge>
                              )}
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "headers", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>

            <Separator />

            {/* Email security */}
            <section className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-lg font-semibold">Email Security Cache</h2>
                <Badge variant="outline" className="text-xs text-muted-foreground">
                  {cachedEmails.length} cached {cachedEmails.length === 1 ? "entry" : "entries"}
                </Badge>
              </div>
              {cachedEmails.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  Run an email security assessment to populate this cache and monitor SPF/DMARC/DKIM posture over time.
                </p>
              ) : (
                <div className="space-y-4">
                  {cachedEmails.map((entry) => {
                    const schedule = getScheduleFor(entry.input, "email", scheduledScans);
                    const grade = entry.result?.grade ?? entry.result?.data?.grade;
                    const emailSecurity =
                      entry.result?.email_security || entry.result?.data?.email_security;
                    const renderPolicyStatus = (label: string, record?: { present?: boolean; record?: string }) =>
                      record ? (
                        <div className="flex items-center gap-2">
                          <span>{label}:</span>
                          <Badge
                            variant={record.present ? "outline" : "destructive"}
                            className={`text-xs ${record.present ? "text-green-600 border-green-600" : ""}`}
                          >
                            {record.present ? "Present" : "Missing"}
                          </Badge>
                        </div>
                      ) : null;

                    return (
                      <div
                        key={`email-${entry.input}`}
                        className="border border-border/40 rounded-lg bg-background/40 p-4 space-y-3"
                      >
                        <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                          <div className="space-y-2">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="text-base font-semibold">{entry.input}</span>
                              {grade && (
                                <Badge variant="outline" className="text-xs">
                                  Grade: {grade}
                                </Badge>
                              )}
                              {schedule?.status === "running" && (
                                <Badge variant="outline" className="text-xs bg-primary/10 text-primary">
                                  Refreshing…
                                </Badge>
                              )}
                              {schedule?.status === "error" && (
                                <Badge variant="destructive" className="text-xs">
                                  Error
                                </Badge>
                              )}
                            </div>
                            <p className="text-xs text-muted-foreground">
                              Cached: {formatTimestamp(entry.timestamp)}
                            </p>
                            <div className="text-xs text-muted-foreground space-y-1">
                              {renderPolicyStatus("SPF", emailSecurity?.spf)}
                              {renderPolicyStatus("DMARC", emailSecurity?.dmarc)}
                              {renderPolicyStatus("DKIM", emailSecurity?.dkim)}
                            </div>
                            {renderScheduleMeta(schedule)}
                          </div>
                          {renderScheduleControls(entry.input, "email", schedule)}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </section>
          </div>
        </Card>
      </div>
    </div>
  );
}

