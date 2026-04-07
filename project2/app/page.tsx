"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  Shield, Globe, Network, Eye, Activity, Upload, MessageSquare,
  ExternalLink, X, Search, ChevronRight, ChevronLeft, AlertTriangle, CheckCircle,
  Lock, Server, Mail, FileText, TrendingUp, Database, Clock, Zap,
  BarChart3, Wifi, Bug, RefreshCw, Copy,
} from "lucide-react";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import * as api from "@/app/lib/api";
import type { DashboardStats, ScanHistoryEntry } from "@/app/types";
import { loadStoredScans, upsertStoredScan } from "@/lib/cache";

/* ───────────── helpers ───────────── */

function riskBadge(level: string | undefined) {
  if (!level) return { text: "N/A", cls: "text-gray-400 border-gray-400/30 bg-gray-400/10" };
  const l = level.toLowerCase();
  if (l === "critical" || l === "high") return { text: level, cls: "text-red-500 border-red-500/30 bg-red-500/10" };
  if (l === "medium") return { text: level, cls: "text-yellow-500 border-yellow-500/30 bg-yellow-500/10" };
  return { text: level, cls: "text-green-400 border-green-400/30 bg-green-400/10" };
}

/* ───────────── component ───────────── */

export default function Dashboard() {
  /* ── Dashboard KPIs ── */
  const [stats, setStats] = useState<DashboardStats | null>(null);

  /* ── Scan tab ── */
  const [activeTab, setActiveTab] = useState<"domain" | "ip" | "pcap" | "ports" | "vuln" | "headers" | "email">("domain");

  /* ── Domain / URL ── */
  const [domainInput, setDomainInput] = useState("");
  const [domainResults, setDomainResults] = useState<any>(null);
  const [urlResults, setUrlResults] = useState<any>(null);
  const [domainLoading, setDomainLoading] = useState(false);

  /* ── IP ── */
  const [ipInput, setIpInput] = useState("");
  const [ipResults, setIpResults] = useState<any>(null);
  const [ipLoading, setIpLoading] = useState(false);

  /* ── PCAP ── */
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [pcapResults, setPcapResults] = useState<any>(null);
  const [pcapLoading, setPcapLoading] = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  /* ── Port scan ── */
  const [portTarget, setPortTarget] = useState("");
  const [portResults, setPortResults] = useState<any>(null);
  const [portLoading, setPortLoading] = useState(false);

  /* ── Vuln scan ── */
  const [vulnTarget, setVulnTarget] = useState("");
  const [vulnResults, setVulnResults] = useState<any>(null);
  const [vulnLoading, setVulnLoading] = useState(false);

  /* ── Security headers ── */
  const [headerUrl, setHeaderUrl] = useState("");
  const [headerResults, setHeaderResults] = useState<any>(null);
  const [headerLoading, setHeaderLoading] = useState(false);

  /* ── Email security ── */
  const [emailDomain, setEmailDomain] = useState("");
  const [emailResults, setEmailResults] = useState<any>(null);
  const [emailLoading, setEmailLoading] = useState(false);

  /* ── Chat ── */
  const [chatOpen, setChatOpen] = useState(false);
  const [chatMessages, setChatMessages] = useState<{ text: string; isUser: boolean; ts: string }[]>([
    { text: "Hello! I'm your CyberRegis AI assistant. Ask me anything about cybersecurity.", isUser: false, ts: "" },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);

  /* ── View modes ── */
  const [jsonView, setJsonView] = useState(false);

  /* ── Inline Scan History ── */
  const [historyScans, setHistoryScans] = useState<ScanHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [historyPage, setHistoryPage] = useState(1);
  const [historyTotal, setHistoryTotal] = useState(0);
  const [historySelected, setHistorySelected] = useState<ScanHistoryEntry | null>(null);
  const HISTORY_PER_PAGE = 8;

  /* ── File content modal ── */
  const [fileModal, setFileModal] = useState<{ title: string; content: string } | null>(null);

  /* ── Load dashboard stats ── */
  useEffect(() => {
    (async () => {
      try {
        const res = await api.getDashboardStats();
        if (res.data) setStats(res.data);
      } catch (e) { console.error("Stats load failed:", e); }
    })();
    setChatMessages(prev => prev.map((m, i) => i === 0 ? { ...m, ts: new Date().toLocaleTimeString() } : m));
  }, []);

  const loadInlineHistory = useCallback(async (page: number) => {
    setHistoryLoading(true);
    try {
      const res = await api.getScanHistory({ page, per_page: HISTORY_PER_PAGE });
      const apiScans = res.data?.scans || [];
      const apiTotal = res.data?.total || 0;

      if (apiTotal > 0) {
        setHistoryScans(apiScans);
        setHistoryTotal(apiTotal);
      } else {
        // Fall back to localStorage cache
        const LOCAL_KEYS: { key: Parameters<typeof loadStoredScans>[0]; type: string }[] = [
          { key: "cyberregis_integrated", type: "domain" },
          { key: "cyberregis_ips",        type: "ip" },
          { key: "cyberregis_ports",      type: "port_scan" },
          { key: "cyberregis_vuln",       type: "vuln_scan" },
          { key: "cyberregis_headers",    type: "headers" },
          { key: "cyberregis_email",      type: "email" },
          { key: "cyberregis_logs",       type: "pcap" },
        ];
        const all: ScanHistoryEntry[] = LOCAL_KEYS.flatMap(({ key, type }) =>
          loadStoredScans(key).map((s, i) => ({
            id: i,
            scan_type: type,
            target: s.input,
            status: "completed",
            timestamp: s.timestamp,
            result_summary: s.result,
          } as ScanHistoryEntry))
        ).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

        const start = (page - 1) * HISTORY_PER_PAGE;
        setHistoryScans(all.slice(start, start + HISTORY_PER_PAGE));
        setHistoryTotal(all.length);
      }
    } catch (e) { console.error("History load failed:", e); }
    setHistoryLoading(false);
  }, []);

  useEffect(() => { loadInlineHistory(historyPage); }, [historyPage, loadInlineHistory]);

  /* ── Auto-scroll chat ── */
  useEffect(() => { chatRef.current?.scrollTo(0, chatRef.current.scrollHeight); }, [chatMessages]);

  /* ──────────────────────────────────────── */
  /*                SCAN HANDLERS             */
  /* ──────────────────────────────────────── */

  const runDomainScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!domainInput.trim()) return;
    setDomainLoading(true);
    setDomainResults(null);
    setUrlResults(null);

    const cached = loadStoredScans("cyberregis_integrated").find(s => s.input === domainInput);
    if (cached) { setDomainResults(cached.result.domainResults); setUrlResults(cached.result.urlResults); setDomainLoading(false); return; }

    const isUrl = domainInput.startsWith("http://") || domainInput.startsWith("https://");
    const urlToScan = isUrl ? domainInput : `https://${domainInput}`;
    const domain = isUrl ? new URL(domainInput).hostname : domainInput.replace(/^www\./, "");
    try {
      const [uRes, dRes] = await Promise.all([api.checkUrl(urlToScan), api.analyzeDomain(domain)]);
      setUrlResults(uRes);
      setDomainResults(dRes);
      upsertStoredScan("cyberregis_integrated", { input: domainInput, result: { urlResults: uRes, domainResults: dRes }, timestamp: new Date().toISOString() });
    } catch (e: any) {
      setDomainResults({ status: "error", message: e.message });
    }
    setDomainLoading(false);
  };

  const runIpScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!ipInput.trim()) return;
    setIpLoading(true);
    setIpResults(null);
    const cached = loadStoredScans("cyberregis_ips").find(s => s.input === ipInput);
    if (cached) { setIpResults(cached.result); setIpLoading(false); return; }
    try {
      const res = await api.checkIp(ipInput.trim());
      setIpResults(res);
      upsertStoredScan("cyberregis_ips", { input: ipInput, result: res, timestamp: new Date().toISOString() });
    } catch (e: any) { setIpResults({ status: "error", message: e.message }); }
    setIpLoading(false);
  };

  const runPcapScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedFile) return;
    setPcapLoading(true);
    setPcapResults(null);
    try {
      const res = await api.analyzePcap(selectedFile);
      setPcapResults(res);
    } catch (e: any) { setPcapResults({ status: "error", message: e.message }); }
    setPcapLoading(false);
  };

  const runPortScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!portTarget.trim()) return;
    setPortLoading(true);
    setPortResults(null);
    const cached = loadStoredScans("cyberregis_ports").find(s => s.input === portTarget);
    if (cached) { setPortResults(cached.result); setPortLoading(false); return; }
    try {
      const res = await api.scanPorts(portTarget.trim());
      setPortResults(res);
      upsertStoredScan("cyberregis_ports", { input: portTarget, result: res, timestamp: new Date().toISOString() });
    } catch (e: any) { setPortResults({ status: "error", message: e.message }); }
    setPortLoading(false);
  };

  const runVulnScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vulnTarget.trim()) return;
    setVulnLoading(true);
    setVulnResults(null);
    const cached = loadStoredScans("cyberregis_vuln").find(s => s.input === vulnTarget);
    if (cached) { setVulnResults(cached.result); setVulnLoading(false); return; }
    try {
      const res = await api.scanVulnerabilities(vulnTarget.trim());
      setVulnResults(res);
      upsertStoredScan("cyberregis_vuln", { input: vulnTarget, result: res, timestamp: new Date().toISOString() });
    } catch (e: any) { setVulnResults({ status: "error", message: e.message }); }
    setVulnLoading(false);
  };

  const runHeaderScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!headerUrl.trim()) return;
    setHeaderLoading(true);
    setHeaderResults(null);
    const cached = loadStoredScans("cyberregis_headers").find(s => s.input === headerUrl);
    if (cached) { setHeaderResults(cached.result); setHeaderLoading(false); return; }
    try {
      const res = await api.scanSecurityHeaders(headerUrl.trim());
      setHeaderResults(res);
      upsertStoredScan("cyberregis_headers", { input: headerUrl, result: res, timestamp: new Date().toISOString() });
    } catch (e: any) { setHeaderResults({ status: "error", message: e.message }); }
    setHeaderLoading(false);
  };

  const runEmailScan = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!emailDomain.trim()) return;
    setEmailLoading(true);
    setEmailResults(null);
    const cached = loadStoredScans("cyberregis_email").find(s => s.input === emailDomain);
    if (cached) { setEmailResults(cached.result); setEmailLoading(false); return; }
    try {
      const res = await api.scanEmailSecurity(emailDomain.trim());
      setEmailResults(res);
      upsertStoredScan("cyberregis_email", { input: emailDomain, result: res, timestamp: new Date().toISOString() });
    } catch (e: any) { setEmailResults({ status: "error", message: e.message }); }
    setEmailLoading(false);
  };

  const sendChat = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!chatInput.trim()) return;
    const msg = chatInput.trim();
    setChatMessages(p => [...p, { text: msg, isUser: true, ts: new Date().toLocaleTimeString() }]);
    setChatInput("");
    setChatLoading(true);
    try {
      const res = await api.sendChatMessage(msg);
      setChatMessages(p => [...p, { text: res.data?.response || "No response.", isUser: false, ts: new Date().toLocaleTimeString() }]);
    } catch { setChatMessages(p => [...p, { text: "Sorry, I couldn't process your request.", isUser: false, ts: new Date().toLocaleTimeString() }]); }
    setChatLoading(false);
  };

  const fetchFileContent = async (domain: string, fileType: "robots" | "security") => {
    try {
      const res = await api.getSecurityFileContent(domain, fileType);
      if (res.status === "success" && res.file_info) {
        setFileModal({ title: `${fileType === "robots" ? "robots.txt" : "security.txt"} — ${domain}`, content: res.file_info.content });
      } else {
        setFileModal({ title: `${fileType === "robots" ? "robots.txt" : "security.txt"} — ${domain}`, content: "File not found on this domain." });
      }
    } catch { setFileModal({ title: "Error", content: "Failed to fetch file content." }); }
  };

  const anyLoading = domainLoading || ipLoading || pcapLoading || portLoading || vulnLoading || headerLoading || emailLoading;

  // Refresh history whenever a scan finishes
  useEffect(() => {
    if (!anyLoading) { loadInlineHistory(historyPage); }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [anyLoading]);

  /* ──────────────────────────────────────── */
  /*                   TABS                   */
  /* ──────────────────────────────────────── */

  const TABS = [
    { id: "domain" as const, label: "Domain Recon", icon: Globe },
    { id: "ip" as const, label: "IP Intel", icon: Network },
    { id: "pcap" as const, label: "PCAP Analysis", icon: Wifi },
    { id: "ports" as const, label: "Port Scan", icon: Server },
    { id: "vuln" as const, label: "Vuln Scan", icon: Bug },
    { id: "headers" as const, label: "HTTP Headers", icon: Lock },
    { id: "email" as const, label: "Email Security", icon: Mail },
  ];

  /* ──────────────────────────────────────── */
  /*                  RENDER                  */
  /* ──────────────────────────────────────── */

  return (
    <div className="min-h-screen bg-background">
      {/* Nav */}
      <header className="sticky top-0 z-50 border-b border-primary/20 bg-background/95 backdrop-blur-md">
        <div className="flex h-16 w-full items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2">
            <div className="relative">
              <div className="absolute inset-0 bg-primary/20 blur-xl rounded-full" />
              <Shield className="h-6 w-6 text-primary relative z-10" />
            </div>
            <span className="text-lg font-bold bg-gradient-to-r from-primary to-primary/50 bg-clip-text text-transparent">CyberRegis</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link href="/" className="text-primary font-semibold">Dashboard</Link>
            <Link href="/threat-intel" className="text-muted-foreground hover:text-primary transition-colors">Threat Intel</Link>
            <Link href="/cve" className="text-muted-foreground hover:text-primary transition-colors">CVE Database</Link>
            <Link href="/history" className="text-muted-foreground hover:text-primary transition-colors">Scan History</Link>
            <Link href="/reports" className="text-muted-foreground hover:text-primary transition-colors">Reports</Link>
            <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
            <div className="flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-green-500 animate-pulse" />
              <span className="text-xs text-muted-foreground">Online</span>
            </div>
          </nav>
        </div>
      </header>

      <main className="w-full px-6 py-8">
        {/* Hero */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground">Threat Intelligence Dashboard</h1>
          <p className="mt-1 text-muted-foreground">Unified security analysis, reconnaissance, and threat detection platform.</p>
        </div>

        {/* KPI Cards */}
        <div className="mb-8 grid grid-cols-2 gap-4 lg:grid-cols-4">
          <div className="rounded-lg border border-primary/20 bg-card/50 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-muted-foreground text-xs"><BarChart3 className="h-4 w-4" /> Total Scans</div>
            <div className="mt-2 text-3xl font-bold text-primary">{stats?.scans?.total_scans ?? 0}</div>
          </div>
          <div className="rounded-lg border border-border bg-card/50 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-muted-foreground text-xs"><Database className="h-4 w-4" /> Unique Targets</div>
            <div className="mt-2 text-3xl font-bold text-foreground">{stats?.scans?.top_targets?.length ?? 0}</div>
          </div>
          <div className="rounded-lg border border-border bg-card/50 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-muted-foreground text-xs"><TrendingUp className="h-4 w-4" /> IOC Count</div>
            <div className="mt-2 text-3xl font-bold text-yellow-500">{stats?.iocs?.total ?? 0}</div>
          </div>
          <div className="rounded-lg border border-border bg-card/50 p-4 backdrop-blur-sm">
            <div className="flex items-center gap-2 text-muted-foreground text-xs"><Clock className="h-4 w-4" /> Today&apos;s Scans</div>
            <div className="mt-2 text-3xl font-bold text-foreground">{stats?.scans?.today ?? 0}</div>
          </div>
        </div>

        {/* Quick Links */}
        <div className="mb-8 grid grid-cols-2 gap-3 lg:grid-cols-4">
          {[
            { href: "/threat-intel", icon: Database, label: "Threat Intel", desc: "IOCs & Feeds" },
            { href: "/cve", icon: Bug, label: "CVE Lookup", desc: "NVD Database" },
            { href: "/history", icon: Clock, label: "Scan History", desc: "Past Results" },
            { href: "/reports", icon: FileText, label: "Reports", desc: "Generate Reports" },
          ].map((link) => (
            <Link key={link.href} href={link.href} className="group flex items-center gap-3 rounded-lg border border-border bg-card/30 p-3 transition-all hover:border-primary/40 hover:bg-primary/5">
              <link.icon className="h-5 w-5 text-muted-foreground group-hover:text-primary transition-colors" />
              <div>
                <div className="text-sm font-medium text-foreground">{link.label}</div>
                <div className="text-xs text-muted-foreground">{link.desc}</div>
              </div>
              <ChevronRight className="ml-auto h-4 w-4 text-muted-foreground group-hover:text-primary transition-colors" />
            </Link>
          ))}
        </div>

        {/* Threat Map */}
        <div className="mb-8 rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-lg font-semibold text-foreground">Live Threat Map</h2>
              <p className="text-xs text-muted-foreground">Real-time global cyber threat visualization (Radware)</p>
            </div>
          </div>
          <div className="relative w-full h-[350px] rounded-md overflow-hidden border border-border">
            <iframe src="https://livethreatmap.radware.com" className="w-full h-full border-none" title="Radware Live Threat Map" />
          </div>
        </div>

        {/* ── Scan Panel ── */}
        <div className="rounded-lg border border-primary/20 bg-card/50 backdrop-blur-sm">
          {/* Tab bar */}
          <div className="flex items-center gap-1 overflow-x-auto border-b border-border px-4 pt-4">
            {TABS.map(({ id, label, icon: Icon }) => (
              <button key={id} onClick={() => setActiveTab(id)}
                className={`flex items-center gap-1.5 whitespace-nowrap rounded-t-lg px-4 py-2 text-xs font-medium transition-colors ${activeTab === id ? "bg-primary/10 text-primary border-b-2 border-primary" : "text-muted-foreground hover:text-foreground"}`}>
                <Icon className="h-3.5 w-3.5" /> {label}
              </button>
            ))}
            <div className="ml-auto flex items-center gap-2 pb-1">
              <button onClick={() => setJsonView(!jsonView)} className={`rounded px-2 py-1 text-[10px] font-mono ${jsonView ? "bg-primary/20 text-primary" : "text-muted-foreground hover:text-foreground"}`}>
                {jsonView ? "JSON" : "UI"}
              </button>
            </div>
          </div>

          <div className="p-6">
            {/* ─── Domain Recon ─── */}
            {activeTab === "domain" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Domain Reconnaissance & URL Scanner</h2>
                  <p className="text-sm text-muted-foreground mt-1">Combined domain WHOIS, DNS, SSL, security features, and URL threat analysis.</p>
                </div>
                <form onSubmit={runDomainScan} className="flex gap-2">
                  <input value={domainInput} onChange={(e) => setDomainInput(e.target.value)} placeholder="example.com or https://example.com" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground placeholder:text-muted-foreground" />
                  <button type="submit" disabled={domainLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors">
                    {domainLoading ? "Scanning..." : "Scan"}
                  </button>
                  {(domainResults || urlResults) && <button type="button" onClick={() => { setDomainResults(null); setUrlResults(null); setDomainInput(""); }} className="rounded-lg border border-red-500/30 px-4 py-2.5 text-xs text-red-400 hover:bg-red-500/10">Clear</button>}
                </form>
                {domainLoading && <ScanProgress text="Running comprehensive domain analysis..." />}
                {jsonView && (domainResults || urlResults) && <JsonBlock data={{ domainResults, urlResults }} />}
                {!jsonView && domainResults && <DomainResultsView data={domainResults} urlData={urlResults} fetchFile={fetchFileContent} />}
              </div>
            )}

            {/* ─── IP Intel ─── */}
            {activeTab === "ip" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">IP Intelligence</h2>
                  <p className="text-sm text-muted-foreground mt-1">AbuseIPDB reputation, geolocation, VirusTotal analysis, and risk assessment.</p>
                </div>
                <form onSubmit={runIpScan} className="flex gap-2">
                  <input value={ipInput} onChange={(e) => setIpInput(e.target.value)} placeholder="8.8.8.8" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground" />
                  <button type="submit" disabled={ipLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {ipLoading ? "Scanning..." : "Check IP"}
                  </button>
                  {ipResults && <button type="button" onClick={() => { setIpResults(null); setIpInput(""); }} className="rounded-lg border border-red-500/30 px-4 py-2.5 text-xs text-red-400 hover:bg-red-500/10">Clear</button>}
                </form>
                {ipLoading && <ScanProgress text="Querying IP intelligence databases..." />}
                {jsonView && ipResults && <JsonBlock data={ipResults} />}
                {!jsonView && ipResults && <IpResultsView data={ipResults} />}
              </div>
            )}

            {/* ─── PCAP ─── */}
            {activeTab === "pcap" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Network Packet Analysis</h2>
                  <p className="text-sm text-muted-foreground mt-1">Upload PCAP files for protocol distribution, VirusTotal scanning, and threat detection.</p>
                </div>
                <form onSubmit={runPcapScan} className="flex items-center gap-2">
                  <input ref={fileRef} type="file" accept=".pcap,.pcapng" onChange={(e) => setSelectedFile(e.target.files?.[0] ?? null)} className="hidden" />
                  <button type="button" onClick={() => fileRef.current?.click()} className="flex items-center gap-2 rounded-lg border border-border px-4 py-2.5 text-sm text-muted-foreground hover:text-foreground">
                    <Upload className="h-4 w-4" /> {selectedFile ? selectedFile.name : "Choose PCAP file"}
                  </button>
                  <button type="submit" disabled={pcapLoading || !selectedFile} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {pcapLoading ? "Analyzing..." : "Analyze"}
                  </button>
                </form>
                {pcapLoading && <ScanProgress text="Processing network capture..." />}
                {jsonView && pcapResults && <JsonBlock data={pcapResults} />}
                {!jsonView && pcapResults && <PcapResultsView data={pcapResults} />}
              </div>
            )}

            {/* ─── Port Scan ─── */}
            {activeTab === "ports" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Port Scanner</h2>
                  <p className="text-sm text-muted-foreground mt-1">Scan open ports, identify services, and detect potential vulnerabilities.</p>
                </div>
                <form onSubmit={runPortScan} className="flex gap-2">
                  <input value={portTarget} onChange={(e) => setPortTarget(e.target.value)} placeholder="Target IP or domain" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground" />
                  <button type="submit" disabled={portLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {portLoading ? "Scanning..." : "Scan Ports"}
                  </button>
                </form>
                {portLoading && <ScanProgress text="Scanning ports (this may take a moment)..." />}
                {jsonView && portResults && <JsonBlock data={portResults} />}
                {!jsonView && portResults && <PortResultsView data={portResults} />}
              </div>
            )}

            {/* ─── Vuln Scan ─── */}
            {activeTab === "vuln" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Vulnerability Scanner</h2>
                  <p className="text-sm text-muted-foreground mt-1">Identify known vulnerabilities in running services with risk assessment.</p>
                </div>
                <form onSubmit={runVulnScan} className="flex gap-2">
                  <input value={vulnTarget} onChange={(e) => setVulnTarget(e.target.value)} placeholder="Target IP or domain" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground" />
                  <button type="submit" disabled={vulnLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {vulnLoading ? "Scanning..." : "Run Vuln Scan"}
                  </button>
                </form>
                {vulnLoading && <ScanProgress text="Running vulnerability assessment..." />}
                {jsonView && vulnResults && <JsonBlock data={vulnResults} />}
                {!jsonView && vulnResults && <VulnResultsView data={vulnResults} />}
              </div>
            )}

            {/* ─── Security Headers ─── */}
            {activeTab === "headers" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Security Headers Analysis</h2>
                  <p className="text-sm text-muted-foreground mt-1">Evaluate HTTP security headers (CSP, HSTS, X-Frame-Options, etc.).</p>
                </div>
                <form onSubmit={runHeaderScan} className="flex gap-2">
                  <input value={headerUrl} onChange={(e) => setHeaderUrl(e.target.value)} placeholder="https://example.com" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground" />
                  <button type="submit" disabled={headerLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {headerLoading ? "Analyzing..." : "Analyze Headers"}
                  </button>
                </form>
                {headerLoading && <ScanProgress text="Checking HTTP security headers..." />}
                {jsonView && headerResults && <JsonBlock data={headerResults} />}
                {!jsonView && headerResults && <HeaderResultsView data={headerResults} />}
              </div>
            )}

            {/* ─── Email Security ─── */}
            {activeTab === "email" && (
              <div className="space-y-6">
                <div>
                  <h2 className="text-xl font-semibold text-foreground">Email Security</h2>
                  <p className="text-sm text-muted-foreground mt-1">SPF, DMARC, and DKIM configuration analysis for email authentication.</p>
                </div>
                <form onSubmit={runEmailScan} className="flex gap-2">
                  <input value={emailDomain} onChange={(e) => setEmailDomain(e.target.value)} placeholder="example.com" required
                    className="flex-1 rounded-lg border border-border bg-background px-4 py-2.5 text-sm text-foreground" />
                  <button type="submit" disabled={emailLoading} className="rounded-lg bg-primary px-6 py-2.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50">
                    {emailLoading ? "Analyzing..." : "Check Email Security"}
                  </button>
                </form>
                {emailLoading && <ScanProgress text="Checking email security records..." />}
                {jsonView && emailResults && <JsonBlock data={emailResults} />}
                {!jsonView && emailResults && <EmailResultsView data={emailResults} />}
              </div>
            )}
          </div>
        </div>

        {/* ── Inline Scan History ── */}
        <div className="mt-8 rounded-lg border border-border bg-card/50 backdrop-blur-sm">
          <div className="flex items-center justify-between border-b border-border px-6 py-4">
            <div className="flex items-center gap-2">
              <Clock className="h-5 w-5 text-primary" />
              <h2 className="text-lg font-semibold text-foreground">Recent Scan History</h2>
              <span className="text-xs text-muted-foreground">({historyTotal} total)</span>
            </div>
            <div className="flex items-center gap-3">
              <button onClick={() => loadInlineHistory(historyPage)} className="flex items-center gap-1.5 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors">
                <RefreshCw className="h-3.5 w-3.5" /> Refresh
              </button>
              <Link href="/history" className="flex items-center gap-1.5 text-xs text-primary hover:text-primary/80 transition-colors">
                View All <ChevronRight className="h-3.5 w-3.5" />
              </Link>
            </div>
          </div>

          <div className="overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-card/80 border-b border-border">
                <tr>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Target</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Type</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Risk Score</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Status</th>
                  <th className="px-6 py-3 text-left font-medium text-muted-foreground">Timestamp</th>
                  <th className="px-6 py-3 text-right font-medium text-muted-foreground">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {historyLoading && (
                  <tr><td colSpan={6} className="px-6 py-10 text-center text-muted-foreground text-sm">Loading...</td></tr>
                )}
                {!historyLoading && historyScans.length === 0 && (
                  <tr><td colSpan={6} className="px-6 py-10 text-center text-muted-foreground text-sm">No scans yet. Run a scan above to see results here.</td></tr>
                )}
                {historyScans.map((scan) => {
                  const SCAN_TYPE_COLORS: Record<string, string> = {
                    domain: "text-blue-400 bg-blue-400/10 border-blue-400/30",
                    ip: "text-purple-400 bg-purple-400/10 border-purple-400/30",
                    url: "text-green-400 bg-green-400/10 border-green-400/30",
                    port_scan: "text-orange-400 bg-orange-400/10 border-orange-400/30",
                    vuln_scan: "text-red-400 bg-red-400/10 border-red-400/30",
                    pcap: "text-cyan-400 bg-cyan-400/10 border-cyan-400/30",
                    ssl: "text-yellow-400 bg-yellow-400/10 border-yellow-400/30",
                    headers: "text-pink-400 bg-pink-400/10 border-pink-400/30",
                    email: "text-indigo-400 bg-indigo-400/10 border-indigo-400/30",
                  };
                  const typeColor = SCAN_TYPE_COLORS[scan.scan_type] || SCAN_TYPE_COLORS.domain;
                  const scoreNum = scan.risk_score;
                  const riskCls = !scoreNum ? "text-gray-400 bg-gray-400/10 border-gray-400/30"
                    : scoreNum >= 80 ? "text-red-500 bg-red-500/10 border-red-500/30"
                    : scoreNum >= 60 ? "text-orange-500 bg-orange-500/10 border-orange-500/30"
                    : scoreNum >= 40 ? "text-yellow-500 bg-yellow-500/10 border-yellow-500/30"
                    : "text-green-400 bg-green-400/10 border-green-400/30";
                  const riskText = !scoreNum ? "N/A" : scoreNum >= 80 ? `${scoreNum} Critical` : scoreNum >= 60 ? `${scoreNum} High` : scoreNum >= 40 ? `${scoreNum} Medium` : `${scoreNum} Low`;
                  return (
                    <tr key={scan.id} className="hover:bg-card/50 transition-colors">
                      <td className="px-6 py-3 font-mono text-foreground text-sm">{scan.target}</td>
                      <td className="px-6 py-3">
                        <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${typeColor}`}>
                          {scan.scan_type.replace("_", " ")}
                        </span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-bold border ${riskCls}`}>{riskText}</span>
                      </td>
                      <td className="px-6 py-3">
                        <span className={`text-xs ${
                          scan.status === "completed" ? "text-green-400" :
                          scan.status === "error" ? "text-red-400" : "text-yellow-400"
                        }`}>{scan.status}</span>
                      </td>
                      <td className="px-6 py-3 text-xs text-muted-foreground">{new Date(scan.created_at || scan.timestamp || "").toLocaleString()}</td>
                      <td className="px-6 py-3 text-right">
                        <button onClick={() => setHistorySelected(historySelected?.id === scan.id ? null : scan)}
                          className="text-primary/70 hover:text-primary transition-colors">
                          <Eye className="h-4 w-4" />
                        </button>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between border-t border-border px-6 py-3">
            <span className="text-xs text-muted-foreground">Page {historyPage} of {Math.ceil(historyTotal / HISTORY_PER_PAGE) || 1}</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setHistoryPage(p => Math.max(1, p - 1))} disabled={historyPage === 1}
                className="flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
                <ChevronLeft className="h-3.5 w-3.5" /> Prev
              </button>
              <button onClick={() => setHistoryPage(p => Math.min(Math.ceil(historyTotal / HISTORY_PER_PAGE) || 1, p + 1))}
                disabled={historyPage >= (Math.ceil(historyTotal / HISTORY_PER_PAGE) || 1)}
                className="flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
                Next <ChevronRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </div>

          {/* Detail Drawer */}
          {historySelected && (
            <div className="border-t border-primary/20 bg-card/30 p-6">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-base font-semibold text-foreground">Scan Details — {historySelected.target}</h3>
                <button onClick={() => setHistorySelected(null)} className="text-xs text-muted-foreground hover:text-foreground transition-colors">Close</button>
              </div>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                <div><span className="text-xs text-muted-foreground block">Scan Type</span><span className="text-sm text-foreground">{historySelected.scan_type}</span></div>
                <div><span className="text-xs text-muted-foreground block">Status</span><span className="text-sm text-foreground">{historySelected.status}</span></div>
                <div><span className="text-xs text-muted-foreground block">Risk Score</span><span className="text-sm text-foreground">{historySelected.risk_score || "N/A"}</span></div>
                <div><span className="text-xs text-muted-foreground block">Duration</span><span className="text-sm text-foreground">{historySelected.scan_duration_ms ? `${historySelected.scan_duration_ms}ms` : "N/A"}</span></div>
              </div>
              {historySelected.result_summary != null && (
                <div>
                  <span className="text-xs text-muted-foreground block mb-1">Result Summary</span>
                  <pre className="rounded-lg bg-background border border-border p-4 text-xs text-muted-foreground overflow-auto max-h-80 font-mono">
                    {typeof historySelected.result_summary === "string" ? historySelected.result_summary : JSON.stringify(historySelected.result_summary as Record<string, unknown>, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </main>

      {/* Chat FAB */}
      <button onClick={() => setChatOpen(!chatOpen)} className="fixed bottom-6 right-6 z-50 flex h-14 w-14 items-center justify-center rounded-full bg-primary text-primary-foreground shadow-lg shadow-primary/25 hover:bg-primary/90 transition-colors">
        {chatOpen ? <X className="h-6 w-6" /> : <MessageSquare className="h-6 w-6" />}
      </button>

      {/* Chat Panel */}
      {chatOpen && (
        <div className="fixed bottom-24 right-6 z-50 w-96 rounded-lg border border-primary/20 bg-card shadow-2xl shadow-primary/10 overflow-hidden">
          <div className="flex items-center justify-between border-b border-border px-4 py-3">
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm font-semibold text-foreground">CyberRegis AI</span>
            </div>
            <button onClick={() => setChatOpen(false)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
          </div>
          <div ref={chatRef} className="h-80 overflow-y-auto p-4 space-y-3">
            {chatMessages.map((m, i) => (
              <div key={`chat-${i}-${m.text.substring(0, 20)}`} className={`flex ${m.isUser ? "justify-end" : "justify-start"}`}>
                <div className={`max-w-[80%] rounded-lg px-3 py-2 text-sm ${m.isUser ? "bg-primary text-primary-foreground" : "bg-muted text-foreground"}`}>
                  {m.isUser ? m.text : <div className="prose prose-sm prose-invert max-w-none [&>p]:m-0"><ReactMarkdown remarkPlugins={[remarkGfm]}>{m.text}</ReactMarkdown></div>}
                  {m.ts && <div className="mt-1 text-[10px] opacity-60">{m.ts}</div>}
                </div>
              </div>
            ))}
            {chatLoading && <div className="flex justify-start"><div className="rounded-lg bg-muted px-3 py-2 text-sm text-muted-foreground animate-pulse">Thinking...</div></div>}
          </div>
          <form onSubmit={sendChat} className="border-t border-border p-3 flex gap-2">
            <input value={chatInput} onChange={(e) => setChatInput(e.target.value)} placeholder="Ask about cybersecurity..." className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground" />
            <button type="submit" disabled={chatLoading} className="rounded-lg bg-primary px-3 py-2 text-sm text-primary-foreground hover:bg-primary/90 disabled:opacity-50"><Zap className="h-4 w-4" /></button>
          </form>
        </div>
      )}

      {/* File Content Modal */}
      {fileModal && (
        <div className="fixed inset-0 z-[60] flex items-center justify-center bg-black/60 backdrop-blur-sm" onClick={() => setFileModal(null)}>
          <div className="mx-4 max-h-[80vh] w-full max-w-2xl rounded-lg border border-primary/20 bg-card overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between border-b border-border px-4 py-3">
              <span className="text-sm font-semibold text-foreground">{fileModal.title}</span>
              <button onClick={() => setFileModal(null)} className="text-muted-foreground hover:text-foreground"><X className="h-4 w-4" /></button>
            </div>
            <pre className="overflow-auto p-4 text-xs font-mono text-muted-foreground max-h-[60vh]">{fileModal.content}</pre>
          </div>
        </div>
      )}
    </div>
  );
}

/* ────────────────────────────────────────── */
/*             SUB-COMPONENTS                 */
/* ────────────────────────────────────────── */

function ScanProgress({ text }: { text: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-primary/20 bg-primary/5 px-4 py-3">
      <div className="h-4 w-4 animate-spin rounded-full border-2 border-primary border-t-transparent" />
      <span className="text-sm text-muted-foreground">{text}</span>
    </div>
  );
}

function JsonBlock({ data }: { data: any }) {
  return (
    <div className="rounded-lg border border-border bg-background overflow-auto max-h-[600px]">
      <pre className="p-4 text-xs font-mono text-green-400 whitespace-pre-wrap">{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}

function SectionCard({ title, children, icon: Icon }: { title: string; children: React.ReactNode; icon?: any }) {
  return (
    <div className="rounded-lg border border-border bg-card/30 p-4">
      <h4 className="flex items-center gap-2 text-sm font-semibold text-foreground mb-3">
        {Icon && <Icon className="h-4 w-4 text-primary" />} {title}
      </h4>
      {children}
    </div>
  );
}

function KV({ label, value, mono }: { label: string; value: any; mono?: boolean }) {
  if (value === undefined || value === null || value === "") return null;
  return (
    <div className="flex items-start justify-between gap-4 py-1 text-sm">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={`text-foreground text-right ${mono ? "font-mono text-xs" : ""}`}>{String(value)}</span>
    </div>
  );
}

function StatusBadge({ ok, labelTrue = "Yes", labelFalse = "No" }: { ok: boolean | undefined; labelTrue?: string; labelFalse?: string }) {
  if (ok === undefined) return <span className="text-xs text-muted-foreground">N/A</span>;
  return (
    <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${ok ? "text-green-400 border-green-400/30 bg-green-400/10" : "text-red-400 border-red-400/30 bg-red-400/10"}`}>
      {ok ? <CheckCircle className="h-3 w-3 mr-1" /> : <AlertTriangle className="h-3 w-3 mr-1" />}
      {ok ? labelTrue : labelFalse}
    </span>
  );
}

/* ─── Domain results ─── */

function DomainResultsView({ data, urlData, fetchFile }: { data: any; urlData: any; fetchFile: (d: string, t: "robots" | "security") => void }) {
  const d = data?.data || data;
  const info = d?.domain_info;
  const risk = d?.risk_score || data?.risk_score;
  const recs = d?.recommendations || data?.recommendations || [];
  const u = urlData?.data || urlData;

  return (
    <div className="space-y-4">
      {/* Risk score banner */}
      {risk && (
        <div className={`rounded-lg border p-4 flex items-center justify-between ${risk.level === "critical" || risk.level === "high" ? "border-red-500/30 bg-red-500/5" : risk.level === "medium" ? "border-yellow-500/30 bg-yellow-500/5" : "border-green-500/30 bg-green-500/5"}`}>
          <div>
            <div className="text-sm font-medium text-muted-foreground">Domain Risk Assessment</div>
            <div className={`text-2xl font-bold ${risk.level === "critical" || risk.level === "high" ? "text-red-500" : risk.level === "medium" ? "text-yellow-500" : "text-green-400"}`}>
              {risk.score}/100 — {risk.level?.toUpperCase()}
            </div>
          </div>
          {u?.threat_analysis && (
            <div className="text-right">
              <div className="text-xs text-muted-foreground">URL Threat</div>
              <StatusBadge ok={!u.threat_analysis.is_malicious} labelTrue="Safe" labelFalse="Malicious" />
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* WHOIS */}
        {info?.whois && (
          <SectionCard title="WHOIS" icon={Globe}>
            <KV label="Registrar" value={info.whois.registrar} />
            <KV label="Created" value={info.whois.creation_date} />
            <KV label="Expires" value={info.whois.expiration_date} />
            <KV label="Registrant" value={info.whois.registrant} />
            <KV label="Country" value={info.whois.country} />
            {info.whois.name_servers?.length > 0 && <KV label="Name Servers" value={info.whois.name_servers.join(", ")} mono />}
          </SectionCard>
        )}

        {/* DNS */}
        {info?.dns_records && (
          <SectionCard title="DNS Records" icon={Network}>
            {Object.entries(info.dns_records).filter(([, v]) => (v as string[])?.length > 0).map(([type, records]) => (
              <KV key={type} label={type} value={(records as string[]).join(", ")} mono />
            ))}
          </SectionCard>
        )}

        {/* SSL */}
        {info?.ssl_info && (
          <SectionCard title="SSL/TLS Certificate" icon={Lock}>
            <KV label="Valid" value={info.ssl_info.valid ? "Yes" : "No"} />
            <KV label="Issuer" value={info.ssl_info.issuer} />
            <KV label="Subject" value={info.ssl_info.subject} />
            <KV label="Valid From" value={info.ssl_info.valid_from} />
            <KV label="Valid Until" value={info.ssl_info.valid_until} />
            <KV label="Days to Expiry" value={info.ssl_info.days_until_expiry} />
          </SectionCard>
        )}

        {/* Security Features */}
        {info?.security_features && (
          <SectionCard title="Security Features" icon={Shield}>
            <div className="space-y-2">
              <div className="flex items-center justify-between"><span className="text-sm text-muted-foreground">DNSSEC</span><StatusBadge ok={info.security_features.dnssec} labelTrue="Enabled" labelFalse="Disabled" /></div>
              <div className="flex items-center justify-between"><span className="text-sm text-muted-foreground">DMARC</span><StatusBadge ok={!!info.security_features.dmarc} labelTrue="Present" labelFalse="Missing" /></div>
              <div className="flex items-center justify-between"><span className="text-sm text-muted-foreground">SPF</span><StatusBadge ok={!!info.security_features.spf} labelTrue="Present" labelFalse="Missing" /></div>
              {info.security_features.robots_txt && (
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">robots.txt</span>
                  <div className="flex items-center gap-2">
                    <StatusBadge ok={info.security_features.robots_txt.present} labelTrue="Present" labelFalse="Not Found" />
                    {info.security_features.robots_txt.present && <button onClick={() => fetchFile(info.domain, "robots")} className="text-xs text-primary hover:underline">View</button>}
                  </div>
                </div>
              )}
              {info.security_features.security_txt && (
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">security.txt</span>
                  <div className="flex items-center gap-2">
                    <StatusBadge ok={info.security_features.security_txt.present} labelTrue="Present" labelFalse="Not Found" />
                    {info.security_features.security_txt.present && <button onClick={() => fetchFile(info.domain, "security")} className="text-xs text-primary hover:underline">View</button>}
                  </div>
                </div>
              )}
            </div>
          </SectionCard>
        )}

        {/* Geolocation */}
        {info?.geolocation && (
          <SectionCard title="Geolocation" icon={Globe}>
            <KV label="IP" value={info.geolocation.ip} mono />
            <KV label="Country" value={info.geolocation.country} />
            <KV label="City" value={info.geolocation.city} />
            <KV label="ISP" value={info.geolocation.isp} />
            <KV label="Organization" value={info.geolocation.organization} />
          </SectionCard>
        )}

        {/* Subdomains */}
        {info?.subdomains?.length > 0 && (
          <SectionCard title={`Subdomains (${info.subdomains.length})`} icon={Globe}>
            <div className="flex flex-wrap gap-1">
              {info.subdomains.map((s: string) => <span key={s} className="rounded-full border border-border px-2 py-0.5 text-xs font-mono text-muted-foreground">{s}</span>)}
            </div>
          </SectionCard>
        )}
      </div>

      {/* Recommendations */}
      {recs.length > 0 && (
        <SectionCard title="Recommendations">
          <ul className="space-y-1">
            {recs.map((r: any, i: number) => {
              const text = typeof r === "string" ? r : r?.text || JSON.stringify(r);
              const severity = typeof r === "object" ? r?.severity : undefined;
              const mitre = typeof r === "object" ? r?.mitre : undefined;
              const category = typeof r === "object" ? r?.category : undefined;
              return (
                <li key={`rec-${i}-${text.substring(0, 20)}`} className="rounded-lg border border-border/50 p-3 space-y-1">
                  <div className="flex items-start gap-2">
                    <span className="text-primary font-bold text-sm shrink-0">{i + 1}.</span>
                    <span className="text-sm text-foreground">{text}</span>
                  </div>
                  {(severity || category || mitre) && (
                    <div className="flex items-center gap-2 ml-5 flex-wrap">
                      {category && <span className="text-xs text-muted-foreground">{category}</span>}
                      {severity && <span className={`rounded-full px-2 py-0.5 text-xs font-medium border ${
                        severity === "high" || severity === "critical" ? "text-red-400 border-red-400/30 bg-red-400/10" :
                        severity === "medium" ? "text-yellow-400 border-yellow-400/30 bg-yellow-400/10" :
                        "text-blue-400 border-blue-400/30 bg-blue-400/10"}`}>{severity}</span>}
                      {mitre && <span className="rounded-full bg-primary/10 border border-primary/30 px-2 py-0.5 text-xs text-primary font-mono">{mitre}</span>}
                    </div>
                  )}
                </li>
              );
            })}
          </ul>
        </SectionCard>
      )}
    </div>
  );
}

/* ─── IP results ─── */

function IpResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  const ip = d?.ip_details || data?.ip_details;
  const risk = d?.risk_assessment || data?.risk_assessment;
  const tech = d?.technical_details || data?.technical_details;
  const vt = d?.virustotal;
  const recs = d?.recommendations || data?.recommendations || [];

  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;

  return (
    <div className="space-y-4">
      {/* Risk banner */}
      {risk && (
        <div className={`rounded-lg border p-4 ${risk.risk_level === "high" ? "border-red-500/30 bg-red-500/5" : risk.risk_level === "medium" ? "border-yellow-500/30 bg-yellow-500/5" : "border-green-500/30 bg-green-500/5"}`}>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-muted-foreground">AbuseIPDB Risk Level</div>
              <div className={`text-xl font-bold ${risk.risk_level === "high" ? "text-red-500" : risk.risk_level === "medium" ? "text-yellow-500" : "text-green-400"}`}>
                {risk.risk_level?.toUpperCase()} — Confidence Score: {risk.confidence_score}%
              </div>
            </div>
            <div className="text-right text-sm text-muted-foreground">
              <div>Reports: {risk.total_reports}</div>
              {risk.last_reported && <div>Last: {risk.last_reported}</div>}
            </div>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {ip && (
          <SectionCard title="IP Details" icon={Network}>
            <KV label="Address" value={ip.address} mono />
            <KV label="Domain" value={ip.domain} />
            <KV label="ISP" value={ip.isp} />
            {ip.location && <>
              <KV label="Country" value={ip.location.country} />
              <KV label="City" value={ip.location.city} />
            </>}
          </SectionCard>
        )}

        {tech && (
          <SectionCard title="Technical" icon={Server}>
            <KV label="ASN" value={tech.asn} mono />
            <KV label="AS Name" value={tech.as_name} />
            <KV label="Usage" value={tech.usage_type} />
            <div className="flex items-center justify-between py-1"><span className="text-sm text-muted-foreground">Public IP</span><StatusBadge ok={tech.is_public} /></div>
            <div className="flex items-center justify-between py-1"><span className="text-sm text-muted-foreground">TOR Node</span><StatusBadge ok={tech.is_tor} labelTrue="Yes" labelFalse="No" /></div>
          </SectionCard>
        )}

        {vt?.risk_assessment && (
          <SectionCard title="VirusTotal Analysis" icon={Shield}>
            <KV label="Risk Score" value={`${vt.risk_assessment.risk_score}/100`} />
            <KV label="Risk Level" value={vt.risk_assessment.risk_level} />
            <KV label="Malicious" value={vt.risk_assessment.malicious_count} />
            <KV label="Suspicious" value={vt.risk_assessment.suspicious_count} />
            <KV label="Detection Ratio" value={vt.risk_assessment.detection_ratio} />
          </SectionCard>
        )}
      </div>

      {recs.length > 0 && (
        <SectionCard title="Recommendations">
          <ul className="space-y-1">{recs.map((r: any, i: number) => {
            const text = typeof r === "string" ? r : r?.text || JSON.stringify(r);
            return <li key={`rec2-${i}-${text.substring(0, 20)}`} className="text-sm text-muted-foreground flex gap-2"><span className="text-primary font-bold">{i + 1}.</span>{text}</li>;
          })}</ul>
        </SectionCard>
      )}
    </div>
  );
}

/* ─── PCAP results ─── */

function PcapResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;

  return (
    <div className="space-y-4">
      {d?.metadata && (
        <SectionCard title="File Info">
          {Object.entries(d.metadata).map(([k, v]) => <KV key={k} label={k} value={v} />)}
        </SectionCard>
      )}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {d?.pcap_analysis && (
          <SectionCard title="Protocol Distribution" icon={Wifi}>
            {Object.entries(d.pcap_analysis).map(([p, c]) => <KV key={p} label={p} value={c} />)}
          </SectionCard>
        )}
        {d?.virustotal?.risk_assessment && (
          <SectionCard title="VirusTotal" icon={Shield}>
            <KV label="Risk Score" value={`${d.virustotal.risk_assessment.risk_score}/100`} />
            <KV label="Risk Level" value={d.virustotal.risk_assessment.risk_level} />
            <KV label="Malicious" value={d.virustotal.risk_assessment.malicious_count} />
            <KV label="Detection Ratio" value={d.virustotal.risk_assessment.detection_ratio} />
          </SectionCard>
        )}
      </div>
      {d?.chart_base64 && (
        <SectionCard title="Protocol Chart">
          <img src={`data:image/png;base64,${d.chart_base64}`} alt="Protocol Chart" className="max-w-full rounded-lg" />
        </SectionCard>
      )}
      {d?.suspicious_ips?.length > 0 && (
        <SectionCard title="Suspicious IPs" icon={AlertTriangle}>
          <div className="flex flex-wrap gap-1">{d.suspicious_ips.map((ip: string) => <span key={ip} className="rounded-full border border-red-500/30 bg-red-500/10 px-2 py-0.5 text-xs font-mono text-red-400">{ip}</span>)}</div>
        </SectionCard>
      )}
      {d?.potential_threats?.length > 0 && (
        <SectionCard title="Potential Threats" icon={AlertTriangle}>
          {d.potential_threats.map((t: any, i: number) => (
            <div key={`threat-${i}-${t.type}-${t.severity}`} className="flex items-center justify-between py-1 text-sm">
              <span className="text-foreground">{t.type}</span>
              <span className={`text-xs ${t.severity === "high" ? "text-red-400" : t.severity === "medium" ? "text-yellow-400" : "text-blue-400"}`}>{t.severity}</span>
            </div>
          ))}
        </SectionCard>
      )}
    </div>
  );
}

/* ─── Port results ─── */

function PortResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  const ports = d?.ports || data?.ports || [];
  const host = d?.host_info || data?.host_info;
  const highRiskPortsRaw = d?.risk_summary?.high_risk_ports;
  const highRiskPorts = Array.isArray(highRiskPortsRaw)
    ? highRiskPortsRaw
    : highRiskPortsRaw !== undefined && highRiskPortsRaw !== null && highRiskPortsRaw !== ""
      ? [highRiskPortsRaw]
      : [];
  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;

  return (
    <div className="space-y-4">
      {host && (
        <SectionCard title="Host Info" icon={Server}>
          <KV label="Hostname" value={host.hostname} />
          <KV label="State" value={host.state} />
          <KV label="Protocols" value={host.protocols?.join(", ")} />
        </SectionCard>
      )}
      {ports.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-card/80 border-b border-border">
              <tr>
                <th className="px-4 py-2 text-left text-muted-foreground text-xs font-medium">Port</th>
                <th className="px-4 py-2 text-left text-muted-foreground text-xs font-medium">Protocol</th>
                <th className="px-4 py-2 text-left text-muted-foreground text-xs font-medium">State</th>
                <th className="px-4 py-2 text-left text-muted-foreground text-xs font-medium">Service</th>
                <th className="px-4 py-2 text-left text-muted-foreground text-xs font-medium">Version</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {ports.map((p: any, i: number) => (
                <tr key={`port-${i}-${p.port}-${p.protocol}`} className="hover:bg-card/50">
                  <td className="px-4 py-2 font-mono text-primary">{p.port}</td>
                  <td className="px-4 py-2 text-muted-foreground">{p.protocol}</td>
                  <td className="px-4 py-2"><span className={`text-xs ${p.state === "open" ? "text-green-400" : "text-red-400"}`}>{p.state}</span></td>
                  <td className="px-4 py-2 text-foreground">{p.service || "—"}</td>
                  <td className="px-4 py-2 text-muted-foreground text-xs">{p.version || p.product || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {d?.risk_summary && (
        <SectionCard title="Risk Summary" icon={AlertTriangle}>
          <KV label="Open Ports" value={d.risk_summary.open_ports} />
          <KV label="High Risk Ports" value={highRiskPorts.length > 0 ? highRiskPorts.join(", ") : "None"} />
        </SectionCard>
      )}
    </div>
  );
}

/* ─── Vuln results ─── */

function VulnResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  const vulns = d?.vulnerabilities || data?.vulnerabilities || [];
  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;

  return (
    <div className="space-y-4">
      {d?.risk_summary && (
        <div className={`rounded-lg border p-4 ${(d.risk_summary.high_severity || 0) > 0 ? "border-red-500/30 bg-red-500/5" : "border-green-500/30 bg-green-500/5"}`}>
          <div className="flex items-center justify-between">
            <div>
              <div className="text-sm text-muted-foreground">Vulnerability Assessment</div>
              <div className="text-lg font-bold text-foreground">{vulns.length} items found</div>
            </div>
            <div className="flex gap-4 text-sm">
              <span className="text-red-400">High: {d.risk_summary.high_severity || 0}</span>
              <span className="text-yellow-400">Medium: {d.risk_summary.medium_severity || 0}</span>
              <span className="text-blue-400">Low: {d.risk_summary.low_severity || 0}</span>
            </div>
          </div>
        </div>
      )}
      {vulns.map((v: any, i: number) => (
        <div key={`vuln-${i}-${v.service}-${v.port}`} className="rounded-lg border border-border p-4">
          <div className="flex items-center justify-between mb-2">
            <span className="text-sm font-medium text-foreground">{v.service} {v.port ? `(port ${v.port})` : ""}</span>
            <span className={`rounded-full px-2 py-0.5 text-xs font-medium border ${v.severity === "high" ? "text-red-400 border-red-400/30 bg-red-400/10" : v.severity === "medium" ? "text-yellow-400 border-yellow-400/30 bg-yellow-400/10" : "text-blue-400 border-blue-400/30 bg-blue-400/10"}`}>{v.severity}</span>
          </div>
          {v.version && <div className="text-xs text-muted-foreground mb-1">Version: {v.version}</div>}
          {v.potential_issues?.length > 0 && (
            <ul className="mt-2 space-y-1">{v.potential_issues.map((issue: string, j: number) => <li key={`issue-${i}-${j}-${issue.substring(0, 20)}`} className="text-xs text-muted-foreground flex gap-1"><AlertTriangle className="h-3 w-3 text-yellow-400 shrink-0 mt-0.5" />{issue}</li>)}</ul>
          )}
          {v.recommendation && <div className="mt-2 text-xs text-primary">{v.recommendation}</div>}
        </div>
      ))}
    </div>
  );
}

/* ─── Header results ─── */

function HeaderResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  const headers = d?.headers || data?.headers;
  const score = d?.security_score ?? data?.security_score;
  const maxScore = d?.max_score ?? data?.max_score;
  const grade = d?.grade || data?.grade;
  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;

  return (
    <div className="space-y-4">
      {score !== undefined && (
        <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 flex items-center justify-between">
          <div>
            <div className="text-sm text-muted-foreground">Security Score</div>
            <div className="text-2xl font-bold text-primary">{score}/{maxScore}</div>
          </div>
          {grade && (
            <div className={`text-4xl font-black ${grade === "A" || grade === "A+" ? "text-green-400" : grade === "B" ? "text-yellow-400" : grade === "C" ? "text-orange-400" : "text-red-400"}`}>
              {grade}
            </div>
          )}
        </div>
      )}
      {headers && Object.entries(headers).map(([name, info]: [string, any]) => (
        <div key={name} className="flex items-center justify-between rounded-lg border border-border p-3">
          <div>
            <span className="text-sm font-medium text-foreground">{name}</span>
            {info.value && <span className="ml-2 text-xs font-mono text-muted-foreground truncate max-w-xs">{info.value.substring(0, 80)}</span>}
          </div>
          <div className="flex items-center gap-2">
            {info.score !== undefined && <span className="text-xs text-muted-foreground">{info.score} pts</span>}
            <StatusBadge ok={info.present} labelTrue="Present" labelFalse="Missing" />
          </div>
        </div>
      ))}
    </div>
  );
}

/* ─── Email results ─── */

function EmailResultsView({ data }: { data: any }) {
  const d = data?.data || data;
  const email = d?.email_security || data?.email_security;
  if (data?.status === "error") return <div className="text-sm text-red-400">{data.message}</div>;
  if (!email) return <div className="text-sm text-muted-foreground">No email security data returned.</div>;

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-primary/20 bg-primary/5 p-4 flex items-center justify-between">
        <div>
          <div className="text-sm text-muted-foreground">Email Security Score</div>
          <div className="text-2xl font-bold text-primary">{email.total_score}/{email.max_score}</div>
        </div>
        {email.grade && (
          <div className={`text-4xl font-black ${email.grade === "A" || email.grade === "A+" ? "text-green-400" : email.grade === "B" ? "text-yellow-400" : "text-red-400"}`}>
            {email.grade}
          </div>
        )}
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {["spf", "dmarc", "dkim"].map((type) => {
          const rec = email[type];
          if (!rec) return null;
          return (
            <SectionCard key={type} title={type.toUpperCase()} icon={Mail}>
              <div className="flex items-center justify-between mb-2"><span className="text-sm text-muted-foreground">Status</span><StatusBadge ok={rec.present} labelTrue="Present" labelFalse="Missing" /></div>
              <KV label="Score" value={rec.score} />
              {rec.record && <div className="mt-2 text-xs font-mono text-muted-foreground break-all bg-background/50 rounded p-2">{rec.record}</div>}
            </SectionCard>
          );
        })}
      </div>
    </div>
  );
}
