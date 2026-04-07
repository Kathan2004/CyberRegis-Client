"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import { Shield, RefreshCw, Search, Plus, Trash2, AlertTriangle, Globe, Hash, Mail, ExternalLink, Database, Activity, TrendingUp, Clock, Zap, Pause } from "lucide-react";
import Link from "next/link";
import * as api from "@/app/lib/api";
import type { IOC, IOCStats, ThreatFeedEntry, CVE, ThreatFeedInsights, LookupLink, MitreTactic } from "@/app/types";

const PAGE_SIZE = 25;
const FEED_FILTERS = ["", "openphish", "feodotracker", "emergingthreats", "ipsum", "cinsscore", "neo23x0_hashes", "threatfox", "urlhaus", "malwarebazaar", "otx"];

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  low: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  info: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};

const IOC_TYPE_ICONS: Record<string, typeof Globe> = {
  ip: Globe, domain: Globe, url: ExternalLink, hash: Hash, email: Mail,
};

interface ActivityLog {
  id: string;
  type: "ioc_added" | "feed_refreshed" | "cve_found";
  title: string;
  description: string;
  timestamp: Date;
  severity?: string;
}

export default function ThreatIntelPage() {
  const [activeTab, setActiveTab] = useState<"iocs" | "feeds" | "search" | "dashboard">("dashboard");
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [iocStats, setIocStats] = useState<IOCStats | null>(null);
  const [feedEntries, setFeedEntries] = useState<ThreatFeedEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [feedsLoading, setFeedsLoading] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const [searchResults, setSearchResults] = useState<ThreatFeedEntry[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);
  const [feedConnectorStatus, setFeedConnectorStatus] = useState<Record<string, { status: string; count?: number; ioc_ingested?: number; error?: string }>>({});
  const [iocTotal, setIocTotal] = useState(0);
  const [feedTotal, setFeedTotal] = useState(0);
  const [iocPage, setIocPage] = useState(1);
  const [feedsPage, setFeedsPage] = useState(1);
  const [searchPage, setSearchPage] = useState(1);
  const [feedFilter, setFeedFilter] = useState("");
  
  // Auto-refresh
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(30); // 30 seconds
  const [lastRefresh, setLastRefresh] = useState<Date | null>(null);
  const autoRefreshIntervalRef = useRef<NodeJS.Timeout | null>(null);

  // CVE Trends
  const [cves, setCves] = useState<CVE[]>([]);
  const [cveLoading, setCveLoading] = useState(false);

  // Activity Log
  const [activityLog, setActivityLog] = useState<ActivityLog[]>([]);
  const [intelCatalog, setIntelCatalog] = useState<any>(null);
  const [feedInsights, setFeedInsights] = useState<ThreatFeedInsights | null>(null);
  const [mitreTactics, setMitreTactics] = useState<MitreTactic[]>([]);

  // IOC form
  const [showAddForm, setShowAddForm] = useState(false);
  const [newIoc, setNewIoc] = useState({ ioc_type: "ip", value: "", threat_type: "malware", severity: "medium", description: "" });

  // Filters
  const [filterType, setFilterType] = useState("");
  const [filterSeverity, setFilterSeverity] = useState("");
  const paginatedSearchResults = searchResults.slice((searchPage - 1) * PAGE_SIZE, searchPage * PAGE_SIZE);

  const addActivityLog = useCallback((activity: Omit<ActivityLog, "id">) => {
    const newActivity: ActivityLog = { ...activity, id: `${Date.now()}-${Math.random()}` };
    setActivityLog((prev) => [newActivity, ...prev.slice(0, 9)]);
  }, []);

  const loadIOCs = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = {};
      if (filterType) params.type = filterType;
      if (filterSeverity) params.severity = filterSeverity;
      params.limit = PAGE_SIZE;
      params.offset = (iocPage - 1) * PAGE_SIZE;
      const res = await api.getIOCs(params);
      setIocs(res.data?.iocs || []);
      setIocStats(res.data?.stats || null);
      setIocTotal(res.meta?.total || res.data?.stats?.total || 0);
    } catch (e) { console.error("Failed to load IOCs:", e); }
    setLoading(false);
  }, [filterType, filterSeverity, iocPage]);

  const loadFeeds = useCallback(async () => {
    setFeedsLoading(true);
    try {
      const res = await api.getThreatFeeds(feedFilter || undefined, PAGE_SIZE, (feedsPage - 1) * PAGE_SIZE);
      setFeedEntries(res.data?.entries || []);
      setFeedTotal(res.meta?.total || res.data?.total || 0);
    } catch (e) { console.error("Failed to load feeds:", e); }
    setFeedsLoading(false);
  }, [feedFilter, feedsPage]);

  const loadCVETrends = useCallback(async () => {
    setCveLoading(true);
    try {
      const res = await api.searchCVEs("latest", 100);
      const cveList = res.data?.cves || res.data?.results || [];
      setCves(cveList.slice(0, 5));
    } catch (e) { console.error("Failed to load CVEs:", e); }
    setCveLoading(false);
  }, []);

  const loadIntelCatalog = useCallback(async () => {
    try {
      const res = await api.getIntelCatalog(20);
      setIntelCatalog(res.data || null);
    } catch (e) {
      console.error("Failed to load intel catalog:", e);
    }
  }, []);

  const loadFeedInsights = useCallback(async () => {
    try {
      const res = await api.getThreatFeedInsights();
      setFeedInsights((res.data as ThreatFeedInsights) || null);
    } catch (e) {
      console.error("Failed to load threat feed insights:", e);
    }
  }, []);

  const loadMitreTactics = useCallback(async () => {
    try {
      const res = await api.getMitreTactics();
      setMitreTactics(res.data?.tactics || []);
    } catch (e) {
      console.error("Failed to load MITRE tactics:", e);
    }
  }, []);

  const renderLookupLinks = useCallback((links?: LookupLink[], fallback?: string | null) => {
    const resolvedLinks = links?.length ? links : fallback ? [{ label: "Open", url: fallback }] : [];
    if (!resolvedLinks.length) {
      return <span className="text-muted-foreground">—</span>;
    }

    return (
      <div className="flex flex-wrap gap-1.5">
        {resolvedLinks.slice(0, 4).map((link) => (
          <a
            key={`${link.label}-${link.url}`}
            href={link.url}
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-0.5 text-[11px] text-primary hover:bg-primary/20"
          >
            <ExternalLink className="h-3 w-3" />
            {link.label}
          </a>
        ))}
        {resolvedLinks.length > 4 && (
          <span className="inline-flex items-center rounded border border-border px-2 py-0.5 text-[11px] text-muted-foreground">
            +{resolvedLinks.length - 4}
          </span>
        )}
      </div>
    );
  }, []);

  // Auto-refresh effect
  useEffect(() => {
    const refreshAll = async () => {
      try {
        await Promise.all([loadIOCs(), loadFeeds(), loadCVETrends(), loadIntelCatalog(), loadFeedInsights(), loadMitreTactics()]);
        setLastRefresh(new Date());
        addActivityLog({
          type: "feed_refreshed",
          title: "Auto-refresh triggered",
          description: `IOCs, feeds, and CVEs updated`,
          timestamp: new Date(),
        });
      } catch (e) {
        console.error("Auto-refresh failed:", e);
      }
    };

    if (autoRefresh) {
      autoRefreshIntervalRef.current = setInterval(refreshAll, refreshInterval * 1000);
      return () => {
        if (autoRefreshIntervalRef.current) clearInterval(autoRefreshIntervalRef.current);
      };
    }
  }, [autoRefresh, refreshInterval, loadIOCs, loadFeeds, loadCVETrends, loadIntelCatalog, loadFeedInsights, loadMitreTactics, addActivityLog]);

  useEffect(() => { loadIOCs(); }, [loadIOCs]);
  useEffect(() => { if (activeTab === "feeds") loadFeeds(); }, [activeTab, loadFeeds]);
  useEffect(() => { if (activeTab === "search") handleSearch(); }, [activeTab]);
  useEffect(() => { if (activeTab === "dashboard") { loadIOCs(); loadFeeds(); loadCVETrends(); loadIntelCatalog(); loadFeedInsights(); loadMitreTactics(); } }, [activeTab, loadIOCs, loadFeeds, loadCVETrends, loadIntelCatalog, loadFeedInsights, loadMitreTactics]);
  useEffect(() => { setIocPage(1); }, [filterType, filterSeverity]);
  useEffect(() => { setFeedsPage(1); }, [feedFilter]);

  const handleAddIOC = async () => {
    if (!newIoc.value.trim()) return;
    try {
      await api.createIOC({ ...newIoc, source: "manual", tags: [] });
      setShowAddForm(false);
      setNewIoc({ ioc_type: "ip", value: "", threat_type: "malware", severity: "medium", description: "" });
      addActivityLog({
        type: "ioc_added",
        title: `${newIoc.ioc_type} added: ${newIoc.value.substring(0, 30)}`,
        description: `New ${newIoc.threat_type} indicator with ${newIoc.severity} severity`,
        timestamp: new Date(),
        severity: newIoc.severity,
      });
      loadIOCs();
    } catch (e) { console.error("Failed to add IOC:", e); }
  };

  const handleDeleteIOC = async (id: number) => {
    try {
      await api.deleteIOC(id);
      loadIOCs();
    } catch (e) { console.error("Failed to delete IOC:", e); }
  };

  const handleRefreshFeeds = async () => {
    setFeedsLoading(true);
    try {
      const refreshRes = await api.refreshThreatFeeds();
      setFeedConnectorStatus((refreshRes.data as Record<string, { status: string; count?: number; ioc_ingested?: number; error?: string }>) || {});
      await loadFeeds();
      await loadFeedInsights();
      addActivityLog({
        type: "feed_refreshed",
        title: "Threat feeds manually refreshed",
        description: `Pulled latest IOCs from OpenPhish, Feodo, EmergingThreats, IPsum, CINSscore, and more`,
        timestamp: new Date(),
      });
    } catch (e) { console.error("Feed refresh failed:", e); }
    setFeedsLoading(false);
  };

  const handleSearch = async () => {
    setSearchLoading(true);
    try {
      const res = await api.searchThreatFeeds(searchQuery.trim());
      setSearchResults(res.data?.results || []);
      setSearchPage(1);
    } catch (e) { console.error("Search failed:", e); }
    setSearchLoading(false);
  };

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-primary/20 bg-background/95 backdrop-blur-md">
        <div className="flex h-16 w-full items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-lg font-bold bg-gradient-to-r from-primary to-primary/50 bg-clip-text text-transparent">CyberRegis</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">Dashboard</Link>
            <Link href="/threat-intel" className="text-primary font-semibold">Threat Intel</Link>
            <Link href="/cve" className="text-muted-foreground hover:text-primary transition-colors">CVE Database</Link>
            <Link href="/history" className="text-muted-foreground hover:text-primary transition-colors">Scan History</Link>
            <Link href="/reports" className="text-muted-foreground hover:text-primary transition-colors">Reports</Link>
            <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
          </nav>
        </div>
      </header>

      <main className="w-full px-6 py-8">
        {/* Page title */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <Database className="h-8 w-8 text-primary" />
            Threat Intelligence
          </h1>
          <p className="mt-2 text-muted-foreground">Manage IOCs, aggregate threat feeds, and search indicators across all sources.</p>
        </div>



        {/* Tabs */}
        <div className="mb-6 flex gap-2 border-b border-border pb-2 items-center justify-between flex-wrap">
          <div className="flex gap-2">
            {(["dashboard", "iocs", "feeds", "search"] as const).map((tab) => (
              <button key={tab} onClick={() => setActiveTab(tab)}
                className={`px-4 py-2 rounded-t-lg text-sm font-medium transition-colors ${activeTab === tab ? "bg-primary/10 text-primary border-b-2 border-primary" : "text-muted-foreground hover:text-foreground"}`}>
                {tab === "dashboard" ? "Dashboard" : tab === "iocs" ? "IOC Management" : tab === "feeds" ? "Threat Feeds" : "Search"}
              </button>
            ))}
          </div>
          
          {/* Auto-refresh controls */}
          <div className="flex items-center gap-3 pl-4 pr-2">
            <button
              onClick={() => setAutoRefresh(!autoRefresh)}
              className={`flex items-center gap-2 rounded-lg px-3 py-1.5 text-xs font-medium transition-colors ${
                autoRefresh 
                  ? "bg-green-500/10 text-green-500 border border-green-500/30" 
                  : "bg-muted text-muted-foreground border border-border"
              }`}
            >
              {autoRefresh ? <Zap className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
              {autoRefresh ? "Auto-Refresh ON" : "Auto-Refresh OFF"}
            </button>
            <select 
              value={refreshInterval} 
              onChange={(e) => setRefreshInterval(parseInt(e.target.value))}
              disabled={!autoRefresh}
              className="rounded-lg border border-border bg-card px-2 py-1.5 text-xs text-foreground disabled:opacity-50"
            >
              <option value={10}>Every 10s</option>
              <option value={30}>Every 30s</option>
              <option value={60}>Every 1m</option>
              <option value={300}>Every 5m</option>
            </select>
            {lastRefresh && (
              <span className="text-xs text-muted-foreground whitespace-nowrap">
                Last: {lastRefresh.toLocaleTimeString()}
              </span>
            )}
          </div>
        </div>

        {/* Dashboard Tab */}
        {activeTab === "dashboard" && (
          <div className="space-y-6">
            {/* Live Stats Grid */}
            {iocStats && (
              <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
                <div className="rounded-lg border border-primary/20 bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 text-muted-foreground text-sm"><Database className="h-4 w-4" /> Total IOCs</div>
                  <div className="mt-2 text-3xl font-bold text-primary">{iocStats.total}</div>
                </div>
                <div className="rounded-lg border border-red-500/20 bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 text-muted-foreground text-sm"><AlertTriangle className="h-4 w-4" /> Critical</div>
                  <div className="mt-2 text-3xl font-bold text-red-500">{iocStats.by_severity?.critical || 0}</div>
                </div>
                <div className="rounded-lg border border-orange-500/20 bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 text-muted-foreground text-sm"><AlertTriangle className="h-4 w-4" /> High</div>
                  <div className="mt-2 text-3xl font-bold text-orange-500">{iocStats.by_severity?.high || 0}</div>
                </div>
                <div className="rounded-lg border border-primary/20 bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 text-muted-foreground text-sm"><Activity className="h-4 w-4" /> Feed Entries</div>
                  <div className="mt-2 text-3xl font-bold text-foreground">{feedEntries.length}</div>
                </div>
                <div className="rounded-lg border border-primary/20 bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 text-muted-foreground text-sm"><TrendingUp className="h-4 w-4" /> Types</div>
                  <div className="mt-2 text-3xl font-bold text-foreground">{Object.keys(iocStats.by_type || {}).length}</div>
                </div>
              </div>
            )}

            <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
              {/* Latest CVEs Trends */}
              <div className="lg:col-span-2 rounded-lg border border-primary/20 bg-card/50 overflow-hidden backdrop-blur-sm">
                <div className="bg-[#070a12] border-b border-primary/20 px-6 py-4 flex items-center justify-between">
                  <h3 className="font-semibold text-foreground flex items-center gap-2">
                    <TrendingUp className="h-5 w-5 text-primary" />
                    Latest Published CVEs
                  </h3>
                  <button
                    onClick={loadCVETrends}
                    disabled={cveLoading}
                    className="flex items-center gap-1 text-xs px-2 py-1 rounded bg-primary/10 text-primary hover:bg-primary/20 transition-colors"
                  >
                    <RefreshCw className={`h-3 w-3 ${cveLoading ? "animate-spin" : ""}`} />
                    Refresh
                  </button>
                </div>
                <div className="divide-y divide-border">
                  {cves.length === 0 ? (
                    <div className="px-6 py-8 text-center text-muted-foreground">
                      {cveLoading ? "Loading CVEs..." : "No critical CVEs found recently"}
                    </div>
                  ) : (
                    cves.map((cve) => (
                      <Link
                        key={cve.cve_id || cve.id}
                        href={`/cve?search=${cve.cve_id || cve.id}`}
                        className="px-6 py-3 hover:bg-card/50 transition-colors block"
                      >
                        <div className="flex items-start gap-3">
                          <div className="flex-1 min-w-0">
                            <div className="font-mono text-sm font-medium text-primary">
                              {cve.cve_id || cve.id}
                            </div>
                            <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                              {cve.description || "No description"}
                            </div>
                            {cve.cvss_score && (
                              <div className="mt-2">
                                <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${
                                  cve.cvss_score >= 9 ? "bg-red-500/10 text-red-400 border-red-500/30" :
                                  cve.cvss_score >= 7 ? "bg-orange-500/10 text-orange-400 border-orange-500/30" :
                                  "bg-yellow-500/10 text-yellow-400 border-yellow-500/30"
                                }`}>
                                  CVSS {cve.cvss_score}
                                </span>
                              </div>
                            )}
                          </div>
                        </div>
                      </Link>
                    ))
                  )}
                </div>
              </div>

              {/* Activity Log */}
              <div className="rounded-lg border border-primary/20 bg-card/50 overflow-hidden backdrop-blur-sm">
                <div className="bg-[#070a12] border-b border-primary/20 px-6 py-4">
                  <h3 className="font-semibold text-foreground flex items-center gap-2">
                    <Clock className="h-5 w-5 text-primary" />
                    Recent Activity
                  </h3>
                </div>
                <div className="divide-y divide-border max-h-[500px] overflow-y-auto">
                  {activityLog.length === 0 ? (
                    <div className="px-6 py-8 text-center text-muted-foreground text-sm">
                      Activity will appear here
                    </div>
                  ) : (
                    activityLog.map((activity) => (
                      <div key={activity.id} className="px-6 py-3 hover:bg-card/50 transition-colors">
                        <div className="flex items-start gap-3">
                          <div className={`mt-1.5 h-2 w-2 rounded-full flex-shrink-0 ${
                            activity.type === "ioc_added" ? "bg-blue-500" :
                            activity.type === "feed_refreshed" ? "bg-green-500" :
                            "bg-yellow-500"
                          }`} />
                          <div className="flex-1 min-w-0">
                            <div className="text-sm font-medium text-foreground">{activity.title}</div>
                            <div className="text-xs text-muted-foreground mt-1">{activity.description}</div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {activity.timestamp.toLocaleTimeString()}
                            </div>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>

            {intelCatalog && (
              <div className="rounded-lg border border-primary/20 bg-card/50 p-4 space-y-4 backdrop-blur-sm">
                <h3 className="text-sm font-semibold text-foreground">Threat Intel Coverage</h3>
                <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs">
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">CISA KEV</div>
                    <div className="mt-1 text-foreground font-medium">{intelCatalog?.cisa_kev?.total || 0} exploited CVEs</div>
                    <div className={`mt-1 ${intelCatalog?.cisa_kev?.status === "success" ? "text-green-400" : "text-red-400"}`}>{intelCatalog?.cisa_kev?.status || "unknown"}</div>
                  </div>
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">OWASP Top 10</div>
                    <div className="mt-1 text-foreground font-medium">{intelCatalog?.owasp_top10_2021?.total || 0} categories</div>
                    <div className="mt-1 text-green-400">available</div>
                  </div>
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">SANS / CWE Top 25</div>
                    <div className="mt-1 text-foreground font-medium">{intelCatalog?.sans_cwe_top25?.total || 0} weakness classes</div>
                    <div className="mt-1 text-green-400">available</div>
                  </div>
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">MITRE ATT&CK</div>
                    <div className="mt-1 text-foreground font-medium">{mitreTactics.length || 0} tactics loaded</div>
                    <div className="mt-1 text-green-400">available</div>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                  <div className="rounded-lg border border-primary/20 bg-[#070a12] p-4">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-foreground">Recent CISA KEV entries</div>
                        <div className="text-xs text-muted-foreground">Latest known exploited vulnerabilities from the live KEV feed</div>
                      </div>
                      <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                        <ExternalLink className="h-3.5 w-3.5" /> CISA
                      </a>
                    </div>
                    <div className="space-y-2">
                      {(intelCatalog?.cisa_kev?.vulnerabilities || []).slice(0, 6).map((item: any) => (
                        <div key={item.cve_id} className="rounded border border-white/[0.08] bg-[#050810] p-3">
                          <div className="flex items-start justify-between gap-3">
                            <Link href={`/cve?search=${item.cve_id}`} className="font-mono text-xs text-primary hover:underline">
                              {item.cve_id}
                            </Link>
                          </div>
                          <div className="mt-1 text-xs text-foreground">{item.vendor} · {item.product}</div>
                          <div className="mt-1 text-xs text-muted-foreground line-clamp-2">{item.notes}</div>
                          <div className="mt-2 flex gap-4 text-[11px] text-muted-foreground">
                            <span>Added: {item.date_added || "—"}</span>
                            <span>Due: {item.due_date || "—"}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-primary/20 bg-[#070a12] p-4">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-foreground">OWASP Top 10 Catalog (Dynamic)</div>
                        <div className="text-xs text-muted-foreground">Automatically fetched from live OWASP project sources.</div>
                      </div>
                      <span className={`rounded px-2 py-0.5 text-[11px] ${intelCatalog?.owasp_top10_catalog?.status === "success" ? "bg-green-500/10 text-green-400" : intelCatalog?.owasp_top10_catalog?.status === "partial" ? "bg-yellow-500/10 text-yellow-400" : "bg-red-500/10 text-red-400"}`}>
                        {intelCatalog?.owasp_top10_catalog?.status || "unknown"}
                      </span>
                    </div>
                    <div className="space-y-3 max-h-[520px] overflow-y-auto pr-1">
                      {(intelCatalog?.owasp_top10_catalog?.projects || []).map((project: any) => (
                        <div key={project.key} className="rounded border border-white/[0.08] bg-[#050810] p-3">
                          <div className="flex items-center justify-between gap-3">
                            <div>
                              <div className="text-xs font-medium text-foreground">{project.name}</div>
                              <div className="text-[11px] text-muted-foreground">Version {project.version || "unknown"} · {project.total || 0} items</div>
                            </div>
                            <a href={project.source} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-[11px] text-primary hover:underline">
                              <ExternalLink className="h-3.5 w-3.5" /> Source
                            </a>
                          </div>
                          <div className="mt-2 grid grid-cols-1 gap-1.5 sm:grid-cols-2">
                            {(project.items || []).slice(0, 10).map((item: any) => (
                              <a
                                key={`${project.key}-${item.id}-${item.name}`}
                                href={item.reference || project.source}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="rounded border border-white/[0.08] bg-[#050810] px-2.5 py-1.5 text-[11px] hover:bg-white/5"
                              >
                                <div className="font-medium text-primary">{item.id}</div>
                                <div className="mt-0.5 text-muted-foreground line-clamp-2">{item.name}</div>
                              </a>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-1 gap-4 xl:grid-cols-2">
                  <div className="rounded-lg border border-primary/20 bg-[#070a12] p-4">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <div className="text-sm font-medium text-foreground">Top SANS / CWE weaknesses</div>
                      <a href="https://cwe.mitre.org/top25/archive/2024/2024_key_insights.html" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                        <ExternalLink className="h-3.5 w-3.5" /> CWE
                      </a>
                    </div>
                    <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                      {(intelCatalog?.sans_cwe_top25?.items || []).slice(0, 10).map((item: any) => (
                        <div key={`${item.cwe}-${item.name}`} className="rounded border border-white/[0.08] bg-[#050810] px-3 py-2 text-xs">
                          <div className="font-medium text-primary">{item.cwe}</div>
                          <div className="mt-1 text-muted-foreground">{item.name}</div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div className="rounded-lg border border-primary/20 bg-[#070a12] p-4">
                    <div className="mb-3 flex items-center justify-between gap-3">
                      <div>
                        <div className="text-sm font-medium text-foreground">MITRE ATT&CK tactics</div>
                        <div className="text-xs text-muted-foreground">Live tactics from the platform MITRE endpoint</div>
                      </div>
                      <a href="https://attack.mitre.org/tactics/enterprise/" target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-xs text-primary hover:underline">
                        <ExternalLink className="h-3.5 w-3.5" /> MITRE
                      </a>
                    </div>
                    <div className="space-y-2">
                      {mitreTactics.slice(0, 8).map((tactic) => (
                        <div key={tactic.id} className="rounded border border-white/[0.08] bg-[#050810] px-3 py-2 text-xs">
                          <div className="flex items-center justify-between gap-3">
                            <span className="font-medium text-primary">{tactic.id}</span>
                            <a href={`/api/mitre/techniques?tactic=${encodeURIComponent(tactic.name)}`} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-primary hover:underline">
                              <ExternalLink className="h-3.5 w-3.5" /> Techniques
                            </a>
                          </div>
                          <div className="mt-1 text-foreground">{tactic.name}</div>
                          <div className="mt-1 text-muted-foreground">{tactic.description}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            )}

            {feedInsights?.openphish && (
              <div className="rounded-lg border border-primary/20 bg-card/50 p-4 backdrop-blur-sm">
                <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-foreground">Live OpenPhish Trends</h3>
                    <p className="mt-1 text-xs text-muted-foreground">
                      Public OpenPhish homepage statistics are rolling and updated continuously, but the free community IOC feed does not expose brand, sector, ASN, IP, or SSL fields per IOC.
                    </p>
                  </div>
                  <div className="flex flex-wrap gap-2 text-xs">
                    <a href={feedInsights.openphish.homepage} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-1 text-primary hover:bg-primary/20">
                      <ExternalLink className="h-3.5 w-3.5" /> Homepage
                    </a>
                    <a href={feedInsights.openphish.community_feed} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 rounded border border-primary/30 bg-primary/10 px-2 py-1 text-primary hover:bg-primary/20">
                      <ExternalLink className="h-3.5 w-3.5" /> Community Feed
                    </a>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">7-day URLs processed</div>
                    <div className="mt-1 text-lg font-semibold text-foreground">{feedInsights.openphish.metrics?.urls_processed || "—"}</div>
                  </div>
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">New phishing URLs</div>
                    <div className="mt-1 text-lg font-semibold text-foreground">{feedInsights.openphish.metrics?.new_phishing_urls || "—"}</div>
                  </div>
                  <div className="rounded border border-primary/20 bg-[#070a12] p-3">
                    <div className="text-muted-foreground">Brands targeted</div>
                    <div className="mt-1 text-lg font-semibold text-foreground">{feedInsights.openphish.metrics?.brands_targeted || "—"}</div>
                  </div>
                </div>

                <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-3">
                  {[
                    { title: "Top Targeted Brands", items: feedInsights.openphish.top_brands },
                    { title: "Top Sectors", items: feedInsights.openphish.top_sectors },
                    { title: "Top ASNs", items: feedInsights.openphish.top_asns },
                  ].map((section) => (
                    <div key={section.title} className="rounded border border-primary/20 bg-[#070a12] p-3">
                      <div className="mb-2 text-xs font-medium text-foreground">{section.title}</div>
                      <div className="space-y-1.5 text-xs">
                        {section.items.slice(0, 5).map((item) => (
                          <div key={`${section.title}-${item.label}`} className="flex items-center justify-between gap-3">
                            <span className="text-muted-foreground truncate">{item.label}</span>
                            <span className="font-medium text-foreground">{item.percentage}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>

                <div className="mt-3 text-xs text-muted-foreground">
                  {feedInsights.openphish.caveat}
                </div>
              </div>
            )}
          </div>
        )}

        {/* IOC Management Tab */}
        {activeTab === "iocs" && (
          <div className="space-y-4">
            {/* Toolbar */}
            <div className="flex items-center gap-4 flex-wrap">
              <button onClick={() => setShowAddForm(true)} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
                <Plus className="h-4 w-4" /> Add IOC
              </button>
              <button onClick={loadIOCs} disabled={loading} className="flex items-center gap-2 rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground transition-colors">
                <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} /> Refresh
              </button>
              <select value={filterType} onChange={(e) => setFilterType(e.target.value)} className="rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground">
                <option value="">All Types</option>
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="url">URL</option>
                <option value="hash">Hash</option>
                <option value="email">Email</option>
              </select>
              <select value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)} className="rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground">
                <option value="">All Severity</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>

            {/* Add IOC Form */}
            {showAddForm && (
              <div className="rounded-lg border border-primary/30 bg-card/50 p-6 backdrop-blur-sm">
                <h3 className="text-lg font-semibold text-foreground mb-4">Add Indicator of Compromise</h3>
                <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <select value={newIoc.ioc_type} onChange={(e) => setNewIoc({ ...newIoc, ioc_type: e.target.value })} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
                    <option value="ip">IP Address</option>
                    <option value="domain">Domain</option>
                    <option value="url">URL</option>
                    <option value="hash">File Hash</option>
                    <option value="email">Email</option>
                  </select>
                  <input value={newIoc.value} onChange={(e) => setNewIoc({ ...newIoc, value: e.target.value })} placeholder="Indicator value..." className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground" />
                  <select value={newIoc.severity} onChange={(e) => setNewIoc({ ...newIoc, severity: e.target.value })} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                  <select value={newIoc.threat_type} onChange={(e) => setNewIoc({ ...newIoc, threat_type: e.target.value })} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
                    <option value="malware">Malware</option>
                    <option value="phishing">Phishing</option>
                    <option value="c2">C2 Server</option>
                    <option value="spam">Spam</option>
                    <option value="apt">APT</option>
                  </select>
                  <input value={newIoc.description} onChange={(e) => setNewIoc({ ...newIoc, description: e.target.value })} placeholder="Description (optional)..." className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground sm:col-span-2" />
                </div>
                <div className="mt-4 flex gap-2">
                  <button onClick={handleAddIOC} className="rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">Save IOC</button>
                  <button onClick={() => setShowAddForm(false)} className="rounded-lg border border-border px-4 py-2 text-sm text-muted-foreground hover:text-foreground">Cancel</button>
                </div>
              </div>
            )}

            {/* IOC Table */}
            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-card/80 border-b border-border">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Indicator</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Threat</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Severity</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Source</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Last Seen</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Link</th>
                    <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {iocs.length === 0 && (
                    <tr><td colSpan={8} className="px-4 py-12 text-center text-muted-foreground">
                      {loading ? "Loading..." : "No IOCs found. Add indicators manually or refresh threat feeds."}
                    </td></tr>
                  )}
                  {iocs.map((ioc) => {
                    const IconComp = IOC_TYPE_ICONS[ioc.ioc_type] || Globe;
                    return (
                      <tr key={ioc.id} className="hover:bg-card/50 transition-colors">
                        <td className="px-4 py-3"><span className="flex items-center gap-2 text-muted-foreground"><IconComp className="h-4 w-4" />{ioc.ioc_type.toUpperCase()}</span></td>
                        <td className="px-4 py-3 font-mono text-foreground text-xs max-w-[300px] truncate">{ioc.value}</td>
                        <td className="px-4 py-3 text-muted-foreground">{ioc.threat_type || "—"}</td>
                        <td className="px-4 py-3"><span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${SEVERITY_COLORS[ioc.severity] || SEVERITY_COLORS.info}`}>{ioc.severity}</span></td>
                        <td className="px-4 py-3 text-muted-foreground">{ioc.source}</td>
                        <td className="px-4 py-3 text-muted-foreground text-xs">{new Date(ioc.last_seen).toLocaleDateString()}</td>
                        <td className="px-4 py-3 text-xs">{renderLookupLinks(ioc.lookup_links, ioc.reference_url)}</td>
                        <td className="px-4 py-3 text-right">
                          <button onClick={() => handleDeleteIOC(ioc.id)} className="text-red-500/70 hover:text-red-500 transition-colors"><Trash2 className="h-4 w-4" /></button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <span>Showing {iocs.length} of {iocTotal} IOCs</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setIocPage((p) => Math.max(1, p - 1))} disabled={iocPage === 1} className="rounded border border-border px-3 py-1 disabled:opacity-50">Previous</button>
                <span>Page {iocPage} / {Math.max(1, Math.ceil(iocTotal / PAGE_SIZE))}</span>
                <button onClick={() => setIocPage((p) => p + 1)} disabled={iocPage >= Math.max(1, Math.ceil(iocTotal / PAGE_SIZE))} className="rounded border border-border px-3 py-1 disabled:opacity-50">Next</button>
              </div>
            </div>
          </div>
        )}

        {/* Threat Feeds Tab */}
        {activeTab === "feeds" && (
          <div className="space-y-4">
            <div className="flex items-center gap-4">
              <button onClick={handleRefreshFeeds} disabled={feedsLoading} className="flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
                <RefreshCw className={`h-4 w-4 ${feedsLoading ? "animate-spin" : ""}`} /> {feedsLoading ? "Refreshing..." : "Refresh All Feeds"}
              </button>
              <select value={feedFilter} onChange={(e) => setFeedFilter(e.target.value)} className="rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground">
                {FEED_FILTERS.map((feed) => <option key={feed || "all"} value={feed}>{feed || "All feeds"}</option>)}
              </select>
              <span className="text-sm text-muted-foreground">{feedTotal} total entries across all configured feeds</span>
            </div>

            <div className="rounded-lg border border-border bg-card/40 p-3 text-xs text-muted-foreground">
              Brand, sector, and ASN summaries can only be shown when the upstream source exposes them publicly. OpenPhish publishes those as live source-wide trends, not as per-IOC fields in the free feed. For each IOC below, live lookup links are provided to continuously updated external intel portals.
            </div>

            {Object.keys(feedConnectorStatus).length > 0 && (
              <div className="rounded-lg border border-border p-4 bg-card/40">
                <div className="mb-3 text-sm font-medium text-foreground">Connector Health</div>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
                  {Object.entries(feedConnectorStatus).map(([name, status]) => (
                    <div key={name} className="rounded border border-border px-3 py-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-foreground">{name}</span>
                        <span className={`rounded px-2 py-0.5 ${
                          status.status === "success" ? "bg-green-500/10 text-green-400" :
                          status.status === "empty" ? "bg-yellow-500/10 text-yellow-400" :
                          "bg-red-500/10 text-red-400"
                        }`}>{status.status}</span>
                      </div>
                      <div className="mt-1 text-muted-foreground">
                        entries: {status.count || 0}, iocs: {status.ioc_ingested || 0}
                      </div>
                      {status.error && (
                        <div className="mt-1 text-red-400 truncate" title={status.error}>{status.error}</div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <div className="rounded-lg border border-border overflow-hidden">
              <table className="w-full text-sm">
                <thead className="bg-card/80 border-b border-border">
                  <tr>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Feed</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Indicator</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Threat</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Confidence</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Link</th>
                    <th className="px-4 py-3 text-left font-medium text-muted-foreground">Description</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {feedEntries.length === 0 && (
                    <tr><td colSpan={7} className="px-4 py-12 text-center text-muted-foreground">
                      {feedsLoading ? "Loading feeds..." : "No feed entries. Click 'Refresh All Feeds' to pull from threat intelligence sources."}
                    </td></tr>
                  )}
                  {feedEntries.map((entry) => (
                    <tr key={entry.id} className="hover:bg-card/50 transition-colors">
                      <td className="px-4 py-3"><span className="rounded-full bg-primary/10 border border-primary/30 px-2 py-0.5 text-xs text-primary font-medium">{entry.feed_name}</span></td>
                      <td className="px-4 py-3 font-mono text-foreground text-xs max-w-[250px] truncate">{entry.indicator}</td>
                      <td className="px-4 py-3 text-muted-foreground">{entry.ioc_type}</td>
                      <td className="px-4 py-3 text-muted-foreground">{entry.threat_type || "—"}</td>
                      <td className="px-4 py-3"><span className={`text-xs font-medium ${(entry.confidence || 0) >= 80 ? "text-red-400" : (entry.confidence || 0) >= 50 ? "text-yellow-400" : "text-blue-400"}`}>{entry.confidence || "N/A"}%</span></td>
                      <td className="px-4 py-3 text-xs">{renderLookupLinks(entry.lookup_links, entry.reference)}</td>
                      <td className="px-4 py-3 text-muted-foreground text-xs max-w-[300px] truncate">{entry.description || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between text-sm text-muted-foreground">
              <span>Showing {feedEntries.length} of {feedTotal} feed entries</span>
              <div className="flex items-center gap-2">
                <button onClick={() => setFeedsPage((p) => Math.max(1, p - 1))} disabled={feedsPage === 1} className="rounded border border-border px-3 py-1 disabled:opacity-50">Previous</button>
                <span>Page {feedsPage} / {Math.max(1, Math.ceil(feedTotal / PAGE_SIZE))}</span>
                <button onClick={() => setFeedsPage((p) => p + 1)} disabled={feedsPage >= Math.max(1, Math.ceil(feedTotal / PAGE_SIZE))} className="rounded border border-border px-3 py-1 disabled:opacity-50">Next</button>
              </div>
            </div>
          </div>
        )}

        {/* Search Tab */}
        {activeTab === "search" && (
          <div className="space-y-4">
            <div className="flex gap-2">
              <input value={searchQuery} onChange={(e) => { setSearchQuery(e.target.value); setSearchPage(1); }} onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                placeholder="Search for IP, domain, URL, or hash. Leave blank to view latest indicators..."
                className="flex-1 rounded-lg border border-border bg-background px-4 py-2 text-sm text-foreground" />
              <button onClick={handleSearch} disabled={searchLoading} className="flex items-center gap-2 rounded-lg bg-primary px-6 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                <Search className={`h-4 w-4 ${searchLoading ? "animate-spin" : ""}`} /> Search
              </button>
            </div>
            {searchResults.length > 0 && (
              <div className="rounded-lg border border-border overflow-hidden">
                <div className="bg-card/80 border-b border-border px-4 py-3">
                  <span className="text-sm font-medium text-foreground">{searchResults.length} {searchQuery.trim() ? `results for "${searchQuery}"` : "latest indicators"}</span>
                </div>
                <div className="divide-y divide-border">
                  {paginatedSearchResults.map((r, i) => (
                    <div key={`ioc-${i}-${r.feed_name}-${r.indicator}`} className="px-4 py-3 hover:bg-card/50">
                      <div className="flex items-center gap-3">
                        <span className="rounded-full bg-primary/10 border border-primary/30 px-2 py-0.5 text-xs text-primary">{r.feed_name}</span>
                        <span className="font-mono text-sm text-foreground">{r.indicator}</span>
                        <span className="text-xs text-muted-foreground">{r.ioc_type}</span>
                        {renderLookupLinks(r.lookup_links, r.reference)}
                      </div>
                      {r.description && <p className="mt-1 text-xs text-muted-foreground">{r.description}</p>}
                    </div>
                  ))}
                </div>
              </div>
            )}
            {searchResults.length > 0 && (
              <div className="flex items-center justify-between text-sm text-muted-foreground">
                <span>Showing {paginatedSearchResults.length} of {searchResults.length} search results</span>
                <div className="flex items-center gap-2">
                  <button onClick={() => setSearchPage((p) => Math.max(1, p - 1))} disabled={searchPage === 1} className="rounded border border-border px-3 py-1 disabled:opacity-50">Previous</button>
                  <span>Page {searchPage} / {Math.max(1, Math.ceil(searchResults.length / PAGE_SIZE))}</span>
                  <button onClick={() => setSearchPage((p) => p + 1)} disabled={searchPage >= Math.max(1, Math.ceil(searchResults.length / PAGE_SIZE))} className="rounded border border-border px-3 py-1 disabled:opacity-50">Next</button>
                </div>
              </div>
            )}
            {!searchLoading && searchResults.length === 0 && (
              <div className="rounded-lg border border-dashed border-border px-4 py-8 text-center text-sm text-muted-foreground">
                No matches found yet. Try `ip`, `url`, `hash`, a threat family, or leave the query blank to load the latest indicators.
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
