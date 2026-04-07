"use client";

import { useState, useEffect, useCallback } from "react";
import { Shield, Search, Clock, Globe, Filter, ChevronLeft, ChevronRight, Eye, Trash2, BarChart3 } from "lucide-react";
import Link from "next/link";
import * as api from "@/app/lib/api";
import type { ScanHistoryEntry } from "@/app/types";

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

function riskBadge(score: number | undefined | null): { text: string; cls: string } {
  if (!score) return { text: "N/A", cls: "text-gray-400 bg-gray-400/10 border-gray-400/30" };
  if (score >= 80) return { text: `${score} Critical`, cls: "text-red-500 bg-red-500/10 border-red-500/30" };
  if (score >= 60) return { text: `${score} High`, cls: "text-orange-500 bg-orange-500/10 border-orange-500/30" };
  if (score >= 40) return { text: `${score} Medium`, cls: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30" };
  return { text: `${score} Low`, cls: "text-green-400 bg-green-400/10 border-green-400/30" };
}

export default function HistoryPage() {
  const [scans, setScans] = useState<ScanHistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [filterType, setFilterType] = useState("");
  const [searchTarget, setSearchTarget] = useState("");
  const [page, setPage] = useState(1);
  const [total, setTotal] = useState(0);
  const [selectedScan, setSelectedScan] = useState<ScanHistoryEntry | null>(null);
  const perPage = 20;

  const loadHistory = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = { page, per_page: perPage };
      if (filterType) params.scan_type = filterType;
      if (searchTarget.trim()) params.target = searchTarget.trim();
      const res = await api.getScanHistory(params);
      setScans(res.data?.scans || []);
      setTotal(res.data?.total || 0);
    } catch (e) { console.error("Failed to load history:", e); }
    setLoading(false);
  }, [page, filterType, searchTarget]);

  useEffect(() => { loadHistory(); }, [loadHistory]);

  const totalPages = Math.ceil(total / perPage) || 1;

  return (
    <div className="min-h-screen bg-background">
      <header className="sticky top-0 z-50 border-b border-primary/20 bg-background/95 backdrop-blur-md">
        <div className="flex h-16 w-full items-center justify-between px-6">
          <Link href="/" className="flex items-center gap-2">
            <Shield className="h-6 w-6 text-primary" />
            <span className="text-lg font-bold bg-gradient-to-r from-primary to-primary/50 bg-clip-text text-transparent">CyberRegis</span>
          </Link>
          <nav className="flex items-center gap-6 text-sm">
            <Link href="/" className="text-muted-foreground hover:text-primary transition-colors">Dashboard</Link>
            <Link href="/threat-intel" className="text-muted-foreground hover:text-primary transition-colors">Threat Intel</Link>
            <Link href="/cve" className="text-muted-foreground hover:text-primary transition-colors">CVE Database</Link>
            <Link href="/history" className="text-primary font-semibold">Scan History</Link>
            <Link href="/reports" className="text-muted-foreground hover:text-primary transition-colors">Reports</Link>
            <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
          </nav>
        </div>
      </header>

      <main className="w-full px-6 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <Clock className="h-8 w-8 text-primary" /> Scan History
          </h1>
          <p className="mt-2 text-muted-foreground">Browse all past scans with risk scores, results, and detailed logs.</p>
        </div>

        {/* Filters */}
        <div className="mb-6 flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2 flex-1 max-w-md">
            <Search className="h-4 w-4 text-muted-foreground" />
            <input value={searchTarget} onChange={(e) => { setSearchTarget(e.target.value); setPage(1); }}
              placeholder="Filter by target..." className="flex-1 rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground" />
          </div>
          <select value={filterType} onChange={(e) => { setFilterType(e.target.value); setPage(1); }}
            className="rounded-lg border border-border bg-card px-3 py-2 text-sm text-foreground">
            <option value="">All Scan Types</option>
            <option value="domain">Domain Analysis</option>
            <option value="ip">IP Intelligence</option>
            <option value="url">URL Check</option>
            <option value="port_scan">Port Scan</option>
            <option value="vuln_scan">Vulnerability Scan</option>
            <option value="pcap">PCAP Analysis</option>
            <option value="ssl">SSL Analysis</option>
            <option value="headers">Security Headers</option>
            <option value="email">Email Security</option>
          </select>
          <span className="text-sm text-muted-foreground">{total} total scans</span>
        </div>

        {/* Table */}
        <div className="rounded-lg border border-border overflow-hidden mb-4">
          <table className="w-full text-sm">
            <thead className="bg-card/80 border-b border-border">
              <tr>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Target</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Type</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Risk Score</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Status</th>
                <th className="px-4 py-3 text-left font-medium text-muted-foreground">Timestamp</th>
                <th className="px-4 py-3 text-right font-medium text-muted-foreground">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {loading && (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">Loading scan history...</td></tr>
              )}
              {!loading && scans.length === 0 && (
                <tr><td colSpan={6} className="px-4 py-12 text-center text-muted-foreground">No scans found. Run a scan from the Dashboard to see results here.</td></tr>
              )}
              {scans.map((scan) => {
                const risk = riskBadge(scan.risk_score);
                const typeColor = SCAN_TYPE_COLORS[scan.scan_type] || SCAN_TYPE_COLORS.domain;
                return (
                  <tr key={scan.id} className="hover:bg-card/50 transition-colors">
                    <td className="px-4 py-3">
                      <span className="font-mono text-foreground text-sm">{scan.target}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium border ${typeColor}`}>
                        {scan.scan_type.replace("_", " ")}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-bold border ${risk.cls}`}>{risk.text}</span>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`text-xs ${scan.status === "completed" ? "text-green-400" : scan.status === "error" ? "text-red-400" : "text-yellow-400"}`}>
                        {scan.status}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{new Date(scan.created_at || scan.timestamp || "").toLocaleString()}</td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => setSelectedScan(selectedScan?.id === scan.id ? null : scan)} className="text-primary/70 hover:text-primary transition-colors">
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
        <div className="flex items-center justify-between">
          <span className="text-sm text-muted-foreground">Page {page} of {totalPages}</span>
          <div className="flex items-center gap-2">
            <button onClick={() => setPage(Math.max(1, page - 1))} disabled={page === 1}
              className="flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
              <ChevronLeft className="h-4 w-4" /> Prev
            </button>
            <button onClick={() => setPage(Math.min(totalPages, page + 1))} disabled={page >= totalPages}
              className="flex items-center gap-1 rounded-lg border border-border px-3 py-1.5 text-sm text-muted-foreground hover:text-foreground disabled:opacity-40 transition-colors">
              Next <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>

        {/* Detail panel */}
        {selectedScan && (
          <div className="mt-6 rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold text-foreground">Scan Details — {selectedScan.target}</h3>
              <button onClick={() => setSelectedScan(null)} className="text-muted-foreground hover:text-foreground text-sm">Close</button>
            </div>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
              <div><span className="text-xs text-muted-foreground block">Scan Type</span><span className="text-sm text-foreground">{selectedScan.scan_type}</span></div>
              <div><span className="text-xs text-muted-foreground block">Status</span><span className="text-sm text-foreground">{selectedScan.status}</span></div>
              <div><span className="text-xs text-muted-foreground block">Risk Score</span><span className="text-sm text-foreground">{selectedScan.risk_score || "N/A"}</span></div>
              <div><span className="text-xs text-muted-foreground block">Duration</span><span className="text-sm text-foreground">{selectedScan.scan_duration_ms ? `${selectedScan.scan_duration_ms}ms` : "N/A"}</span></div>
            </div>
            {selectedScan.result_summary != null && (
              <div>
                <span className="text-xs text-muted-foreground block mb-1">Result Summary</span>
                <pre className="rounded-lg bg-background border border-border p-4 text-xs text-muted-foreground overflow-auto max-h-96 font-mono">
                  {typeof selectedScan.result_summary === "string" ? selectedScan.result_summary : JSON.stringify(selectedScan.result_summary as Record<string, unknown>, null, 2)}
                </pre>
              </div>
            )}
          </div>
        )}
      </main>
    </div>
  );
}
