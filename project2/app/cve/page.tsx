"use client";

import { useState } from "react";
import { Shield, Search, AlertTriangle, ExternalLink, ChevronDown, ChevronUp, Bug, Clock, Tag, Layers } from "lucide-react";
import Link from "next/link";
import * as api from "@/app/lib/api";
import type { CVE } from "@/app/types";

const CVSS_COLORS: Record<string, string> = {
  CRITICAL: "text-red-500 bg-red-500/10 border-red-500/30",
  HIGH: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  MEDIUM: "text-yellow-500 bg-yellow-500/10 border-yellow-500/30",
  LOW: "text-blue-400 bg-blue-400/10 border-blue-400/30",
  NONE: "text-gray-400 bg-gray-400/10 border-gray-400/30",
};

function cvssColor(score: number | undefined): string {
  if (!score) return CVSS_COLORS.NONE;
  if (score >= 9.0) return CVSS_COLORS.CRITICAL;
  if (score >= 7.0) return CVSS_COLORS.HIGH;
  if (score >= 4.0) return CVSS_COLORS.MEDIUM;
  return CVSS_COLORS.LOW;
}

function cvssLabel(score: number | undefined): string {
  if (!score) return "N/A";
  if (score >= 9.0) return "Critical";
  if (score >= 7.0) return "High";
  if (score >= 4.0) return "Medium";
  return "Low";
}

async function copyText(value: string) {
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
  } catch {
    const area = document.createElement("textarea");
    area.value = value;
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.focus();
    area.select();
    document.execCommand("copy");
    document.body.removeChild(area);
  }
}

export default function CVEPage() {
  const [mode, setMode] = useState<"lookup" | "search">("search");
  const [cveId, setCveId] = useState("");
  const [keyword, setKeyword] = useState("");
  const [loading, setLoading] = useState(false);
  const [singleCve, setSingleCve] = useState<CVE | null>(null);
  const [cveList, setCveList] = useState<CVE[]>([]);
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [page, setPage] = useState(1);
  const pageSize = 25;

  const handleLookup = async () => {
    if (!cveId.trim()) return;
    setLoading(true);
    setError("");
    setSingleCve(null);
    try {
      const res = await api.lookupCVE(cveId.trim().toUpperCase());
      if (res.status === "success" && res.data) {
        const cveData = (res.data as any)?.cve || res.data;
        setSingleCve(cveData as CVE);
      } else {
        setError("CVE not found or NVD API error.");
      }
    } catch (e) {
      setError("Failed to lookup CVE. Check format (e.g., CVE-2021-44228).");
    }
    setLoading(false);
  };

  const handleSearch = async () => {
    if (!keyword.trim()) return;
    setLoading(true);
    setError("");
    setCveList([]);
    try {
      const res = await api.searchCVEs(keyword.trim(), 200);
      if (res.status === "success" && res.data) {
        const list = (res.data as any)?.cves || (res.data as any)?.results || [];
        if (Array.isArray(list) && list.length > 0) {
          setCveList(list);
          setPage(1);
        } else {
          setError("No CVEs found for that keyword.");
        }
      } else {
        setError("No CVEs found for that keyword.");
      }
    } catch (e) {
      setError("Search failed. Try different keywords.");
    }
    setLoading(false);
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
            <Link href="/threat-intel" className="text-muted-foreground hover:text-primary transition-colors">Threat Intel</Link>
            <Link href="/cve" className="text-primary font-semibold">CVE Database</Link>
            <Link href="/history" className="text-muted-foreground hover:text-primary transition-colors">Scan History</Link>
            <Link href="/reports" className="text-muted-foreground hover:text-primary transition-colors">Reports</Link>
            <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
          </nav>
        </div>
      </header>

      <main className="w-full px-6 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <Bug className="h-8 w-8 text-primary" /> CVE Database
          </h1>
          <p className="mt-2 text-muted-foreground">Search NVD CVEs by ID or keyword. Results are prioritized by newest publish date, then severity.</p>
        </div>

        {/* Mode toggle + search */}
        <div className="mb-8 rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
          <div className="flex items-center gap-4 mb-4">
            <button onClick={() => setMode("search")} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${mode === "search" ? "bg-primary text-primary-foreground" : "border border-border text-muted-foreground hover:text-foreground"}`}>
              <Search className="h-4 w-4 inline mr-1" /> Keyword Search
            </button>
            <button onClick={() => setMode("lookup")} className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${mode === "lookup" ? "bg-primary text-primary-foreground" : "border border-border text-muted-foreground hover:text-foreground"}`}>
              <Tag className="h-4 w-4 inline mr-1" /> CVE Lookup
            </button>
          </div>

          {mode === "lookup" ? (
            <div className="flex gap-2">
              <input value={cveId} onChange={(e) => setCveId(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleLookup()}
                placeholder="CVE-2021-44228" className="flex-1 rounded-lg border border-border bg-background px-4 py-2 text-sm font-mono text-foreground" />
              <button onClick={handleLookup} disabled={loading} className="flex items-center gap-2 rounded-lg bg-primary px-6 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                {loading ? "Looking up..." : "Lookup"}
              </button>
            </div>
          ) : (
            <div className="flex gap-2">
              <input value={keyword} onChange={(e) => setKeyword(e.target.value)} onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                placeholder="Search keywords (e.g., log4j, apache, buffer overflow)..." className="flex-1 rounded-lg border border-border bg-background px-4 py-2 text-sm text-foreground" />
              <button onClick={handleSearch} disabled={loading} className="flex items-center gap-2 rounded-lg bg-primary px-6 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90">
                {loading ? "Searching..." : "Search"}
              </button>
            </div>
          )}

          {error && <p className="mt-3 text-sm text-red-400 flex items-center gap-1"><AlertTriangle className="h-4 w-4" /> {error}</p>}
        </div>

        {/* Single CVE detail */}
        {singleCve && mode === "lookup" && <CVEDetailCard cve={singleCve} defaultExpanded />}

        {/* Search results */}
        {cveList.length > 0 && mode === "search" && (
          <div className="space-y-3">
            <p className="text-sm text-muted-foreground">{cveList.length} results found</p>
            {cveList.slice((page - 1) * pageSize, page * pageSize).map((cve) => {
              const cveKey = cve.cve_id || cve.id;
              return (
                <CVEDetailCard
                  key={cveKey}
                  cve={cve}
                  expanded={expandedId === cveKey}
                  onToggle={() => setExpandedId(expandedId === cveKey ? null : cveKey)}
                />
              );
            })}
            <div className="flex items-center justify-between pt-2 text-sm text-muted-foreground">
              <span>Showing {Math.min(pageSize, Math.max(cveList.length - (page - 1) * pageSize, 0))} entries on page {page}</span>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => setPage((p) => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="rounded border border-border px-3 py-1 disabled:opacity-50"
                >
                  Previous
                </button>
                <span>Page {page} / {Math.max(1, Math.ceil(cveList.length / pageSize))}</span>
                <button
                  onClick={() => setPage((p) => p + 1)}
                  disabled={page >= Math.max(1, Math.ceil(cveList.length / pageSize))}
                  className="rounded border border-border px-3 py-1 disabled:opacity-50"
                >
                  Next
                </button>
              </div>
            </div>
          </div>
        )}
      </main>
    </div>
  );
}

function CVEDetailCard({ cve, defaultExpanded, expanded, onToggle }: { cve: CVE; defaultExpanded?: boolean; expanded?: boolean; onToggle?: () => void }) {
  const isExpanded = defaultExpanded || expanded;
  const score = cve.cvss_score ?? undefined;
  const cveKey = cve.cve_id || cve.id;
  const sourceLabel = cve.source || "NVD API";
  const referenceSources = Array.from(
    new Set(
      (cve.references || [])
        .map((ref) => (typeof ref === "string" ? "" : ref.source || ""))
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );

  return (
    <div className="rounded-lg border border-border bg-card/50 backdrop-blur-sm overflow-hidden">
      <div className="w-full flex items-center justify-between px-6 py-4 hover:bg-card/80 transition-colors">
        <div className="flex items-center gap-4 min-w-0">
          <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-bold border whitespace-nowrap ${cvssColor(score)}`}>
            {score ? score.toFixed(1) : "N/A"} — {cvssLabel(score)}
          </span>
          <button
            onClick={() => copyText(cveKey)}
            className="font-mono text-sm font-semibold text-primary select-text hover:underline"
            title="Click to copy CVE"
            type="button"
          >
            {cveKey}
          </button>
          <span className="text-sm text-muted-foreground max-w-[500px] truncate select-text">{cve.description?.slice(0, 100)}...</span>
        </div>
        {onToggle && (
          <button onClick={onToggle} type="button" className="rounded border border-border p-1.5 text-muted-foreground hover:text-foreground" title={isExpanded ? "Collapse" : "Expand"}>
            {isExpanded ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>
        )}
      </div>

      {isExpanded && (
        <div className="px-6 pb-6 border-t border-border pt-4 space-y-4">
          <div>
            <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Description</h4>
            <p className="text-sm text-foreground leading-relaxed select-text">{cve.description}</p>
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Published</h4>
              <p className="text-sm text-foreground flex items-center gap-1"><Clock className="h-3.5 w-3.5" /> {cve.published ? new Date(cve.published).toLocaleDateString() : "N/A"}</p>
            </div>
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Modified</h4>
              <p className="text-sm text-foreground">{cve.modified ? new Date(cve.modified).toLocaleDateString() : "N/A"}</p>
            </div>
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">CVSS Vector</h4>
              <button
                onClick={() => copyText(cve.cvss_vector || "")}
                className="text-xs font-mono text-muted-foreground select-text hover:text-foreground"
                title={cve.cvss_vector ? "Click to copy vector" : "CVSS vector not provided"}
                type="button"
              >
                {cve.cvss_vector || "Not provided by source"}
              </button>
            </div>
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-1">Source</h4>
              <p className="text-sm text-foreground select-text">{sourceLabel}</p>
              {referenceSources.length > 0 && (
                <p className="text-xs text-muted-foreground mt-1 select-text">Refs: {referenceSources.slice(0, 4).join(", ")}</p>
              )}
            </div>
          </div>

          {cve.affected_products && cve.affected_products.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">Affected Products</h4>
              <div className="flex flex-wrap gap-2">
                {cve.affected_products.map((p, i) => (
                  <span key={i} className="rounded-full border border-border px-2.5 py-0.5 text-xs text-muted-foreground">{p}</span>
                ))}
              </div>
            </div>
          )}

          {cve.references && cve.references.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">References</h4>
              <div className="space-y-1">
                {cve.references.slice(0, 5).map((ref, i) => {
                  const url = typeof ref === "string" ? ref : ref.url;
                  return (
                    <a key={i} href={url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 text-xs text-primary hover:underline truncate">
                      <ExternalLink className="h-3 w-3 flex-shrink-0" /> {url}
                    </a>
                  );
                })}
              </div>
            </div>
          )}

          {cve.mitre_techniques && cve.mitre_techniques.length > 0 && (
            <div>
              <h4 className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2 flex items-center gap-1"><Layers className="h-3.5 w-3.5" /> MITRE ATT&CK Mapping</h4>
              <div className="flex flex-wrap gap-2">
                {cve.mitre_techniques.map((t, i) => (
                  <span key={i} className="rounded-full bg-primary/10 border border-primary/30 px-2.5 py-0.5 text-xs text-primary font-mono">{typeof t === "string" ? t : t.id}</span>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
