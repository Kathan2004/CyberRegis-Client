"use client";

import { useState, useEffect } from "react";
import { Shield, FileText, Download, RefreshCw, Target, Calendar, AlertTriangle, CheckCircle, TrendingUp, Clock } from "lucide-react";
import Link from "next/link";
import * as api from "@/app/lib/api";

interface ReportTarget {
  target: string;
  scan_count: number;
  scan_types?: string[];
  last_scanned: string;
  first_scanned?: string;
}

interface Report {
  target: string;
  report_type: string;
  generated_at: string;
  total_scans: number;
  unique_targets: number;
  executive_summary: {
    target: string;
    overall_risk: string;
    scan_coverage: string[];
    total_assessments: number;
    findings_count: number;
  };
  scan_results: Record<string, Array<{ id: string; target: string; risk_level: string; score: number; summary: string; created_at: string }>>;
  risk_assessment: {
    distribution: Record<string, number>;
    overall_score: number;
    high_critical_count: number;
    total_assessed: number;
  };
  recommendations: Array<{ text: string; category: string; severity: string }>;
  timeline: Array<{ time: string; type: string; target: string; risk_level: string; summary: string }>;
}

export default function ReportsPage() {
  const [targets, setTargets] = useState<ReportTarget[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [report, setReport] = useState<Report | null>(null);
  const [selectedTarget, setSelectedTarget] = useState("");
  const [dateRange, setDateRange] = useState("30");

  useEffect(() => {
    (async () => {
      try {
        const res = await api.getReportTargets();
        setTargets(res.data?.targets || []);
      } catch (e) { console.error("Failed to load targets:", e); }
    })();
  }, []);

  const handleGenerate = async () => {
    setGenerating(true);
    try {
      const params: Record<string, string | number> = {};
      if (selectedTarget) params.target = selectedTarget;
      if (dateRange) params.days = parseInt(dateRange);
      const res = await api.generateReport(params);
      if (res.status === "success") setReport(res.data as unknown as Report);
    } catch (e) { console.error("Report generation failed:", e); }
    setGenerating(false);
  };

  const riskColor = (level: string) => {
    const l = level?.toLowerCase();
    if (l === "critical") return "text-red-500";
    if (l === "high") return "text-orange-500";
    if (l === "medium") return "text-yellow-500";
    return "text-green-400";
  };

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
            <Link href="/history" className="text-muted-foreground hover:text-primary transition-colors">Scan History</Link>
            <Link href="/reports" className="text-primary font-semibold">Reports</Link>
            <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
          </nav>
        </div>
      </header>

      <main className="w-full px-6 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground flex items-center gap-3">
            <FileText className="h-8 w-8 text-primary" /> Security Reports
          </h1>
          <p className="mt-2 text-muted-foreground">Generate executive-level security assessment reports with risk analysis and recommendations.</p>
        </div>

        {/* Report config */}
        <div className="mb-8 rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
          <h3 className="text-lg font-semibold text-foreground mb-4">Generate Report</h3>
          <div className="flex items-end gap-4 flex-wrap">
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Target (optional)</label>
              <select value={selectedTarget} onChange={(e) => setSelectedTarget(e.target.value)} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground min-w-[200px]">
                <option value="">All Targets</option>
                {targets.map((t) => <option key={t.target} value={t.target}>{t.target} ({t.scan_count} scans)</option>)}
              </select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground block mb-1">Time Range</label>
              <select value={dateRange} onChange={(e) => setDateRange(e.target.value)} className="rounded-lg border border-border bg-background px-3 py-2 text-sm text-foreground">
                <option value="7">Last 7 Days</option>
                <option value="30">Last 30 Days</option>
                <option value="90">Last 90 Days</option>
                <option value="365">Last Year</option>
              </select>
            </div>
            <button onClick={handleGenerate} disabled={generating} className="flex items-center gap-2 rounded-lg bg-primary px-6 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 transition-colors">
              <RefreshCw className={`h-4 w-4 ${generating ? "animate-spin" : ""}`} />
              {generating ? "Generating..." : "Generate Report"}
            </button>
          </div>
        </div>

        {/* Scanned targets overview */}
        {targets.length > 0 && !report && (
          <div className="mb-8">
            <h3 className="text-lg font-semibold text-foreground mb-4">Scanned Targets</h3>
            <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {targets.map((t) => (
                <div key={t.target} className="rounded-lg border border-border bg-card/50 p-4 backdrop-blur-sm">
                  <div className="flex items-center gap-2 mb-2">
                    <Target className="h-4 w-4 text-primary" />
                    <span className="font-mono text-sm text-foreground font-medium">{t.target}</span>
                  </div>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>{t.scan_count} scans</span>
                    <span>{t.scan_types?.join(", ") || "—"}</span>
                  </div>
                  <div className="mt-1 text-xs text-muted-foreground flex items-center gap-1">
                    <Clock className="h-3 w-3" /> Last: {new Date(t.last_scanned).toLocaleDateString()}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Generated Report */}
        {report && (
          <div className="space-y-6">
            {/* Executive Summary */}
            <div className="rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
              <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                <TrendingUp className="h-5 w-5 text-primary" /> Executive Summary
              </h3>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">
                <div className="rounded-lg border border-border p-3">
                  <div className="text-xs text-muted-foreground">Total Scans</div>
                    <div className="text-2xl font-bold text-foreground mt-1">{report.executive_summary.total_assessments ?? report.total_scans}</div>
                </div>
                <div className="rounded-lg border border-border p-3">
                  <div className="text-xs text-muted-foreground">Unique Targets</div>
                    <div className="text-2xl font-bold text-foreground mt-1">{report.unique_targets ?? "—"}</div>
                </div>
                <div className="rounded-lg border border-border p-3">
                    <div className="text-xs text-muted-foreground">Overall Score</div>
                    <div className={`text-2xl font-bold mt-1 ${riskColor(report.executive_summary.overall_risk)}`}>{report.risk_assessment.overall_score ?? "N/A"}</div>
                </div>
                <div className="rounded-lg border border-border p-3">
                  <div className="text-xs text-muted-foreground">Risk Level</div>
                    <div className={`text-2xl font-bold mt-1 uppercase ${riskColor(report.executive_summary.overall_risk)}`}>{report.executive_summary.overall_risk || "N/A"}</div>
                </div>
              </div>

                <div className="flex flex-wrap gap-2 mt-2">
                  {report.executive_summary.scan_coverage?.map((c, i) => (
                    <span key={i} className="rounded-full border border-primary/30 bg-primary/10 px-3 py-0.5 text-xs text-primary font-mono">{c}</span>
                  ))}
                </div>
                {report.executive_summary.findings_count > 0 && (
                  <div className="mt-3 flex items-center gap-2 text-sm text-orange-400">
                    <AlertTriangle className="h-4 w-4" />
                    {report.executive_summary.findings_count} high/critical finding{report.executive_summary.findings_count !== 1 ? "s" : ""} detected
                  </div>
                )}
            </div>

              {/* Risk Assessment */}
              {report.risk_assessment?.distribution && (
              <div className="rounded-lg border border-border bg-card/50 p-6 backdrop-blur-sm">
                  <h3 className="text-lg font-semibold text-foreground mb-4">Risk Distribution</h3>
                  <div className="grid grid-cols-3 sm:grid-cols-6 gap-3 mb-4">
                    {Object.entries(report.risk_assessment.distribution).map(([level, count]) => (
                      <div key={level} className="rounded-lg border border-border p-3 text-center">
                        <div className={`text-xl font-bold ${riskColor(level)}`}>{count as number}</div>
                        <div className="text-xs text-muted-foreground mt-1 capitalize">{level}</div>
                      </div>
                  ))}
                </div>
                  <div className="flex items-center gap-3">
                    <div className="flex-1 bg-background rounded-full h-3 overflow-hidden">
                      <div className="h-full rounded-full bg-primary transition-all"
                        style={{ width: `${Math.min(100, report.risk_assessment.overall_score)}%` }} />
                    </div>
                    <span className={`text-sm font-bold ${riskColor(report.executive_summary.overall_risk)}`}>
                      Score: {report.risk_assessment.overall_score}/100
                    </span>
                  </div>
              </div>
            )}

              {/* Scan Breakdown */}
              {report.scan_results && Object.keys(report.scan_results).length > 0 && (
              <div className="rounded-lg border border-border bg-card/50 p-6 backdrop-blur-sm">
                <h3 className="text-lg font-semibold text-foreground mb-4">Scan Type Breakdown</h3>
                <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                    {Object.entries(report.scan_results).map(([type, scans]) => (
                    <div key={type} className="rounded-lg border border-border p-3 text-center">
                        <div className="text-2xl font-bold text-primary">{Array.isArray(scans) ? scans.length : 0}</div>
                      <div className="text-xs text-muted-foreground mt-1">{type.replace("_", " ")}</div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Recommendations */}
            {report.recommendations?.length > 0 && (
              <div className="rounded-lg border border-primary/20 bg-card/50 p-6 backdrop-blur-sm">
                <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                  <CheckCircle className="h-5 w-5 text-primary" /> Recommendations
                </h3>
                <div className="space-y-2">
                  {report.recommendations.map((rec, i) => (
                    <div key={i} className="flex items-start gap-3 rounded-lg border border-border p-3">
                      <span className="flex-shrink-0 rounded-full bg-primary/10 border border-primary/30 w-6 h-6 flex items-center justify-center text-xs text-primary font-bold">{i + 1}</span>
                        <div className="flex-1">
                          <p className="text-sm text-foreground">{typeof rec === "string" ? rec : rec.text}</p>
                          {typeof rec !== "string" && (
                            <div className="flex gap-2 mt-1">
                              <span className={`text-xs px-2 py-0.5 rounded-full border ${rec.severity === "high" || rec.severity === "critical" ? "border-red-500/30 bg-red-500/10 text-red-400" : rec.severity === "medium" ? "border-yellow-500/30 bg-yellow-500/10 text-yellow-400" : "border-green-500/30 bg-green-500/10 text-green-400"}`}>{rec.severity}</span>
                              <span className="text-xs text-muted-foreground">{rec.category}</span>
                            </div>
                          )}
                        </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

              {/* Timeline */}
              {report.timeline?.length > 0 && (
                <div className="rounded-lg border border-border bg-card/50 p-6 backdrop-blur-sm">
                  <h3 className="text-lg font-semibold text-foreground mb-4 flex items-center gap-2">
                    <Clock className="h-5 w-5 text-primary" /> Recent Activity
                  </h3>
                  <div className="space-y-2 max-h-64 overflow-y-auto">
                    {report.timeline.map((evt, i) => (
                      <div key={i} className="flex items-center gap-4 rounded-lg border border-border p-3">
                        <span className="text-xs text-muted-foreground min-w-[140px]">{evt.time ? new Date(evt.time).toLocaleString() : "—"}</span>
                        <span className="font-mono text-xs text-primary px-2 py-0.5 rounded border border-primary/20 bg-primary/5">{evt.type}</span>
                        <span className="font-mono text-xs text-foreground flex-1">{evt.target}</span>
                        {evt.risk_level && <span className={`text-xs font-medium ${riskColor(evt.risk_level)}`}>{evt.risk_level}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Report metadata */}
              <div className="text-xs text-muted-foreground text-center pb-4">
                Report generated {new Date(report.generated_at).toLocaleString()} · {report.target}
              </div>
          </div>
        )}
      </main>
    </div>
  );
}
