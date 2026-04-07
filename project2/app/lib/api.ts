/**
 * CyberRegis API Service
 * Centralized, type-safe API client for all backend endpoints.
 */
import type {
  ApiResponse, LegacyResponse,
  DomainAnalysis, IpAnalysis, UrlAnalysis, PcapAnalysis,
  PortScanResult, VulnScanResult, SecurityHeadersResult, EmailSecurityResult,
  IOC, IOCStats, ThreatFeedEntry, CVE, ThreatFeedInsights,
  MitreTactic, MitreTechnique,
  ScanHistoryEntry, DashboardStats, SecurityReport,
} from "@/app/types";

const API_URL = process.env.NEXT_PUBLIC_BACKEND_URL || "http://localhost:5000";

/** Generic fetch wrapper with error handling. */
async function apiFetch<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${API_URL}${path}`;
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json", ...options.headers as Record<string,string> },
    ...options,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body?.error?.message || `HTTP ${res.status}`);
  }
  return res.json();
}

/** POST helper. */
function apiPost<T>(path: string, body: Record<string, unknown>): Promise<T> {
  return apiFetch<T>(path, { method: "POST", body: JSON.stringify(body) });
}

// ─── Domain Analysis ─────────────────────────────────────────

export async function analyzeDomain(domain: string) {
  return apiPost<ApiResponse<DomainAnalysis>>("/api/analyze-domain", { domain });
}

export async function fetchSecurityFile(domain: string, fileType: "robots" | "security") {
  return apiPost<ApiResponse<{ domain: string; file_type: string; url: string; content: string; content_length: number }>>
    ("/api/security-file-content", { domain, file_type: fileType });
}

/** Alias used by dashboard page. */
export async function getSecurityFileContent(domain: string, fileType: "robots" | "security") {
  const url = `${API_URL}/api/security-file-content`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ domain, file_type: fileType }),
  });
  return res.json();
}

// ─── URL Analysis ────────────────────────────────────────────

export async function checkUrl(url: string) {
  return apiPost<LegacyResponse<UrlAnalysis>>("/api/check-url", { url });
}

// ─── IP Intelligence ─────────────────────────────────────────

export async function checkIp(ip: string) {
  return apiPost<LegacyResponse<IpAnalysis>>("/api/check-ip", { ip });
}

// ─── PCAP Analysis ───────────────────────────────────────────

export async function analyzePcap(file: File) {
  const formData = new FormData();
  formData.append("file", file);
  return apiFetch<ApiResponse<PcapAnalysis>>("/api/analyze-pcap", {
    method: "POST",
    body: formData,
    headers: {}, // Let browser set content-type for multipart
  });
}

// ─── Port Scanner ────────────────────────────────────────────

export async function scanPorts(target: string) {
  return apiPost<ApiResponse<PortScanResult>>("/api/scan-ports", { target });
}

// ─── Vulnerability Scan ──────────────────────────────────────

export async function scanVulnerabilities(target: string) {
  return apiPost<ApiResponse<VulnScanResult>>("/api/vulnerability-scan", { target });
}

// ─── SSL Analysis ────────────────────────────────────────────

export async function analyzeSSL(domain: string) {
  return apiPost<ApiResponse>("/api/ssl-analysis", { domain });
}

// ─── Security Headers ────────────────────────────────────────

export async function scanSecurityHeaders(url: string) {
  return apiPost<ApiResponse<SecurityHeadersResult>>("/api/security-headers", { url });
}

// ─── Email Security ──────────────────────────────────────────

export async function scanEmailSecurity(domain: string) {
  return apiPost<ApiResponse<EmailSecurityResult>>("/api/email-security", { domain });
}

// ─── Chat ────────────────────────────────────────────────────

export async function sendChatMessage(message: string) {
  return apiPost<LegacyResponse<{ response: string }>>("/api/chat", { message });
}

// ─── IOC Management ──────────────────────────────────────────

export async function getIOCs(params?: {
  type?: string; severity?: string; source?: string; q?: string; limit?: number; offset?: number;
}) {
  const qs = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined) qs.set(k, String(v)); });
  }
  return apiFetch<ApiResponse<{ iocs: IOC[]; stats: IOCStats }>>(`/api/iocs?${qs}`);
}

export async function createIOC(ioc: {
  ioc_type: string; value: string; threat_type?: string; severity?: string;
  source?: string; tags?: string[]; description?: string; mitre_ids?: string[];
}) {
  return apiPost<ApiResponse<{ id: number; value: string }>>("/api/iocs", ioc as Record<string, unknown>);
}

export async function deleteIOC(id: number) {
  return apiFetch<ApiResponse>(`/api/iocs/${id}`, { method: "DELETE" });
}

export async function checkIOC(value: string) {
  return apiPost<ApiResponse<{ match: boolean; ioc: IOC | null }>>("/api/iocs/check", { value });
}

// ─── Threat Feeds ────────────────────────────────────────────

export async function getThreatFeeds(feed?: string, limit?: number, offset?: number) {
  const qs = new URLSearchParams();
  if (feed) qs.set("feed", feed);
  if (limit) qs.set("limit", String(limit));
  if (offset) qs.set("offset", String(offset));
  return apiFetch<ApiResponse<{ entries: ThreatFeedEntry[]; total: number }>>(`/api/threat-feeds?${qs}`);
}

export async function refreshThreatFeeds() {
  return apiPost<ApiResponse>("/api/threat-feeds/refresh", {});
}

export async function getThreatFeedInsights(refresh = false) {
  return apiFetch<ApiResponse<ThreatFeedInsights>>(`/api/threat-feeds/insights${refresh ? "?refresh=true" : ""}`);
}

export async function searchThreatFeeds(query: string) {
  return apiFetch<ApiResponse<{ results: ThreatFeedEntry[]; total: number }>>
    (`/api/threat-feeds/search?q=${encodeURIComponent(query)}`);
}

// ─── CVE Lookup ──────────────────────────────────────────────

export async function lookupCVE(cveId: string) {
  return apiFetch<ApiResponse<{ cve: CVE; source: string }>>(`/api/cve/${cveId}`);
}

export async function searchCVEs(query: string, limit = 100) {
  return apiFetch<ApiResponse<{ cves: CVE[]; results?: CVE[]; total: number }>>
    (`/api/cve/search?q=${encodeURIComponent(query)}&limit=${limit}`);
}

export async function getIntelCatalog(limitKev = 50) {
  return apiFetch<ApiResponse>(`/api/intel/catalog?limit_kev=${limitKev}`);
}

// ─── MITRE ATT&CK ───────────────────────────────────────────

export async function getMitreTactics() {
  return apiFetch<ApiResponse<{ tactics: MitreTactic[] }>>("/api/mitre/tactics");
}

export async function getMitreTechniques(params?: { tactic?: string; q?: string }) {
  const qs = new URLSearchParams();
  if (params?.tactic) qs.set("tactic", params.tactic);
  if (params?.q) qs.set("q", params.q);
  return apiFetch<ApiResponse<{ techniques: MitreTechnique[]; total: number }>>(`/api/mitre/techniques?${qs}`);
}

export async function getMitreTechnique(id: string) {
  return apiFetch<ApiResponse<MitreTechnique>>(`/api/mitre/technique/${id}`);
}

// ─── Dashboard & Monitoring ──────────────────────────────────

export async function getDashboardStats() {
  return apiFetch<ApiResponse<DashboardStats>>("/api/dashboard/stats");
}

export async function getScanHistory(params?: Record<string, string | number>) {
  const qs = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([k, v]) => { if (v !== undefined) qs.set(k, String(v)); });
  }
  return apiFetch<ApiResponse<{ scans: ScanHistoryEntry[]; total: number }>>(`/api/scan-history?${qs}`);
}

export async function getHealthStatus() {
  return apiFetch<ApiResponse<{ service: string; version: string; status: string; uptime_seconds: number }>>("/api/health");
}

export async function getSystemStatus() {
  return apiFetch<ApiResponse>("/api/status");
}

// ─── Reports ─────────────────────────────────────────────────

export async function generateReport(params: Record<string, string | number> = {}) {
  return apiPost<ApiResponse<SecurityReport>>("/api/reports/generate", params);
}

export async function getReportTargets() {
  return apiFetch<ApiResponse<{ targets: { target: string; scan_count: number; last_scanned: string; first_scanned: string }[] }>>
    ("/api/reports/targets");
}
