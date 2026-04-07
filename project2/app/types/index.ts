/**
 * CyberRegis Threat Intelligence Platform — TypeScript Types
 * Shared type definitions for the entire application.
 */

// ─── API Response Wrapper ────────────────────────────────────
export interface ApiResponse<T = unknown> {
  status: "success" | "error";
  timestamp: string;
  data?: T;
  message?: string;
  error?: { message: string; code: string; details?: unknown };
  meta?: { total?: number; limit?: number; offset?: number; has_more?: boolean };
}

// ─── Legacy wrappers (URL check, IP check, chat) ────────────
export interface LegacyResponse<T = unknown> {
  status: string;
  timestamp: string;
  data: T;
  formatted?: string;
  scan_duration_ms?: number;
}

// ─── Domain Analysis ─────────────────────────────────────────
export interface DomainAnalysis {
  domain_info: DomainInfo;
  recommendations: DomainRecommendation[];
  risk_score: RiskScore;
  scan_duration_ms: number;
}

export interface DomainInfo {
  domain: string;
  whois: Record<string, string>;
  dns_records: Record<string, string[]>;
  dns_matrix?: {
    queried_types: string[];
    present_types: string[];
    missing_types: string[];
    coverage_percent: number;
  };
  ssl_info: {
    issuer?: string;
    subject?: string;
    valid_from?: string;
    valid_until?: string;
    days_until_expiry?: number;
    valid?: boolean;
    grade?: string;
  };
  security_features: SecurityFeatures;
  subdomains: string[];
  geolocation: Record<string, string>;
  technology?: Record<string, string>;
  shodan?: {
    enabled: boolean;
    dns?: Record<string, unknown>;
    resolve?: Record<string, string>;
    host?: { ip?: string; org?: string; isp?: string; asn?: string; ports?: number[]; vulns?: string[]; last_update?: string };
    dns_error?: string;
    resolve_error?: string;
    host_error?: string;
    error?: string;
  };
}

export interface SecurityFeatures {
  dnssec: boolean;
  dmarc: string;
  waf_detected: string;
  robots_txt: { present: boolean; url: string | null };
  security_txt: { present: boolean; url: string | null };
}

export interface DomainRecommendation {
  category: string;
  severity: string;
  text: string;
  mitre?: string | null;
}

export interface RiskScore {
  score: number;
  level: "critical" | "high" | "medium" | "low";
  factors: string[];
}

// ─── IP Intelligence ─────────────────────────────────────────
export interface IpAnalysis {
  ip_details: {
    address: string;
    domain: string;
    isp: string;
    location: { city: string; region: string; country: string; country_code: string };
  };
  risk_assessment: {
    risk_level: string;
    confidence_score: number;
    total_reports: number;
    last_reported: string;
    categories: string[];
  };
  technical_details: {
    as_name: string;
    asn: string;
    is_public: boolean;
    is_tor: boolean;
    usage_type: string;
    organization: string;
  };
  virustotal: VirusTotalResult;
  shodan?: {
    enabled: boolean;
    error?: string;
    ip?: string;
    org?: string;
    isp?: string;
    asn?: string;
    country?: string;
    city?: string;
    os?: string;
    ports?: number[];
    open_ports_count?: number;
    hostnames?: string[];
    tags?: string[];
    vulnerabilities?: string[];
    last_update?: string;
  };
  virustotal_summary: string;
  recommendations: string[];
  scan_duration_ms: number;
}

export interface VirusTotalResult {
  risk_assessment: {
    risk_score: number;
    risk_level: string;
    malicious_count: number;
    suspicious_count: number;
    detection_ratio: string;
    total_engines: number;
    harmless_count?: number;
    undetected_count?: number;
  };
  metadata: { reputation: number; file_type: string; analysis_date: string | null };
  data?: { attributes: { stats: Record<string, number>; results: Record<string, unknown> } };
  error?: string;
}

// ─── URL Analysis ────────────────────────────────────────────
export interface UrlAnalysis {
  url_analysis: {
    input_url: string;
    parsed_details: { scheme: string; domain: string; path: string; query_params: Record<string, string>; fragment: string };
    security_check_time: string;
  };
  threat_analysis: {
    is_malicious: boolean;
    threats_found: number;
    threat_details: unknown[];
    google_safe_browsing: { status: string; response_code?: number };
  };
  additional_checks: {
    ssl_security: { valid: boolean; error?: string; tls_version?: string; cipher?: string; issuer?: string; subject?: string; expires_in_days?: number };
    suspicious_patterns: { found: boolean; matches: string[]; risk_level: string; risk_score?: number; flags?: Record<string, boolean> };
    domain_analysis: { risk_score: number; risk_level: string; risk_factors: string[]; whois: Record<string, unknown> };
    http_behavior?: { status_code?: number; final_url?: string; redirect_count?: number; redirect_chain?: string[]; server?: string; powered_by?: string; content_type?: string; hsts_present?: boolean; set_cookie_count?: number; error?: string };
    shodan?: { enabled: boolean; error?: string; ip?: string; org?: string; isp?: string; asn?: string; ports?: number[]; tags?: string[]; vulnerabilities?: string[]; last_update?: string };
  };
  risk_summary?: { overall_risk_score: number; overall_risk_level: string; factors: string[] };
  recommendations: Array<string | { category: string; severity: string; text: string }>;
}

// ─── PCAP / Network ─────────────────────────────────────────
export interface PcapAnalysis {
  metadata: { filename: string; size_bytes: number; file_type: string };
  virustotal: VirusTotalResult;
  pcap_analysis: Record<string, number>;
  chart_base64: string;
  protocol_summary?: { total_packets: number; unique_protocols: number; top_protocols: { name: string; count: number; percentage: number }[] };
  network_insights?: {
    total_packets: number;
    total_bytes: number;
    capture_duration_seconds: number;
    avg_packets_per_second: number;
    packet_size_stats: { min: number; max: number; avg: number };
    top_source_ips: { ip: string; count: number; percentage: number }[];
    top_destination_ips: { ip: string; count: number; percentage: number }[];
    top_ports: { port: number; protocol: string; count: number; percentage: number }[];
    top_flows: { flow: string; packets: number }[];
    tcp_flags: { syn: number; ack: number; fin: number; rst: number; psh: number; urg: number };
  };
  suspicious_ips?: string[];
  potential_threats?: { type: string; severity: string; details?: string }[];
  scan_duration_ms: number;
}

// ─── Scanners ────────────────────────────────────────────────
export interface PortScanResult {
  status: string;
  target: string;
  host_info: { hostname: string; state: string; protocols: string[] };
  ports: PortInfo[];
  total_ports: number;
  scan_type: string;
  risk_summary: {
    open_ports: number;
    high_risk_ports: number;
    risk_level: string;
    attack_surface_score?: number;
    top_services?: { service: string; count: number }[];
    high_risk_port_details?: { port: number; service: string; reason: string }[];
    recommendations?: string[];
  };
  shodan?: { enabled: boolean; error?: string; ip?: string; org?: string; isp?: string; asn?: string; ports?: number[]; vulnerabilities?: string[]; last_update?: string };
  scan_duration_ms: number;
}

export interface PortInfo {
  port: number;
  protocol: string;
  state: string;
  service: string;
  version: string;
  product: string;
  extrainfo: string;
}

export interface VulnScanResult {
  status: string;
  target: string;
  vulnerabilities: VulnerabilityInfo[];
  total_found: number;
  scan_type: string;
  scan_duration_ms: number;
}

export interface VulnerabilityInfo {
  service: string;
  version: string;
  port: number;
  potential_issues: string[];
  severity: string;
  recommendation: string;
  confidence?: string;
  cve_examples?: string[];
  remediation_priority?: number;
  risk_score?: number;
}

// ─── Security Headers ────────────────────────────────────────
export interface SecurityHeadersResult {
  status: string;
  url: string;
  headers: Record<string, { present: boolean; value: string; score: number; max_score?: number; severity_if_missing?: string; recommendation?: string }>;
  security_score: number;
  max_score: number;
  grade: string;
  response_info?: { final_url?: string; status_code?: number; redirect_count?: number; server?: string; powered_by?: string };
  missing_headers?: string[];
  critical_missing_headers?: string[];
  hardening_summary?: {
    strengths?: string[];
    gaps?: string[];
    prioritized_remediation?: { header: string; severity: string; recommendation: string }[];
  };
  scan_duration_ms: number;
}

// ─── Email Security ──────────────────────────────────────────
export interface EmailSecurityResult {
  status: string;
  email_security: {
    domain: string;
    spf: { present: boolean; record?: string; score: number };
    dmarc: { present: boolean; record?: string; score: number };
    dkim: { present: boolean; selector?: string; score: number };
    total_score: number;
    max_score: number;
    grade: string;
  };
  scan_duration_ms: number;
}

// ─── IOC Management ──────────────────────────────────────────
export interface IOC {
  id: number;
  ioc_type: "ip" | "domain" | "url" | "hash" | "email";
  value: string;
  threat_type: string | null;
  severity: "critical" | "high" | "medium" | "low" | "info";
  source: string;
  tags: string[];
  description: string | null;
  first_seen: string;
  last_seen: string;
  is_active: number;
  mitre_ids: string[];
  reference_url?: string | null;
  lookup_links?: LookupLink[];
}

export interface LookupLink {
  label: string;
  url: string;
}

export interface IOCStats {
  total: number;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
  by_source: Record<string, number>;
}

// ─── Threat Feeds ────────────────────────────────────────────
export interface ThreatFeedEntry {
  id: number;
  feed_name: string;
  indicator: string;
  ioc_type: string;
  threat_type: string | null;
  confidence: number | null;
  description: string | null;
  reference: string | null;
  fetched_at: string;
  lookup_links?: LookupLink[];
}

export interface ThreatSourceTrendItem {
  label: string;
  percentage: string;
}

export interface OpenPhishInsights {
  status: string;
  homepage: string;
  community_feed: string;
  caveat: string;
  metrics: {
    urls_processed?: string;
    new_phishing_urls?: string;
    brands_targeted?: string;
  };
  top_brands: ThreatSourceTrendItem[];
  top_sectors: ThreatSourceTrendItem[];
  top_asns: ThreatSourceTrendItem[];
  error?: string;
}

export interface ThreatFeedInsights {
  fetched_at: string;
  openphish: OpenPhishInsights;
}

// ─── CVE ─────────────────────────────────────────────────────
export interface CVE {
  id: string;
  cve_id?: string;
  description: string;
  severity?: string;
  cvss_score?: number | null;
  cvss_vector?: string;
  published?: string | null;
  modified?: string | null;
  source?: string;
  references?: (string | { url: string; source?: string })[];
  affected_products?: string[];
  affected?: { criteria: string; vulnerable: boolean; version_start?: string; version_end?: string }[];
  weaknesses?: string[];
  mitre_techniques?: (string | { id: string; name?: string })[];
}

// ─── MITRE ATT&CK ───────────────────────────────────────────
export interface MitreTactic {
  id: string;
  name: string;
  description: string;
}

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  mitigations: string[];
  detection: string[];
}

// ─── Scan History ────────────────────────────────────────────
export interface ScanHistoryEntry {
  id: number;
  scan_type: string;
  target: string;
  status: string;
  risk_level?: string | null;
  risk_score?: number | null;
  score?: number | null;
  result?: unknown;
  result_summary?: unknown;
  summary?: string | null;
  timestamp: string;
  created_at?: string;
  scan_duration_ms?: number | null;
  duration_ms?: number | null;
}

// ─── Dashboard Stats ─────────────────────────────────────────
export interface DashboardStats {
  // Nested shape returned by /api/dashboard/stats
  scans?: {
    total_scans: number;
    by_type: Record<string, number>;
    today: number;
    risk_distribution: Record<string, number>;
    hourly_trend: Record<string, number>;
    top_targets: { target: string; count: number }[];
  };
  iocs?: IOCStats;
  // Flat shape (forward-compat)
  total_scans?: number;
  unique_targets?: number;
  avg_risk_score?: number | null;
  scans_last_24h?: number;
}

// ─── Reports ─────────────────────────────────────────────────
export interface SecurityReport {
  target: string;
  report_type: string;
  generated_at: string;
  executive_summary: {
    target: string;
    overall_risk: string;
    scan_coverage: string[];
    total_assessments: number;
    findings_count: number;
  };
  scan_results: Record<string, unknown[]>;
  risk_assessment: {
    distribution: Record<string, number>;
    overall_score: number;
    high_critical_count: number;
    total_assessed: number;
  };
  recommendations: { text: string; category: string; severity: string }[];
  timeline: { time: string; type: string; target: string; risk_level: string; summary: string }[];
  total_scans: number;
}

// ─── Chat ────────────────────────────────────────────────────
export interface ChatMessage {
  id: number;
  role: "user" | "assistant";
  content: string;
  timestamp?: string;
}

// ─── Common ──────────────────────────────────────────────────
export type ScanType = "domain" | "ip" | "url" | "pcap" | "port" | "vuln" | "headers" | "email" | "ssl";

export interface StoredScan {
  key: string;
  target: string;
  timestamp: string;
  data: unknown;
  scanType: ScanType;
}
