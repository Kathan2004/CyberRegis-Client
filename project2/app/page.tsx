"use client";

import { useState, useEffect, useRef } from "react";
import { Shield, Globe, Network, Eye, Activity, FileText, BarChart4, Upload, FileUp, MessageSquare, ExternalLink, X } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { loadStoredScans, StoredScan, upsertStoredScan } from "@/lib/cache";

// Define interface for API responses
interface ScanResult {
  data?: {
    url_analysis?: {
      input_url: string;
      parsed_details?: {
        domain: string;
        scheme: string;
        path: string;
        fragment?: string;
        query_params?: any;
      };
      security_check_time?: string;
    };
    threat_analysis?: {
      is_malicious: boolean;
      threats_found?: number;
      threat_details?: any[];
      google_safe_browsing?: {
        status: string;
        response_code: number;
      };
    };
    additional_checks?: {
      domain_analysis?: {
        risk_level: string;
        risk_score?: number;
        risk_factors?: string[];
        analysis?: {
          length: number;
          subdomains: number;
          suspicious_tld: boolean;
          special_chars: boolean;
          number_substitution: boolean;
        };
        whois?: {
          registrar: string;
          creation_date: string;
          expiration_date: string;
          name_servers: string[];
          status: string;
        };
      };
      ssl_security?: {
        valid: boolean;
        status_code?: number;
      };
      suspicious_patterns?: {
        risk_level: string;
        found: boolean;
        matches?: string[];
      };
    };
    protocols?: { [protocol: string]: number };
    metadata?: { [key: string]: string | number };
    suspicious_ips?: string[];
    potential_threats?: { type: string; severity: string; source?: string; domain?: string }[];
    recommendations?: string[];
    message?: string;
    response?: string;
    virustotal?: {
      data?: {
        attributes?: {
          stats?: { [key: string]: number };
          results?: { [engine: string]: { category: string; result: string } };
        };
      };
      // Enhanced security analysis structure
      risk_assessment?: {
        risk_score: number;
        risk_level: 'HIGH' | 'MEDIUM' | 'LOW' | 'VERY_LOW' | 'UNKNOWN';
        malicious_count: number;
        suspicious_count: number;
        detection_ratio: string;
        total_engines: number;
      };
      metadata?: {
        reputation?: number;
        file_type?: string;
        analysis_date?: number;
      };
      error?: string;
    };
    virustotal_summary?: string;
    pcap_analysis?: { [protocol: string]: number };
    chart_base64?: string;
    // IP-specific fields that might be nested under data
    ip_details?: {
      address: string;
      domain?: string;
      hostname?: string[];
      isp?: string;
      location?: {
        city?: string | null;
        country?: string;
        country_code?: string;
        region?: string | null;
      };
    };
    risk_assessment?: {
      confidence_score: number;
      last_reported?: string;
      risk_level: string;
      total_reports: number;
      whitelisted: boolean;
    };
    technical_details?: {
      as_name?: string | null;
      asn?: string | null;
      is_public: boolean;
      is_tor: boolean;
      usage_type?: string;
    };
    // Advanced Scanner fields
    ports?: Array<{
      port: number;
      protocol: string;
      state: string;
      service?: string;
      version?: string;
      product?: string;
      extrainfo?: string;
    }>;
    host_info?: {
      hostname?: string;
      state: string;
      protocols?: string[];
    };
    vulnerabilities?: Array<{
      service: string;
      version?: string;
      product?: string;
      port?: number;
      potential_issues: string[];
      severity: string;
      recommendation?: string;
    }>;
    ssl_analysis?: {
      basic_info?: any;
      cipher_info?: any;
      domain?: string;
      timestamp?: string;
    };
    // Security Scanner fields
    headers?: {
      [headerName: string]: {
        present: boolean;
        value?: string;
        score?: number;
      };
    };
    security_score?: number;
    max_score?: number;
    grade?: string;
    email_security?: {
      domain?: string;
      spf: {
        present: boolean;
        score: number;
        record?: string;
      };
      dmarc: {
        present: boolean;
        score: number;
        record?: string;
      };
      dkim: {
        present: boolean;
        score: number;
        selector?: string;
      };
      total_score: number;
      max_score: number;
      grade: string;
      timestamp?: string;
    };
  };
  // IP-specific fields
  ip_details?: {
    address: string;
    domain?: string;
    hostname?: string[];
    isp?: string;
    location?: {
      city?: string | null;
      country?: string;
      country_code?: string;
      region?: string | null;
    };
  };
  risk_assessment?: {
    confidence_score: number;
    last_reported?: string;
    risk_level: string;
    total_reports: number;
    whitelisted: boolean;
  };
  technical_details?: {
    as_name?: string | null;
    asn?: string | null;
    is_public: boolean;
    is_tor: boolean;
    usage_type?: string;
  };
  // Domain reconnaissance specific fields
  domain_info?: {
    domain: string;
    whois?: {
      registrar?: string;
      creation_date?: string;
      expiration_date?: string;
      registrant?: string;
      country?: string;
      name_servers?: string[];
    };
    dns_records?: {
      A?: string[];
      AAAA?: string[];
      MX?: string[];
      NS?: string[];
      CNAME?: string[];
      TXT?: string[];
      SOA?: string[];
    };
    ssl_info?: {
      valid?: boolean;
      issuer?: string;
      subject?: string;
      valid_from?: string;
      valid_until?: string;
      days_until_expiry?: number;
      grade?: string;
    };
    subdomains?: string[];
    security_features?: {
      dnssec?: boolean;
      dmarc?: string;
      spf?: string;
      waf_detected?: string;
      robots_txt?: {
        present: boolean;
        url?: string;
      };
      security_txt?: {
        present: boolean;
        url?: string;
      };
    };
    geolocation?: {
      ip?: string;
      country?: string;
      city?: string;
      isp?: string;
      organization?: string;
    };
  };
  recommendations?: string[];
  formatted?: string;
  status: "success" | "error";
  timestamp?: string;
  message?: string;

  // Advanced Scanner fields (root level)
  ports?: Array<{
    port: number;
    protocol: string;
    state: string;
    service?: string;
    version?: string;
    product?: string;
    extrainfo?: string;
  }>;
  host_info?: {
    hostname?: string;
    state: string;
    protocols?: string[];
  };
  vulnerabilities?: Array<{
    service: string;
    version?: string;
    product?: string;
    port?: number;
    potential_issues: string[];
    severity: string;
    recommendation?: string;
  }>;

  // Security Scanner fields (root level)
  headers?: {
    [headerName: string]: {
      present: boolean;
      value?: string;
      score?: number;
    };
  };
  security_score?: number;
  max_score?: number;
  grade?: string;
  email_security?: {
    domain?: string;
    spf: {
      present: boolean;
      score: number;
      record?: string;
    };
    dmarc: {
      present: boolean;
      score: number;
      record?: string;
    };
    dkim: {
      present: boolean;
      score: number;
      selector?: string;
    };
    total_score: number;
    max_score: number;
    grade: string;
    timestamp?: string;
  };
}

// Interface for chatbot messages
interface ChatMessage {
  id: number;
  text: string;
  isUser: boolean;
  timestamp: string | null;
}

export default function Home() {
  const [integratedInput, setIntegratedInput] = useState("");
  const [integratedResults, setIntegratedResults] = useState<{
    urlResults: ScanResult | null;
    domainResults: ScanResult | null;
  } | null>(null);
  const [integratedLoading, setIntegratedLoading] = useState(false);
  const [integratedViewMode, setIntegratedViewMode] = useState<'normal' | 'json'>('normal');
  const [ip, setIp] = useState("");
  const [ipResults, setIpResults] = useState<ScanResult | null>(null);
  const [logResults, setLogResults] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isCached, setIsCached] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 1,
      text: "Hey! How can I assist you with your cybersecurity concerns today? Do you have a specific question or issue you'd like help with?",
      isUser: false,
      timestamp: null,
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const chatScrollRef = useRef<HTMLDivElement>(null);

  // View mode states for each scan type
  const [ipViewMode, setIpViewMode] = useState<'normal' | 'json'>('normal');
  const [logViewMode, setLogViewMode] = useState<'normal' | 'json'>('normal');

  // File content modal state
  const [fileContent, setFileContent] = useState<{
    domain: string;
    file_type: string;
    url: string;
    content: string;
    content_length: number;
    last_modified: string;
    content_type: string;
  } | null>(null);
  const [fileModalOpen, setFileModalOpen] = useState(false);
  const [loadingFile, setLoadingFile] = useState(false);

  // Advanced Scanner states
  const [portTarget, setPortTarget] = useState("");
  const [portResults, setPortResults] = useState<any>(null);
  const [portLoading, setPortLoading] = useState(false);
  const [portViewMode, setPortViewMode] = useState<'normal' | 'json'>('normal');

  const [vulnTarget, setVulnTarget] = useState("");
  const [vulnResults, setVulnResults] = useState<any>(null);
  const [vulnLoading, setVulnLoading] = useState(false);
  const [vulnViewMode, setVulnViewMode] = useState<'normal' | 'json'>('normal');


  // Security Scanner states
  const [headerUrl, setHeaderUrl] = useState("");
  const [headerResults, setHeaderResults] = useState<any>(null);
  const [headerLoading, setHeaderLoading] = useState(false);
  const [headerViewMode, setHeaderViewMode] = useState<'normal' | 'json'>('normal');

  const [emailDomain, setEmailDomain] = useState("");
  const [emailResults, setEmailResults] = useState<any>(null);
  const [emailLoading, setEmailLoading] = useState(false);
  const [emailViewMode, setEmailViewMode] = useState<'normal' | 'json'>('normal');

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000";

  useEffect(() => {
    // Set initial chat message timestamp on client side to avoid hydration mismatch
    setChatMessages(prev => prev.map(msg =>
      msg.id === 1 ? { ...msg, timestamp: new Date().toLocaleTimeString() } : msg
    ));
  }, []);

  const checkIp = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    setIsCached(false);

    // Check localStorage
    const storedIps = loadStoredScans("cyberregis_ips");
    const cached = storedIps.find((scan) => scan.input === ip);
    if (cached) {
      setIpResults(cached.result);
      setIsCached(true);
      setLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/check-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      const data = await response.json();
      console.log("IP scan response:", data);
      console.log("Security analysis data in response:", data.virustotal || data.data?.virustotal);
      setIpResults(data);

      upsertStoredScan("cyberregis_ips", {
        input: ip,
        result: data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setIpResults({
        status: "error",
        message: "Failed to check IP. Please try again.",
      });
      console.error("Error checking IP:", error);
    }
    setLoading(false);
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      setSelectedFile(e.target.files[0]);
    }
  };

  const handleFileUploadClick = () => {
    if (fileInputRef.current) {
      fileInputRef.current.click();
    }
  };

  const analyzeNetworkLog = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!selectedFile) {
      setLogResults({
        status: "error",
        message: "Please select a file to analyze.",
      });
      return;
    }

    setLoading(true);
    setIsCached(false);

    // Check localStorage (using file name as key)
    const storedLogs = loadStoredScans("cyberregis_logs");
    const cached = storedLogs.find((scan) => scan.input === selectedFile.name);
    if (cached) {
      setLogResults(cached.result);
      setIsCached(true);
      setLoading(false);
      return;
    }

    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      console.log("Uploading file:", selectedFile.name, selectedFile.size);

      const response = await fetch(`${API_URL}/api/analyze-pcap`, {
        method: "POST",
        body: formData,
      });

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error("Server error:", response.status, errorData);
        throw new Error(errorData.message || `Server responded with status: ${response.status}`);
      }

      const data = await response.json();
      console.log("Analysis response:", data);
      setLogResults(data);

      // Store in localStorage
      upsertStoredScan("cyberregis_logs", {
        input: selectedFile.name,
        result: data,
        timestamp: new Date().toISOString(),
      });
    } catch (error) {
      setLogResults({
        status: "error",
        message: `Failed to analyze network log: ${error instanceof Error ? error.message : 'Unknown error occurred'}`,
      });
      console.error("Error analyzing network log:", error);
    } finally {
      setLoading(false);
    }
  };

  const fetchFileContent = async (domain: string, fileType: 'robots' | 'security') => {
    setLoadingFile(true);
    try {
      const response = await fetch(`${API_URL}/api/security-file-content`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, file_type: fileType }),
      });

      const data = await response.json();

      if (data.status === "success") {
        setFileContent(data.file_info);
        setFileModalOpen(true);
      } else {
        // Handle error - could show a toast or alert
        console.error("Failed to fetch file:", data.message);
      }
    } catch (error) {
      console.error("Error fetching file content:", error);
    } finally {
      setLoadingFile(false);
    }
  };

  const formatResults = (results: ScanResult | null, viewMode: 'normal' | 'json' = 'normal'): JSX.Element => {
    if (!results) return <></>;
    if (results.status === "error") {
      return <p>{results.message || "An error occurred."}</p>;
    }

    // JSON view
    if (viewMode === 'json') {
      return (
        <div className="bg-slate-900 rounded-md p-4 overflow-auto">
          <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
            {JSON.stringify(results, null, 2)}
          </pre>
        </div>
      );
    }

    // Handle PCAP analysis results
    if (results.data?.pcap_analysis) {
      return (
        <div className="space-y-4">
          {/* File Information */}
          {results.data.metadata && (
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">File Information</h4>
              <div className="text-xs space-y-1">
                {Object.entries(results.data.metadata).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-muted-foreground">{key}:</span>
                    <span>{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Enhanced Security Analysis Results */}
          {results.data.virustotal && (
            <div className="space-y-3">
              <h4 className="text-sm font-semibold">🦠 Security Analysis</h4>

              {/* VirusTotal Summary */}
              {results.data.virustotal_summary && results.data.virustotal_summary !== 'No VirusTotal data available' && (
                <div className="bg-blue-50 p-3 rounded-lg">
                  <h5 className="font-medium text-blue-900 mb-2 text-xs">📋 Quick Summary</h5>
                  <pre className="text-xs text-blue-800 whitespace-pre-wrap">{results.data.virustotal_summary}</pre>
                </div>
              )}

              {/* Enhanced Security Analysis Data */}
              {results.data.virustotal.risk_assessment ? (
                <div className="bg-gray-50 p-3 rounded-lg space-y-3">
                  {/* Risk Score Display */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium">Risk Score:</span>
                      <span className={`text-lg font-bold ${results.data.virustotal.risk_assessment.risk_level === 'HIGH' ? 'text-red-600' :
                        results.data.virustotal.risk_assessment.risk_level === 'MEDIUM' ? 'text-orange-600' :
                          results.data.virustotal.risk_assessment.risk_level === 'LOW' ? 'text-yellow-600' : 'text-green-600'
                        }`}>
                        {results.data.virustotal.risk_assessment.risk_score}/100
                      </span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${results.data.virustotal.risk_assessment.risk_level === 'HIGH' ? 'bg-red-500' :
                          results.data.virustotal.risk_assessment.risk_level === 'MEDIUM' ? 'bg-orange-500' :
                            results.data.virustotal.risk_assessment.risk_level === 'LOW' ? 'bg-yellow-500' : 'bg-green-500'
                          }`}
                        style={{ width: `${results.data.virustotal.risk_assessment.risk_score}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Risk Level Badge */}
                  <div>
                    <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${results.data.virustotal.risk_assessment.risk_level === 'HIGH' ? 'bg-red-100 text-red-800' :
                      results.data.virustotal.risk_assessment.risk_level === 'MEDIUM' ? 'bg-orange-100 text-orange-800' :
                        results.data.virustotal.risk_assessment.risk_level === 'LOW' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-green-100 text-green-800'
                      }`}>
                      Risk Level: {results.data.virustotal.risk_assessment.risk_level}
                    </span>
                  </div>

                  {/* Detection Statistics */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="text-center">
                      <div className="text-lg font-bold text-red-600">
                        {results.data.virustotal.risk_assessment.malicious_count || 0}
                      </div>
                      <div className="text-xs text-gray-600">Malicious</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-bold text-orange-600">
                        {results.data.virustotal.risk_assessment.suspicious_count || 0}
                      </div>
                      <div className="text-xs text-gray-600">Suspicious</div>
                    </div>
                  </div>

                  {/* Additional Details */}
                  <div className="space-y-1 text-xs text-gray-600">
                    {results.data.virustotal.risk_assessment.detection_ratio && (
                      <div>Detection Ratio: {results.data.virustotal.risk_assessment.detection_ratio}</div>
                    )}
                    {results.data.virustotal.risk_assessment.total_engines && (
                      <div>Total Engines: {results.data.virustotal.risk_assessment.total_engines}</div>
                    )}
                    {results.data.virustotal.metadata?.reputation && (
                      <div>Reputation: {results.data.virustotal.metadata.reputation}</div>
                    )}
                    {results.data.virustotal.metadata?.file_type && (
                      <div>File Type: {results.data.virustotal.metadata.file_type}</div>
                    )}
                    {results.data.virustotal.metadata?.analysis_date && (
                      <div>Analysis Date: {new Date(results.data.virustotal.metadata.analysis_date * 1000).toLocaleString()}</div>
                    )}
                  </div>
                </div>
              ) : (
                /* Fallback to legacy structure */
                results.data.virustotal?.data?.attributes?.stats && (
                  <div className="space-y-1">
                    <h4 className="text-sm font-semibold">Security Stats</h4>
                    <div className="text-xs space-y-1">
                      {Object.entries(results.data.virustotal.data.attributes.stats).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between">
                          <span className="text-muted-foreground">{key}:</span>
                          <span>{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              )}

              {/* Error Handling */}
              {results.data.virustotal.error && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                  <div className="text-yellow-800 text-xs">
                    ⚠️ Security Analysis Issue: {results.data.virustotal.error}
                  </div>
                  <div className="text-xs text-yellow-700 mt-2">
                    This could be due to:
                    <ul className="list-disc list-inside mt-1 ml-4">
                      <li>Rate limiting (try again later)</li>
                      <li>Invalid API key</li>
                      <li>File analysis timeout</li>
                      <li>Network connectivity issues</li>
                    </ul>
                  </div>
                </div>
              )}

              {/* Engine Results - Fallback to legacy structure */}
              {results.data.virustotal?.data?.attributes?.results && (
                <div className="space-y-1">
                  <h4 className="text-sm font-semibold">Engine Results</h4>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {Object.entries(results.data.virustotal.data.attributes.results).slice(0, 8).map(([engine, result]) => (
                      <div key={engine} className="flex justify-between text-xs bg-muted/20 p-1 rounded">
                        <span>{engine}</span>
                        <span className={`${result.category === 'malicious' ? 'text-red-500' :
                          result.category === 'suspicious' ? 'text-yellow-500' :
                            'text-green-500'}`}>
                          {result.category}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Protocol Distribution */}
          {results.data.pcap_analysis && (
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Protocol Distribution</h4>
              <div className="grid grid-cols-2 gap-2 text-xs">
                {Object.entries(results.data.pcap_analysis).map(([protocol, count]) => (
                  <div key={protocol} className="flex justify-between">
                    <span className="text-muted-foreground">{protocol}:</span>
                    <span>{String(count)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Protocol Chart */}
          {results.data.chart_base64 && (
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">Protocol Chart</h4>
              <img
                src={`data:image/png;base64,${results.data.chart_base64}`}
                alt="Protocol Analysis Chart"
                className="max-w-full h-auto rounded-md"
              />
            </div>
          )}
        </div>
      );
    }

    // Handle IP-specific results (check both root level and nested in data)
    if (results.ip_details || results.risk_assessment || results.technical_details ||
      results.data?.ip_details || results.data?.risk_assessment || results.data?.technical_details) {

      // Use data from root level or nested under data
      const ipDetails = results.ip_details || results.data?.ip_details;
      const riskAssessment = results.risk_assessment || results.data?.risk_assessment;
      const technicalDetails = results.technical_details || results.data?.technical_details;
      const recommendations = results.recommendations || results.data?.recommendations;
      const virustotalData = results.data?.virustotal;

      // Debug logging
      console.log("IP Results Debug:", {
        ipDetails,
        riskAssessment,
        technicalDetails,
        recommendations,
        virustotalData,
        fullResults: results
      });

      return (
        <div className="space-y-3">
          {/* IP Details */}
          {ipDetails && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">IP Address:</span>
                <span className="text-sm font-mono font-medium">{ipDetails.address}</span>
              </div>
              {ipDetails.domain && (
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Domain:</span>
                  <span className="text-sm font-medium">{ipDetails.domain}</span>
                </div>
              )}
              {ipDetails.isp && (
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">ISP:</span>
                  <span className="text-sm font-medium">{ipDetails.isp}</span>
                </div>
              )}
              {ipDetails.location && (
                <div className="space-y-1">
                  <div className="text-sm text-muted-foreground">Location:</div>
                  <div className="text-sm space-y-1 ml-4">
                    {ipDetails.location.city && (
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">City:</span>
                        <span>{ipDetails.location.city}</span>
                      </div>
                    )}
                    {ipDetails.location.region && (
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Region:</span>
                        <span>{ipDetails.location.region}</span>
                      </div>
                    )}
                    {ipDetails.location.country && (
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Country:</span>
                        <span>{ipDetails.location.country}</span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* VirusTotal Analysis for IP */}
          {virustotalData && (
            <div className="space-y-3">
              <h4 className="text-sm font-semibold">🦠 Security Analysis</h4>

              {/* VirusTotal Summary */}
              {results.data?.virustotal_summary && results.data.virustotal_summary !== 'No VirusTotal data available' && (
                <div className="bg-blue-50 p-3 rounded-lg">
                  <h5 className="font-medium text-blue-900 mb-2 text-xs">📋 Quick Summary</h5>
                  <pre className="text-xs text-blue-800 whitespace-pre-wrap">{results.data.virustotal_summary}</pre>
                </div>
              )}

              {/* Enhanced Security Analysis Data */}
              {virustotalData.risk_assessment ? (
                <div className="bg-gray-50 p-3 rounded-lg space-y-3">
                  {/* Risk Score Display */}
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs font-medium">Risk Score:</span>
                      <span className={`text-lg font-bold ${virustotalData.risk_assessment.risk_level === 'HIGH' ? 'text-red-600' :
                        virustotalData.risk_assessment.risk_level === 'MEDIUM' ? 'text-orange-600' :
                          virustotalData.risk_assessment.risk_level === 'LOW' ? 'text-yellow-600' : 'text-green-600'
                        }`}>
                        {virustotalData.risk_assessment.risk_score}/100
                      </span>
                    </div>

                    {/* Progress Bar */}
                    <div className="w-full bg-gray-200 rounded-full h-2">
                      <div
                        className={`h-2 rounded-full ${virustotalData.risk_assessment.risk_level === 'HIGH' ? 'bg-red-500' :
                          virustotalData.risk_assessment.risk_level === 'MEDIUM' ? 'bg-orange-500' :
                            virustotalData.risk_assessment.risk_level === 'LOW' ? 'bg-yellow-500' : 'bg-green-500'
                          }`}
                        style={{ width: `${virustotalData.risk_assessment.risk_score}%` }}
                      ></div>
                    </div>
                  </div>

                  {/* Risk Level Badge */}
                  <div>
                    <span className={`inline-block px-2 py-1 rounded-full text-xs font-medium ${virustotalData.risk_assessment.risk_level === 'HIGH' ? 'bg-red-100 text-red-800' :
                      virustotalData.risk_assessment.risk_level === 'MEDIUM' ? 'bg-orange-100 text-orange-800' :
                        virustotalData.risk_assessment.risk_level === 'LOW' ? 'bg-yellow-100 text-yellow-800' :
                          'bg-green-100 text-green-800'
                      }`}>
                      Risk Level: {virustotalData.risk_assessment.risk_level}
                    </span>
                  </div>

                  {/* Detection Statistics */}
                  <div className="grid grid-cols-2 gap-3">
                    <div className="text-center">
                      <div className="text-lg font-bold text-red-600">
                        {virustotalData.risk_assessment.malicious_count || 0}
                      </div>
                      <div className="text-xs text-gray-600">Malicious</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-bold text-orange-600">
                        {virustotalData.risk_assessment.suspicious_count || 0}
                      </div>
                      <div className="text-xs text-gray-600">Suspicious</div>
                    </div>
                  </div>

                  {/* Additional Details */}
                  <div className="space-y-1 text-xs text-gray-600">
                    {virustotalData.risk_assessment.detection_ratio && (
                      <div>Detection Ratio: {virustotalData.risk_assessment.detection_ratio}</div>
                    )}
                    {virustotalData.risk_assessment.total_engines && (
                      <div>Total Engines: {virustotalData.risk_assessment.total_engines}</div>
                    )}
                    {virustotalData.metadata?.reputation && (
                      <div>Reputation: {virustotalData.metadata.reputation}</div>
                    )}
                    {virustotalData.metadata?.file_type && (
                      <div>File Type: {virustotalData.metadata.file_type}</div>
                    )}
                    {virustotalData.metadata?.analysis_date && (
                      <div>Analysis Date: {new Date(virustotalData.metadata.analysis_date * 1000).toLocaleString()}</div>
                    )}
                  </div>
                </div>
              ) : (
                /* Fallback to legacy structure */
                virustotalData?.data?.attributes?.stats && (
                  <div className="space-y-1">
                    <h4 className="text-sm font-semibold">Security Stats</h4>
                    <div className="text-xs space-y-1">
                      {Object.entries(virustotalData.data.attributes.stats).map(([key, value]) => (
                        <div key={key} className="flex items-center justify-between">
                          <span className="text-muted-foreground">{key}:</span>
                          <span>{value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )
              )}

              {/* Error Handling */}
              {virustotalData.error && (
                <div className="bg-yellow-50 border border-yellow-200 rounded-lg p-3">
                  <div className="text-yellow-800 text-xs">
                    ⚠️ Security Analysis Issue: {virustotalData.error}
                  </div>
                  <div className="text-xs text-yellow-700 mt-2">
                    This could be due to:
                    <ul className="list-disc list-inside mt-1 ml-4">
                      <li>Rate limiting (try again later)</li>
                      <li>Invalid API key</li>
                      <li>IP analysis timeout</li>
                      <li>Network connectivity issues</li>
                    </ul>
                  </div>
                </div>
              )}

              {/* Engine Results - Fallback to legacy structure */}
              {virustotalData?.data?.attributes?.results && (
                <div className="space-y-1">
                  <h4 className="text-sm font-semibold">Engine Results</h4>
                  <div className="space-y-1 max-h-32 overflow-y-auto">
                    {Object.entries(virustotalData.data.attributes.results).slice(0, 8).map(([engine, result]) => (
                      <div key={engine} className="flex justify-between text-xs bg-muted/20 p-1 rounded">
                        <span>{engine}</span>
                        <span className={`${(result as any).category === 'malicious' ? 'text-red-500' :
                          (result as any).category === 'suspicious' ? 'text-yellow-500' :
                            'text-green-500'}`}>
                          {(result as any).category}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* VirusTotal Status - Show when no data is available */}
          {!virustotalData && (
            <div className="bg-gray-50 p-3 rounded-lg border border-gray-200">
              <div className="flex items-center space-x-2">
                <div className="text-gray-400">🦠</div>
                <div className="text-xs text-gray-600">
                  <strong>Security Analysis:</strong> No data available. This could mean:
                  <ul className="list-disc list-inside mt-1 ml-2">
                    <li>The backend API doesn't include security analysis data for IPs</li>
                    <li>The IP hasn't been analyzed by our security systems</li>
                    <li>There was an error retrieving security data</li>
                  </ul>
                </div>
              </div>
            </div>
          )}

          {/* Risk Assessment */}
          {riskAssessment && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Risk Assessment:</div>
              <div className="space-y-1 ml-4">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Risk Level:</span>
                  <span className={`text-sm font-medium ${riskAssessment.risk_level === 'High' ? 'text-red-500' :
                    riskAssessment.risk_level === 'Medium' ? 'text-yellow-500' :
                      'text-green-500'
                    }`}>
                    {riskAssessment.risk_level}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Confidence Score:</span>
                  <span className="text-sm font-medium">{riskAssessment.confidence_score}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Total Reports:</span>
                  <span className="text-sm font-medium">{riskAssessment.total_reports}</span>
                </div>
                {riskAssessment.last_reported && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Last Reported:</span>
                    <span className="text-sm font-medium">{new Date(riskAssessment.last_reported).toLocaleDateString()}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Technical Details */}
          {technicalDetails && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Technical Details:</div>
              <div className="space-y-1 ml-4">
                {technicalDetails.as_name && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">AS Name:</span>
                    <span className="text-sm font-medium">{technicalDetails.as_name}</span>
                  </div>
                )}
                {technicalDetails.asn && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">ASN:</span>
                    <span className="text-sm font-medium">{technicalDetails.asn}</span>
                  </div>
                )}
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Public IP:</span>
                  <span className="text-sm font-medium">{technicalDetails.is_public ? 'Yes' : 'No'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">TOR Exit Node:</span>
                  <span className="text-sm font-medium">{technicalDetails.is_tor ? 'Yes' : 'No'}</span>
                </div>
                {technicalDetails.usage_type && (
                  <div className="flex items-center justify-between">
                    <span className="text-muted-foreground">Usage Type:</span>
                    <span className="text-sm font-medium">{technicalDetails.usage_type}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {recommendations && recommendations.length > 0 && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Recommendations:</div>
              <div className="space-y-1 ml-4">
                {recommendations.map((rec, index) => (
                  <div key={index} className="text-sm text-muted-foreground">• {rec}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    // Handle Port Scanner results
    if (results.ports || results.data?.ports) {
      const ports = results.ports || results.data?.ports;
      const hostInfo = results.host_info || results.data?.host_info;
      if (!ports) return <></>;

      return (
        <div className="space-y-3">
          {hostInfo && (
            <div className="space-y-2">
              <div className="text-sm text-muted-foreground">Host Information:</div>
              <div className="space-y-1 ml-4">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Hostname:</span>
                  <span className="text-sm font-medium">{hostInfo.hostname || 'N/A'}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">State:</span>
                  <span className="text-sm font-medium">{hostInfo.state}</span>
                </div>
              </div>
            </div>
          )}

          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">Open Ports ({ports.length}):</div>
            <div className="space-y-2">
              {ports.map((port: any, index: number) => (
                <div key={index} className="border border-border/20 rounded p-2 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-mono font-medium">Port {port.port}/{port.protocol}</span>
                    <span className={`text-xs px-2 py-1 rounded ${port.state === 'open' ? 'bg-green-500/20 text-green-600' : 'bg-gray-500/20 text-gray-600'
                      }`}>
                      {port.state}
                    </span>
                  </div>
                  {port.service && (
                    <div className="text-xs text-muted-foreground">Service: {port.service}</div>
                  )}
                  {port.product && (
                    <div className="text-xs text-muted-foreground">Product: {port.product}</div>
                  )}
                  {port.version && (
                    <div className="text-xs text-muted-foreground">Version: {port.version}</div>
                  )}
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    // Handle Vulnerability Scanner results
    if (results.vulnerabilities || results.data?.vulnerabilities) {
      const vulnerabilities = results.vulnerabilities || results.data?.vulnerabilities;
      if (!vulnerabilities) return <></>;

      return (
        <div className="space-y-3">
          <div className="text-sm text-muted-foreground">Vulnerabilities Found ({vulnerabilities.length}):</div>
          <div className="space-y-2">
            {vulnerabilities.map((vuln: any, index: number) => (
              <div key={index} className="border border-border/20 rounded p-2 space-y-1">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{vuln.service}</span>
                  <span className={`text-xs px-2 py-1 rounded ${vuln.severity === 'High' ? 'bg-red-500/20 text-red-600' :
                    vuln.severity === 'Medium' ? 'bg-yellow-500/20 text-yellow-600' :
                      'bg-green-500/20 text-green-600'
                    }`}>
                    {vuln.severity}
                  </span>
                </div>
                {vuln.version && (
                  <div className="text-xs text-muted-foreground">Version: {vuln.version}</div>
                )}
                {vuln.port && (
                  <div className="text-xs text-muted-foreground">Port: {vuln.port}</div>
                )}
                {vuln.potential_issues && vuln.potential_issues.length > 0 && (
                  <div className="text-xs text-muted-foreground">
                    Issues: {vuln.potential_issues.join(', ')}
                  </div>
                )}
                {vuln.recommendation && (
                  <div className="text-xs text-muted-foreground">Recommendation: {vuln.recommendation}</div>
                )}
              </div>
            ))}
          </div>
        </div>
      );
    }


    // Handle Security Headers results
    if (results.headers || results.data?.headers) {
      const headers = (results.headers || results.data?.headers || {}) as Record<
        string,
        { present?: boolean; value?: string }
      >;
      const securityScore = results.security_score || results.data?.security_score;
      const grade = results.grade || results.data?.grade;
      return (
        <div className="space-y-3">
          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">Security Score:</div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold">{grade}</span>
              <span className="text-sm text-muted-foreground">
                ({securityScore}/{results.max_score || results.data?.max_score})
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">Security Headers:</div>
            <div className="space-y-2">
              {Object.entries(headers).map(([headerName, headerInfo]) => {
                const present = !!headerInfo?.present;
                const value = headerInfo?.value;
                return (
                  <div key={headerName} className="border border-border/20 rounded p-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{headerName}</span>
                      <span className={`text-xs px-2 py-1 rounded ${present ? 'bg-green-500/20 text-green-600' : 'bg-red-500/20 text-red-600'
                        }`}>
                        {present ? 'Present' : 'Missing'}
                      </span>
                    </div>
                    {value && (
                      <div className="text-xs text-muted-foreground mt-1">{value}</div>
                    )}
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      );
    }

    // Handle Email Security results
    if (results.email_security || results.data?.email_security) {
      const emailSecurity = results.email_security || results.data?.email_security;
      return (
        <div className="space-y-3">
          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">Email Security Score:</div>
            <div className="flex items-center space-x-2">
              <span className="text-lg font-bold">{emailSecurity?.grade ?? "N/A"}</span>
              <span className="text-sm text-muted-foreground">
                ({emailSecurity?.total_score ?? "–"}/{emailSecurity?.max_score ?? "–"})
              </span>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-sm text-muted-foreground">Security Features:</div>
            <div className="space-y-2">
              {["spf", "dmarc", "dkim"].map((feature) => {
                const info = (emailSecurity as Record<string, any>)[feature];
                if (!info) return null;
                const present = !!info.present;
                return (
                  <div key={feature} className="border border-border/20 rounded p-2">
                    <div className="flex items-center justify-between">
                      <span className="text-sm font-medium">{feature.toUpperCase()}</span>
                      <span className={`text-xs px-2 py-1 rounded ${present ? 'bg-green-500/20 text-green-600' : 'bg-red-500/20 text-red-600'
                        }`}>
                        {present ? 'Present' : 'Missing'}
                      </span>
                    </div>
                    {present && info.record && (
                      <div className="text-xs text-muted-foreground mt-1 font-mono">{info.record}</div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      );
    }

    // Handle Domain reconnaissance results
    if (results.domain_info) {
      return (
        <div className="space-y-4">
          {/* Domain Overview */}
          <div className="space-y-2">
            <span className="text-sm font-medium">Domain Information:</span>
            <div className="text-sm pl-4 space-y-1">
              <div>Domain: {results.domain_info.domain}</div>
              {results.domain_info.geolocation?.ip && (
                <div>Primary IP: {results.domain_info.geolocation.ip}</div>
              )}
            </div>
          </div>

          {/* WHOIS Information */}
          {results.domain_info.whois && (
            <div className="space-y-2">
              <span className="text-sm font-medium">WHOIS Information:</span>
              <div className="text-sm pl-4 space-y-1">
                {results.domain_info.whois.registrar && (
                  <div>Registrar: {results.domain_info.whois.registrar}</div>
                )}
                {results.domain_info.whois.creation_date && (
                  <div>Created: {new Date(results.domain_info.whois.creation_date).toLocaleDateString()}</div>
                )}
                {results.domain_info.whois.expiration_date && (
                  <div>Expires: {new Date(results.domain_info.whois.expiration_date).toLocaleDateString()}</div>
                )}
                {results.domain_info.whois.registrant && (
                  <div>Registrant: {results.domain_info.whois.registrant}</div>
                )}
                {results.domain_info.whois.country && (
                  <div>Country: {results.domain_info.whois.country}</div>
                )}
              </div>
            </div>
          )}

          {/* DNS Records */}
          {results.domain_info.dns_records && (
            <div className="space-y-2">
              <span className="text-sm font-medium">DNS Records:</span>
              <div className="text-sm pl-4 space-y-1">
                {Object.entries(results.domain_info.dns_records).map(([type, records]) => (
                  records && records.length > 0 && (
                    <div key={type}>
                      <span className="font-medium">{type}:</span> {records.slice(0, 3).join(", ")}
                      {records.length > 3 && ` (and ${records.length - 3} more)`}
                    </div>
                  )
                ))}
              </div>
            </div>
          )}

          {/* SSL Certificate */}
          {results.domain_info.ssl_info && (
            <div className="space-y-2">
              <span className="text-sm font-medium">SSL Certificate:</span>
              <div className="text-sm pl-4 space-y-1">
                <div>Valid: {results.domain_info.ssl_info.valid ? "Yes" : "No"}</div>
                {results.domain_info.ssl_info.issuer && (
                  <div>Issuer: {results.domain_info.ssl_info.issuer}</div>
                )}
                {results.domain_info.ssl_info.valid_until && (
                  <div>Expires: {new Date(results.domain_info.ssl_info.valid_until).toLocaleDateString()}</div>
                )}
                {results.domain_info.ssl_info.days_until_expiry !== undefined && (
                  <div>Days Until Expiry: {results.domain_info.ssl_info.days_until_expiry}</div>
                )}
                {results.domain_info.ssl_info.grade && (
                  <div>SSL Grade: {results.domain_info.ssl_info.grade}</div>
                )}
              </div>
            </div>
          )}

          {/* Security Features */}
          {results.domain_info.security_features && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Security Features:</span>
              <div className="text-sm pl-4 space-y-1">
                <div>DNSSEC: {results.domain_info.security_features.dnssec ? "Enabled" : "Disabled"}</div>
                {results.domain_info.security_features.dmarc && (
                  <div>DMARC: {results.domain_info.security_features.dmarc}</div>
                )}
                {results.domain_info.security_features.spf && (
                  <div>SPF: {results.domain_info.security_features.spf}</div>
                )}
                {results.domain_info.security_features.waf_detected && (
                  <div>WAF: {results.domain_info.security_features.waf_detected}</div>
                )}

                {/* robots.txt with clickable link */}
                <div className="flex items-center gap-2">
                  <span>robots.txt: {results.domain_info.security_features.robots_txt?.present ? "Present" : "Not Found"}</span>
                  {results.domain_info.security_features.robots_txt?.present && results.domain_info.security_features.robots_txt.url && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => fetchFileContent(results.domain_info!.domain, 'robots')}
                      disabled={loadingFile}
                      className="h-6 px-2 text-xs"
                    >
                      <FileText className="w-3 h-3 mr-1" />
                      View
                    </Button>
                  )}
                </div>

                {/* security.txt with clickable link */}
                <div className="flex items-center gap-2">
                  <span>security.txt: {results.domain_info.security_features.security_txt?.present ? "Present" : "Not Found"}</span>
                  {results.domain_info.security_features.security_txt?.present && results.domain_info.security_features.security_txt.url && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => fetchFileContent(results.domain_info!.domain, 'security')}
                      disabled={loadingFile}
                      className="h-6 px-2 text-xs"
                    >
                      <FileText className="w-3 h-3 mr-1" />
                      View
                    </Button>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Subdomains */}
          {results.domain_info.subdomains && results.domain_info.subdomains.length > 0 && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Subdomains Found:</span>
              <div className="text-sm pl-4 space-y-1">
                {results.domain_info.subdomains.slice(0, 10).map((subdomain, index) => (
                  <div key={index}>{subdomain}</div>
                ))}
                {results.domain_info.subdomains.length > 10 && (
                  <div className="text-muted-foreground">
                    ... and {results.domain_info.subdomains.length - 10} more subdomains
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Geolocation */}
          {results.domain_info.geolocation && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Server Location:</span>
              <div className="text-sm pl-4 space-y-1">
                {results.domain_info.geolocation.country && (
                  <div>Country: {results.domain_info.geolocation.country}</div>
                )}
                {results.domain_info.geolocation.city && (
                  <div>City: {results.domain_info.geolocation.city}</div>
                )}
                {results.domain_info.geolocation.isp && (
                  <div>ISP: {results.domain_info.geolocation.isp}</div>
                )}
                {results.domain_info.geolocation.organization && (
                  <div>Organization: {results.domain_info.geolocation.organization}</div>
                )}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {results.recommendations && results.recommendations.length > 0 && (
            <div className="space-y-2">
              <span className="text-sm font-medium text-green-600">Recommendations:</span>
              <div className="text-sm pl-4 space-y-1">
                {results.recommendations.map((rec, index) => (
                  <div key={index}>• {rec}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    // Handle URL and IP results - Normal view (Clean design)
    if (results.data) {
      return (
        <div className="space-y-3">
          {/* Basic Status - Clean and minimal */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Status:</span>
              <span className={`text-sm font-medium ${results.data.threat_analysis?.is_malicious ? 'text-red-500' : 'text-green-500'}`}>
                {results.data.threat_analysis?.is_malicious ? "Malicious" : "Safe"}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">Risk Level:</span>
              <span className="text-sm font-medium">{results.data.additional_checks?.domain_analysis?.risk_level || "Unknown"}</span>
            </div>
            {results.data.additional_checks?.ssl_security && (
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">SSL Valid:</span>
                <span className={`text-sm font-medium ${results.data.additional_checks.ssl_security.valid ? 'text-green-500' : 'text-red-500'}`}>
                  {results.data.additional_checks.ssl_security.valid ? "Yes" : "No"}
                </span>
              </div>
            )}
            {results.data.url_analysis?.input_url && (
              <div className="space-y-1">
                <span className="text-sm text-muted-foreground">Analyzed URL:</span>
                <div className="text-xs font-mono pl-4 break-all">{results.data.url_analysis.input_url}</div>
              </div>
            )}
          </div>

          {/* Potential Threats - Minimal design */}
          {results.data.potential_threats && results.data.potential_threats.length > 0 && (
            <div className="space-y-2">
              <span className="text-sm font-medium text-red-500">Potential Threats:</span>
              {results.data.potential_threats.map((threat, index) => (
                <div key={index} className="text-sm pl-4 space-y-1">
                  <div>Type: {threat.type}</div>
                  <div>Severity: {threat.severity}</div>
                  {threat.domain && <div>Domain: {threat.domain}</div>}
                  {threat.source && <div>Source: {threat.source}</div>}
                </div>
              ))}
            </div>
          )}

          {/* Suspicious IPs */}
          {results.data.suspicious_ips && results.data.suspicious_ips.length > 0 && (
            <div className="space-y-2">
              <span className="text-sm font-medium text-yellow-600">Suspicious IPs:</span>
              <div className="text-sm pl-4">
                {results.data.suspicious_ips.map((ip, index) => (
                  <div key={index} className="font-mono">{ip}</div>
                ))}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {results.data.recommendations && results.data.recommendations.length > 0 && (
            <div className="space-y-2">
              <span className="text-sm font-medium text-green-600">Recommendations:</span>
              <div className="text-sm pl-4 space-y-1">
                {results.data.recommendations.map((rec, index) => (
                  <div key={index}>• {rec}</div>
                ))}
              </div>
            </div>
          )}

          {/* VirusTotal Results - Clean stats */}
          {results.data.virustotal?.data?.attributes?.stats && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Security Analysis:</span>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {Object.entries(results.data.virustotal.data.attributes.stats).map(([key, value]) => (
                  <div key={key} className="text-center bg-muted/30 p-2 rounded">
                    <div className="text-lg font-bold">{value}</div>
                    <div className="text-xs text-muted-foreground capitalize">{key.replace('_', ' ')}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* VirusTotal Engine Results - Simplified */}
          {results.data.virustotal?.data?.attributes?.results && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Engine Results:</span>
              <div className="space-y-1 max-h-32 overflow-y-auto">
                {Object.entries(results.data.virustotal.data.attributes.results).slice(0, 8).map(([engine, result]) => (
                  <div key={engine} className="flex justify-between text-sm bg-muted/20 p-1 rounded">
                    <span>{engine}</span>
                    <span className={`${result.category === 'malicious' ? 'text-red-500' :
                      result.category === 'suspicious' ? 'text-yellow-500' :
                        'text-green-500'}`}>
                      {result.category}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Technical Details - Properly formatted */}
          {(results.data?.additional_checks || results.data?.threat_analysis || results.data?.url_analysis) && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Technical Details:</span>

              {/* URL Analysis */}
              {results.data.url_analysis && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">URL Analysis:</div>
                  <div className="text-sm pl-4 space-y-1">
                    <div>Input URL: {results.data.url_analysis.input_url}</div>
                    {results.data.url_analysis.parsed_details && (
                      <div className="space-y-1">
                        <div>Domain: {results.data.url_analysis.parsed_details.domain}</div>
                        <div>Scheme: {results.data.url_analysis.parsed_details.scheme}</div>
                        <div>Path: {results.data.url_analysis.parsed_details.path}</div>
                        {results.data.url_analysis.parsed_details.fragment && (
                          <div>Fragment: {results.data.url_analysis.parsed_details.fragment}</div>
                        )}
                      </div>
                    )}
                    {results.data.url_analysis.security_check_time && (
                      <div>Check Time: {new Date(results.data.url_analysis.security_check_time).toLocaleString()}</div>
                    )}
                  </div>
                </div>
              )}

              {/* Domain Analysis */}
              {results.data.additional_checks?.domain_analysis && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">Domain Analysis:</div>
                  <div className="text-sm pl-4 space-y-1">
                    <div>Risk Level: {results.data.additional_checks.domain_analysis.risk_level}</div>
                    {results.data.additional_checks.domain_analysis.risk_score !== undefined && (
                      <div>Risk Score: {results.data.additional_checks.domain_analysis.risk_score}</div>
                    )}
                    {results.data.additional_checks.domain_analysis.analysis && (
                      <div className="space-y-1">
                        <div>Domain Length: {results.data.additional_checks.domain_analysis.analysis.length}</div>
                        <div>Subdomains: {results.data.additional_checks.domain_analysis.analysis.subdomains}</div>
                        <div>Suspicious TLD: {results.data.additional_checks.domain_analysis.analysis.suspicious_tld ? "Yes" : "No"}</div>
                        <div>Special Characters: {results.data.additional_checks.domain_analysis.analysis.special_chars ? "Yes" : "No"}</div>
                      </div>
                    )}
                    {results.data.additional_checks.domain_analysis.whois && (
                      <div className="space-y-1">
                        <div className="font-medium">WHOIS Information:</div>
                        <div>Registrar: {results.data.additional_checks.domain_analysis.whois.registrar}</div>
                        <div>Created: {new Date(results.data.additional_checks.domain_analysis.whois.creation_date).toLocaleDateString()}</div>
                        <div>Expires: {new Date(results.data.additional_checks.domain_analysis.whois.expiration_date).toLocaleDateString()}</div>
                        {results.data.additional_checks.domain_analysis.whois.name_servers && (
                          <div>Name Servers: {results.data.additional_checks.domain_analysis.whois.name_servers.slice(0, 2).join(", ")}</div>
                        )}
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* SSL Security */}
              {results.data.additional_checks?.ssl_security && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">SSL Security:</div>
                  <div className="text-sm pl-4 space-y-1">
                    <div>Status: {results.data.additional_checks.ssl_security.valid ? "Valid" : "Invalid"}</div>
                    {results.data.additional_checks.ssl_security.status_code && (
                      <div>Status Code: {results.data.additional_checks.ssl_security.status_code}</div>
                    )}
                  </div>
                </div>
              )}

              {/* Threat Analysis */}
              {results.data.threat_analysis && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">Threat Analysis:</div>
                  <div className="text-sm pl-4 space-y-1">
                    <div>Malicious: {results.data.threat_analysis.is_malicious ? "Yes" : "No"}</div>
                    <div>Threats Found: {results.data.threat_analysis.threats_found || 0}</div>
                    {results.data.threat_analysis.google_safe_browsing && (
                      <div>Google Safe Browsing: {results.data.threat_analysis.google_safe_browsing.status}</div>
                    )}
                  </div>
                </div>
              )}

              {/* Suspicious Patterns */}
              {results.data.additional_checks?.suspicious_patterns && (
                <div className="space-y-1">
                  <div className="text-sm font-medium">Pattern Analysis:</div>
                  <div className="text-sm pl-4 space-y-1">
                    <div>Suspicious Patterns Found: {results.data.additional_checks.suspicious_patterns.found ? "Yes" : "No"}</div>
                    <div>Risk Level: {results.data.additional_checks.suspicious_patterns.risk_level}</div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Additional Information */}
          {results.data.metadata && (
            <div className="space-y-2">
              <span className="text-sm font-medium">Additional Info:</span>
              <div className="space-y-1">
                {Object.entries(results.data.metadata).map(([key, value]) => (
                  <div key={key} className="flex justify-between text-sm">
                    <span className="text-muted-foreground">{key}:</span>
                    <span>{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      );
    }

    // Fallback for any other data structure
    return (
      <div className="p-2">
        <p><strong>Analysis Results:</strong></p>
        <p className="mt-1">
          {results.message || "Analysis completed successfully. Switch to JSON view for detailed technical data."}
        </p>
      </div>
    );
  };

  const addChatMessage = (text: string, isUser: boolean = false) => {
    const newMessage: ChatMessage = {
      id: chatMessages.length + 1,
      text,
      isUser,
      timestamp: new Date().toLocaleTimeString(),
    };
    setChatMessages((prev) => [...prev, newMessage]);
  };

  // Advanced Scanner Functions
  const scanPorts = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setPortLoading(true);
    setPortResults(null);
    setIsCached(false);

    const storedPorts = loadStoredScans("cyberregis_ports");
    const cached = storedPorts.find((scan) => scan.input === portTarget);
    if (cached) {
      setPortResults(cached.result);
      setIsCached(true);
      setPortLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/scan-ports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: portTarget }),
      });

      if (response.ok) {
        const data = await response.json();
        setPortResults(data);
        upsertStoredScan("cyberregis_ports", {
          input: portTarget,
          result: data,
          timestamp: new Date().toISOString(),
        });
      } else {
        setPortResults({
          status: "error",
          message: `Port scan failed: ${response.statusText}`,
        });
      }
    } catch (error) {
      setPortResults({
        status: "error",
        message: `Port scan failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      });
    } finally {
      setPortLoading(false);
    }
  };

  const scanVulnerabilities = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setVulnLoading(true);
    setVulnResults(null);
    setIsCached(false);

    const storedVulns = loadStoredScans("cyberregis_vuln");
    const cached = storedVulns.find((scan) => scan.input === vulnTarget);
    if (cached) {
      setVulnResults(cached.result);
      setIsCached(true);
      setVulnLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/vulnerability-scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: vulnTarget }),
      });

      if (response.ok) {
        const data = await response.json();
        setVulnResults(data);
        upsertStoredScan("cyberregis_vuln", {
          input: vulnTarget,
          result: data,
          timestamp: new Date().toISOString(),
        });
      } else {
        setVulnResults({
          status: "error",
          message: `Vulnerability scan failed: ${response.statusText}`,
        });
      }
    } catch (error) {
      setVulnResults({
        status: "error",
        message: `Vulnerability scan failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      });
    } finally {
      setVulnLoading(false);
    }
  };


  // Security Scanner Functions
  const scanSecurityHeaders = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setHeaderLoading(true);
    setHeaderResults(null);
    setIsCached(false);

    const storedHeaders = loadStoredScans("cyberregis_headers");
    const cached = storedHeaders.find((scan) => scan.input === headerUrl);
    if (cached) {
      setHeaderResults(cached.result);
      setIsCached(true);
      setHeaderLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/security-headers`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: headerUrl }),
      });

      if (response.ok) {
        const data = await response.json();
        setHeaderResults(data);
        upsertStoredScan("cyberregis_headers", {
          input: headerUrl,
          result: data,
          timestamp: new Date().toISOString(),
        });
      } else {
        setHeaderResults({
          status: "error",
          message: `Security headers scan failed: ${response.statusText}`,
        });
      }
    } catch (error) {
      setHeaderResults({
        status: "error",
        message: `Security headers scan failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      });
    } finally {
      setHeaderLoading(false);
    }
  };

  const analyzeEmailSecurity = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setEmailLoading(true);
    setEmailResults(null);
    setIsCached(false);

    const storedEmails = loadStoredScans("cyberregis_email");
    const cached = storedEmails.find((scan) => scan.input === emailDomain);
    if (cached) {
      setEmailResults(cached.result);
      setIsCached(true);
      setEmailLoading(false);
      return;
    }

    try {
      const response = await fetch(`${API_URL}/api/email-security`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: emailDomain }),
      });

      if (response.ok) {
        const data = await response.json();
        setEmailResults(data);
        upsertStoredScan("cyberregis_email", {
          input: emailDomain,
          result: data,
          timestamp: new Date().toISOString(),
        });
      } else {
        setEmailResults({
          status: "error",
          message: `Email security analysis failed: ${response.statusText}`,
        });
      }
    } catch (error) {
      setEmailResults({
        status: "error",
        message: `Email security analysis failed: ${error instanceof Error ? error.message : "Unknown error"}`,
      });
    } finally {
      setEmailLoading(false);
    }
  };

  const runIntegratedScan = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setIntegratedLoading(true);
    setIntegratedResults(null);

    // Check localStorage for cached results
    const storedIntegrated = loadStoredScans("cyberregis_integrated");
    const cached = storedIntegrated.find((scan) => scan.input === integratedInput);
    if (cached) {
      setIntegratedResults(cached.result as any);
      setIsCached(true);
      setIntegratedLoading(false);
      return;
    }

    // Check if input is a URL or domain
    const isUrl = integratedInput.startsWith('http://') || integratedInput.startsWith('https://');
    const domain = isUrl ? new URL(integratedInput).hostname : integratedInput;

    try {
      // Run both scans in parallel
      const [urlResponse, domainResponse] = await Promise.all([
        fetch(`${API_URL}/api/check-url`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url: integratedInput }),
        }),
        fetch(`${API_URL}/api/analyze-domain`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ domain }),
        }),
      ]);

      const urlData = await urlResponse.json();
      const domainData = await domainResponse.json();

      setIntegratedResults({
        urlResults: urlData,
        domainResults: domainData,
      });

      upsertStoredScan("cyberregis_integrated", {
        input: integratedInput,
        result: { urlResults: urlData, domainResults: domainData } as any,
        timestamp: new Date().toISOString(),
      });

    } catch (error) {
      setIntegratedResults({
        urlResults: {
          status: "error",
          message: `Integrated scan failed: ${error instanceof Error ? error.message : "Unknown error"}`,
        },
        domainResults: {
          status: "error",
          message: `Integrated scan failed: ${error instanceof Error ? error.message : "Unknown error"}`,
        },
      });
      console.error("Error in integrated scan:", error);
    } finally {
      setIntegratedLoading(false);
    }
  };

  const handleChatSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    addChatMessage(chatInput, true);
    setChatInput("");
    setLoading(true);

    try {
      const response = await fetch(`${API_URL}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: chatInput }),
      });
      const data = await response.json();

      if (data.status === "error") {
        throw new Error(data.message || "Failed to get response");
      }

      addChatMessage(data.data.response || "No response received.", false);
    } catch (error) {
      addChatMessage("Sorry, I couldn't process your request. Please try again.", false);
      console.error("Error in chat:", error);
    } finally {
      setLoading(false);
    }
  };

  // Auto-scroll to bottom of chat
  useEffect(() => {
    if (chatScrollRef.current) {
      chatScrollRef.current.scrollTop = chatScrollRef.current.scrollHeight;
    }
  }, [chatMessages]);

  return (
    <div
      className="min-h-screen bg-background"
      style={{
        backgroundImage: "radial-gradient(circle at 50% 50%, hsl(var(--background)) 0%, hsl(var(--card)) 100%)",
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
              <Link href="/" className="text-primary transition-colors">
                Dashboard
              </Link>
              <Link href="/resources" className="text-foreground hover:text-primary transition-colors">
                Resources
              </Link>
              <Link href="/monitoring" className="text-foreground hover:text-primary transition-colors">
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

      <div className="max-w-7xl mx-auto p-8">
        <div className="flex items-center justify-between mb-12">
          <div>

            <p className="text-muted-foreground">Advanced Threat Detection System</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          <Card className="p-6 border-primary/20 bg-card/50 backdrop-blur-sm">
            <div className="flex items-center space-x-2 mb-4">
              <Eye className="w-5 h-5 text-primary" />
              <h3 className="text-lg font-semibold">Security Status</h3>
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Threat Level</span>
                <Badge variant="secondary" className="bg-green-500/20 text-green-500">
                  Low
                </Badge>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm text-muted-foreground">Active Scans</span>
                <span className="text-sm">{loading ? "1" : "0"}</span>
              </div>
            </div>
          </Card>
        </div>

        <Card className="p-6 border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <div className="space-y-6">
            <div className="space-y-2">
              <h2 className="text-2xl font-semibold">Threat Map Live</h2>
              <p className="text-sm text-muted-foreground">
                Real-time visualization of global cyber threats (Source: Radware)
              </p>
            </div>
            <Separator />
            <div className="relative w-full h-[400px] rounded-md overflow-hidden">
              <iframe
                src="https://livethreatmap.radware.com"
                className="w-full h-full border-none"
                title="Radware Live Threat Map"
                allowFullScreen
              />
            </div>
          </div>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <Tabs defaultValue="integrated" className="p-6">
            <TabsList className="grid w-full grid-cols-5 lg:w-[600px] mb-6">
              <TabsTrigger value="integrated" className="data-[state=active]:bg-primary/20 text-xs">
                <Eye className="w-3 h-3 mr-1" />
                Domain Recon
              </TabsTrigger>
              <TabsTrigger value="ip" className="data-[state=active]:bg-primary/20 text-xs">
                <Network className="w-3 h-3 mr-1" />
                IP
              </TabsTrigger>
              <TabsTrigger value="network" className="data-[state=active]:bg-primary/20 text-xs">
                <BarChart4 className="w-3 h-3 mr-1" />
                Network
              </TabsTrigger>
              <TabsTrigger value="advanced" className="data-[state=active]:bg-primary/20 text-xs">
                <Shield className="w-3 h-3 mr-1" />
                Advanced
              </TabsTrigger>
              <TabsTrigger value="security" className="data-[state=active]:bg-primary/20 text-xs">
                <Activity className="w-3 h-3 mr-1" />
                Security
              </TabsTrigger>
            </TabsList>

            <TabsContent value="integrated" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Domain Reconnaissance & URL Scanner</h2>
                <p className="text-sm text-muted-foreground">
                  Comprehensive analysis combining domain reconnaissance and URL threat detection in one scan
                </p>
              </div>
              <Separator />
              <form onSubmit={runIntegratedScan} className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    type="text"
                    placeholder="Enter domain (e.g., example.com) or URL (e.g., https://example.com)"
                    value={integratedInput}
                    onChange={(e) => {
                      let value = e.target.value;
                      // Auto-add https:// if user starts with 'h'
                      if (value.startsWith('h') && !value.startsWith('http')) {
                        value = 'https://' + value.substring(1);
                      }
                      // Auto-add https:// if user enters just a domain without protocol
                      else if (value && !value.includes('://') && !value.startsWith('http')) {
                        if (value.includes('.') && !value.startsWith('www.')) {
                          value = 'https://' + value;
                        }
                      }
                      setIntegratedInput(value);
                    }}
                    onBlur={(e) => {
                      let value = e.target.value;
                      // Auto-add https:// if user enters just a domain without protocol
                      if (value && !value.includes('://') && !value.startsWith('http')) {
                        if (value.includes('.') && !value.startsWith('www.')) {
                          value = 'https://' + value;
                          setIntegratedInput(value);
                        }
                      }
                    }}
                    required
                    className="bg-background/50"
                  />
                  <Button
                    type="submit"
                    disabled={integratedLoading}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {integratedLoading ? "Running Scan..." : "Run Scan"}
                  </Button>
                  {integratedResults && (
                    <Button
                      type="button"
                      variant="outline"
                      onClick={() => {
                        setIntegratedResults(null);
                        setIntegratedInput("");
                        setIsCached(false);
                      }}
                      className="border-destructive/20 text-destructive hover:bg-destructive/10"
                    >
                      Clear Results
                    </Button>
                  )}
                </div>
                {integratedLoading && (
                  <div className="text-center py-4">
                    <div className="inline-flex items-center space-x-2">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                      <span className="text-sm text-muted-foreground">Running comprehensive security analysis...</span>
                    </div>
                  </div>
                )}
                {integratedResults && (
                  <div className="space-y-6">
                    {/* Scan Summary Header */}
                    <div className="bg-gradient-to-r from-primary/10 to-primary/5 border border-primary/20 rounded-lg p-4">
                      <div className="flex items-center justify-between">
                        <div className="space-y-1">
                          <h3 className="text-lg font-semibold text-primary">Scan Summary</h3>
                          <p className="text-sm text-muted-foreground">
                            Input: <span className="font-mono text-primary">{integratedInput}</span>
                          </p>
                          <p className="text-xs text-muted-foreground">
                            {isCached ? "Showing cached results" : "Fresh scan completed"}
                          </p>
                        </div>
                        <div className="text-right">
                          <div className="text-2xl font-bold text-primary">
                            {integratedResults.urlResults?.data?.threat_analysis?.is_malicious ? "⚠️" : "✅"}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {integratedResults.urlResults?.data?.threat_analysis?.is_malicious ? "High Risk" : "Low Risk"}
                          </div>
                        </div>
                      </div>
                    </div>

                    {/* URL Analysis Results */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-lg font-semibold text-primary">URL Threat Analysis</h3>
                        {integratedResults.urlResults?.timestamp && (
                          <span className="text-xs text-muted-foreground">
                            Scanned: {new Date(integratedResults.urlResults.timestamp).toLocaleString()}
                          </span>
                        )}
                      </div>
                      <Alert className="bg-primary/10 border-primary/20">
                        <AlertDescription>
                          <div className="space-y-4">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                {isCached && (
                                  <Badge variant="secondary" className="bg-blue-500/20 text-blue-600 text-xs">
                                    Cached Results
                                  </Badge>
                                )}
                                <span className="text-sm text-muted-foreground">View:</span>
                                <Button
                                  variant={integratedViewMode === 'normal' ? 'default' : 'outline'}
                                  size="sm"
                                  onClick={() => setIntegratedViewMode('normal')}
                                  className="h-7 px-2 text-xs"
                                >
                                  Normal
                                </Button>
                                <Button
                                  variant={integratedViewMode === 'json' ? 'default' : 'outline'}
                                  size="sm"
                                  onClick={() => setIntegratedViewMode('json')}
                                  className="h-7 px-2 text-xs"
                                >
                                  JSON
                                </Button>
                              </div>
                            </div>
                            {integratedViewMode === 'json' ? (
                              <div className="bg-slate-900 rounded-md p-4 overflow-auto">
                                <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                                  {JSON.stringify(integratedResults.urlResults, null, 2)}
                                </pre>
                              </div>
                            ) : (
                              formatResults(integratedResults.urlResults, 'normal')
                            )}
                          </div>
                        </AlertDescription>
                      </Alert>
                    </div>

                    {/* Domain Analysis Results */}
                    <div className="space-y-3">
                      <div className="flex items-center justify-between">
                        <h3 className="text-lg font-semibold text-primary">Domain Reconnaissance</h3>
                        {integratedResults.domainResults?.timestamp && (
                          <span className="text-xs text-muted-foreground">
                            Scanned: {new Date(integratedResults.domainResults.timestamp).toLocaleString()}
                          </span>
                        )}
                      </div>
                      <Alert className="bg-primary/10 border-primary/20">
                        <AlertDescription>
                          <div className="space-y-4">
                            {integratedViewMode === 'json' ? (
                              <div className="bg-slate-900 rounded-md p-4 overflow-auto">
                                <pre className="text-green-400 text-sm font-mono whitespace-pre-wrap">
                                  {JSON.stringify(integratedResults.domainResults, null, 2)}
                                </pre>
                              </div>
                            ) : (
                              formatResults(integratedResults.domainResults, 'normal')
                            )}
                          </div>
                        </AlertDescription>
                      </Alert>
                    </div>

                    {/* Combined Summary */}
                    <div className="space-y-3">
                      <h3 className="text-lg font-semibold text-primary">Combined Security Assessment</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        {/* Overall Risk Level */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-2">Overall Risk Level</h4>
                          <div className="text-2xl font-bold text-center">
                            {integratedResults.urlResults?.data?.threat_analysis?.is_malicious ||
                              integratedResults.domainResults?.status === "error" ? (
                              <span className="text-red-500">HIGH</span>
                            ) : (
                              <span className="text-green-500">LOW</span>
                            )}
                          </div>
                        </div>

                        {/* SSL Status */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-2">SSL Certificate</h4>
                          <div className="text-2xl font-bold text-center">
                            {integratedResults.urlResults?.data?.additional_checks?.ssl_security?.valid ? (
                              <span className="text-green-500">VALID</span>
                            ) : (
                              <span className="text-red-500">INVALID</span>
                            )}
                          </div>
                        </div>

                        {/* Domain Age */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-2">Domain Age</h4>
                          <div className="text-2xl font-bold text-center">
                            {integratedResults.domainResults?.domain_info?.whois?.creation_date ? (
                              <span className="text-blue-500">
                                {Math.floor((Date.now() - new Date(integratedResults.domainResults.domain_info.whois.creation_date).getTime()) / (1000 * 60 * 60 * 24 * 365))}y
                              </span>
                            ) : (
                              <span className="text-muted-foreground">N/A</span>
                            )}
                          </div>
                        </div>

                        {/* Subdomain Count */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-2">Subdomains</h4>
                          <div className="text-2xl font-bold text-center">
                            {integratedResults.domainResults?.domain_info?.subdomains ? (
                              <span className="text-purple-500">
                                {integratedResults.domainResults.domain_info.subdomains.length}
                              </span>
                            ) : (
                              <span className="text-muted-foreground">0</span>
                            )}
                          </div>
                        </div>
                      </div>

                      {/* Additional Security Insights */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
                        {/* Security Features */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-3">Security Features</h4>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-sm">DNSSEC:</span>
                              <Badge variant={integratedResults.domainResults?.domain_info?.security_features?.dnssec ? "default" : "secondary"} className="text-xs">
                                {integratedResults.domainResults?.domain_info?.security_features?.dnssec ? "Enabled" : "Disabled"}
                              </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-sm">DMARC:</span>
                              <Badge variant={integratedResults.domainResults?.domain_info?.security_features?.dmarc ? "default" : "secondary"} className="text-xs">
                                {integratedResults.domainResults?.domain_info?.security_features?.dmarc ? "Present" : "Missing"}
                              </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-sm">SPF:</span>
                              <Badge variant={integratedResults.domainResults?.domain_info?.security_features?.spf ? "default" : "secondary"} className="text-xs">
                                {integratedResults.domainResults?.domain_info?.security_features?.spf ? "Present" : "Missing"}
                              </Badge>
                            </div>
                          </div>
                        </div>

                        {/* Threat Indicators */}
                        <div className="bg-card/50 border border-border/20 rounded-lg p-4">
                          <h4 className="font-medium text-sm text-muted-foreground mb-3">Threat Indicators</h4>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-sm">Malicious URL:</span>
                              <Badge variant={integratedResults.urlResults?.data?.threat_analysis?.is_malicious ? "destructive" : "default"} className="text-xs">
                                {integratedResults.urlResults?.data?.threat_analysis?.is_malicious ? "Yes" : "No"}
                              </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-sm">Suspicious Patterns:</span>
                              <Badge variant={integratedResults.urlResults?.data?.additional_checks?.suspicious_patterns?.found ? "destructive" : "default"} className="text-xs">
                                {integratedResults.urlResults?.data?.additional_checks?.suspicious_patterns?.found ? "Found" : "None"}
                              </Badge>
                            </div>
                            <div className="flex items-center justify-between">
                              <span className="text-sm">Security Score:</span>
                              <Badge variant="outline" className="text-xs">
                                {integratedResults.urlResults?.data?.virustotal?.risk_assessment ?
                                  `${integratedResults.urlResults.data.virustotal.risk_assessment.malicious_count || 0} / ${integratedResults.urlResults.data.virustotal.risk_assessment.total_engines || 0}` :
                                  integratedResults.urlResults?.data?.virustotal?.data?.attributes?.stats ?
                                    `${integratedResults.urlResults.data.virustotal.data.attributes.stats.malicious || 0} / ${integratedResults.urlResults.data.virustotal.data.attributes.stats.total || 0}` :
                                    '0 / 0'
                                }
                              </Badge>
                            </div>
                          </div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}
              </form>
            </TabsContent>

            <TabsContent value="ip" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">IP Reputation Scanner</h2>
                <p className="text-sm text-muted-foreground">
                  Check IP addresses for malicious activity with comprehensive security analysis
                </p>
              </div>
              <Separator />
              <form onSubmit={checkIp} className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    type="text"
                    placeholder="Enter IP address"
                    value={ip}
                    onChange={(e) => setIp(e.target.value)}
                    required
                    pattern="^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
                    className="bg-background/50"
                  />
                  <Button
                    type="submit"
                    disabled={loading}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Scanning..." : "Scan IP"}
                  </Button>
                </div>

                {/* Enhanced Loading State for IP Scanner */}
                {loading && (
                  <div className="text-center py-4">
                    <div className="inline-flex items-center space-x-2">
                      <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-primary"></div>
                      <span className="text-sm text-muted-foreground">Analyzing IP address and running security checks...</span>
                    </div>
                  </div>
                )}

                {ipResults && (
                  <Alert
                    className={`bg-${ipResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${ipResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(ipResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm text-muted-foreground">View:</span>
                            <Button
                              variant={ipViewMode === 'normal' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setIpViewMode('normal')}
                              className="h-7 px-2 text-xs"
                            >
                              Normal
                            </Button>
                            <Button
                              variant={ipViewMode === 'json' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setIpViewMode('json')}
                              className="h-7 px-2 text-xs"
                            >
                              JSON
                            </Button>
                          </div>
                        </div>
                        {formatResults(ipResults, ipViewMode)}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="network" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Network Log Analysis</h2>
                <p className="text-sm text-muted-foreground">
                  Upload PCAP files for comprehensive network traffic analysis with enhanced security scanning
                </p>
              </div>
              <Separator />
              <form onSubmit={analyzeNetworkLog} className="space-y-4">
                <div className="border-2 border-dashed border-border/50 rounded-lg p-8 text-center bg-background/30">
                  <input
                    type="file"
                    ref={fileInputRef}
                    onChange={handleFileChange}
                    accept=".pcap,.cap,.pcapng"
                    className="hidden"
                  />
                  <div className="space-y-4">
                    <div className="mx-auto w-12 h-12 rounded-full bg-primary/10 flex items-center justify-center">
                      <FileUp className="w-6 h-6 text-primary" />
                    </div>
                    <div className="space-y-1">
                      <h3 className="text-lg font-medium">Upload PCAP File</h3>
                      <p className="text-sm text-muted-foreground">
                        Drag and drop your PCAP file here, or click to browse
                      </p>
                      <p className="text-xs text-muted-foreground mt-2">
                        Files will be analyzed for protocols, traffic patterns, and scanned for security threats
                      </p>
                    </div>
                    {selectedFile ? (
                      <div className="bg-primary/5 p-3 rounded-md inline-flex items-center space-x-2">
                        <FileText className="w-4 h-4 text-primary" />
                        <span className="text-sm font-medium">{selectedFile.name}</span>
                        <Badge variant="outline" className="bg-primary/10 text-xs">
                          {(selectedFile.size / 1024).toFixed(1)} KB
                        </Badge>
                      </div>
                    ) : null}
                    <Button
                      type="button"
                      variant="outline"
                      onClick={handleFileUploadClick}
                      className="bg-secondary/50"
                    >
                      Select File
                    </Button>
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    disabled={loading || !selectedFile}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Analyzing..." : "Analyze Network Log"}
                  </Button>
                </div>

                {/* Enhanced Loading State */}
                {loading && (
                  <div className="text-center py-6">
                    <div className="inline-flex items-center space-x-3">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-primary"></div>
                      <div className="space-y-1">
                        <p className="text-sm font-medium">Analyzing PCAP file...</p>
                        <p className="text-xs text-muted-foreground">
                          This may take a few minutes for large files
                        </p>
                      </div>
                    </div>
                  </div>
                )}

                {logResults && (
                  <Alert
                    className={`bg-${logResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${logResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div className="space-y-2">
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(logResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                            <p
                              className={`text-${logResults.status === "error" ? "destructive" : "primary"
                                }`}
                            >
                              {logResults.message || `Analysis completed for ${selectedFile?.name}`}
                            </p>
                          </div>
                          {logResults.data && (
                            <div className="flex items-center space-x-2">
                              <span className="text-sm text-muted-foreground">View:</span>
                              <Button
                                variant={logViewMode === 'normal' ? 'default' : 'outline'}
                                size="sm"
                                onClick={() => setLogViewMode('normal')}
                                className="h-7 px-2 text-xs"
                              >
                                Normal
                              </Button>
                              <Button
                                variant={logViewMode === 'json' ? 'default' : 'outline'}
                                size="sm"
                                onClick={() => setLogViewMode('json')}
                                className="h-7 px-2 text-xs"
                              >
                                JSON
                              </Button>
                            </div>
                          )}
                        </div>
                        {logResults.data && <div className="mt-4">{formatResults(logResults, logViewMode)}</div>}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="advanced" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Advanced Security Scanners</h2>
                <p className="text-sm text-muted-foreground">
                  Port scanning and vulnerability assessment
                </p>
              </div>
              <Separator />

              {/* Port Scanner Section */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Port Scanner</h3>
                <form onSubmit={scanPorts} className="space-y-4">
                  <div className="flex space-x-2">
                    <Input
                      type="text"
                      placeholder="Enter IP address or hostname"
                      value={portTarget}
                      onChange={(e) => setPortTarget(e.target.value)}
                      className="bg-background/50"
                    />
                    <Button
                      type="submit"
                      disabled={portLoading}
                      className="bg-primary hover:bg-primary/90"
                    >
                      {portLoading ? "Scanning..." : "Scan Ports"}
                    </Button>
                  </div>
                </form>
                {portResults && (
                  <Alert
                    className={`bg-${portResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${portResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(portResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm text-muted-foreground">View:</span>
                            <Button
                              variant={portViewMode === 'normal' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setPortViewMode('normal')}
                              className="h-7 px-2 text-xs"
                            >
                              Normal
                            </Button>
                            <Button
                              variant={portViewMode === 'json' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setPortViewMode('json')}
                              className="h-7 px-2 text-xs"
                            >
                              JSON
                            </Button>
                          </div>
                        </div>
                        {formatResults(portResults, portViewMode)}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </div>

              <Separator />

              {/* Vulnerability Scanner Section */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Vulnerability Scanner</h3>
                <form onSubmit={scanVulnerabilities} className="space-y-4">
                  <div className="flex space-x-2">
                    <Input
                      type="text"
                      placeholder="Enter target for CVE scanning"
                      value={vulnTarget}
                      onChange={(e) => setVulnTarget(e.target.value)}
                      className="bg-background/50"
                    />
                    <Button
                      type="submit"
                      disabled={vulnLoading}
                      className="bg-primary hover:bg-primary/90"
                    >
                      {vulnLoading ? "Scanning..." : "Scan CVEs"}
                    </Button>
                  </div>
                </form>
                {vulnResults && (
                  <Alert
                    className={`bg-${vulnResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${vulnResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(vulnResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm text-muted-foreground">View:</span>
                            <Button
                              variant={vulnViewMode === 'normal' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setVulnViewMode('normal')}
                              className="h-7 px-2 text-xs"
                            >
                              Normal
                            </Button>
                            <Button
                              variant={vulnViewMode === 'json' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setVulnViewMode('json')}
                              className="h-7 px-2 text-xs"
                            >
                              JSON
                            </Button>
                          </div>
                        </div>
                        {formatResults(vulnResults, vulnViewMode)}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </div>

            </TabsContent>

            <TabsContent value="security" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Security Headers & Email Analysis</h2>
                <p className="text-sm text-muted-foreground">
                  Security headers analysis and email security assessment
                </p>
              </div>
              <Separator />

              {/* Security Headers Scanner */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Security Headers Scanner</h3>
                <form onSubmit={scanSecurityHeaders} className="space-y-4">
                  <div className="flex space-x-2">
                    <Input
                      type="url"
                      placeholder="Enter website URL"
                      value={headerUrl}
                      onChange={(e) => setHeaderUrl(e.target.value)}
                      className="bg-background/50"
                    />
                    <Button
                      type="submit"
                      disabled={headerLoading}
                      className="bg-primary hover:bg-primary/90"
                    >
                      {headerLoading ? "Scanning..." : "Scan Headers"}
                    </Button>
                  </div>
                </form>
                {headerResults && (
                  <Alert
                    className={`bg-${headerResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${headerResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(headerResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm text-muted-foreground">View:</span>
                            <Button
                              variant={headerViewMode === 'normal' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setHeaderViewMode('normal')}
                              className="h-7 px-2 text-xs"
                            >
                              Normal
                            </Button>
                            <Button
                              variant={headerViewMode === 'json' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setHeaderViewMode('json')}
                              className="h-7 px-2 text-xs"
                            >
                              JSON
                            </Button>
                          </div>
                        </div>
                        {formatResults(headerResults, headerViewMode)}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </div>

              <Separator />

              {/* Email Security Scanner */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold">Email Security Analysis</h3>
                <form onSubmit={analyzeEmailSecurity} className="space-y-4">
                  <div className="flex space-x-2">
                    <Input
                      type="text"
                      placeholder="Enter domain for email security scan"
                      value={emailDomain}
                      onChange={(e) => setEmailDomain(e.target.value)}
                      className="bg-background/50"
                    />
                    <Button
                      type="submit"
                      disabled={emailLoading}
                      className="bg-primary hover:bg-primary/90"
                    >
                      {emailLoading ? "Analyzing..." : "Analyze Email Security"}
                    </Button>
                  </div>
                </form>
                {emailResults && (
                  <Alert
                    className={`bg-${emailResults.status === "error" ? "destructive" : "primary"
                      }/10 border-${emailResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-4">
                        <div className="flex items-center justify-between">
                          <div>
                            {isCached && (
                              <p className="text-sm text-muted-foreground">
                                Showing cached results from {new Date(emailResults.timestamp || "").toLocaleString()}
                              </p>
                            )}
                          </div>
                          <div className="flex items-center space-x-2">
                            <span className="text-sm text-muted-foreground">View:</span>
                            <Button
                              variant={emailViewMode === 'normal' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setEmailViewMode('normal')}
                              className="h-7 px-2 text-xs"
                            >
                              Normal
                            </Button>
                            <Button
                              variant={emailViewMode === 'json' ? 'default' : 'outline'}
                              size="sm"
                              onClick={() => setEmailViewMode('json')}
                              className="h-7 px-2 text-xs"
                            >
                              JSON
                            </Button>
                          </div>
                        </div>
                        {formatResults(emailResults, emailViewMode)}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </div>
            </TabsContent>
          </Tabs>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm p-6">
          <div className="space-y-6">
            <div className="space-y-2">
              <h2 className="text-2xl font-semibold flex items-center">
                <MessageSquare className="w-6 h-6 text-primary mr-2" />
                CyberRegis Assistant
              </h2>
              <p className="text-sm text-muted-foreground">
                Ask questions about cyber threats, scan results, or security best practices
              </p>
            </div>
            <Separator />
            <ScrollArea className="h-[300px] w-full rounded-md bg-background/30 p-4" ref={chatScrollRef}>
              {chatMessages.length === 0 ? (
                <div className="text-center text-muted-foreground text-sm">
                  Start a conversation with the CyberRegis Assistant
                </div>
              ) : (
                chatMessages.map((message) => (
                  <div
                    key={message.id}
                    className={`mb-4 flex ${message.isUser ? "justify-end" : "justify-start"}`}
                  >
                    <div
                      className={`max-w-[70%] rounded-lg p-3 ${message.isUser
                        ? "bg-primary/20 text-primary-foreground"
                        : "bg-secondary/50 text-foreground"
                        }`}
                    >
                      {message.isUser ? (
                        <p className="text-sm">{message.text}</p>
                      ) : (
                        <div className="text-sm prose prose-invert max-w-none">
                          <ReactMarkdown
                            remarkPlugins={[remarkGfm]}
                            components={{
                              h1: ({ node, ...props }) => <h1 className="text-lg font-semibold mt-2 mb-1" {...props} />,
                              h2: ({ node, ...props }) => <h2 className="text-base font-medium mt-2 mb-1" {...props} />,
                              h3: ({ node, ...props }) => <h3 className="text-sm font-medium mt-2 mb-1" {...props} />,
                              p: ({ node, ...props }) => <p className="mb-2" {...props} />,
                              ul: ({ node, ...props }) => <ul className="list-disc pl-4 mb-2" {...props} />,
                              ol: ({ node, ...props }) => <ol className="list-decimal pl-4 mb-2" {...props} />,
                              li: ({ node, ...props }) => <li className="mb-1" {...props} />,
                              strong: ({ node, ...props }) => <strong className="font-medium" {...props} />,
                            }}
                          >
                            {message.text}
                          </ReactMarkdown>
                        </div>
                      )}
                      <span className="text-xs text-muted-foreground mt-1 block">
                        {message.timestamp}
                      </span>
                    </div>
                  </div>
                ))
              )}
            </ScrollArea>
            <form onSubmit={handleChatSubmit} className="flex space-x-2">
              <Input
                type="text"
                placeholder="Ask a question..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
                className="bg-background/50"
              />
              <Button
                type="submit"
                disabled={loading || !chatInput.trim()}
                className="bg-primary hover:bg-primary/90"
              >
                {loading ? "Processing..." : "Send"}
              </Button>
            </form>
          </div>
        </Card>

        {/* File Content Modal */}
        <Dialog open={fileModalOpen} onOpenChange={setFileModalOpen}>
          <DialogContent className="max-w-4xl max-h-[80vh]">
            <DialogHeader>
              <DialogTitle className="flex items-center justify-between">
                <span>
                  {fileContent?.file_type === 'robots' ? 'robots.txt' : 'security.txt'} - {fileContent?.domain}
                </span>
                <div className="flex items-center gap-2">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => fileContent?.url && window.open(fileContent.url, '_blank')}
                    className="h-7 px-2 text-xs"
                  >
                    <ExternalLink className="w-3 h-3 mr-1" />
                    Open Original
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => setFileModalOpen(false)}
                    className="h-7 w-7 p-0"
                  >
                    <X className="w-4 h-4" />
                  </Button>
                </div>
              </DialogTitle>
            </DialogHeader>

            {fileContent && (
              <div className="space-y-4">
                {/* File Info */}
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="font-medium text-muted-foreground">URL:</span>
                    <p className="font-mono text-xs break-all">{fileContent.url}</p>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Size:</span>
                    <p>{fileContent.content_length} bytes</p>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Content Type:</span>
                    <p>{fileContent.content_type}</p>
                  </div>
                  <div>
                    <span className="font-medium text-muted-foreground">Last Modified:</span>
                    <p className="text-xs">{fileContent.last_modified}</p>
                  </div>
                </div>

                <Separator />

                {/* File Content */}
                <div>
                  <h4 className="font-medium mb-2">File Content:</h4>
                  <ScrollArea className="h-96 w-full border rounded-md">
                    <pre className="p-4 text-sm font-mono whitespace-pre-wrap bg-muted/20">
                      {fileContent.content}
                    </pre>
                  </ScrollArea>
                </div>
              </div>
            )}
          </DialogContent>
        </Dialog>
      </div>
    </div>
  );
}