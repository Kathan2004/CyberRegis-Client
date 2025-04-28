"use client";

import { useState, useEffect, useRef } from "react";
import { Shield, Globe, Network, Eye, Activity, FileText, BarChart4, Upload, FileUp, MessageSquare } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

// Define interface for API responses
interface ScanResult {
  data?: {
    url_analysis?: { input_url: string };
    threat_analysis?: { is_malicious: boolean };
    additional_checks?: {
      domain_analysis?: { risk_level: string };
      ssl_security?: { valid: boolean };
      suspicious_patterns?: { risk_level: string };
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
    };
    pcap_analysis?: { [protocol: string]: number };
    chart_base64?: string;
  };
  formatted?: string;
  status: "success" | "error";
  timestamp?: string;
  message?: string;
}

// Interface for chatbot messages
interface ChatMessage {
  id: number;
  text: string;
  isUser: boolean;
  timestamp: string;
}

export default function Home() {
  const [url, setUrl] = useState("");
  const [ip, setIp] = useState("");
  const [urlResults, setUrlResults] = useState<ScanResult | null>(null);
  const [ipResults, setIpResults] = useState<ScanResult | null>(null);
  const [logResults, setLogResults] = useState<ScanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([
    {
      id: 1,
      text: "Hey! How can I assist you with your cybersecurity concerns today? Do you have a specific question or issue you'd like help with?",
      isUser: false,
      timestamp: new Date().toLocaleTimeString(),
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const chatScrollRef = useRef<HTMLDivElement>(null);

  const checkUrl = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const API_URL = "https://cyberregisserver-production.up.railway.app";

    try {
      const response = await fetch(`${API_URL}/api/check-url`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await response.json();
      setUrlResults(data);
    } catch (error) {
      setUrlResults({
        status: "error",
        message: "Failed to check URL. Please try again.",
      });
      console.error("Error checking URL:", error);
    }
    setLoading(false);
  };

  const checkIp = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    setLoading(true);
    const API_URL = "https://cyberregisserver-production.up.railway.app";

    try {
      const response = await fetch(`${API_URL}/api/check-ip`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      const data = await response.json();
      setIpResults(data);
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
    try {
      const formData = new FormData();
      formData.append("file", selectedFile);
      console.log("Uploading file:", selectedFile.name, selectedFile.size);

      const response = await fetch(
        "https://effective-computing-machine-w6pqwrj9rj93gvp9-4000.app.github.dev/api/analyze-pcap",
        {
          method: "POST",
          body: formData,
        }
      );

      if (!response.ok) {
        const errorData = await response.json().catch(() => ({}));
        console.error("Server error:", response.status, errorData);
        throw new Error(
          errorData.message || `Server responded with status: ${response.status}`
        );
      }

      const data = await response.json();
      console.log("Analysis response:", data);

      // Store the full response
      setLogResults(data);

      // Optionally, extract and display specific fields
      if (data.status === "success") {
        const { chart_base64, metadata, pcap_analysis, virustotal } = data.data;
        console.log("Metadata:", metadata);
        console.log("PCAP Analysis:", pcap_analysis);
        console.log("VirusTotal:", virustotal);
      }
    } catch (error) {
      setLogResults({
        status: "error",
        message: `Failed to analyze network log: ${error.message}`,
      });
      console.error("Error analyzing network log:", error);
    } finally {
      setLoading(false);
    }
  };

  const formatResults = (results: ScanResult | null): JSX.Element => {
    if (!results) return <></>;
    if (results.status === "error") {
      return <p>{results.message || "An error occurred."}</p>;
    }

    // Handle PCAP analysis results
    if (results.data?.pcap_analysis) {
      return (
        <div className="space-y-4">
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
          {results.data.virustotal?.data?.attributes?.stats && (
            <div className="space-y-1">
              <h4 className="text-sm font-semibold">VirusTotal Stats</h4>
              <div className="text-xs space-y-1">
                {Object.entries(results.data.virustotal.data.attributes.stats).map(([key, value]) => (
                  <div key={key} className="flex justify-between">
                    <span className="text-muted-foreground">{key}:</span>
                    <span>{value}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
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

    // Handle URL and IP results
    if (results.formatted) {
      return (
        <div>
          {results.data && (
            <div className="mb-4">
              <p>
                <strong>Status:</strong>{" "}
                {results.data.threat_analysis?.is_malicious ? "Malicious" : "Safe"}
              </p>
              <p>
                <strong>Risk Level:</strong>{" "}
                {results.data.additional_checks?.domain_analysis?.risk_level || "Unknown"}
              </p>
              {results.data.recommendations?.length ? (
                <div>
                  <strong>Recommendations:</strong>
                  <ul className="list-disc pl-5">
                    {results.data.recommendations.map((rec, index) => (
                      <li key={index}>{rec}</li>
                    ))}
                  </ul>
                </div>
              ) : null}
            </div>
          )}
          <details>
            <summary className="cursor-pointer text-primary">View Full Details</summary>
            <div className="bg-black p-4 rounded-md">
              <style jsx>{`
                .bg-black pre {
                  background: transparent !important;
                  color: #4ade80;
                  padding: 0;
                  border-radius: 0;
                }
              `}</style>
              <div dangerouslySetInnerHTML={{ __html: results.formatted }} />
            </div>
          </details>
        </div>
      );
    }
    return <pre>{JSON.stringify(results, null, 2)}</pre>;
  };

  const handleChatSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    if (!chatInput.trim()) return;

    const newUserMessage: ChatMessage = {
      id: chatMessages.length + 1,
      text: chatInput,
      isUser: true,
      timestamp: new Date().toLocaleTimeString(),
    };

    setChatMessages((prev) => [...prev, newUserMessage]);
    setChatInput("");
    setLoading(true);

    try {
      const response = await fetch("https://cyberregisserver-production.up.railway.app/api/chat", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: chatInput }),
      });
      const data = await response.json();

      if (data.status === "error") {
        throw new Error(data.message || "Failed to get response");
      }

      const botResponse: ChatMessage = {
        id: chatMessages.length + 2,
        text: data.data.response || "No response received.",
        isUser: false,
        timestamp: new Date().toLocaleTimeString(),
      };

      setChatMessages((prev) => [...prev, botResponse]);
    } catch (error) {
      const errorMessage: ChatMessage = {
        id: chatMessages.length + 2,
        text: "Sorry, I couldn't process your request. Please try again.",
        isUser: false,
        timestamp: new Date().toLocaleTimeString(),
      };
      setChatMessages((prev) => [...prev, errorMessage]);
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
            <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
              CyberRegis
            </h1>
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

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <Tabs defaultValue="url" className="p-6">
            <TabsList className="grid w-full grid-cols-3 lg:w-[400px] mb-6">
              <TabsTrigger value="url" className="data-[state=active]:bg-primary/20">
                <Globe className="w-4 h-4 mr-2" />
                URL
              </TabsTrigger>
              <TabsTrigger value="ip" className="data-[state=active]:bg-primary/20">
                <Network className="w-4 h-4 mr-2" />
                IP
              </TabsTrigger>
              <TabsTrigger value="network" className="data-[state=active]:bg-primary/20">
                <BarChart4 className="w-4 h-4 mr-2" />
                Network Log
              </TabsTrigger>
            </TabsList>

            <TabsContent value="url" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Phishing URL Scanner</h2>
                <p className="text-sm text-muted-foreground">Analyze URLs for potential phishing threats</p>
              </div>
              <Separator />
              <form onSubmit={checkUrl} className="space-y-4">
                <div className="flex space-x-2">
                  <Input
                    type="url"
                    placeholder="Enter website URL"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    required
                    className="bg-background/50"
                  />
                  <Button
                    type="submit"
                    disabled={loading}
                    className="bg-primary hover:bg-primary/90"
                  >
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>
                {urlResults && (
                  <Alert
                    className={`bg-${
                      urlResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${urlResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>{formatResults(urlResults)}</AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="ip" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">IP Reputation Scanner</h2>
                <p className="text-sm text-muted-foreground">Check IP addresses for malicious activity</p>
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
                    {loading ? "Scanning..." : "Scan"}
                  </Button>
                </div>
                {ipResults && (
                  <Alert
                    className={`bg-${
                      ipResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${ipResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>{formatResults(ipResults)}</AlertDescription>
                  </Alert>
                )}
              </form>
            </TabsContent>

            <TabsContent value="network" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Network Log Analysis</h2>
                <p className="text-sm text-muted-foreground">
                  Upload PCAP files for comprehensive network traffic analysis
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
                {logResults && (
                  <Alert
                    className={`bg-${
                      logResults.status === "error" ? "destructive" : "primary"
                    }/10 border-${logResults.status === "error" ? "destructive" : "primary"}/20`}
                  >
                    <AlertDescription>
                      <div className="space-y-2">
                        <p
                          className={`text-${
                            logResults.status === "error" ? "destructive" : "primary"
                          }`}
                        >
                          {logResults.message || `Analysis completed for ${selectedFile?.name}`}
                        </p>
                        {logResults.data && <div className="mt-4">{formatResults(logResults)}</div>}
                      </div>
                    </AlertDescription>
                  </Alert>
                )}
              </form>
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
                      className={`max-w-[70%] rounded-lg p-3 ${
                        message.isUser
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
      </div>
    </div>
  );
}