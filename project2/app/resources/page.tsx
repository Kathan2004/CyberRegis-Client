"use client";

import { useState } from "react";
import { Shield, ArrowRight, BookOpen, Newspaper, AlertTriangle, Lock, Eye, Activity, FileText } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";

// Mock data for blogs
const blogs = [
  {
    id: 1,
    title: "Understanding Zero-Day Vulnerabilities",
    excerpt: "Zero-day vulnerabilities are unknown software flaws that hackers can exploit before developers have a chance to fix them.",
    author: "Jane Smith",
    date: "May 15, 2025",
    category: "Cybersecurity",
    readTime: "8 min read"
  },
  {
    id: 2,
    title: "The Rise of Ransomware-as-a-Service",
    excerpt: "Ransomware-as-a-Service (RaaS) has transformed the cybercrime landscape by lowering the barrier to entry for would-be attackers.",
    author: "Michael Chen",
    date: "May 10, 2025",
    category: "Threats",
    readTime: "6 min read"
  },
  {
    id: 3,
    title: "Securing Your Remote Workforce",
    excerpt: "With remote work becoming the norm, organizations must implement robust security measures to protect sensitive data.",
    author: "Sarah Johnson",
    date: "May 5, 2025",
    category: "Best Practices",
    readTime: "10 min read"
  },
  {
    id: 4,
    title: "The Importance of Multi-Factor Authentication",
    excerpt: "Multi-factor authentication adds an essential layer of security beyond passwords, significantly reducing the risk of unauthorized access.",
    author: "David Wilson",
    date: "April 28, 2025",
    category: "Authentication",
    readTime: "5 min read"
  },
  {
    id: 5,
    title: "AI in Cybersecurity: Friend or Foe?",
    excerpt: "Artificial intelligence is revolutionizing cybersecurity, but it's also being weaponized by attackers. Learn about this double-edged sword.",
    author: "Emily Zhang",
    date: "April 22, 2025",
    category: "Technology",
    readTime: "12 min read"
  }
];

// Mock data for threat news
const threatNews = [
  {
    id: 1,
    title: "New Phishing Campaign Targets Financial Institutions",
    summary: "A sophisticated phishing campaign is targeting major banks with convincing emails that bypass traditional security measures.",
    severity: "High",
    date: "May 18, 2025",
    source: "Security Intelligence"
  },
  {
    id: 2,
    title: "Critical Vulnerability Discovered in Popular VPN Service",
    summary: "Researchers have identified a critical vulnerability in a widely-used VPN service that could allow attackers to intercept encrypted traffic.",
    severity: "Critical",
    date: "May 16, 2025",
    source: "Threat Post"
  },
  {
    id: 3,
    title: "Botnet Targeting IoT Devices Grows to 1 Million Nodes",
    summary: "A massive botnet specifically targeting smart home devices has grown to over one million compromised devices in just two weeks.",
    severity: "Medium",
    date: "May 14, 2025",
    source: "Dark Reading"
  },
  {
    id: 4,
    title: "New Ransomware Variant Evades Detection Systems",
    summary: "A new ransomware variant using advanced obfuscation techniques is successfully evading most antivirus and endpoint detection systems.",
    severity: "High",
    date: "May 12, 2025",
    source: "Krebs on Security"
  },
  {
    id: 5,
    title: "Supply Chain Attack Compromises Popular JavaScript Library",
    summary: "A widely-used JavaScript library was compromised in a supply chain attack, potentially affecting thousands of websites and applications.",
    severity: "Critical",
    date: "May 10, 2025",
    source: "The Hacker News"
  }
];

// Mock data for security resources
const resources = [
  {
    id: 1,
    title: "OWASP Top 10",
    description: "The definitive guide to the most critical web application security risks.",
    type: "Guide",
    url: "https://owasp.org/www-project-top-ten/"
  },
  {
    id: 2,
    title: "NIST Cybersecurity Framework",
    description: "A set of guidelines for mitigating organizational cybersecurity risks.",
    type: "Framework",
    url: "https://www.nist.gov/cyberframework"
  },
  {
    id: 3,
    title: "Have I Been Pwned",
    description: "Check if your email or phone is in a data breach.",
    type: "Tool",
    url: "https://haveibeenpwned.com/"
  },
  {
    id: 4,
    title: "Security Headers",
    description: "Analyze HTTP response headers and provide recommendations for improvement.",
    type: "Tool",
    url: "https://securityheaders.com/"
  },
  {
    id: 5,
    title: "SANS Internet Storm Center",
    description: "Cooperative cybersecurity monitoring and alert system.",
    type: "Resource",
    url: "https://isc.sans.edu/"
  }
];

export default function Resources() {
  const [activeTab, setActiveTab] = useState("blogs");

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'text-red-500 bg-red-500/10';
      case 'high':
        return 'text-orange-500 bg-orange-500/10';
      case 'medium':
        return 'text-yellow-500 bg-yellow-500/10';
      case 'low':
        return 'text-green-500 bg-green-500/10';
      default:
        return 'text-blue-500 bg-blue-500/10';
    }
  };

  return (
    <div 
      className="min-h-screen bg-background"
      style={{
        backgroundImage: 'radial-gradient(circle at 50% 50%, hsl(var(--background)) 0%, hsl(var(--card)) 100%)',
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
              <Link href="/resources" className="text-primary transition-colors">
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
        <div className="mb-12">
          <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
            Security Resources
          </h1>
          <p className="text-muted-foreground">Stay informed with the latest security insights, threat intelligence, and educational resources</p>
        </div>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <Tabs defaultValue="blogs" className="p-6" onValueChange={setActiveTab}>
            <TabsList className="grid w-full grid-cols-3 lg:w-[400px] mb-6">
              <TabsTrigger value="blogs" className="data-[state=active]:bg-primary/20">
                <BookOpen className="w-4 h-4 mr-2" />
                Blogs
              </TabsTrigger>
              <TabsTrigger value="threats" className="data-[state=active]:bg-primary/20">
                <AlertTriangle className="w-4 h-4 mr-2" />
                Threat News
              </TabsTrigger>
              <TabsTrigger value="resources" className="data-[state=active]:bg-primary/20">
                <FileText className="w-4 h-4 mr-2" />
                Resources
              </TabsTrigger>
            </TabsList>

            <TabsContent value="blogs" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Security Blog</h2>
                <p className="text-sm text-muted-foreground">Expert insights and educational content on cybersecurity topics</p>
              </div>
              <Separator />
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                {blogs.map((blog) => (
                  <Card key={blog.id} className="overflow-hidden border-border/50 hover:border-primary/50 transition-colors">
                    <div className="p-6 space-y-4">
                      <div className="space-y-2">
                        <div className="flex items-center justify-between">
                          <Badge variant="outline" className="bg-primary/10">
                            {blog.category}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{blog.readTime}</span>
                        </div>
                        <h3 className="text-xl font-semibold">{blog.title}</h3>
                        <p className="text-muted-foreground text-sm">{blog.excerpt}</p>
                      </div>
                      <div className="flex items-center justify-between pt-4 border-t border-border/50">
                        <div className="text-sm">
                          <span className="text-foreground font-medium">{blog.author}</span>
                          <span className="text-muted-foreground"> · {blog.date}</span>
                        </div>
                        <button className="text-primary hover:text-primary/80 transition-colors flex items-center space-x-1 text-sm">
                          <span>Read more</span>
                          <ArrowRight className="w-3 h-3" />
                        </button>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="threats" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Threat Intelligence</h2>
                <p className="text-sm text-muted-foreground">Latest information on emerging cyber threats and vulnerabilities</p>
              </div>
              <Separator />
              <div className="space-y-4">
                {threatNews.map((threat) => (
                  <Card key={threat.id} className="border-border/50 hover:border-primary/50 transition-colors">
                    <div className="p-6 space-y-4">
                      <div className="flex items-center justify-between">
                        <h3 className="text-lg font-semibold">{threat.title}</h3>
                        <Badge className={getSeverityColor(threat.severity)}>
                          {threat.severity}
                        </Badge>
                      </div>
                      <p className="text-muted-foreground text-sm">{threat.summary}</p>
                      <div className="flex items-center justify-between text-sm">
                        <div>
                          <span className="text-muted-foreground">Source: </span>
                          <span className="text-foreground">{threat.source}</span>
                        </div>
                        <span className="text-muted-foreground">{threat.date}</span>
                      </div>
                    </div>
                  </Card>
                ))}
              </div>
            </TabsContent>

            <TabsContent value="resources" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Security Resources</h2>
                <p className="text-sm text-muted-foreground">Useful tools, guides, and frameworks for improving your security posture</p>
              </div>
              <Separator />
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                {resources.map((resource) => (
                  <Card key={resource.id} className="border-border/50 hover:border-primary/50 transition-colors">
                    <div className="p-6 space-y-4">
                      <div className="space-y-2">
                        <Badge variant="outline" className="bg-primary/10">
                          {resource.type}
                        </Badge>
                        <h3 className="text-lg font-semibold">{resource.title}</h3>
                        <p className="text-muted-foreground text-sm">{resource.description}</p>
                      </div>
                      <a 
                        href={resource.url} 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="text-primary hover:text-primary/80 transition-colors flex items-center space-x-1 text-sm"
                      >
                        <span>Visit resource</span>
                        <ArrowRight className="w-3 h-3" />
                      </a>
                    </div>
                  </Card>
                ))}
              </div>
            </TabsContent>
          </Tabs>
        </Card>

        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm">
          <div className="p-6 space-y-4">
            <div className="flex items-center space-x-2">
              <Lock className="w-5 h-5 text-primary" />
              <h2 className="text-xl font-semibold">Stay Protected</h2>
            </div>
            <p className="text-muted-foreground">
              Our security resources are regularly updated to help you stay ahead of emerging threats. 
              Bookmark this page and check back often for the latest security insights and best practices.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-4">
              <div className="bg-card/80 p-4 rounded-lg border border-border/50">
                <div className="flex items-center space-x-2 mb-2">
                  <Eye className="w-4 h-4 text-primary" />
                  <h3 className="font-medium">Stay Informed</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Keep up with the latest security trends and emerging threats
                </p>
              </div>
              <div className="bg-card/80 p-4 rounded-lg border border-border/50">
                <div className="flex items-center space-x-2 mb-2">
                  <Shield className="w-4 h-4 text-primary" />
                  <h3 className="font-medium">Enhance Protection</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Implement best practices to strengthen your security posture
                </p>
              </div>
              <div className="bg-card/80 p-4 rounded-lg border border-border/50">
                <div className="flex items-center space-x-2 mb-2">
                  <AlertTriangle className="w-4 h-4 text-primary" />
                  <h3 className="font-medium">Respond Effectively</h3>
                </div>
                <p className="text-sm text-muted-foreground">
                  Learn how to respond quickly and effectively to security incidents
                </p>
              </div>
            </div>
          </div>
        </Card>
      </div>
    </div>
  );
}