"use client";

import { useState, useEffect } from "react";
import { Shield, ArrowRight, BookOpen, AlertTriangle, Lock, Eye, Activity, FileText } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";

// Define interfaces for props
type Blog = {
  id: string;
  title: string;
  excerpt: string;
  author: string;
  date: string;
  category: string;
  readTime: string;
  source: string;
  imageUrl?: string;
};

type Threat = {
  id: string;
  title: string;
  summary: string;
  severity: string;
  date: string;
  source: string;
  imageUrl?: string;
  link?: string;
};

type Resource = {
  id: number;
  title: string;
  description: string;
  type: string;
  url: string;
  language?: string;
  topics?: string[];
  imageUrl?: string;
};

interface ClientResourcesProps {
  initialBlogs: Blog[];
  initialThreatNews: Threat[];
  initialResources: Resource[];
  error?: string;
}

export default function ClientResources({ initialBlogs, initialThreatNews, initialResources, error }: ClientResourcesProps) {
  const [activeTab, setActiveTab] = useState("blogs");
  const [blogs, setBlogs] = useState(initialBlogs);
  const [threatNews, setThreatNews] = useState(initialThreatNews);
  const [isLoading, setIsLoading] = useState(false);
  const [lastUpdated, setLastUpdated] = useState<string | null>(null);

  // Polling for updates (5 minutes for News API, 1 minute for others)
  useEffect(() => {
    // Set initial time only on client side to avoid hydration mismatch
    setLastUpdated(new Date().toLocaleTimeString());
    
    const fetchUpdates = async () => {
      setIsLoading(true);
      try {
        const response = await fetch('/api/news', { cache: 'no-store' });
        if (response.ok) {
          const { blogs: newBlogs, threatNews: newThreatNews } = await response.json();
          setBlogs(newBlogs);
          setThreatNews(newThreatNews);
          setLastUpdated(new Date().toLocaleTimeString());
        }
      } catch (error) {
        console.error('Error fetching updates:', error);
      } finally {
        setIsLoading(false);
      }
    };

    const interval = setInterval(fetchUpdates, 60000); // Every 60 seconds
    return () => clearInterval(interval);
  }, []);

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

  // Loading skeleton
  const renderSkeleton = () => (
    <div className="space-y-4">
      {[...Array(5)].map((_, i) => (
        <Card key={i} className="border-border/50">
          <div className="p-6 space-y-4">
            <div className="h-6 bg-muted rounded w-3/4 animate-pulse"></div>
            <div className="h-4 bg-muted rounded w-full animate-pulse"></div>
            <div className="flex justify-between">
              <div className="h-4 bg-muted rounded w-1/4 animate-pulse"></div>
              <div className="h-4 bg-muted rounded w-1/4 animate-pulse"></div>
            </div>
          </div>
        </Card>
      ))}
    </div>
  );

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
        {error && (
          <div className="mb-8 p-4 bg-red-500/10 border border-red-500/20 rounded-md">
            <p className="text-red-500">{error}</p>
          </div>
        )}
        <div className="mb-12">
          <h1 className="text-4xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-primary to-primary/50">
            Security Resources
          </h1>
          <p className="text-muted-foreground">Stay informed with the latest security insights, threat intelligence, and educational resources</p>
          <p className="text-sm text-muted-foreground mt-2">Last updated: {lastUpdated}</p>
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
              {isLoading ? renderSkeleton() : blogs.length > 0 ? (
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
                            <span className="text-muted-foreground"> · {blog.date} · {blog.source}</span>
                          </div>
                          <a
                            href={blog.id}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-primary hover:text-primary/80 transition-colors flex items-center space-x-1 text-sm"
                          >
                            <span>Read more</span>
                            <ArrowRight className="w-3 h-3" />
                          </a>
                        </div>
                      </div>
                    </Card>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No blog posts available at the moment. Please check back later.</p>
              )}
            </TabsContent>
            <TabsContent value="threats" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Threat Intelligence</h2>
                <p className="text-sm text-muted-foreground">Latest information on emerging cyber threats and vulnerabilities</p>
              </div>
              <Separator />
              {isLoading ? renderSkeleton() : threatNews.length > 0 ? (
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
              ) : (
                <p className="text-muted-foreground">No threat news available at the moment. Please check back later.</p>
              )}
            </TabsContent>
            <TabsContent value="resources" className="space-y-6">
              <div className="space-y-2">
                <h2 className="text-2xl font-semibold">Security Resources</h2>
                <p className="text-sm text-muted-foreground">Useful tools, guides, and frameworks for improving your security posture</p>
              </div>
              <Separator />
              {initialResources.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {initialResources.map((resource) => (
                    <Card key={resource.id} className="border-border/50 hover:border-primary/50 transition-colors">
                      <div className="p-6 space-y-4">
                        <div className="space-y-2">
                          <div className="flex items-center space-x-2">
                            <Badge variant="outline" className="bg-primary/10">
                              {resource.type}
                            </Badge>
                            {resource.language && (
                              <Badge variant="outline" className="bg-secondary/10">
                                {resource.language}
                              </Badge>
                            )}
                            {resource.topics && resource.topics.slice(0, 3).map((topic) => (
                              <Badge key={topic} variant="secondary">{topic}</Badge>
                            ))}
                          </div>
                          <h3 className="text-lg font-semibold">{resource.title}</h3>
                          <p className="text-muted-foreground text-sm">{resource.description}</p>
                        </div>
                        <a
                          href={resource.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-primary hover:text-primary/80 transition-colors flex items-center space-x-1 text-sm"
                        >
                          <span>Visit repository</span>
                          <ArrowRight className="w-3 h-3" />
                        </a>
                      </div>
                    </Card>
                  ))}
                </div>
              ) : (
                <p className="text-muted-foreground">No resources available at the moment. Please check back later.</p>
              )}
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