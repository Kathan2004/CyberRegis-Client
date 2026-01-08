"use client";

import React, { useEffect, useMemo, useState, useCallback } from "react";
import { Shield, ArrowRight, BookOpen, AlertTriangle, Lock, Eye, Activity, FileText, Star } from "lucide-react";
import { Card } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import Link from "next/link";
import Header from "@/components/Header";

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
  features?: { search?: boolean; filters?: boolean; favorites?: boolean; infiniteScroll?: boolean };
  revalidateInterval?: number;
}

export default function ClientResources({ initialBlogs, initialThreatNews, initialResources, error, features = {}, revalidateInterval }: ClientResourcesProps) {
  // UI state
  const [query, setQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("Severity");
  const [sourceFilter, setSourceFilter] = useState<string>("Source");
  const [visibleCount, setVisibleCount] = useState(5);
  const [favorites, setFavorites] = useState<Record<string, boolean>>({});
  const [showOnlyFavorites, setShowOnlyFavorites] = useState(false);
  const [activeTab, setActiveTab] = useState<string>("blogs");

  // Load favorites from localStorage
  useEffect(() => {
    try {
      const raw = localStorage.getItem("cr_favorites");
      if (raw) setFavorites(JSON.parse(raw));
    } catch {
      /* ignore */
    }
  }, []);

  // Persist favorites
  useEffect(() => {
    try {
      localStorage.setItem("cr_favorites", JSON.stringify(favorites));
    } catch {
      /* ignore */
    }
  }, [favorites]);

  // Toggle favorite for an item id (prefix with type to avoid collisions)
  const toggleFavorite = useCallback((key: string) => {
    setFavorites((prev) => {
      const next = { ...prev };
      if (next[key]) delete next[key];
      else next[key] = true;
      return next;
    });
  }, []);

  // Combine items into a unified list for searching/filtering
  const unified = useMemo(() => {
    const blogs = initialBlogs.map((b) => ({ kind: "blog" as const, id: b.id, title: b.title, body: b.excerpt, meta: b }));
    const threats = initialThreatNews.map((t) => ({ kind: "threat" as const, id: t.id, title: t.title, body: t.summary, meta: t }));
    const resources = initialResources.map((r) => ({ kind: "resource" as const, id: String(r.id), title: r.title, body: r.description, meta: r }));
    return [...threats, ...blogs, ...resources];
  }, [initialBlogs, initialThreatNews, initialResources]);

  // Filter / search logic
  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    return unified.filter((item) => {
      if (features.search && q) {
        if (!(item.title.toLowerCase().includes(q) || (item.body && item.body.toLowerCase().includes(q)))) return false;
      }
      if (features.filters) {
        if (severityFilter !== "Severity" && item.kind === "threat") {
          const sev = (item.meta as Threat).severity || "";
          if (sev.toLowerCase() !== severityFilter.toLowerCase()) return false;
        }
        if (sourceFilter !== "Source") {
          const src = (item.meta as any).source || (item.meta as any).author || "";
          if (!src || !String(src).toLowerCase().includes(sourceFilter.toLowerCase())) return false;
        }
      }
      return true;
    });
  }, [unified, query, features.search, features.filters, severityFilter, sourceFilter]);

  // Paging / load more
  const visible = filtered.slice(0, features.infiniteScroll ? visibleCount : filtered.length);

  // Optionally auto-refresh on focus (hint from revalidateInterval)
  useEffect(() => {
    if (!revalidateInterval) return;
    const onFocus = () => {
      // Basic visibility hint: if you want, implement a fetch to refresh client-side-only endpoints
      // For now we simply reset visibleCount to show fresh UI
      setVisibleCount(5);
    };
    window.addEventListener("focus", onFocus);
    return () => window.removeEventListener("focus", onFocus);
  }, [revalidateInterval]);

  // Utilities for UI
  const uniqueSources = useMemo(() => {
    const s = new Set<string>();
    unified.forEach((i) => {
      const src = (i.meta as any).source || (i.meta as any).author || "Unknown";
      s.add(String(src));
    });
    return ["Source", ...Array.from(s).slice(0, 20)];
  }, [unified]);

  const severities = useMemo(() => ["Severity", "Critical", "High", "Medium", "Low"], []);

  // helper to get items by kind after unified filtering + favorites toggle
  const getItemsByKind = useCallback(
    (kind: "blog" | "threat" | "resource") => {
      let items = filtered.filter((i) => i.kind === kind);
      if (features.favorites && showOnlyFavorites) {
        items = items.filter((i) => !!favorites[`${i.kind}:${i.id}`]);
      }
      return items;
    },
    [filtered, favorites, features.favorites, showOnlyFavorites]
  );

  // small UI helpers to satisfy references in JSX
  const isLoading = false; // toggle if you add client-side loading later
  const blogs = initialBlogs;
  const threatNews = initialThreatNews;
  // derive displayed lists for each tab (apply search/filters/favorites)
  const displayedBlogs = getItemsByKind("blog").map((i) => i.meta as Blog);
  const displayedThreats = getItemsByKind("threat").map((i) => i.meta as Threat);
  const displayedResources = getItemsByKind("resource").map((i) => i.meta as Resource);

  const getSeverityColor = (severity: string) => {
    switch ((severity || "").toLowerCase()) {
      case "critical":
        return "bg-red-100 text-red-700";
      case "high":
        return "bg-orange-100 text-orange-700";
      case "medium":
        return "bg-yellow-100 text-yellow-700";
      case "low":
        return "bg-green-100 text-green-700";
      default:
        return "bg-muted/10 text-muted-foreground";
    }
  };

  const renderSkeleton = () => (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
      {Array.from({ length: 4 }).map((_, i) => (
        <Card key={i} className="animate-pulse">
          <div className="p-6 space-y-4">
            <div className="h-4 bg-muted/20 rounded w-3/4" />
            <div className="h-3 bg-muted/10 rounded w-full" />
            <div className="h-3 bg-muted/10 rounded w-5/6" />
          </div>
        </Card>
      ))}
    </div>
  );

  // inline toolbar renderer for each tab
  const renderInlineToolbar = (tab: "blogs" | "threats" | "resources") => {
    const showSeverity = tab === "threats" && features.filters;
    const showSource = features.filters;
    const showSearch = features.search;
    const showFavBtn = features.favorites;
    return (showSeverity || showSource || showSearch || showFavBtn) ? (
      <div className="mt-3 flex flex-wrap items-center gap-3 px-2 py-2 rounded-md border border-border/20 bg-transparent text-sm">
        {showSearch && (
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search..."
            className="bg-transparent text-foreground placeholder:text-muted-foreground border border-transparent focus:border-primary rounded px-2 py-1 text-sm w-full md:w-64"
          />
        )}
        {showSeverity && (
          <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)} className="bg-transparent text-foreground border border-border/20 rounded px-2 py-1 text-sm">
            {severities.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        )}
        {showSource && (
          <select value={sourceFilter} onChange={(e) => setSourceFilter(e.target.value)} className="bg-transparent text-foreground border border-border/20 rounded px-2 py-1 text-sm">
            {uniqueSources.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        )}
        {showFavBtn && (
          <button
            onClick={() => setShowOnlyFavorites((v) => !v)}
            className={`inline-flex items-center gap-2 px-3 py-1 rounded text-sm ${showOnlyFavorites ? 'bg-primary/10 border border-primary text-foreground' : 'border border-border/20 text-muted-foreground'}`}
          >
            <Star className="w-4 h-4" />
            <span>{showOnlyFavorites ? 'Favorites' : 'All'}</span>
          </button>
        )}
      </div>
    ) : null;
  };

  return (
    <div
      className="min-h-screen bg-background"
      style={{
        backgroundImage: "radial-gradient(circle at 50% 50%, hsl(var(--background)) 0%, hsl(var(--card)) 100%)",
      }}
    >
      <Header />
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
        {isLoading ? <p>Loading...</p> : blogs.length > 0 ? (
          <>
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
        </div>
        <Card className="border-primary/20 bg-card/50 backdrop-blur-sm mb-8">
          <Tabs defaultValue={activeTab} className="p-6" onValueChange={setActiveTab}>
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
              {renderInlineToolbar("blogs")}
               <Separator />
               {isLoading ? renderSkeleton() : displayedBlogs.length > 0 ? (
                 <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                   {displayedBlogs.map((blog) => {
                     const favKey = `blog:${blog.id}`;
                     const isFav = !!favorites[favKey];
                     return (
                       <Card key={blog.id} className="overflow-hidden border-border/50 hover:border-primary/50 transition-colors">
                         <div className="p-6 space-y-4">
                           <div className="space-y-2">
                             <div className="flex items-center justify-between">
                               <Badge variant="outline" className="bg-primary/10">
                                 {blog.category}
                               </Badge>
                               <div className="flex items-center space-x-2">
                                 <span className="text-xs text-muted-foreground">{blog.readTime}</span>
                                 <button onClick={() => toggleFavorite(favKey)} aria-label="Toggle favorite" className={`p-1 rounded ${isFav ? "text-yellow-500" : "text-muted-foreground"}`}>
                                   <Star className="w-4 h-4" />
                                 </button>
                               </div>
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
                     );
                   })}
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
              {renderInlineToolbar("threats")}
              <Separator />
              {isLoading ? renderSkeleton() : displayedThreats.length > 0 ? (
                <div className="space-y-4">
                  {displayedThreats.map((threat) => {
                    const favKey = `threat:${threat.id}`;
                    const isFav = !!favorites[favKey];
                    return (
                      <Card key={threat.id} className="border-border/50 hover:border-primary/50 transition-colors">
                        <div className="p-6 space-y-4">
                          <div className="flex items-center justify-between">
                            <h3 className="text-lg font-semibold">{threat.title}</h3>
                            <div className="flex items-center space-x-2">
                              <Badge className={getSeverityColor(threat.severity)}>
                                {threat.severity}
                              </Badge>
                              <button onClick={() => toggleFavorite(favKey)} aria-label="Toggle favorite" className={`p-1 rounded ${isFav ? "text-yellow-500" : "text-muted-foreground"}`}>
                                <Star className="w-4 h-4" />
                              </button>
                            </div>
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
                    );
                  })}
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
              {renderInlineToolbar("resources")}
              <Separator />
              {displayedResources.length > 0 ? (
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  {displayedResources.map((resource) => {
                    const favKey = `resource:${resource.id}`;
                    const isFav = !!favorites[favKey];
                    return (
                      <Card key={resource.id} className="border-border/50 hover:border-primary/50 transition-colors">
                        <div className="p-6 space-y-4">
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
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
                              <button onClick={() => toggleFavorite(favKey)} aria-label="Toggle favorite" className={`p-1 rounded ${isFav ? "text-yellow-500" : "text-muted-foreground"}`}>
                                <Star className="w-4 h-4" />
                              </button>
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
                    );
                  })}
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
          </>
        ) : (
          <p className="text-muted-foreground">No content available.</p>
        )}
      </div>
    </div>
  );
}