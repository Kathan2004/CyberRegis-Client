import { NextResponse } from 'next/server';
import Parser from 'rss-parser';

// Simple in-memory cache
const cache = {
  blogs: null as any[] | null,
  threatNews: null as any[] | null,
  lastUpdated: 0,
};

interface Blog {
  id: string;
  title: string;
  excerpt: string;
  author: string;
  date: string;
  category: string;
  readTime: string;
  source: string;
  imageUrl?: string;
}

interface Threat {
  id: string;
  title: string;
  summary: string;
  severity: string;
  date: string;
  source: string;
  imageUrl?: string;
  link?: string;
}

// Deduplicate utility
function deduplicateByTitle<T extends { title: string }>(items: T[]): T[] {
  const seen = new Set<string>();
  return items.filter(item => {
    const normalizedTitle = item.title.toLowerCase().trim();
    if (seen.has(normalizedTitle)) return false;
    seen.add(normalizedTitle);
    return true;
  });
}

// Retry fetch with timeout and backoff
async function fetchWithRetry(url: string, options: RequestInit = {}, retries = 3, timeout = 15000): Promise<Response> {
  const controller = new AbortController();
  const id = setTimeout(() => controller.abort(), timeout);

  for (let i = 0; i < retries; i++) {
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      clearTimeout(id);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return response;
    } catch (error) {
      clearTimeout(id);
      if (i === retries - 1) throw error;
      await new Promise(resolve => setTimeout(resolve, 2 ** i * 1000)); // Exponential backoff
    }
  }
  throw new Error('Max retries reached');
}

// Determine severity based on tags or content
function determineSeverity(tags: string[] = [], content: string = ''): string {
  const lowerContent = content.toLowerCase();
  const criticalKeywords = ['exploit', 'rce', 'critical', 'zero-day', 'ransomware'];
  const highKeywords = ['vulnerability', 'cve', 'breach', 'attack', 'malware'];
  const mediumKeywords = ['update', 'patch', 'advisory', 'alert'];
  const lowKeywords = ['tip', 'guide', 'best practice', 'tutorial'];

  if (tags.length > 0 && tags.some(tag => criticalKeywords.includes(tag.toLowerCase())) || criticalKeywords.some(keyword => lowerContent.includes(keyword))) {
    return 'Critical';
  }
  if (tags.length > 0 && tags.some(tag => highKeywords.includes(tag.toLowerCase())) || highKeywords.some(keyword => lowerContent.includes(keyword))) {
    return 'High';
  }
  if (tags.length > 0 && tags.some(tag => mediumKeywords.includes(tag.toLowerCase())) || mediumKeywords.some(keyword => lowerContent.includes(keyword))) {
    return 'Medium';
  }
  if (tags.length > 0 && tags.some(tag => lowKeywords.includes(tag.toLowerCase())) || lowKeywords.some(keyword => lowerContent.includes(keyword))) {
    return 'Low';
  }
  // Fallback: Distribute severities evenly for testing
  const severities = ['Critical', 'High', 'Medium', 'Low'];
  return severities[Math.floor(Math.random() * severities.length)];
}

export async function GET() {
  const now = Date.now();
  if (cache.blogs && cache.threatNews && now - cache.lastUpdated < 60000) {
    return NextResponse.json({ blogs: cache.blogs, threatNews: cache.threatNews });
  }

  const NEWS_API_KEY = process.env.NEWS_API_KEY || 'ca14ca03cd5f42b59beff258e3f551d4'; // Use env variable
  const OTX_API_KEY = process.env.OTX_API_KEY || 'ada6338cfb89921d907dafd55cfe364f43f33f0c920777a9e44e8c5c9573323b'; // Use env variable
  const parser = new Parser();
  const blogs: Blog[] = [];
  const threats: Threat[] = [];

  // News API
  const shouldFetchNewsApi = !cache.lastUpdated || now - cache.lastUpdated >= 300000;
  if (shouldFetchNewsApi) {
    try {
      const response = await fetchWithRetry(
        `https://newsapi.org/v2/everything?q=cybersecurity OR infosec OR "data breach"&language=en&sortBy=publishedAt&apiKey=${NEWS_API_KEY}`,
        { cache: 'no-store' }
      );
      const data = await response.json();
      if (data.articles) {
        blogs.push(...data.articles.map((article: any) => ({
          id: article.url,
          title: article.title || 'Untitled',
          excerpt: article.description || 'No description available',
          author: article.author ? `${article.author} - ${article.source.name}` : article.source.name || 'Unknown',
          date: new Date(article.publishedAt).toLocaleDateString(),
          category: 'Cybersecurity',
          readTime: '5 min read',
          source: article.source.name || 'News API',
          imageUrl: article.urlToImage || '/images/placeholder.jpg',
        })));
      }
    } catch (error) {
      console.error('Error fetching News API:', error);
    }
  } else if (cache.blogs) {
    blogs.push(...cache.blogs.filter(blog => blog.source === 'News API'));
  }

  // The Hacker News RSS
  try {
    const feed = await parser.parseURL('https://feeds.feedburner.com/TheHackersNews');
    blogs.push(...feed.items.map((item: any) => ({
      id: item.link,
      title: item.title || 'Untitled',
      excerpt: item['content:encodedSnippet']?.slice(0, 200) || 'No description available',
      author: item.creator || 'The Hacker News',
      date: new Date(item.pubDate).toLocaleDateString(),
      category: 'Cybersecurity',
      readTime: '6 min read',
      source: 'The Hacker News',
      imageUrl: '/images/thehackernews.png',
    })));
  } catch (error) {
    console.error('Error fetching The Hacker News RSS:', error);
  }

  // Dark Reading RSS
  try {
    const feed = await parser.parseURL('https://www.darkreading.com/rss.xml');
    blogs.push(...feed.items.map((item: any) => ({
      id: item.link,
      title: item.title || 'Untitled',
      excerpt: item.description?.slice(0, 200) || 'No description available',
      author: item.creator || 'Dark Reading',
      date: new Date(item.pubDate).toLocaleDateString(),
      category: 'Cybersecurity',
      readTime: '7 min read',
      source: 'Dark Reading',
      imageUrl: '/images/darkreading.png',
    })));
  } catch (error) {
    console.error('Error fetching Dark Reading RSS:', error);
  }

  // Bleeping Computer RSS
  try {
    const feed = await parser.parseURL('https://www.bleepingcomputer.com/feed/');
    blogs.push(...feed.items.map((item: any) => ({
      id: item.link,
      title: item.title || 'Untitled',
      excerpt: item.description?.slice(0, 200) || 'No description available',
      author: item.creator || 'Bleeping Computer',
      date: new Date(item.pubDate).toLocaleDateString(),
      category: 'Cybersecurity',
      readTime: '6 min read',
      source: 'Bleeping Computer',
      imageUrl: '/images/bleepingcomputer.png',
    })));
  } catch (error) {
    console.error('Error fetching Bleeping Computer RSS:', error);
  }

  // AlienVault OTX API
  try {
    const response = await fetchWithRetry('https://otx.alienvault.com/api/v1/pulses/subscribed', {
      headers: {
        'X-OTX-API-KEY': OTX_API_KEY,
      },
      cache: 'no-store',
    });
    const data = await response.json();
    if (data.results) {
      threats.push(...data.results.map((pulse: any) => ({
        id: pulse.id,
        title: pulse.name || 'Untitled',
        summary: pulse.description || 'No summary available',
        severity: determineSeverity(pulse.tags, pulse.description),
        date: new Date(pulse.created).toLocaleDateString(),
        source: pulse.author_name || 'AlienVault OTX',
        imageUrl: '/images/otx.png',
        link: `https://otx.alienvault.com/pulse/${pulse.id}`,
      })));
    }
  } catch (error) {
    console.error('Error fetching OTX API:', error);
  }

  // Threatpost RSS
  try {
    const feed = await parser.parseURL('https://threatpost.com/feed/');
    threats.push(...feed.items.map((item: any) => ({
      id: item.link,
      title: item.title || 'Untitled',
      summary: item['content:encoded']?.slice(0, 1000) || item.description || 'No summary available',
      severity: determineSeverity(item.categories, item['content:encoded'] || item.description),
      date: new Date(item.pubDate).toLocaleDateString(),
      source: 'Threatpost',
      imageUrl: '/images/threatpost.png',
      link: item.link,
    })));
  } catch (error) {
    console.error('Error fetching Threatpost RSS:', error);
  }

  // Deduplicate and sort
  const dedupedBlogs = deduplicateByTitle(blogs)
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
    .slice(0, 10);
  const dedupedThreats = deduplicateByTitle(threats)
    .sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime())
    .slice(0, 10);

  // Update cache
  cache.blogs = dedupedBlogs;
  cache.threatNews = dedupedThreats;
  cache.lastUpdated = now;

  return NextResponse.json({ blogs: dedupedBlogs, threatNews: dedupedThreats });
}