import React from "react";
import Link from "next/link";
import { Shield, Activity } from "lucide-react";

// Shared header used across pages
export default function Header() {
  return (
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
          <Link href="/reports" className="text-muted-foreground hover:text-primary transition-colors">Reports</Link>
          <Link href="/monitoring" className="text-muted-foreground hover:text-primary transition-colors">Monitoring</Link>
          <Link href="/resources" className="text-muted-foreground hover:text-primary transition-colors">Resources</Link>
          <div className="flex items-center gap-1.5">
            <Activity className="h-3.5 w-3.5 text-green-500 animate-pulse" />
            <span className="text-xs text-muted-foreground">Online</span>
          </div>
        </nav>
      </div>
    </header>
  );
}
