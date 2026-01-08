import React from "react";
import Link from "next/link";
import { Shield, Activity } from "lucide-react";

// Shared header used across pages
export default function Header() {
  return (
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
            <Link href="/monitoring" className="text-foreground hover:text-primary transition-colors">
              Monitoring
            </Link>
            <Link href="/resources" className="text-primary transition-colors">
              Resources
            </Link>
            <div className="flex items-center space-x-1">
              <Activity className="w-4 h-4 text-green-500 animate-pulse" />
              <span className="text-sm text-muted-
      </div>
    </header>
  );
}
