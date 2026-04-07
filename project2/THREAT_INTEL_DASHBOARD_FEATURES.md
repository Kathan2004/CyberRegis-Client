# Threat Intelligence Dashboard - Auto-Refresh Features

## Overview

The Threat Intelligence page now features **continuous live updates** with real-time threat data fetching from open-source feeds. The dashboard automatically pulls the latest IOCs, CVEs, and threat intelligence data at configurable intervals.

---

## Key Features

### 1. **Auto-Refresh Dashboard** 🔄
- **Enabled by Default**: Dashboard continuously fetches latest threat data
- **Configurable Intervals**: 
  - Every 10 seconds (live mode)
  - Every 30 seconds (recommended)
  - Every 1 minute
  - Every 5 minutes
- **One-Click Toggle**: Enable/disable auto-refresh with Zap button
- **Last Refresh Timestamp**: Always shows when data was last updated

### 2. **Live Statistics** 📊
Dashboard automatically updates KPI cards showing:
- **Total IOCs**: Real-time count of all indicators in database
- **Critical Severity**: Count of critical-level threats
- **High Severity**: Count of high-level threats
- **Feed Entries**: Total entries pulled from threat feeds
- **IOC Types**: Count of different indicator types (IP, domain, URL, hash, email)

### 3. **CVE Trends Widget** 🔥
- **Latest Critical CVEs**: Auto-fetches most recent critical vulnerabilities
- **Manual Refresh**: Button to pull latest CVEs on-demand
- **CVE Details**: Shows CVE-ID, description, and CVSS score
- **Color-Coded Severity**:
  - CVSS 9+: Red (Critical)
  - CVSS 7-8.9: Orange (High)
  - CVSS <7: Yellow (Medium)
- **Quick Links**: Click any CVE to view full details on CVE Database page

### 4. **Activity Log** 📝
Real-time activity tracking showing:
- **IOC Added**: When new indicators are manually added or ingested
- **Feed Refreshed**: When threat feeds are automatically or manually refreshed
- **CVE Found**: When critical CVEs are discovered
- **Timestamps**: Exact time each action occurred
- **Severity Tracking**: Shows severity level for each action
- **Last 10 Activities**: Scrollable log of recent events

### 5. **Comprehensive IOC Management** 🛡️
- **IOC Database**: Full catalog of indicators with real-time updates
- **Advanced Filters**: 
  - Filter by IOC Type (IP, Domain, URL, Hash, Email)
  - Filter by Severity (Critical, High, Medium, Low)
- **Severity Badges**: Color-coded badges for quick risk assessment
- **Manual Add**: Add custom indicators with threat type and description
- **Delete**: Remove indicators individually
- **Source Tracking**: Shows which feed each IOC came from

### 6. **Threat Feed Management** 📡
- **Multi-Source Aggregation**: Pulls from:
  - Feodo Tracker (C2 servers)
  - URLhaus (Malicious URLs)
  - ThreatFox (Recent threats)
  - OTX AlienVault (Community intelligence)
- **Manual Refresh**: Trigger immediate feed update
- **Feed Status**: Shows number of entries from each feed
- **Last 100 Entries**: Browse recent threat data
- **Confidence Scoring**: Color-coded confidence levels (80%+ red, 50%+ yellow, <50% blue)

### 7. **IOC Search** 🔍
- **Cross-Feed Search**: Search indicators across all threat feeds
- **Search Types**: IP, domain, URL, hash, email
- **Result Display**: Shows feed source, indicator, type, and description
- **Real-Time**: Results displayed instantly as data loads

---

## Architecture

### Data Flow
```
Open-Source Feeds (Feodo, URLhaus, ThreatFox, OTX)
    ↓
Flask Backend (threat_feed_service.py)
    ↓
SQLite Database (threat_feeds, iocs tables)
    ↓
React Frontend (threat-intel/page.tsx)
    ↓
Auto-Refresh Timer (10s-5m configurable)
    ↓
Live Dashboard Updates
```

### State Management
- **Auto-refresh timer**: Configurable interval (default: 30s)
- **IOC stats**: Updated on each refresh
- **Feed entries**: Latest 200 entries cached
- **CVE trends**: Top 5 critical CVEs cached
- **Activity log**: Last 10 actions tracked in real-time

### API Endpoints Used
- `GET /api/iocs` - Fetch IOC list with stats
- `GET /api/threat-feeds/<count>` - Fetch threat feed entries
- `POST /api/threat-feeds/refresh` - Manually trigger feed refresh
- `GET /api/cve/search?q=<keyword>` - Search critical CVEs
- `POST /api/iocs` - Add manual IOC
- `DELETE /api/iocs/<id>` - Delete IOC
- `GET /api/threat-feeds/search?q=<query>` - Search threat feeds

---

## Usage Guide

### Viewing the Dashboard
1. **Navigate** to Threat Intelligence page
2. **Default View**: Dashboard tab shows all live data
3. **Live Updates**: Red pulsing indicator shows active auto-refresh

### Controlling Auto-Refresh
**Button Locations**: Top-right of Threat Intelligence header

- **Enable/Disable**: Click "Auto-Refresh ON/OFF" button
  - Green = Active (fetching every 30s)
  - Gray = Disabled (manual refresh only)

- **Change Interval**: Select from dropdown:
  - Every 10s: Real-time monitoring mode
  - Every 30s: **Recommended** (balanced)
  - Every 1m: Minimal network usage
  - Every 5m: Low-traffic mode

### Viewing CVE Trends
1. **Look at "Latest Critical CVEs"** widget
2. **Refresh manually**: Click Refresh button
3. **View full details**: Click any CVE to open CVE Database
4. **Auto-updates**: Every 30s (or selected interval)

### Checking Activity Log
1. **Right side panel**: "Recent Activity"
2. **Shows last 10**: Actions chronologically ordered
3. **Scroll**: View older activities
4. **Colored dots**:
   - Blue = IOC Added
   - Green = Feed Refreshed
   - Yellow = CVE Found

### Managing IOCs
1. **IOC Management tab**: View all indicators
2. **Filter**: By type and severity
3. **Add**: Click "+ Add IOC" button
4. **Delete**: Click trash icon on any row
5. **Source**: See which feed each IOC came from

### Refreshing Threat Feeds
1. **Threat Feeds tab**: View all feed entries
2. **Manual Refresh**: Click "Refresh All Feeds" button
3. **Status**: Shows number of entries per feed
4. **Auto-Refresh**: Happens every 30s automatically

### Searching Indicators
1. **Search tab**: Enter indicator (IP, domain, URL, hash, email)
2. **Results**: Click "Search" or press Enter
3. **Display**: Shows feed source and confidence
4. **Details**: Hover for full description

---

## Configuration

### Backend Settings (`.env`)
```bash
# Threat Feed Sources
FEODO_TRACKER_DAYS=7          # Lookback window for Feodo
THREATFOX_DAYS=3              # Lookback window for ThreatFox

# CVE Search
NVD_API_KEY=<your_key>        # Optional NVD API key (increases rate limit)

# Network
SSL_VERIFY=true               # Set to false for corporate proxy
```

### Frontend Settings (React State)
```typescript
const [autoRefresh, setAutoRefresh] = useState(true);           // Enable/disable
const [refreshInterval, setRefreshInterval] = useState(30);     // Seconds
```

---

## Features in Action

### Scenario 1: Real-Time Threat Monitoring
1. Open Threat Intelligence Dashboard
2. Enable auto-refresh (every 10s for live mode)
3. Watch IOC count update in real-time
4. Activity log shows new IOCs as they're ingested
5. CVE trends refresh automatically

### Scenario 2: Quick CVE Assessment
1. View CVE Trends widget
2. See CVSS scores color-coded by severity
3. Click any CVE to dive into details
4. Auto-refresh brings new CVEs as they're discovered

### Scenario 3: Investigating a Breach
1. Use Search tab to find indicator
2. View all activities related to discovery
3. Check which feed the indicator came from
4. Track when it was first detected

### Scenario 4: Feed Health Monitoring
1. Go to Threat Feeds tab
2. See count of entries from each source
3. Manually refresh to pull latest data
4. Check activity log to confirm success

---

## Performance Considerations

### Network Impact
- **10s interval**: ~6 requests/min per page (minimal impact)
- **30s interval**: ~2 requests/min per page (recommended)
- **1m interval**: ~1 request/min per page (low traffic)
- **5m interval**: ~0.2 requests/min per page (minimal)

### Database Load
- Each refresh fetches up to 200 threat feed entries
- IOC stats calculated on-demand
- CVE search cached for 30 seconds

### Browser Memory
- Activity log limited to last 10 entries (trimmed automatically)
- Feed entries paginated (showing first 100)
- Auto-cleanup of old data prevents memory leaks

---

## Troubleshooting

### Auto-Refresh Not Working
1. **Check Status**: Is "Auto-Refresh ON" button visible in green?
2. **Verify Network**: Open browser DevTools → Network tab
   - Should see API requests every 30s
3. **Check Backend**: Verify Flask service is running
   - `curl http://localhost:5000/api/health`
4. **Reset**: Disable and re-enable auto-refresh

### No CVEs Showing
1. **Backend Issue**: Check if `/api/cve/search` is responding
2. **NVD Connection**: Verify NVD API is accessible (may be blocked by corporate proxy)
3. **Timeout**: If slow connection, increase refresh interval to 1-5 min

### Activity Log Not Updating
1. **Check Browser Console**: Are there JavaScript errors?
2. **Verify API Calls**: Open DevTools → Network tab
3. **Refresh Page**: Hard refresh (Ctrl+Shift+R) to clear cache

### Threat Feeds Show No Data
1. **Manual Refresh**: Click "Refresh All Feeds" button
2. **Check Backend Logs**: Look for feed fetch errors
3. **Verify Internet**: Feed sources need external connectivity
4. **API Keys**: Some feeds may require authentication

---

## Future Enhancements

### Planned Features
- [ ] **Email Alerts**: Send alerts for critical IOCs
- [ ] **Feed Scheduling**: Set custom refresh times (e.g., hourly)
- [ ] **IOC Expiration**: Auto-remove old/stale indicators
- [ ] **Slack Integration**: Post threats to Slack channel
- [ ] **Custom Feeds**: Add your own threat feed sources
- [ ] **Threat Timeline**: Visualize threat activity over time
- [ ] **Bulk Actions**: Export, delete, or modify multiple IOCs
- [ ] **Feed Health Dashboard**: Monitor feed uptime/success rates

---

## Summary

The Threat Intelligence Dashboard now provides **real-time visibility** into your threat landscape with:

✅ **Continuous Auto-Refresh** (configurable 10s-5m)  
✅ **Live IOC & CVE Updates** (from open-source feeds)  
✅ **Activity Tracking** (last 10 events logged)  
✅ **CVE Trends** (auto-fetch critical vulnerabilities)  
✅ **Multi-Source Aggregation** (Feodo, URLhaus, ThreatFox, OTX)  
✅ **Real-Time Statistics** (KPI cards update every refresh)  
✅ **Advanced Search** (search indicators across all feeds)  
✅ **Comprehensive Filtering** (by type, severity, source)  

**Status**: ✅ **LIVE AND DEPLOYED** — Threat Intelligence Dashboard is now production-ready with full auto-refresh capabilities.

---

**Version**: 1.0  
**Updated**: April 2026  
**Status**: Production Ready
