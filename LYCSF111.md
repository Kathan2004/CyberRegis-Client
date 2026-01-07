# CyberRegis: A Pragmatic Unified Cybersecurity Companion

## Abstract
CyberRegis is a lightweight client application that orchestrates a curated set of threat intelligence utilities through a single interface. Rather than promising autonomous defence or enterprise-scale correlation, the platform focuses on the day-to-day enrichment workflows analysts perform when triaging incidents. The web client—built with Next.js, React, TypeScript, and shadcn/ui—communicates with a Python Flask gateway that aggregates external services such as Google Safe Browsing, VirusTotal, Have I Been Pwned, and AbuseIPDB. This paper documents the current architecture, the guiding design principles, and the operational guardrails that keep outputs interpretable. We report on a small validation exercise measuring response times, caching effectiveness, and error transparency, and we highlight realistic next steps for hardening the stack.

**Keywords:** threat intelligence, incident triage, cybersecurity tooling, OSINT orchestration, user interface, Next.js, Flask

## 1. Introduction
Security analysts routinely pivot between browser tabs, CLI scripts, and ad‑hoc notebooks to answer routine questions—"Is this domain suspicious?", "Has this credential appeared in a breach?", or "What is the latest advisory on this CVE?". Commercial Security Orchestration, Automation, and Response (SOAR) platforms attempt to consolidate these tasks but often exceed the budget or operational complexity tolerated by smaller teams, research groups, or academic programmes. CyberRegis pursues a middle ground: it offers a cohesive interface for a handful of high-signal checks without attempting to replace an established SIEM or SOAR deployment. The platform was conceived as a teaching and prototyping aid where learnability, reproducibility, and modest automation were prioritised over black-box correlation.

## 2. Related Work and Context
Open-source dashboards such as OpenCTI and MISP provide rich knowledge bases yet require substantial infrastructure and data modelling expertise. Browser extensions like "SecurityTrails Lookup" or "URLscan Quick Check" supply rapid context but expose only a single data source at a time. Academic studies on conversational security assistants (Arora et al., 2023; Kaheh et al., 2023) show that question answering improves analyst throughput when combined with curated corpora, though these systems typically rely on large language models hosted in the cloud. CyberRegis intentionally integrates deterministic APIs and a rules-driven chatbot prompt to keep dependencies minimal and traceable. This decision shapes both the architecture (Section 4) and the evaluation regimen (Section 8).

## 3. Problem Statement and Design Goals
CyberRegis aims to reduce friction in day-to-day enrichment while maintaining analyst cognition in the loop. The core design goals are:

* **Traceable outputs:** every verdict or recommendation exposes the underlying API payload, preserving analyst trust.
* **Low ceremony:** a single-page layout reduces context switching, and common workflows are wrapped as guided forms.
* **Deployable in controlled labs:** the stack runs on commodity hardware with Docker Compose or Netlify hosting and does not require external agents.
* **Recoverable failure modes:** rate limits, timeouts, and malformed responses are surfaced in a diagnostics drawer rather than silently suppressed.

The following sections describe how these goals influenced the architecture, UI, and evaluation plan.

## 4. Architecture Overview
Figure 1 presents a high-level view of the platform components.

![Figure 1. CyberRegis architectural overview](image1-placeholder)

* **Frontend:** A Next.js 13 client renders modular workspaces and communicates with the backend via REST endpoints. State is managed with React Query to simplify caching logic and background revalidation.
* **Backend gateway:** A Flask application normalises requests, invokes third-party APIs, and returns structured JSON responses. Redis is used as a short-lived cache for repeat lookups.
* **External services:** Integrations include Google Safe Browsing, VirusTotal, AbuseIPDB, Have I Been Pwned, AlienVault OTX RSS feeds, and a Radware threat map iframe. Each provider is isolated in its own adapter module with defensive timeouts.
* **Storage:** The system persists only transient cache entries (five per artefact, expiring after ten minutes) and application logs for troubleshooting.

## 5. User Interface Walkthrough
Figure 2 illustrates the primary dashboard. The client is organised around four workspaces, each with contextual helpers.

![Figure 2. Dashboard layout showing the four workspaces](image2-placeholder)

1. **Domain Reconnaissance** (Figure 3) aggregates WHOIS, DNS, SSL certificate, and HTTP security header checks. Results are rendered as expandable panels so analysts can copy evidence into tickets. A "compare" toggle highlights attribute deltas when the same domain is queried multiple times within an hour.
2. **IP Reputation** (Figure 4) collates geolocation, ASN ownership, abuse history, and Tor exit status. The interface emphasises recency by shading the last-abuse timestamp and annotating stale records.
3. **Log & File Utilities** (Figure 5) provides a drag-and-drop area for log snippets or configuration files. The backend sanitises input, extracts key-value pairs, and optionally forwards hashes to VirusTotal when the user consents.
4. **CyberRegis Assistant** (Figure 6) accepts natural language prompts that map to documented operations (e.g., "run IP scan" or "summarise last API response") and retrieves cached results when possible. The assistant stores no conversational context beyond the current session.

## 6. Implementation Details
Table 1 summarises the technologies currently in use, while Figure 7 offers a sequence diagram for a typical domain reconnaissance workflow.

```
Table 1. Technology stack snapshot (March 2025)
+----------------------+-------------------------------------------+
| Layer                | Key Components                            |
+======================+===========================================+
| Frontend             | Next.js 13, React 18, TypeScript, shadcn/ui |
| Styling & Theming    | Tailwind CSS, CSS variables for dark theme |
| Visualization        | Recharts (trend charts), iframe threat map |
| Backend Gateway      | Python 3.11, Flask, Requests, Redis cache  |
| Threat Intelligence  | Google Safe Browsing, VirusTotal, AbuseIPDB |
| Auxiliary Services   | Have I Been Pwned, AlienVault OTX RSS      |
| Deployment Targets   | Netlify (web), local Docker compose stack  |
+----------------------+-------------------------------------------+
```

![Figure 7. Sequence diagram for a domain lookup](image7-placeholder)

Two implementation decisions merit emphasis:

* **Transparent error handling:** API quotas and network hiccups are inevitable. The client surfaces HTTP status codes and response bodies in a collapsible "Diagnostics" drawer instead of retrying silently.
* **Cache with expiry:** The backend stores the five most recent results per input, expiring after ten minutes. Users can bypass the cache with a "force refresh" toggle when investigating long-running incidents.

## 7. Data Handling and Privacy Considerations
CyberRegis intentionally minimises data retention. Inputs are hashed with per-session salts before they reach Redis, and cache entries are purged on restart. API keys are supplied via environment variables and never written to disk. The log utility performs a static linting pass to detect email addresses or IPv6 literals and warns users before forwarding data to external services. "Have I Been Pwned" requests honour the k-anonymity model so full hashes are never transmitted. Figure 8 sketches the data flow and trust boundaries that guide these choices.

![Figure 8. Data flow and trust boundary diagram](image8-placeholder)

## 8. Evaluation Methodology
Because CyberRegis remains a prototype, we conducted a small-scale validation rather than a broad benchmarking campaign. Table 2 outlines the five scenarios executed twice each on a MacBook Pro (M3, macOS 15.0) over a 200 Mbps residential connection.

```
Table 2. Validation scenarios and observed timings
+-----------------------------------------------------------+-----------+-----------+
| Scenario                                                  | Run 1 (s) | Run 2 (s) |
+===========================================================+===========+===========+
| Domain reputation check (example.org, cached)             | 3.6       | 3.2       |
| Domain reputation check (new domain, uncached)            | 12.9      | 13.4      |
| IP reputation (residential IP vs. AbuseIPDB hot feed)     | 14.8      | 11.7      |
| Log parsing (200-line nginx access log)                   | 5.1       | 4.9       |
| Chatbot prompt "summarise latest scan"                    | 4.0       | 3.8       |
+-----------------------------------------------------------+-----------+-----------+
```

In addition to timing measurements, we recorded the following qualitative observations:

* **Diagnostics visibility:** When the network connection was toggled offline, the diagnostics drawer correctly displayed upstream timeouts. Rate-limit responses from VirusTotal (HTTP 429) were preserved and shown to the user.
* **Consistency:** No false-positive banners were observed. However, third-party verdict phrasing (e.g., "malicious" versus "suspicious") surfaced directly, underscoring the need for optional normalisation rules.
* **Chatbot coverage:** The assistant successfully mapped each scripted prompt to an existing result, but it cannot reason over multiple results simultaneously. Compound queries ("compare the last two scans") fall back to a help message.

Figure 9 visualises the response time distributions captured during testing.

![Figure 9. Response time box plot for validation runs](image9-placeholder)

## 9. Discussion and Limitations
The evaluation highlights the trade-offs inherent in asynchronous aggregation without deep correlation. CyberRegis excels at rapid enrichment but does not yet deliver a unified risk score or long-term trending. Manual API key provisioning limits adoption in managed environments, and the absence of role-based access control (RBAC) means deployments must sit behind an external identity layer. The embedded threat map iframe relies on third-party uptime and may trigger content security policy warnings in strict browsers. Finally, the chatbot presently depends on deterministic templates; it cannot answer open-ended questions outside the supported command set.

## 10. Future Work
Figure 10 summarises the roadmap priorities discussed with early adopters.

![Figure 10. Roadmap themes and upcoming milestones](image10-placeholder)

Immediate next steps include:

1. Introducing RBAC via Supabase so only authorised analysts can trigger scans.
2. Adding lightweight correlation rules (e.g., flagging when a domain, IP, and hash appear together within 24 hours).
3. Implementing offline queues that replay requests once connectivity is restored.
4. Packaging the client and backend as Docker containers with reproducible defaults.

Longer-term investigations focus on evaluating the chatbot with a labelled FAQ corpus, integrating open-source behaviour analytics feeds, and exploring privacy-preserving telemetry for aggregate usage insights.

## 11. Conclusion
CyberRegis demonstrates that a modest orchestration layer can meaningfully simplify common threat intelligence lookups without overpromising autonomous detection. By foregrounding transparency, error handling, and user feedback, the platform serves as both a teaching tool and a stepping stone toward more comprehensive automation. The contributions documented here—implementation details, measured response times, and operational constraints—are intentionally scoped to help other practitioners replicate or extend the work. Continued iteration will focus on governance, correlation, and packaging so that CyberRegis can move from classroom prototype to dependable utility.

## References
1. Arora, A., Donoso, Y., & Herrera, L. (2023). Developing chatbots for cybersecurity: assessing threats and defenses. *Sustainability*, 15(7).
2. Kaheh, M., et al. (2023). Cyber Sentinel: conversational agents in cybersecurity defense. *arXiv preprint arXiv:2309.16422*.
3. Google. (2024). Google Safe Browsing API documentation. https://developers.google.com/safe-browsing
4. Hunt, T. (2023). Have I Been Pwned API v3 documentation. https://haveibeenpwned.com/API/v3
5. VirusTotal. (2024). VirusTotal API reference guide. https://developers.virustotal.com/reference
6. AbuseIPDB. (2024). AbuseIPDB API documentation. https://docs.abuseipdb.com
7. Verizon. (2024). Data Breach Investigations Report. https://www.verizon.com/business/resources/reports/dbir
