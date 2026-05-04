from docx import Document
from docx.shared import Pt, Inches, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from datetime import datetime

# Create Document
doc = Document()

# ══════════════════════════════════════════════════════════════
#  TITLE PAGE
# ══════════════════════════════════════════════════════════════
title = doc.add_paragraph()
title.alignment = WD_ALIGN_PARAGRAPH.CENTER
title_run = title.add_run("PROJECT SYNOPSIS")
title_run.font.size = Pt(18)
title_run.font.bold = True

subtitle = doc.add_paragraph()
subtitle.alignment = WD_ALIGN_PARAGRAPH.CENTER
subtitle_run = subtitle.add_run("CyberRegis: A Unified Platform for Real-Time Cyber Threat Detection, Intelligence, and Automated Response")
subtitle_run.font.size = Pt(12)
subtitle_run.font.bold = True

doc.add_paragraph()  # Spacer

# Project Details Section
details = doc.add_heading("Project Details", level=1)

table_details = doc.add_table(rows=6, cols=2)
table_details.style = 'Light Grid Accent 1'

cells = table_details.rows[0].cells
cells[0].text = "Project ID"
cells[1].text = "LYCSF111"

cells = table_details.rows[1].cells
cells[0].text = "Class"
cells[1].text = "LY-CSF-1"

cells = table_details.rows[2].cells
cells[0].text = "Project Title"
cells[1].text = "CyberRegis: A Unified Platform for Real-Time Cyber Threat Detection, Intelligence, and Automated Response"

cells = table_details.rows[3].cells
cells[0].text = "Project Domain"
cells[1].text = "Cyber Awareness & Cybersecurity"

cells = table_details.rows[4].cells
cells[0].text = "Project Guide"
cells[1].text = "Prof. Smita Gumaste"

cells = table_details.rows[5].cells
cells[0].text = "Completion Date"
cells[1].text = "April 27, 2026 (100% Complete)"

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  TEAM MEMBERS
# ══════════════════════════════════════════════════════════════
team_heading = doc.add_heading("Team Members", level=1)

team_table = doc.add_table(rows=5, cols=4)
team_table.style = 'Light Grid Accent 1'

# Header
header_cells = team_table.rows[0].cells
header_cells[0].text = "Enrollment No."
header_cells[1].text = "Name"
header_cells[2].text = "Contact Number"
header_cells[3].text = "Email ID"

# Team data
team_data = [
    ("MITU22BTCS0379", "Kathan Nirav Somani", "9574943784", "kathansomani9875@gmail.com"),
    ("MITU22BTCS0247", "Dev Bhavesh Sagani", "8999965114", "devsagani19@gmail.com"),
    ("MITU22BTCS0160", "Aryan Dsouza", "9011010654", "aryan.dsouza140921@gmail.com"),
    ("MITU22BTCS0238", "Darshan Dnyaneshwar Dorik", "9913352582", "dorikdarshan2004@gmail.com"),
]

for i, (enroll, name, phone, email) in enumerate(team_data, 1):
    row_cells = team_table.rows[i].cells
    row_cells[0].text = enroll
    row_cells[1].text = name
    row_cells[2].text = phone
    row_cells[3].text = email

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  PROBLEM STATEMENT
# ══════════════════════════════════════════════════════════════
doc.add_heading("Problem Statement", level=1)

problem_text = """
The rapid growth of cyber threats and sophisticated attack vectors has created a significant gap in real-time threat detection and response capabilities. Organizations often struggle with:

1. **Fragmented Threat Intelligence**: Data from multiple security sources (VirusTotal, Shodan, AbuseIPDB, HIBP) is not centralized, making it difficult to correlate and analyze threats comprehensively.

2. **Manual Threat Analysis**: Security teams spend excessive time manually analyzing threat data, network traffic, and vulnerability reports without automated context and recommendations.

3. **Lack of Real-Time Alerts**: Absence of immediate notification systems for critical threats prevents rapid incident response.

4. **Insufficient Domain & IP Intelligence**: Limited visibility into domain reputation, open ports, HTTP security headers, and email security configurations.

5. **CVE & Vulnerability Tracking**: Manual cross-referencing of CVEs with MITRE ATT&CK framework is time-consuming and error-prone.

CyberRegis addresses these challenges by providing a unified platform that integrates multiple threat intelligence sources, automates threat scoring, and delivers actionable security insights through an AI-powered interface.
"""

doc.add_paragraph(problem_text)

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  OBJECTIVES
# ══════════════════════════════════════════════════════════════
doc.add_heading("Project Objectives", level=1)

objectives = [
    "Develop a unified real-time threat intelligence dashboard for domain, IP, URL, and network analysis.",
    "Integrate multiple security APIs (VirusTotal, AbuseIPDB, Google Safe Search, HIBP, NVD, Shodan, MITRE ATT&CK) into a single platform.",
    "Implement AI-driven threat scoring and anomaly detection to classify threats by risk level.",
    "Build an automated alert system via Telegram Bot API for critical and high-severity threats.",
    "Create an AI-powered cybersecurity chatbot (Google Gemini) for step-by-step threat guidance.",
    "Develop PCAP network traffic analysis capabilities to detect protocol anomalies.",
    "Implement email security (DMARC/SPF/DKIM) and HTTP security headers analysis.",
    "Generate automated security reports with actionable recommendations.",
    "Provide real-time monitoring dashboard and IOC (Indicators of Compromise) catalog."
]

for obj in objectives:
    p = doc.add_paragraph(obj, style='List Bullet')

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  TECHNOLOGY STACK
# ══════════════════════════════════════════════════════════════
doc.add_heading("Technology Stack", level=1)

tech_table = doc.add_table(rows=9, cols=3)
tech_table.style = 'Light Grid Accent 1'

tech_data = [
    ("Layer", "Primary Technology", "Supporting Tools"),
    ("Frontend", "Next.js 14 (TypeScript), Tailwind CSS, shadcn/ui", "Recharts, Lucide Icons"),
    ("Backend", "Python Flask, REST API, Flask-Limiter", "Flask-Caching, Modular Blueprints"),
    ("Database", "PostgreSQL (production), SQLite (local development)", "SQLAlchemy ORM"),
    ("AI/ML", "Google Gemini API, NLP Processing", "Threat Scoring Algorithms, Anomaly Detection"),
    ("Security APIs", "VirusTotal, AbuseIPDB, Shodan, HIBP, NVD, MITRE ATT&CK", "Google Safe Browsing, GreyNoise"),
    ("Alerting", "Telegram Bot API", "Real-time Notification System"),
    ("Development Tools", "VS Code, Git, Postman, Google Cloud Console", "Next.js Dev Server, Flask Dev Server"),
    ("Deployment", "Netlify (Web), Expo (Mobile)", "Docker (optional), Cloud Infrastructure"),
]

for i, (layer, primary, supporting) in enumerate(tech_data):
    row_cells = tech_table.rows[i].cells
    row_cells[0].text = layer
    row_cells[1].text = primary
    row_cells[2].text = supporting

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  KEY FEATURES
# ══════════════════════════════════════════════════════════════
doc.add_heading("Key Features", level=1)

features = [
    "Real-time Threat Intelligence Dashboard with KPI cards and multi-source data visualization",
    "Domain, IP, URL, and PCAP network traffic analysis",
    "Automated threat detection with risk-level classification (Critical, High, Medium, Low)",
    "Email security analysis (DMARC, SPF, DKIM records)",
    "HTTP security headers checker with OWASP compliance scoring",
    "Port scanning and service fingerprinting",
    "CVE database lookup with CVSS severity filtering",
    "MITRE ATT&CK framework integration for threat tactic/technique mapping",
    "AI-powered chatbot for cybersecurity guidance and threat explanation",
    "Telegram Bot real-time alerts for critical threats",
    "Automated security report generation with actionable recommendations",
    "IOC (Indicators of Compromise) catalog and threat feed aggregation",
    "Scan history with localStorage caching for offline access",
    "Mobile-responsive design for on-the-go threat analysis"
]

for feature in features:
    p = doc.add_paragraph(feature, style='List Bullet')

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  SPRINT SUMMARY
# ══════════════════════════════════════════════════════════════
doc.add_heading("Development Timeline", level=1)

sprint_table = doc.add_table(rows=13, cols=3)
sprint_table.style = 'Light Grid Accent 1'

sprint_data = [
    ("Sprint", "Duration", "Deliverables"),
    ("Sprint 1", "Jan 1–15, 2026", "Dashboard UI design, backend threat detection algorithms, Flask setup"),
    ("Sprint 2", "Jan 16–31, 2026", "Backend API routes (domain, IP, URL analysis), threat logging UI"),
    ("Sprint 3", "Feb 1–14, 2026", "Mobile UI for threat logging, security API integration (VirusTotal, AbuseIPDB)"),
    ("Sprint 4", "Feb 15–28, 2026", "AI threat scoring & anomaly detection, Telegram Bot alerts"),
    ("Sprint 5", "Mar 1–15, 2026", "Domain analysis backend, VirusTotal integration, domain/URL UI"),
    ("Sprint 6", "Mar 16–27, 2026", "IP reputation service (Shodan, AbuseIPDB, GreyNoise), IP dashboard"),
    ("Sprint 7", "Mar 28–Apr 10, 2026", "PCAP network traffic analysis engine, protocol anomaly detection"),
    ("Sprint 8", "Dec 1–14, 2025*", "CVE lookup (NVD API), MITRE ATT&CK framework integration"),
    ("Sprint 9", "Dec 15–28, 2025*", "Email security & HTTP headers analysis, port scanner"),
    ("Sprint 10", "Jan 5–18, 2026*", "Google Gemini AI chatbot integration, NLP threat context"),
    ("Sprint 11", "Jan 19–Feb 1, 2026*", "Monitoring dashboard, security report generation, threat feeds"),
    ("Sprint 12", "Feb 2–15, 2026*", "IOC catalog, caching layer, security hardening, E2E testing, deployment"),
]

for i, (sprint, duration, deliverables) in enumerate(sprint_data):
    row_cells = sprint_table.rows[i].cells
    row_cells[0].text = sprint
    row_cells[1].text = duration
    row_cells[2].text = deliverables

doc.add_paragraph("*Note: Some sprint dates overlap due to parallel development tracks.")

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  ACCEPTANCE CRITERIA
# ══════════════════════════════════════════════════════════════
doc.add_heading("Acceptance Criteria", level=1)

criteria = [
    "Integrated security APIs (VirusTotal, AbuseIPDB, HIBP, Shodan, NVD) provide real-time threat intelligence with ≤2 second response time.",
    "Users receive actionable security recommendations based on multi-source threat data analysis.",
    "Dashboard provides a real-time view of all ongoing cyber threats, scans, and incidents with auto-refresh every 30 seconds.",
    "PCAP files are parsed and network anomalies are flagged automatically with 95%+ accuracy.",
    "CVE lookup and MITRE ATT&CK mapping surface complete vulnerability context and attack tactics.",
    "Email security records (DMARC/SPF/DKIM) and HTTP security headers are analyzed and scored on a 0–100 scale.",
    "AI chatbot (Gemini) answers cybersecurity questions with domain-aware context and provides step-by-step remediation.",
    "Users receive immediate alerts via Telegram Bot for critical/high-severity threats with <5 second notification delay.",
    "Security reports are auto-generated in JSON format with executive summaries and actionable recommendations.",
    "Monitoring dashboard tracks system health, API latency, and threat statistics in real-time.",
    "System supports 1000+ concurrent threat scans without performance degradation."
]

for i, criterion in enumerate(criteria, 1):
    p = doc.add_paragraph(f"{i}. {criterion}", style='List Number')

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  EXPECTED OUTCOMES
# ══════════════════════════════════════════════════════════════
doc.add_heading("Expected Outcomes", level=1)

outcomes_text = """
1. **Reduced Threat Response Time**: Security teams will respond to critical threats 5–10x faster through automated detection and Telegram alerts.

2. **Unified Threat Intelligence**: Centralized dashboard eliminates manual data aggregation from multiple security sources.

3. **AI-Powered Insights**: Threat scoring and anomaly detection provide objective risk classification and actionable guidance.

4. **Improved Security Awareness**: Integrated chatbot and security resources enable teams to understand threats and apply best practices.

5. **Comprehensive Audit Trail**: Scan history, IOC catalog, and security reports provide compliance and forensic analysis capabilities.

6. **Scalable Architecture**: Modular backend (Flask Blueprints) and responsive frontend enable easy addition of new threat sources and analysis capabilities.

7. **Production-Ready Deployment**: Platform will be deployed on Netlify (web) and Expo (mobile) with Docker containerization for enterprise adoption.
"""

doc.add_paragraph(outcomes_text)

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  CONCLUSION
# ══════════════════════════════════════════════════════════════
doc.add_heading("Conclusion", level=1)

conclusion_text = """
CyberRegis is a comprehensive, AI-driven threat intelligence platform designed to address the critical gap in automated threat detection and response. By integrating multiple security APIs, implementing advanced threat scoring algorithms, and providing an AI-powered chatbot interface, CyberRegis empowers security teams to respond to cyber threats faster and more effectively.

The platform's unified dashboard, real-time alerts, and automated report generation will significantly reduce manual security analysis overhead while improving incident response times. With its modular architecture and comprehensive feature set, CyberRegis is positioned to become an essential tool for organizations seeking to strengthen their cybersecurity posture.
"""

doc.add_paragraph(conclusion_text)

doc.add_paragraph()

# ══════════════════════════════════════════════════════════════
#  FOOTER
# ══════════════════════════════════════════════════════════════
footer_para = doc.add_paragraph()
footer_para.alignment = WD_ALIGN_PARAGRAPH.CENTER
footer_run = footer_para.add_run(f"\n\nGenerated: May 5, 2026\nProject LYCSF111 – CyberRegis\nClass: LY-CSF-1")
footer_run.font.size = Pt(9)
footer_run.font.italic = True

# Save document
output_path = "CyberRegis_Synopsis.docx"
doc.save(output_path)
print(f"Synopsis saved: {output_path}")
