# CyberRegis Feature Descriptions for Research Paper

## 1. Domain Analysis

The Domain Analysis module conducts comprehensive reconnaissance on target domains by extracting WHOIS registration details, DNS record configurations, and SSL certificate information. It performs subdomain enumeration to identify potential attack surfaces and evaluates security implementations including DNSSEC, DMARC, and SPF records. The system also detects web application firewalls and analyzes domain age patterns to assess legitimacy. Geolocation data is correlated with registration information to provide a complete security profile of the examined domain.

## 2. IP Analysis

IP Analysis evaluates the reputation and security posture of IPv4 addresses through multiple threat intelligence sources including VirusTotal and AbuseIPDB databases. The module extracts geolocation details, ISP information, and Autonomous System Number (ASN) data to understand the network context. It detects whether the IP address is associated with Tor exit nodes or other anonymizing services that could indicate malicious intent. Risk assessment scores are calculated based on historical abuse reports and current threat intelligence feeds, providing a confidence level for potential security threats.

## 3. Network Analysis

Network Analysis processes packet capture (PCAP) files to identify protocols, traffic patterns, and potential security anomalies within network communications. The system extracts protocol statistics and generates visual representations of network traffic distribution across different protocol types. Each captured file undergoes malware scanning through VirusTotal's API to detect known threats embedded in network traffic. The analysis identifies suspicious IP addresses and potential attack vectors by correlating protocol usage with known malicious patterns.

## 4. Live Threat Map

The Live Threat Map integrates Radware's real-time threat visualization service to display global cyber attack activity as it occurs. This feature provides a geographic representation of active threats, showing attack origins, destinations, and types in real-time. Security professionals can observe attack patterns, identify emerging threats, and understand the current threat landscape worldwide. The visualization helps contextualize individual scan results within the broader cybersecurity environment.

## 5. Advanced Analysis

Advanced Analysis combines port scanning, vulnerability assessment, and SSL/TLS configuration analysis to provide deeper security insights. Port scanning identifies open services and their versions, enabling the detection of potentially vulnerable configurations. The vulnerability assessment correlates discovered services with known Common Vulnerabilities and Exposures (CVE) databases to identify security weaknesses. SSL/TLS analysis examines cipher suite configurations, certificate validity, and encryption strength to ensure proper cryptographic implementation.

## 6. Security Analysis

Security Analysis evaluates web application security through HTTP header examination and email security configuration assessment. The headers scanner checks for presence and proper configuration of security headers such as Content-Security-Policy, X-Frame-Options, and Strict-Transport-Security. Email security analysis verifies SPF, DMARC, and DKIM record configurations to assess protection against email spoofing and phishing attacks. The module generates security scores and provides actionable recommendations for improving overall security posture.

## 7. Resource Tab

The Resource Tab aggregates cybersecurity intelligence from multiple sources including News API, RSS feeds from security blogs, and threat intelligence platforms like AlienVault OTX. It displays curated cybersecurity articles, threat news with severity classifications, and educational resources from GitHub repositories. The content is automatically updated through polling mechanisms and categorized to help users stay informed about current threats and security best practices. This centralized repository supports continuous learning and threat awareness for security professionals.







