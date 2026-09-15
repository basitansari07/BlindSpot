BlindSpot — Website Vulnerability Scanner

BlindSpot is a full-stack web security scanning platform that maps attack surfaces, detects real vulnerabilities through passive and active probing, and delivers evidence-backed security reports with clear remediation guidance — all from a single, easy-to-use dashboard.


Team ID: 48 
Team Name: Cyberdefeders 
Hackathon: GLS Nexus Hackathon 2026


Table of Contents:
Overview
Features
Tech Stack
Architecture
Screenshots
Setup Instructions
Usage
Live Demo
Project Documentation
Team



Overview:

BlindSpot is a security assessment platform built to give developers, students, and security enthusiasts an accessible way to scan web applications for common vulnerabilities. It combines passive analysis (headers, TLS configuration, exposed files, outdated components) with active probing (SQL Injection, XSS, CRLF injection, open redirects, path traversal) to produce a realistic, evidence-backed picture of a target's security posture.

Every finding in a BlindSpot report is backed by actual proof — the exact request sent, the response received, and the specific signal that confirmed the vulnerability — so results are transparent and verifiable, not just guesses.


Features:
Passive Security Scanning — missing security headers (CSP, HSTS, X-Frame-Options, etc.), TLS/HTTPS misconfigurations, outdated JS libraries, exposed sensitive files (.git, robots.txt), and more.
Active Vulnerability Probing — real, non-destructive probes for:
Reflected XSS (canary-based verification)
Error-Based SQL Injection
Time-Based Blind SQL Injection
CRLF / HTTP Header Injection
Local File Inclusion / Path Traversal
Open Redirect
Configurable Scan Intensity — Passive, Light Active, or Full Active modes depending on how deep the assessment should go.
OWASP Top 10 Mapping — every finding is categorized against the current OWASP Top 10 for clear risk context.
Risk Scoring Engine — an automated risk score (0–100) and letter grade (A–F) calculated from finding severity and coverage.
Evidence-Backed Reporting — every finding includes the exact probe request, response evidence, and remediation steps.
Detection Rules Engine — a searchable library of security rules (CVE-based, Wappalyzer, and Nuclei-derived) that power passive detection.
AI-Generated PDF Reports — a professional, downloadable security assessment report generated from scan results.
JSON Export — full raw scan data available for further analysis or integration.
Authenticated Scanning — supports custom cookies/headers so authenticated areas of an application can be assessed.
Scan History Dashboard — track all past assessments, risk trends, and findings in one place.
Modern, Responsive UI — a clean dark-themed dashboard built for clarity during security reviews.



Tech Stack

Frontend:
React (Vite)
Custom CSS (design system with CSS variables, no UI framework dependency)

Backend:
Python 3
FastAPI (ASGI, via Uvicorn)
Async HTTP scanning engine (httpx)
Pydantic for data validation

Scanning Engine
Custom passive scanner (headers, TLS, tech fingerprinting)
Custom active probe engine (SQLi, XSS, CRLF, LFI, Open Redirect)
Rule-based detection engine (CVE, Wappalyzer, Nuclei template imports)
Risk correlation and scoring engine

Data & Reporting
Elasticsearch (optional persistent storage; falls back to in-memory mode)
AI-powered report generation (PDF)



Auth
Token-based authentication with session handling
🏗️ Architecture
┌─────────────┐      REST API      ┌──────────────────┐
│   React UI  │ ─────────────────► │   FastAPI Backend │
│ (Dashboard) │ ◄───────────────── │     (app.py)       │
└─────────────┘                    └─────────┬──────────┘
                                              │
                          ┌───────────────────┼───────────────────┐
                          ▼                   ▼                   ▼
                 ┌────────────────┐  ┌────────────────┐  ┌────────────────┐
                 │ Passive Scanner │  │ Active Scanner  │  │ Rule Engine    │
                 │ (headers, TLS,  │  │ (SQLi, XSS,     │  │ (CVE/Wappalyzer│
                 │  tech detect)   │  │  CRLF, LFI...)  │  │  /Nuclei rules)│
                 └────────────────┘  └────────────────┘  └────────────────┘
                          │                   │                   │
                          └───────────────────┼───────────────────┘
                                              ▼
                                  ┌────────────────────┐
                                  │  Risk Scoring &      │
                                  │  Finding Correlator  │
                                  └──────────┬───────────┘
                                             ▼
                                  ┌────────────────────┐
                                  │  Report + AI PDF     │
                                  │  Generator           │
                                  └────────────────────┘



📸 Screenshots

Add screenshots of the dashboard, scan report, and detection rules page here before final submission.

/assets/screenshot-dashboard.png
/assets/screenshot-report.png
/assets/screenshot-new-scan.png



Setup Instructions:
Prerequisites
Python 3.10+
Node.js 18+
Docker — for testing against a local vulnerable target (Optional)
Elasticsearch — for persistent scan storage (Optional)

1. Clone the repository
bash
git clone https://github.com/basitansari07/BlindSpot.git
cd BlindSpot

3. Backend Setup
bash
cd backend
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

Start the backend:
bash
uvicorn app:app --reload
The API will be available at http://127.0.0.1:8000.

Default login (auto-created on first run):
Username: admin
Password: admin123

3. Frontend Setup
bash
cd web_frontend
npm install
npm run dev

The dashboard will be available at http://localhost:5173 (or the port Vite assigns).

4. (Optional) Set up a local vulnerable test target

To safely test scanning features, spin up a deliberately vulnerable app:

bash
docker run -d -p 4280:80 vulnerables/web-dvwa

Then scan http://localhost:4280 from the New Scan page.

Note: scanning localhost/private IPs is blocked by default for safety. To allow it during local testing, set ALLOW_PRIVATE_SCAN=true before starting the backend.



Usage:
Log in to the dashboard.
Go to New Scan, enter a target URL you are authorized to test.
Choose scan options (Deep scan, Security headers, TLS analysis) and a scan intensity (Passive / Light Active / Full Active).
Confirm authorization and start the scan.
View the generated Security Report — risk score, findings by severity, OWASP coverage, and active probe logs.
Export the report as JSON or download the AI-generated PDF report.



Live Demo:
<ADD_DEPLOYED_DEMO_URL_HERE_IF_AVAILABLE>



Project Documentation:
Presentation: /docs/BlindSpot-Presentation.pdf (add file to repo)
Additional documentation: <ADD_LINKS_HERE_IF_ANY>



Cyberdefeders(Members):

Name	          Role
Basit Ansari	  Scanning Engine (Detection & Probes) + Frontend (React Dashboard)
Nischal Anand 	Backend API + Risk Scoring & Reporting



Responsible Use:
BlindSpot is designed strictly for authorized security testing. Users must obtain explicit permission before scanning any target they do not own or operate. Unauthorized scanning of third-party systems may violate applicable laws and is not condoned by this project. This tool was built as part of the GLS Nexus Hackathon 2026 for educational and demonstration purposes only.
