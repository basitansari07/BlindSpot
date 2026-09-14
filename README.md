# BlindSpot

A website vulnerability scanning tool for detecting OWASP Top 10 risks and outdated components.

BlindSpot combines passive detection rules, Nuclei-based signature scanning, and non-destructive active probing to assess the security posture of a target web application — accessible via both a web dashboard and a browser extension.

## Features

- **Passive Security Checks** — headers, misconfigurations, insecure design patterns
- **Active Probing** (`full_active` mode) — non-destructive verification of:
  - Reflected XSS (canary injection)
  - Error-based SQL Injection
  - Time-based Blind SQL Injection
  - Local File Inclusion / Path Traversal
  - CRLF / Header Injection
  - Open Redirect
- **Nuclei Template Integration** — thousands of community-maintained detection signatures
- **OWASP Top 10 Mapping** — findings classified against current OWASP categories
- **CVSS Scoring & Risk Grading** — each scan produces a calculated risk score (0–100) and letter grade
- **AI-Generated Reports** — professional PDF security assessment reports generated per scan
- **Authenticated Access** — JWT-based auth for the API
- **Dual Access** — scan via the web dashboard or the browser extension, with consistent results across both

## Project Structure

BlindSpot/
├── backend/ # FastAPI backend & scanner engine
│ ├── app.py # Main API server
│ ├── auth.py # Authentication (JWT)
│ ├── config.py # App configuration
│ ├── requirements.txt
│ ├── demo.sh # Demo/setup helper script
│ ├── engine/
│ ├── enrichment/ # CVSS/CVE enrichment
│ ├── export/ # Report export (e.g. AI PDF reports)
│ ├── importers/ # Nuclei template importer
│ ├── scanner/
│ │ ├── active_scanner.py
│ │ ├── passive_scanner.py
│ │ └── scan_manager.py
│ ├── storage/
│ └── ai/ # AI report generation
├── data/
│ ├── nuclei-templates/
│ └── safe_versions.json
├── rules/
│ ├── scan_rules.json
│ └── correlation_rules.json
├── extension/ # Browser extension (Manifest V3)
│ ├── manifest.json
│ ├── background.js
│ ├── popup.html / popup.js / popup.css
│ └── icons/
└── web_frontend/ # Web dashboard (React + Vite)
├── src/
├── public/
├── package.json
└── vite.config.js


## Getting Started

### Prerequisites

- Python 3.10+
- Node.js + npm (for the web dashboard)
- A Chromium-based browser (for the extension)

### Backend Setup

```bash
cd backend
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Run the API server:

```bash
python -m uvicorn app:app --host 0.0.0.0 --port 8000
```

The API will be available at `http://localhost:8000`.

> **Note:** The backend uses JWT authentication (`auth.py`) with a local secret file (`.jwt_secret`) and a `users.json` user store. Both are excluded from version control — set these up locally before running the server.

### Web Dashboard Setup

```bash
cd web_frontend
npm install
npm run dev
```

By default this starts a Vite dev server. Point the dashboard at your running backend instance (`http://localhost:8000`) to submit and view scans.

### Browser Extension Setup

1. Open your browser's extensions page (e.g. `chrome://extensions`)
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` folder
4. The extension will now be available to scan the currently active tab's target

## Scan Modes

| Mode | Description |
|---|---|
| Passive only | Header and configuration checks, no active injection |
| `full_active` | Passive checks + full active probe suite (XSS, SQLi, Blind SQLi, LFI, CRLF, Open Redirect) |

## Configuration

Key environment variables (backend):

| Variable | Default | Description |
|---|---|---|
| `ALLOW_PRIVATE_SCAN` | `false` | When `true`, allows scanning private/internal IP ranges and loopback addresses. Use only in controlled/authorized testing environments. |

Additional runtime configuration lives in `backend/config.py`.

## Reports

Each completed scan can generate a downloadable, AI-authored PDF report including:

- Executive summary and overall risk grade
- Severity breakdown (Critical / High / Medium / Low / Informational)
- OWASP category coverage
- Prioritized findings with CVSS scores and remediation guidance

## Disclaimer

BlindSpot is intended for authorized security testing only. Only scan targets you own or have explicit written permission to test. The maintainers are not responsible for misuse of this tool.

## License

Specify your project license here.
