"""
config.py — Central configuration for the Vulnerability Scanner backend.
All settings in one place for easy environment-specific overrides.
"""

import os
import secrets

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ── Elasticsearch ──────────────────────────────────────────
ES_HOST = os.getenv("ES_HOST", "https://localhost:9200")
ES_USER = os.getenv("ES_USER", "elastic")
ES_PASS = os.getenv("ES_PASS", "")  # MUST be set via env var in production
ES_VERIFY_CERTS = os.getenv("ES_VERIFY_CERTS", "false").lower() == "true"
SCAN_INDEX_PREFIX = "scan-results"       # index: scan-results-YYYY.MM.DD
SCAN_META_INDEX = "scan-metadata"        # stores scan job metadata

# ── Server ─────────────────────────────────────────────────
MAPPER_PORT = int(os.getenv("MAPPER_PORT", "5001"))

# ── JWT Authentication ─────────────────────────────────────
# Persist JWT_SECRET so tokens survive restarts
_JWT_SECRET_FILE = os.path.join(BASE_DIR, ".jwt_secret")

def _get_jwt_secret():
    """Read JWT secret from env, file, or generate and persist."""
    env_secret = os.getenv("JWT_SECRET", "")
    if env_secret:
        return env_secret
    if os.path.exists(_JWT_SECRET_FILE):
        with open(_JWT_SECRET_FILE, "r") as f:
            return f.read().strip()
    new_secret = secrets.token_hex(32)
    try:
        with open(_JWT_SECRET_FILE, "w") as f:
            f.write(new_secret)
        os.chmod(_JWT_SECRET_FILE, 0o600)
    except OSError:
        pass
    return new_secret

JWT_SECRET = _get_jwt_secret()
JWT_ALGORITHM = "HS256"
JWT_EXPIRY_HOURS = 720

# ── CORS ───────────────────────────────────────────────────
# Include "*" as fallback so the scanner works when accessed from any IP on the network
ALLOWED_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://127.0.0.1:5001,http://localhost:5001,http://127.0.0.1:8081,http://localhost:8081,*").split(",")

# ── Rate Limiting ──────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_SECONDS = 900  # 15 minutes

# ── Paths ──────────────────────────────────────────────────
USERS_PATH = os.path.join(BASE_DIR, "users.json")
SCAN_RULES_PATH = os.path.join(BASE_DIR, "..", "rules", "scan_rules.json")
CORRELATION_RULES_PATH = os.path.join(BASE_DIR, "..", "rules", "correlation_rules.json")
SAFE_VERSIONS_PATH = os.path.join(BASE_DIR, "..", "data", "safe_versions.json")
WAPPALYZER_DATA_PATH = os.path.join(BASE_DIR, "..", "data", "wappalyzer")
NUCLEI_TEMPLATES_PATH = os.path.join(BASE_DIR, "..", "data", "nuclei-templates")

# ── Scanner Settings ──────────────────────────────────────
MAX_CONCURRENT_SCANS = 3
SCAN_TIMEOUT = 300          # seconds per scan
FETCH_TIMEOUT = 10          # seconds per HTTP request
MAX_REDIRECTS = 10
USER_AGENT = "Mozilla/5.0 (compatible; VulnScanner/1.0; +https://github.com/mapper)"
MAX_BODY_SIZE = 5 * 1024 * 1024   # 5 MB cap on response body

# ── Active Scanner Settings ────────────────────────────────
ACTIVE_SCAN_ENABLED = True
MAX_ACTIVE_PROBES_PER_TARGET = 20    # Max probes per scan
ACTIVE_REQUEST_DELAY = 0.2           # 200ms delay between active probes
ACTIVE_XSS_CANARY = "mapper_xss_probe"

# ── Rate Limiting (Active Probes) ─────────────────────────
DEFAULT_RPS_LIMIT = 10               # Max requests per second (0 = unlimited)

# ── Blind SQLi Probe Settings ─────────────────────────────
BLIND_SQLI_SLEEP_SECONDS = 3         # Sleep duration injected into blind SQLi payloads
BLIND_SQLI_THRESHOLD = 2.5           # Response delay threshold to flag as vulnerable

# ── CVE Enrichment ─────────────────────────────────────────
OSV_API_URL = "https://api.osv.dev/v1/vulns"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CVE_CACHE_TTL = 86400  # 24 hours
