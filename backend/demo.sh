#!/bin/bash
# BlindSpot — One-command live demo script
# Usage: ./demo.sh [target_url]
# Make sure the backend is already running (python app.py) in another terminal.

BASE_URL="http://localhost:5001"
TARGET="${1:-https://example.com}"
USERNAME="admin"
PASSWORD="admin123"

echo "============================================================"
echo "  BlindSpot — Live Demo"
echo "  Target: $TARGET"
echo "============================================================"
echo ""

# ── Step 1: Health check ─────────────────────────────
echo "[1/4] Checking backend health..."
HEALTH=$(curl -s "$BASE_URL/api/health")
echo "$HEALTH" | python3 -m json.tool
echo ""

# ── Step 2: Login ────────────────────────────────────
echo "[2/4] Logging in as '$USERNAME'..."
LOGIN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"username\": \"$USERNAME\", \"password\": \"$PASSWORD\"}")

TOKEN=$(echo "$LOGIN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('token', ''))")

if [ -z "$TOKEN" ]; then
  echo "❌ Login failed. Response:"
  echo "$LOGIN_RESPONSE"
  exit 1
fi
echo "✅ Logged in successfully."
echo ""

# ── Step 3: Submit scan ──────────────────────────────
echo "[3/4] Submitting scan for $TARGET ..."
SCAN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/scan" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "{\"url\": \"$TARGET\", \"authorized\": true, \"scan_mode\": \"full_active\"}")

SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('scan_id', ''))")

if [ -z "$SCAN_ID" ]; then
  echo "❌ Scan submission failed. Response:"
  echo "$SCAN_RESPONSE"
  exit 1
fi
echo "✅ Scan submitted — ID: $SCAN_ID"
echo ""

# ── Step 4: Poll until complete, then show report ────
echo "[4/4] Scanning in progress..."
for i in $(seq 1 40); do
  STATUS_RESPONSE=$(curl -s "$BASE_URL/api/scan/$SCAN_ID" -H "Authorization: Bearer $TOKEN")
  STATUS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('scan', {}).get('status', 'unknown'))")
  PROGRESS=$(echo "$STATUS_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin).get('scan', {}).get('progress', 0))")
  echo -ne "   Status: $STATUS   Progress: $PROGRESS%   \r"

  if [ "$STATUS" == "completed" ] || [ "$STATUS" == "failed" ]; then
    echo ""
    break
  fi
  sleep 1
done

echo ""
echo "============================================================"
echo "  SCAN REPORT"
echo "============================================================"

REPORT=$(curl -s "$BASE_URL/api/scan/$SCAN_ID/report" -H "Authorization: Bearer $TOKEN")

echo "$REPORT" | python3 -c "
import sys, json
data = json.load(sys.stdin)
r = data.get('report', {})
print(f\"Target:          {r.get('target_url')}\")
print(f\"Scan duration:   {r.get('scan_duration_ms')} ms\")
print(f\"Technologies:    {', '.join(r.get('technologies', [])) or 'none detected'}\")
print(f\"Risk score:      {r.get('risk_score')}/100  (Grade {r.get('risk_grade')} — {r.get('risk_grade_label')})\")
print()
vs = r.get('vulnerability_summary', {})
print(f\"Total findings:  {vs.get('total_findings')}\")
print(f\"Unique findings: {vs.get('total_unique')}\")
print(f\"OWASP categories affected: {vs.get('affected_owasp_categories')}/10\")
print()
print('Summary:')
print(' ', r.get('summary', ''))
print()
print('Top findings:')
for f in vs.get('unique_findings', [])[:10]:
    print(f\"  - {f.get('one_liner')}\")
"

echo ""
echo "============================================================"
echo "Full raw JSON report saved to: scan_report_${SCAN_ID:0:8}.json"
echo "$REPORT" > "scan_report_${SCAN_ID:0:8}.json"
echo "============================================================"
