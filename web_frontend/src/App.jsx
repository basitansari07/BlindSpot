import { useEffect, useMemo, useState } from "react";

import "./App.css";

const API_BASE =
  import.meta.env.VITE_API_BASE || "http://127.0.0.1:8000/api";

const severityOrder = ["critical", "high", "medium", "low", "info"];

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem("blindspot_token") || ""
  );
  const [user, setUser] = useState(
    () => localStorage.getItem("blindspot_user") || "admin"
  );
  const [page, setPage] = useState("dashboard");
  const [loading, setLoading] = useState(false);
  const [loginError, setLoginError] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [stats, setStats] = useState(null);
  const [scans, setScans] = useState([]);
  const [rules, setRules] = useState([]);
  const [selectedScan, setSelectedScan] = useState(null);
  const [report, setReport] = useState(null);
  const [findingFilter, setFindingFilter] = useState("all");
  const [scanForm, setScanForm] = useState({
    target: "",
    deep_scan: true,
    security_headers: true,
    tls: true,
    scan_mode: "passive",
    rate_limit: "",
    session_cookies: "",
    custom_headers: "",
    authorized: false,
  });
  const [scanProgress, setScanProgress] = useState(null);
  const [toast, setToast] = useState("");

  const isAuthenticated = Boolean(token);

  const api = async (path, options = {}) => {
    const headers = {
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(options.headers || {}),
    };

    const response = await fetch(`${API_BASE}${path}`, {
      ...options,
      headers,
    });

    let data = {};

    try {
      data = await response.json();
    } catch {
      data = {};
    }

    if (!response.ok) {
      throw new Error(
        data.detail ||
          data.message ||
          data.error ||
          `Request failed (${response.status})`
      );
    }

    return data;
  };

  const showToast = (message) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 3000);
  };

  const login = async (event) => {
    event.preventDefault();
    setLoginError("");

    const username = event.currentTarget.username.value.trim();
    const password = event.currentTarget.password.value;

    if (!username || !password) {
      setLoginError("Enter username and password.");
      return;
    }

    setLoading(true);

    try {
      const data = await fetch(`${API_BASE}/auth/login`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const result = await data.json();

      if (!data.ok) {
        throw new Error(
          result.detail || result.message || "Invalid credentials"
        );
      }

      const jwt = result.token || result.access_token;

      if (!jwt) {
        throw new Error("Login succeeded but no token was returned.");
      }

      localStorage.setItem("blindspot_token", jwt);
      localStorage.setItem(
        "blindspot_user",
        result.username || username
      );

      setToken(jwt);
      setUser(result.username || username);
      setPage("dashboard");
      showToast("Signed in successfully.");
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoading(false);
    }
  };

  const logout = async () => {
    try {
      if (token) {
        await api("/auth/logout", { method: "POST" });
      }
    } catch {
      // Local logout should still happen if backend logout is unavailable.
    }

    localStorage.removeItem("blindspot_token");
    localStorage.removeItem("blindspot_user");

    setToken("");
    setUser("admin");
    setStats(null);
    setScans([]);
    setRules([]);
    setSelectedScan(null);
    setReport(null);
  };

  const loadDashboard = async () => {
    try {
      const data = await api("/stats");
      setStats(data);
    } catch {
      setStats(null);
    }

    try {
      const data = await api("/scans");
      setScans(data.scans || data || []);
    } catch {
      setScans([]);
    }
  };

  const loadScans = async () => {
    try {
      const data = await api("/scans");
      setScans(data.scans || data || []);
    } catch (error) {
      showToast(error.message);
    }
  };

  const loadRules = async () => {
    try {
      const data = await api("/rules");
      setRules(data.rules || data || []);
    } catch (error) {
      showToast(error.message);
    }
  };

  const reloadRules = async () => {
    try {
      const data = await api("/rules/reload", {
        method: "POST",
      });

      showToast(
        data.message || `Rules reloaded: ${data.rules_loaded || "OK"}`
      );

      await loadRules();
    } catch (error) {
      showToast(error.message);
    }
  };

  useEffect(() => {
    if (!token) return;
    loadDashboard();
  }, [token]);

  useEffect(() => {
    if (!token) return;

    if (page === "scans") loadScans();
    if (page === "rules") loadRules();
  }, [page, token]);

  const startScan = async (event) => {
    event.preventDefault();

    if (!scanForm.target.trim()) {
      showToast("Enter a target URL.");
      return;
    }

    if (!scanForm.authorized) {
      showToast("Authorization confirmation is required.");
      return;
    }

    setLoading(true);

    setScanProgress({
      status: "queued",
      progress: 0,
      scan_id: null,
    });

    try {
      let normalizedTarget = scanForm.target.trim();

      if (!/^https?:\/\//i.test(normalizedTarget)) {
        normalizedTarget = `https://${normalizedTarget}`;
      }

      let customHeaders = scanForm.custom_headers.trim();

      try {
        if (customHeaders) {
          customHeaders = JSON.parse(customHeaders);
        } else {
          customHeaders = {};
        }
      } catch {
        throw new Error("Custom headers must be valid JSON.");
      }

      /*
       * IMPORTANT:
       * Backend /api/scan expects the field "url".
       * Previously the frontend sent "target", which caused
       * the backend to return HTTP 400.
       */

      const body = {
        url: normalizedTarget,
        deep_scan: scanForm.deep_scan,
        security_headers: scanForm.security_headers,
        tls: scanForm.tls,
        scan_mode: scanForm.scan_mode,
        rate_limit: scanForm.rate_limit
          ? Number(scanForm.rate_limit)
          : undefined,
        session_cookies:
          scanForm.session_cookies.trim() || undefined,
        auth_headers: customHeaders,
        authorized: true,
      };

      const data = await api("/scan", {
        method: "POST",
        body: JSON.stringify(body),
      });

      const scanId = data.scan_id || data.id;

      if (!scanId) {
        throw new Error("Backend did not return a scan ID.");
      }

      setScanProgress({
        status: "running",
        progress: 5,
        scan_id: scanId,
      });

      showToast("Scan started.");
      pollScan(scanId);
    } catch (error) {
      setScanProgress(null);
      showToast(error.message);
    } finally {
      setLoading(false);
    }
  };

  const pollScan = async (scanId) => {
    let finished = false;

    while (!finished) {
      try {
        const data = await api(`/scan/${scanId}`);
        const scan = data.scan || data;

        const progress = Number(scan.progress ?? 0);
        const status = String(
          scan.status || "running"
        ).toLowerCase();

        setScanProgress({
          status,
          progress,
          scan_id: scanId,
          scan,
        });

        if (
          [
            "completed",
            "complete",
            "finished",
            "failed",
            "error",
          ].includes(status)
        ) {
          finished = true;

          if (
            ["completed", "complete", "finished"].includes(status)
          ) {
            showToast("Scan completed.");
            await loadDashboard();
            await openScan(scanId);
          } else {
            showToast(`Scan ${status}.`);
          }

          break;
        }
      } catch (error) {
        showToast(error.message);
        finished = true;
        break;
      }

      await new Promise((resolve) => setTimeout(resolve, 1500));
    }
  };

  const openScan = async (scanId) => {
    try {
      const data = await api(`/scan/${scanId}/report`);

      setReport(data.report || data);
      setSelectedScan(scanId);
      setPage("report");
    } catch (error) {
      showToast(error.message);
    }
  };

  const deleteScan = async (scanId) => {
    const confirmed = window.confirm(
      "Delete this scan and its stored report?"
    );

    if (!confirmed) return;

    try {
      await api(`/scan/${scanId}`, {
        method: "DELETE",
      });

      showToast("Scan deleted.");

      await loadScans();
      await loadDashboard();
    } catch (error) {
      showToast(error.message);
    }
  };

  const exportReport = async (format) => {
    if (!selectedScan) return;

    try {
      const response = await fetch(
        `${API_BASE}/scan/${selectedScan}/export?format=${encodeURIComponent(
          format
        )}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        throw new Error(`Export failed (${response.status})`);
      }

      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition");

      let filename = `blindspot-report.${format}`;

      if (disposition) {
        const match = disposition.match(/filename="?([^"]+)"?/i);

        if (match?.[1]) {
          filename = match[1];
        }
      }

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");

      anchor.href = url;
      anchor.download = filename;

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      URL.revokeObjectURL(url);

      showToast("Report exported.");
    } catch (error) {
      showToast(error.message);
    }
  };

  const downloadAIReport = async () => {
    if (!selectedScan) return;

    try {
      const response = await fetch(
        `${API_BASE}/scan/${selectedScan}/ai-report`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        }
      );

      if (!response.ok) {
        throw new Error(`AI report failed (${response.status})`);
      }

      const blob = await response.blob();
      const disposition = response.headers.get("Content-Disposition");

      let filename = `blindspot-ai-security-report-${selectedScan}.pdf`;

      if (disposition) {
        const match = disposition.match(/filename="?([^"]+)"?/i);

        if (match?.[1]) {
          filename = match[1];
        }
      }

      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");

      anchor.href = url;
      anchor.download = filename;

      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();

      URL.revokeObjectURL(url);

      showToast("AI security report downloaded.");
    } catch (error) {
      showToast(error.message);
    }
  };

  const findings = useMemo(() => {
    const list =
      report?.findings ||
      report?.results?.findings ||
      selectedScan?.findings ||
      [];

    if (!Array.isArray(list)) return [];

    if (findingFilter === "all") return list;

    return list.filter(
      (finding) =>
        String(finding.severity || "").toLowerCase() ===
        findingFilter
    );
  }, [report, selectedScan, findingFilter]);

  const severityCounts = useMemo(() => {
    const counts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      info: 0,
    };

    const allFindings =
      report?.findings ||
      report?.results?.findings ||
      [];

    if (Array.isArray(allFindings)) {
      allFindings.forEach((finding) => {
        const severity = String(
          finding.severity || "info"
        ).toLowerCase();

        if (counts[severity] !== undefined) {
          counts[severity] += 1;
        }
      });
    }

    return counts;
  }, [report]);

  const riskScore =
    Number(
      report?.risk_score ??
        report?.risk?.score ??
        report?.summary?.risk_score ??
        selectedScan?.risk_score ??
        0
    ) || 0;

  const riskGrade =
    report?.risk_grade ||
    report?.grade ||
    report?.risk?.grade ||
    selectedScan?.risk_grade ||
    getRiskGrade(riskScore);

  if (!isAuthenticated) {
    return (
      <div className="login-shell">
        <div className="login-glow glow-one" />
        <div className="login-glow glow-two" />

        <div className="login-panel">
          <div className="login-card">
            <div className="login-brand">
              <div className="brand-mark">
                <svg
                  viewBox="0 0 32 32"
                  xmlns="http://www.w3.org/2000/svg"
                  aria-hidden="true"
                >
                  <path
                    d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
                    fill="#22D3EE"
                    clipPath="inset(0 50% 0 0)"
                  />

                  <path
                    d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
                    fill="none"
                    stroke="#22D3EE"
                    strokeWidth="3.5"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>

              <div>
                <div className="brand-name">BlindSpot</div>
                <div className="brand-subtitle">
                  Website Vulnerability Scanner
                </div>
              </div>
            </div>

            <div className="login-heading">
              <p>
                Sign in to scan any website and get a detailed security report.
              </p>
            </div>

            <form className="login-form" onSubmit={login}>
              <label className="login-field">
                Username

                <div className="input-with-icon">
                  <svg
                    className="field-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <circle cx="12" cy="8" r="4" />
                    <path d="M4 21C4.8 16.8 7.5 14.5 12 14.5C16.5 14.5 19.2 16.8 20 21" />
                  </svg>

                  <input
                    name="username"
                    type="text"
                    placeholder="Enter username"
                    autoComplete="username"
                  />
                </div>
              </label>

              <label className="login-field">
                Password

                <div className="input-with-icon">
                  <svg
                    className="field-icon"
                    viewBox="0 0 24 24"
                    fill="none"
                    stroke="currentColor"
                    strokeWidth="1.8"
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    aria-hidden="true"
                  >
                    <rect
                      x="4"
                      y="10"
                      width="16"
                      height="11"
                      rx="2"
                    />
                    <path d="M8 10V7C8 4.8 9.8 3 12 3C14.2 3 16 4.8 16 7V10" />
                  </svg>

                  <input
                    name="password"
                    type={showPassword ? "text" : "password"}
                    placeholder="Enter password"
                    autoComplete="current-password"
                  />

                  <button
                    type="button"
                    className="password-toggle"
                    onClick={() =>
                      setShowPassword((current) => !current)
                    }
                    aria-label={
                      showPassword
                        ? "Hide password"
                        : "Show password"
                    }
                  >
                    {showPassword ? (
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden="true"
                      >
                        <path d="M3 3L21 21" />
                        <path d="M10.6 10.6C10.2 11 10 11.5 10 12C10 13.1 10.9 14 12 14C12.5 14 13 13.8 13.4 13.4" />
                        <path d="M9.9 4.3C10.6 4.1 11.3 4 12 4C17.2 4 20.5 8 21 12C20.8 13.7 20.1 15.2 19 16.5" />
                        <path d="M6.2 6.2C4.4 7.5 3.3 9.3 3 12C3.5 16 6.8 20 12 20C13.7 20 15.2 19.6 16.5 18.8" />
                      </svg>
                    ) : (
                      <svg
                        viewBox="0 0 24 24"
                        fill="none"
                        stroke="currentColor"
                        strokeWidth="1.8"
                        strokeLinecap="round"
                        strokeLinejoin="round"
                        aria-hidden="true"
                      >
                        <path d="M2.5 12C3.8 7.7 7.4 5 12 5C16.6 5 20.2 7.7 21.5 12C20.2 16.3 16.6 19 12 19C7.4 19 3.8 16.3 2.5 12Z" />
                        <circle cx="12" cy="12" r="3" />
                      </svg>
                    )}
                  </button>
                </div>
              </label>

              {loginError && (
                <div className="form-error">
                  <span>!</span>
                  {loginError}
                </div>
              )}

              <button
                className="primary-button login-button"
                disabled={loading}
              >
                {loading ? "Signing in..." : "Sign in"}
              </button>
            </form>
          </div>
        </div>

        <div className="login-showcase">
          <div className="showcase-grid" />

          <div className="showcase-content">
            <span className="showcase-kicker">
              WEB SECURITY PLATFORM
            </span>

            <h2 className="showcase-title">
              See Your Security Gaps.
              <span>Fix Them Before Attackers Do.</span>
            </h2>

            <p className="showcase-copy">
              Discover what’s exposed, identify security weaknesses, and turn findings into clear insights.
            </p>

            <div className="showcase-visual">
              <div className="showcase-ring ring-one" />
              <div className="showcase-ring ring-two" />

              <div className="showcase-shield">
                <svg
                  viewBox="0 0 32 32"
                  xmlns="http://www.w3.org/2000/svg"
                  aria-hidden="true"
                >
                  <path
                    d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
                    fill="#22D3EE"
                    clipPath="inset(0 50% 0 0)"
                  />

                  <path
                    d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
                    fill="none"
                    stroke="#22D3EE"
                    strokeWidth="3.5"
                    strokeLinejoin="round"
                  />
                </svg>
              </div>

              <div className="scan-beam" />
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div>
          <div className="sidebar-brand">
  <div className="brand-mark small">
    <svg
      viewBox="0 0 32 32"
      xmlns="http://www.w3.org/2000/svg"
      aria-hidden="true"
    >
      <path
        d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
        fill="#22D3EE"
        clipPath="inset(0 50% 0 0)"
      />
      <path
        d="M16 3L27 7.5V14C27 21.2 22.8 26.5 16 29C9.2 26.5 5 21.2 5 14V7.5L16 3Z"
        fill="none"
        stroke="#22D3EE"
        strokeWidth="3.5"
        strokeLinejoin="round"
      />
    </svg>
  </div>

  <div>
    <div className="brand-name">BlindSpot</div>
    <div className="brand-subtitle">
      Website Vulnerability Scanner
    </div>
  </div>
</div>

          <div className="sidebar-section-label">
            WORKSPACE
          </div>

          <nav className="sidebar-nav">
            <NavButton
              active={page === "dashboard"}
              onClick={() => setPage("dashboard")}
              icon="⌂"
              label="Overview"
            />

            <NavButton
              active={page === "new-scan"}
              onClick={() => setPage("new-scan")}
              icon="+"
              label="New Scan"
            />

            <NavButton
              active={page === "scans"}
              onClick={() => setPage("scans")}
              icon="◫"
              label="Scan History"
            />

            <NavButton
              active={page === "rules"}
              onClick={() => setPage("rules")}
              icon="◇"
              label="Detection Rules"
            />
          </nav>

          <div className="sidebar-section-label second">
            ANALYSIS
          </div>

          <nav className="sidebar-nav">
            <NavButton
              active={page === "report"}
              onClick={() =>
                selectedScan && setPage("report")
              }
              disabled={!selectedScan}
              icon="▤"
              label="Report"
            />
          </nav>
        </div>

        <div className="sidebar-bottom">
          <div className="backend-status">
            <span className="status-dot" />

            <div>
              <strong>API Online</strong>
              <span>127.0.0.1:8000</span>
            </div>
          </div>

          <div className="user-box">
            <div className="avatar">
              {user.charAt(0).toUpperCase()}
            </div>

            <div className="user-details">
              <strong>{user}</strong>
              <span>Administrator</span>
            </div>

            <button
              className="logout-button"
              onClick={logout}
            >
              ↪
            </button>
          </div>
        </div>
      </aside>

      <main className="main-content">
        {page === "dashboard" && (
          <Dashboard
            stats={stats}
            scans={scans}
            onNewScan={() => setPage("new-scan")}
            onOpenScan={openScan}
            riskGrade={riskGrade}
          />
        )}

        {page === "new-scan" && (
          <NewScanPage
            form={scanForm}
            setForm={setScanForm}
            onSubmit={startScan}
            loading={loading}
            progress={scanProgress}
          />
        )}

        {page === "scans" && (
          <ScansPage
            scans={scans}
            onOpen={openScan}
            onDelete={deleteScan}
            onRefresh={loadScans}
          />
        )}

        {page === "rules" && (
          <RulesPage
            rules={rules}
            onReload={reloadRules}
            onRefresh={loadRules}
          />
        )}

        {page === "report" && (
          <ReportPage
            report={report}
            findings={findings}
            findingFilter={findingFilter}
            setFindingFilter={setFindingFilter}
            severityCounts={severityCounts}
            riskScore={riskScore}
            riskGrade={riskGrade}
            onExport={exportReport}
            onAIReport={downloadAIReport}
            scanId={selectedScan}
          />
        )}
      </main>

      {toast && <div className="toast">{toast}</div>}
    </div>
  );
}

function NavButton({
  active,
  onClick,
  icon,
  label,
  disabled,
}) {
  return (
    <button
      className={`nav-button ${active ? "active" : ""}`}
      onClick={onClick}
      disabled={disabled}
    >
      <span className="nav-icon">{icon}</span>
      <span>{label}</span>
    </button>
  );
}

function Dashboard({
  stats,
  scans,
  onNewScan,
  onOpenScan,
  riskGrade,
}) {
  const totalScans = stats?.total_scans ?? scans.length ?? 0;
  const completed = stats?.completed_scans ?? 0;
  const running = stats?.running_scans ?? 0;
  const averageRisk = stats?.average_risk_score ?? 0;

  return (
    <div className="page">
      <PageHeader
        eyebrow="SECURITY OVERVIEW"
        title="Overview"
        description="Monitor your web security posture from one place."
        action={
          <button
            className="primary-button"
            onClick={onNewScan}
          >
            <span>+</span>
            New scan
          </button>
        }
      />

      <div className="hero-grid">
        <div className="hero-card">
          <div>
            <span className="eyebrow">
              SECURITY POSTURE
            </span>

            <h2>Know what attackers can see.</h2>

            <p>
              BlindSpot continuously maps exposed surfaces, security
              headers, application behavior and vulnerability signals.
            </p>
          </div>

          <div className="hero-line">
            <span />
            <span />
            <span />
            <span />
            <span />
          </div>

          <div className="hero-meta">
            <span>
              <i className="status-dot" />
              Scanner operational
            </span>

            <span>Passive-first detection</span>
          </div>
        </div>

        <div className="posture-card">
          <div className="card-topline">
            <span className="eyebrow">AVG. RISK</span>

            <span className={`risk-grade ${riskGrade}`}>
              {riskGrade}
            </span>
          </div>

          <div className="mini-risk">
            <div
              className="mini-risk-fill"
              style={{
                width: `${Math.min(
                  Number(averageRisk) || 0,
                  100
                )}%`,
              }}
            />
          </div>

          <div className="posture-score">
            <strong>{averageRisk}</strong>
            <span>/100</span>
          </div>

          <p>
            Average risk score across completed scans
          </p>
        </div>
      </div>

      <div className="metrics-grid">
        <MetricCard
          label="Total scans"
          value={totalScans}
          icon="◫"
          accent="blue"
        />

        <MetricCard
          label="Completed"
          value={completed}
          icon="✓"
          accent="green"
        />

        <MetricCard
          label="Running"
          value={running}
          icon="◌"
          accent="orange"
        />

        <MetricCard
          label="Detection rules"
          value="1163"
          icon="◇"
          accent="purple"
        />
      </div>

      <div className="section-card">
        <div className="section-header">
          <div>
            <span className="eyebrow">ACTIVITY</span>
            <h3>Recent scans</h3>
          </div>

          <button
            className="ghost-button"
            onClick={() =>
              window.scrollTo({
                top: 0,
                behavior: "smooth",
              })
            }
          >
            View overview
          </button>
        </div>

        <ScanTable
          scans={scans.slice(0, 6)}
          onOpen={onOpenScan}
          compact
        />
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon,
  accent,
}) {
  return (
    <div className="metric-card">
      <div className={`metric-icon ${accent}`}>
        {icon}
      </div>

      <div>
        <span>{label}</span>
        <strong>{value}</strong>
      </div>
    </div>
  );
}

function NewScanPage({
  form,
  setForm,
  onSubmit,
  loading,
  progress,
}) {
  const update = (key, value) => {
    setForm((current) => ({
      ...current,
      [key]: value,
    }));
  };

  return (
    <div className="page narrow-page">
      <PageHeader
        eyebrow="ATTACK SURFACE"
        title="New scan"
        description="Run a controlled security assessment against an authorized target."
      />

      <form className="scan-form" onSubmit={onSubmit}>
        <div className="form-card">
          <div className="form-card-heading">
            <div>
              <span className="eyebrow">TARGET</span>
              <h3>Scan configuration</h3>
            </div>

            <span className="secure-label">
              AUTHORIZED ONLY
            </span>
          </div>

          <label className="large-label">
            Target URL

            <input
              value={form.target}
              onChange={(event) =>
                update("target", event.target.value)
              }
              placeholder="https://example.com"
            />
          </label>

          <div className="scan-options">
            <OptionToggle
              checked={form.deep_scan}
              onChange={(value) =>
                update("deep_scan", value)
              }
              title="Deep scan"
              description="Discover common paths and deeper application surfaces."
            />

            <OptionToggle
              checked={form.security_headers}
              onChange={(value) =>
                update("security_headers", value)
              }
              title="Security headers"
              description="Inspect HTTP security headers and policy configuration."
            />

            <OptionToggle
              checked={form.tls}
              onChange={(value) =>
                update("tls", value)
              }
              title="TLS analysis"
              description="Inspect TLS configuration and certificate signals."
            />
          </div>
        </div>

        <div className="form-card">
          <div className="form-card-heading">
            <div>
              <span className="eyebrow">
                SCAN MODE
              </span>

              <h3>Detection intensity</h3>
            </div>
          </div>

          <div className="mode-grid">
            {[
              [
                "passive",
                "Passive",
                "Low impact. Analyze responses, headers, cookies and discovered surfaces.",
              ],
              [
                "light_active",
                "Light active",
                "Adds controlled active checks with limited request intensity.",
              ],
              [
                "full_active",
                "Full active",
                "Broader active probing. Use only with explicit authorization.",
              ],
            ].map(([value, title, description]) => (
              <button
                type="button"
                key={value}
                className={`mode-card ${
                  form.scan_mode === value
                    ? "selected"
                    : ""
                }`}
                onClick={() =>
                  update("scan_mode", value)
                }
              >
                <span className="mode-radio">
                  {form.scan_mode === value
                    ? "●"
                    : "○"}
                </span>

                <strong>{title}</strong>
                <p>{description}</p>
              </button>
            ))}
          </div>

          {form.scan_mode !== "passive" && (
            <div className="warning-box">
              <span>!</span>
              Active scanning can generate additional requests. Only scan
              systems you own or have explicit permission to test.
            </div>
          )}
        </div>

        <div className="form-card">
          <div className="form-card-heading">
            <div>
              <span className="eyebrow">
                ADVANCED
              </span>

              <h3>Optional controls</h3>
            </div>
          </div>

          <div className="two-column">
            <label>
              Rate limit

              <input
                value={form.rate_limit}
                onChange={(event) =>
                  update(
                    "rate_limit",
                    event.target.value
                  )
                }
                placeholder="Requests / second"
                type="number"
                min="0"
              />
            </label>

            <label>
              Session cookies

              <input
                value={form.session_cookies}
                onChange={(event) =>
                  update(
                    "session_cookies",
                    event.target.value
                  )
                }
                placeholder="name=value; name2=value2"
              />
            </label>
          </div>

          <label>
            Custom headers

            <textarea
              value={form.custom_headers}
              onChange={(event) =>
                update(
                  "custom_headers",
                  event.target.value
                )
              }
              placeholder={'{"X-Custom-Header":"value"}'}
              rows="4"
            />
          </label>
        </div>

        <div className="authorization-box">
          <label className="checkbox-row">
            <input
              type="checkbox"
              checked={form.authorized}
              onChange={(event) =>
                update(
                  "authorized",
                  event.target.checked
                )
              }
            />

            <span className="custom-checkbox" />

            <span>
              <strong>
                I confirm that I am authorized to scan this target.
              </strong>

              <small>
                BlindSpot should only be used against systems you own or
                have explicit permission to assess.
              </small>
            </span>
          </label>
        </div>

        <button
          type="submit"
          className="primary-button scan-submit"
          disabled={loading}
        >
          {loading
            ? "Starting scan..."
            : "Start security scan"}

          {!loading && <span>→</span>}
        </button>
      </form>

      {progress && (
        <div className="progress-card">
          <div className="progress-heading">
            <div>
              <span className="eyebrow">
                LIVE SCAN
              </span>

              <h3>{progress.status}</h3>
            </div>

            <strong>
              {Math.round(progress.progress)}%
            </strong>
          </div>

          <div className="progress-track">
            <div
              className="progress-fill"
              style={{
                width: `${progress.progress}%`,
              }}
            />
          </div>

          <div className="progress-meta">
            <span>Scan ID</span>

            <code>
              {progress.scan_id || "Preparing..."}
            </code>
          </div>
        </div>
      )}
    </div>
  );
}

function OptionToggle({
  checked,
  onChange,
  title,
  description,
}) {
  return (
    <button
      type="button"
      className={`option-toggle ${
        checked ? "checked" : ""
      }`}
      onClick={() => onChange(!checked)}
    >
      <span className="toggle">
        <span />
      </span>

      <span>
        <strong>{title}</strong>
        <small>{description}</small>
      </span>
    </button>
  );
}

function ScansPage({
  scans,
  onOpen,
  onDelete,
  onRefresh,
}) {
  return (
    <div className="page">
      <PageHeader
        eyebrow="HISTORY"
        title="Scan history"
        description="Review previously completed and running security assessments."
        action={
          <button
            className="ghost-button"
            onClick={onRefresh}
          >
            ↻ Refresh
          </button>
        }
      />

      <div className="section-card">
        <ScanTable
          scans={scans}
          onOpen={onOpen}
          onDelete={onDelete}
        />
      </div>
    </div>
  );
}

function ScanTable({
  scans,
  onOpen,
  onDelete,
  compact = false,
}) {
  if (!scans.length) {
    return (
      <div className="empty-state">
        <div className="empty-icon">◫</div>

        <h3>No scans yet</h3>

        <p>
          Start your first BlindSpot security assessment.
        </p>
      </div>
    );
  }

  return (
    <div className="table-wrap">
      <table className="scan-table">
        <thead>
          <tr>
            <th>Target</th>
            <th>Status</th>
            <th>Risk</th>
            <th>Findings</th>
            <th>Date</th>

            {!compact && <th />}
          </tr>
        </thead>

        <tbody>
          {scans.map((scan) => {
            const id = scan.scan_id || scan.id;
            const risk =
              scan.risk_score ??
              scan.risk ??
              "—";

            const findings =
              scan.findings_count ??
              scan.total_findings ??
              scan.findings?.length ??
              "—";

            return (
              <tr key={id}>
                <td>
                  <button
                    className="target-button"
                    onClick={() => onOpen(id)}
                  >
                    <span className="target-icon">
                      ↗
                    </span>

                    <span>
                      <strong>
                        {scan.target ||
                          scan.url ||
                          "Unknown target"}
                      </strong>

                      <small>{id}</small>
                    </span>
                  </button>
                </td>

                <td>
                  <StatusBadge status={scan.status} />
                </td>

                <td>
                  <strong className="table-risk">
                    {risk}
                  </strong>
                </td>

                <td>{findings}</td>

                <td className="muted-cell">
                  {formatDate(
                    scan.created_at ||
                      scan.timestamp ||
                      scan.date
                  )}
                </td>

                {!compact && (
                  <td>
                    <div className="table-actions">
                      <button
                        className="small-action"
                        onClick={() => onOpen(id)}
                      >
                        View
                      </button>

                      {onDelete && (
                        <button
                          className="small-action danger"
                          onClick={() => onDelete(id)}
                        >
                          Delete
                        </button>
                      )}
                    </div>
                  </td>
                )}
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function StatusBadge({ status }) {
  const normalized = String(
    status || "unknown"
  ).toLowerCase();

  return (
    <span className={`status-badge ${normalized}`}>
      <span />
      {normalized}
    </span>
  );
}

function RulesPage({
  rules,
  onReload,
  onRefresh,
}) {
  return (
    <div className="page">
      <PageHeader
        eyebrow="DETECTION ENGINE"
        title="Detection rules"
        description="Inspect the rule set powering BlindSpot's vulnerability detection."
        action={
          <div className="header-actions">
            <button
              className="ghost-button"
              onClick={onRefresh}
            >
              ↻ Refresh
            </button>

            <button
              className="primary-button"
              onClick={onReload}
            >
              Reload rules
            </button>
          </div>
        }
      />

      <div className="rule-summary">
        <div>
          <span className="eyebrow">
            LOADED RULES
          </span>

          <strong>{rules.length || 1163}</strong>

          <p>
            Detection signatures currently available.
          </p>
        </div>

        <div className="rule-engine-status">
          <span className="status-dot" />
          Rule engine ready
        </div>
      </div>

      <div className="section-card">
        {!rules.length ? (
          <div className="empty-state">
            <div className="empty-icon">◇</div>

            <h3>Rule details unavailable</h3>

            <p>
              The backend did not return individual rules. The scanner
              reports 1163 loaded rules.
            </p>
          </div>
        ) : (
          <div className="rules-grid">
            {rules.slice(0, 120).map((rule, index) => (
              <div
                className="rule-card"
                key={
                  rule.id ||
                  rule.rule_id ||
                  index
                }
              >
                <div className="rule-card-top">
                  <span>
                    {rule.id ||
                      rule.rule_id ||
                      `RULE-${index + 1}`}
                  </span>

                  <span
                    className={`severity-dot ${String(
                      rule.severity || "info"
                    ).toLowerCase()}`}
                  />
                </div>

                <strong>
                  {rule.name ||
                    rule.title ||
                    "Detection rule"}
                </strong>

                <p>
                  {rule.description ||
                    rule.category ||
                    rule.owasp ||
                    "BlindSpot detection signature"}
                </p>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function ReportPage({
  report,
  findings,
  findingFilter,
  setFindingFilter,
  severityCounts,
  riskScore,
  riskGrade,
  onExport,
  onAIReport,
  scanId,
}) {
  if (!report) {
    return (
      <div className="page">
        <PageHeader
          eyebrow="ANALYSIS"
          title="Report"
          description="Run a scan and open its report to see findings."
        />

        <div className="empty-state large">
          <div className="empty-icon">▤</div>

          <h3>No report selected</h3>

          <p>
            Select a completed scan from Scan History.
          </p>
        </div>
      </div>
    );
  }

  const totalFindings =
    report.total_findings ??
    report.summary?.total_findings ??
    Object.values(severityCounts).reduce(
      (a, b) => a + b,
      0
    );

  const owasp =
    report.owasp ??
    report.owasp_coverage ??
    report.summary?.owasp_coverage ??
    {};

  const activeProbes =
    report.active_probes ??
    report.active_probe_results ??
    report.summary?.active_probes ??
    [];

  return (
    <div className="page">
      <PageHeader
        eyebrow="SECURITY REPORT"
        title="Scan report"
        description={
          report.target ||
          report.url ||
          "Security assessment results"
        }
        action={
          <div className="header-actions">
            <button
              className="ghost-button"
              onClick={() => onExport("json")}
            >
              Export JSON
            </button>

            <button
              className="ghost-button"
              onClick={() => onExport("html")}
            >
              Export HTML
            </button>

            <button
              className="primary-button"
              onClick={onAIReport}
            >
              AI security report
            </button>
          </div>
        }
      />

      <div className="report-overview">
        <div className="risk-card">
          <div
            className="risk-ring"
            style={ringStyle(riskScore)}
          >
            <div className="risk-ring-inner">
              <strong>{riskScore}</strong>
              <span>/100</span>
            </div>
          </div>

          <div>
            <span className="eyebrow">
              OVERALL RISK
            </span>

            <h2>{riskGrade}</h2>

            <p>
              Risk score is calculated from finding severity and
              security posture signals.
            </p>
          </div>
        </div>

        <div className="finding-metrics">
          <FindingMetric
            label="Critical"
            value={severityCounts.critical}
            severity="critical"
          />

          <FindingMetric
            label="High"
            value={severityCounts.high}
            severity="high"
          />

          <FindingMetric
            label="Medium"
            value={severityCounts.medium}
            severity="medium"
          />

          <FindingMetric
            label="Low"
            value={severityCounts.low}
            severity="low"
          />

          <FindingMetric
            label="Total"
            value={totalFindings}
            severity="info"
          />
        </div>
      </div>

      <div className="report-grid">
        <div className="section-card">
          <div className="section-header">
            <div>
              <span className="eyebrow">
                VULNERABILITIES
              </span>

              <h3>
                Findings{" "}
                <span>({findings.length})</span>
              </h3>
            </div>

            <select
              className="filter-select"
              value={findingFilter}
              onChange={(event) =>
                setFindingFilter(
                  event.target.value
                )
              }
            >
              <option value="all">
                All severities
              </option>

              <option value="critical">
                Critical
              </option>

              <option value="high">
                High
              </option>

              <option value="medium">
                Medium
              </option>

              <option value="low">
                Low
              </option>

              <option value="info">
                Info
              </option>
            </select>
          </div>

          <div className="findings-list">
            {findings.length ? (
              findings.map((finding, index) => (
                <FindingRow
                  finding={finding}
                  key={finding.id || index}
                />
              ))
            ) : (
              <div className="empty-state compact">
                <h3>
                  No findings in this filter
                </h3>
              </div>
            )}
          </div>
        </div>

        <div className="side-report">
          <div className="section-card">
            <div className="section-header">
              <div>
                <span className="eyebrow">
                  OWASP
                </span>

                <h3>Coverage</h3>
              </div>
            </div>

            <OwaspChart data={owasp} />
          </div>

          <div className="section-card">
            <div className="section-header">
              <div>
                <span className="eyebrow">
                  ACTIVE CHECKS
                </span>

                <h3>Probe results</h3>
              </div>
            </div>

            <ProbeList probes={activeProbes} />
          </div>
        </div>
      </div>

      <div className="report-footer-meta">
        <span>Scan ID</span>
        <code>{scanId}</code>
      </div>
    </div>
  );
}

function FindingMetric({
  label,
  value,
  severity,
}) {
  return (
    <div className={`finding-metric ${severity}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function FindingRow({ finding }) {
  const severity = String(
    finding.severity || "info"
  ).toLowerCase();

  return (
    <details className="finding-row">
      <summary>
        <span className={`severity-pill ${severity}`}>
          {severity}
        </span>

        <span className="finding-main">
          <strong>
            {finding.title ||
              finding.name ||
              finding.rule_name ||
              "Security finding"}
          </strong>

          <small>
            {finding.url ||
              finding.endpoint ||
              finding.path ||
              finding.category ||
              "Detected security issue"}
          </small>
        </span>

        <span className="finding-arrow">
          +
        </span>
      </summary>

      <div className="finding-details">
        {finding.description && (
          <div>
            <span>Description</span>
            <p>{finding.description}</p>
          </div>
        )}

        {finding.evidence && (
          <div>
            <span>Evidence</span>
            <pre>
              {String(finding.evidence)}
            </pre>
          </div>
        )}

        {finding.recommendation && (
          <div>
            <span>Recommendation</span>
            <p>{finding.recommendation}</p>
          </div>
        )}

        <div className="finding-tags">
          {finding.owasp && (
            <span>
              OWASP: {finding.owasp}
            </span>
          )}

          {finding.cve && (
            <span>
              CVE: {finding.cve}
            </span>
          )}

          {finding.cvss != null && (
            <span>
              CVSS: {finding.cvss}
            </span>
          )}
        </div>
      </div>
    </details>
  );
}

function OwaspChart({ data }) {
  const entries = Object.entries(
    data || {}
  ).slice(0, 10);

  if (!entries.length) {
    return (
      <div className="mini-empty">
        OWASP mapping data was not included in this report.
      </div>
    );
  }

  const max = Math.max(
    ...entries.map(
      ([, value]) => Number(value) || 0
    ),
    1
  );

  return (
    <div className="owasp-chart">
      {entries.map(([name, value]) => (
        <div
          className="owasp-row"
          key={name}
        >
          <span>{name}</span>

          <div className="owasp-bar">
            <div
              style={{
                width: `${
                  ((Number(value) || 0) / max) *
                  100
                }%`,
              }}
            />
          </div>

          <strong>{value}</strong>
        </div>
      ))}
    </div>
  );
}

function ProbeList({ probes }) {
  if (!Array.isArray(probes) || !probes.length) {
    return (
      <div className="mini-empty">
        No active probe results were recorded.
      </div>
    );
  }

  return (
    <div className="probe-list">
      {probes.slice(0, 12).map(
        (probe, index) => (
          <div
            className="probe-row"
            key={probe.name || index}
          >
            <span className="probe-status">
              {probe.success === false ||
              probe.finding
                ? "!"
                : "✓"}
            </span>

            <div>
              <strong>
                {probe.name ||
                  probe.probe ||
                  `Probe ${index + 1}`}
              </strong>

              <small>
                {probe.message ||
                  probe.status ||
                  (probe.finding
                    ? "Finding detected"
                    : "No issue detected")}
              </small>
            </div>
          </div>
        )
      )}
    </div>
  );
}

function PageHeader({
  eyebrow,
  title,
  description,
  action,
}) {
  return (
    <header className="page-header">
      <div>
        <span className="eyebrow">
          {eyebrow}
        </span>

        <h1>{title}</h1>

        <p>{description}</p>
      </div>

      {action && (
        <div className="page-header-action">
          {action}
        </div>
      )}
    </header>
  );
}

function getRiskGrade(score) {
  if (score >= 90) return "F";
  if (score >= 80) return "E";
  if (score >= 70) return "D";
  if (score >= 60) return "C";
  if (score >= 40) return "B";
  return "A";
}

function ringStyle(score) {
  const value = Math.max(
    0,
    Math.min(Number(score) || 0, 100)
  );

  return {
    background: `conic-gradient(var(--accent) ${
      value * 3.6
    }deg, var(--surface-3) 0deg)`,
  };
}

function formatDate(value) {
  if (!value) return "—";

  const date = new Date(value);

  if (Number.isNaN(date.getTime())) {
    return String(value);
  }

  return date.toLocaleString([], {
    year: "numeric",
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default App;