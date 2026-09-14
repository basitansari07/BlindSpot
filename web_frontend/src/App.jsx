import React, { useEffect, useMemo, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000/api";

const severityOrder = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
  informational: 4,
};

const severityClass = (severity = "info") =>
  String(severity).toLowerCase();

const sortFindings = (items = []) =>
  [...items].sort((a, b) => {
    const sa = severityOrder[severityClass(a.severity)] ?? 99;
    const sb = severityOrder[severityClass(b.severity)] ?? 99;

    if (sa !== sb) return sa - sb;

    return String(a.title || "").localeCompare(
      String(b.title || "")
    );
  });

function App() {
  const [token, setToken] = useState(
    () => localStorage.getItem("blindspot_token") || ""
  );

  const [user, setUser] = useState(() => {
    try {
      return JSON.parse(
        localStorage.getItem("blindspot_user") || "null"
      );
    } catch {
      return null;
    }
  });

  const [page, setPage] = useState("overview");

  const [loading, setLoading] = useState(true);
  const [loginLoading, setLoginLoading] = useState(false);
  const [loginError, setLoginError] = useState("");

  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);

  const [stats, setStats] = useState({});
  const [scans, setScans] = useState([]);
  const [rules, setRules] = useState([]);

  const [selectedScan, setSelectedScan] = useState(null);
  const [report, setReport] = useState(null);

  const [findingFilter, setFindingFilter] = useState("all");
  const [showLogoutConfirm, setShowLogoutConfirm] = useState(false);

  const [scanForm, setScanForm] = useState({
    url: "https://www.example.com",
    deep_scan: false,
    security_headers: true,
    tls_analysis: true,
    scan_mode: "full_active",
    custom_headers: "",
  });

  const [scanProgress, setScanProgress] = useState(null);
  const [toast, setToast] = useState("");

  /* =====================================================
     API
     ===================================================== */

  async function api(path, options = {}) {
    const headers = {
      ...(options.headers || {}),
    };

    if (token) {
      headers.Authorization = "Bearer " + token;
    }

    if (options.body && !headers["Content-Type"]) {
      headers["Content-Type"] = "application/json";
    }

    const response = await fetch(API_BASE + path, {
      ...options,
      headers,
    });

    let data = null;

    try {
      data = await response.json();
    } catch {
      data = null;
    }

    if (!response.ok) {
      const message =
        data?.detail ||
        data?.message ||
        "Request failed (" + response.status + ")";

      throw new Error(message);
    }

    return data;
  }

  /* =====================================================
     AUTH
     ===================================================== */

  async function login(event) {
    event?.preventDefault();

    setLoginError("");
    setLoginLoading(true);

    try {
      const result = await fetch(API_BASE + "/auth/login", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          username,
          password,
        }),
      });

      const data = await result.json();

      if (!result.ok) {
        throw new Error(
          data?.detail ||
            data?.message ||
            "Invalid username or password"
        );
      }

      const newToken =
        data.token || data.access_token;

      if (!newToken) {
        throw new Error(
          "Authentication token was not returned."
        );
      }

      const loggedUser = data.user || {
        username,
        role: "admin",
      };

      localStorage.setItem(
        "blindspot_token",
        newToken
      );

      localStorage.setItem(
        "blindspot_user",
        JSON.stringify(loggedUser)
      );

      setToken(newToken);
      setUser(loggedUser);
      setPage("overview");
      setPassword("");
    } catch (error) {
      setLoginError(error.message);
    } finally {
      setLoginLoading(false);
    }
  }

  async function logout() {
    try {
      if (token) {
        await api("/auth/logout", {
          method: "POST",
        });
      }
    } catch {
      // Continue logout even if backend logout fails.
    }

    localStorage.removeItem("blindspot_token");
    localStorage.removeItem("blindspot_user");

    setToken("");
    setUser(null);
    setStats({});
    setScans([]);
    setRules([]);
    setSelectedScan(null);
    setReport(null);
  }

  /* =====================================================
     DASHBOARD DATA
     ===================================================== */

  async function loadDashboard() {
    if (!token) return;

    try {
      const [statsData, scansData] =
        await Promise.all([
          api("/stats"),
          api("/scans"),
        ]);

      setStats(statsData || {});

      const scanList =
        scansData?.scans ||
        scansData?.items ||
        (Array.isArray(scansData)
          ? scansData
          : []);

      setScans(scanList);
    } catch (error) {
      console.error(
        "Dashboard load failed:",
        error
      );
    }
  }

  async function loadScans() {
    if (!token) return;

    try {
      const data = await api("/scans");

      const scanList =
        data?.scans ||
        data?.items ||
        (Array.isArray(data)
          ? data
          : []);

      setScans(scanList);
    } catch (error) {
      console.error(
        "Scans load failed:",
        error
      );
    }
  }

  async function loadRules() {
    if (!token) return;

    try {
      const data = await api("/rules");

      const ruleList =
        data?.rules ||
        data?.items ||
        (Array.isArray(data)
          ? data
          : []);

      setRules(ruleList);
    } catch (error) {
      console.error(
        "Rules load failed:",
        error
      );
    }
  }

  async function reloadRules() {
    try {
      await api("/rules/reload", {
        method: "POST",
      });

      showToast(
        "Detection rules reloaded."
      );

      await loadRules();
      await loadDashboard();
    } catch (error) {
      showToast(error.message);
    }
  }

  /* =====================================================
     EFFECTS
     ===================================================== */

  useEffect(() => {
    if (!token) {
      setLoading(false);
      return;
    }

    async function initialLoad() {
      setLoading(true);

      await Promise.all([
        loadDashboard(),
        page === "rules"
          ? loadRules()
          : Promise.resolve(),
      ]);

      setLoading(false);
    }

    initialLoad();
  }, [token]);

  useEffect(() => {
    if (!token) return;

    if (
      page === "overview" ||
      page === "scans"
    ) {
      loadDashboard();
    }

    if (page === "rules") {
      loadRules();
    }
  }, [page]);

  /* =====================================================
     TOAST
     ===================================================== */

  function showToast(message) {
    setToast(message);

    window.setTimeout(() => {
      setToast("");
    }, 3500);
  }

  /* =====================================================
     START SCAN
     ===================================================== */

  async function startScan(event) {
    event?.preventDefault();

    const rawUrl =
      scanForm.url.trim();

    if (!rawUrl) {
      showToast("Enter a target URL.");
      return;
    }

    let targetUrl = rawUrl;

    if (
      !/^https?:\/\//i.test(targetUrl)
    ) {
      targetUrl =
        "https://" + targetUrl;
    }

    let customHeaders = {};

    if (
      scanForm.custom_headers.trim()
    ) {
      try {
        customHeaders = JSON.parse(
          scanForm.custom_headers
        );
      } catch {
        showToast(
          "Custom headers must be valid JSON."
        );
        return;
      }
    }

    try {
      setScanProgress({
        percent: 5,
        status: "Starting scan...",
        scanId: null,
      });

      const result = await api("/scan", {
        method: "POST",
        body: JSON.stringify({
          url: targetUrl,
          authorized: true,
          scan_mode:
            scanForm.scan_mode,
          deep_scan:
            scanForm.deep_scan,
          security_headers:
            scanForm.security_headers,
          tls_analysis:
            scanForm.tls_analysis,
          custom_headers:
            customHeaders,
        }),
      });

      const scanId =
        result?.scan_id ||
        result?.id ||
        result?.scan?.id;

      if (!scanId) {
        throw new Error(
          "Backend did not return a scan ID."
        );
      }

      setScanProgress({
        percent: 10,
        status: "Scan running...",
        scanId,
      });

      await pollScan(scanId);
    } catch (error) {
      setScanProgress(null);
      showToast(error.message);
    }
  }

  async function pollScan(scanId) {
    const startedAt = Date.now();

    while (true) {
      const statusResponse = await api(
        "/scan/" + scanId
      );

      const status =
        statusResponse?.scan ||
        statusResponse?.data ||
        statusResponse?.result ||
        statusResponse ||
        {};

      const currentStatus =
        String(
          status?.status ||
          status?.scan_status ||
          status?.state ||
          status?.phase ||
          statusResponse?.status ||
          ""
        )
          .trim()
          .toLowerCase();

      const progressValue = Number(
        status?.progress ??
        status?.percentage ??
        statusResponse?.progress ??
        statusResponse?.percentage ??
        0
      );

      const elapsed = Date.now() - startedAt;

      let calculatedProgress = progressValue;

      if (!calculatedProgress) {
        calculatedProgress = Math.min(
          95,
          15 + elapsed / 1000
        );
      }

      if (
        currentStatus === "completed" ||
        currentStatus === "complete" ||
        currentStatus === "finished" ||
        currentStatus === "done" ||
        status?.completed === true ||
        statusResponse?.completed === true
      ) {
        setScanProgress({
          percent: 100,
          status: "Scan completed.",
          scanId,
        });

        await Promise.all([
          loadDashboard(),
          openScan(scanId),
        ]);

        window.setTimeout(() => {
          setScanProgress(null);
        }, 800);

        return;
      }

      if (
        currentStatus === "failed" ||
        currentStatus === "error"
      ) {
        throw new Error(
          status?.error ||
          statusResponse?.error ||
          status?.message ||
          statusResponse?.message ||
          "Scan failed."
        );
      }

      setScanProgress({
        percent: Math.round(
          Math.min(99, calculatedProgress)
        ),
        status:
          status?.message ||
          statusResponse?.message ||
          "",
        scanId,
      });

      await new Promise((resolve) =>
        setTimeout(resolve, 500)
      );
    }
  }

  /* =====================================================
     OPEN SCAN / REPORT
     ===================================================== */

  async function openScan(scanId) {
    try {
      const [
        reportResponse,
        scanResponse,
      ] = await Promise.all([
        api(
          "/scan/" +
            scanId +
            "/report"
        ),
        api("/scan/" + scanId),
      ]);

      const scanData =
        scanResponse?.scan ||
        scanResponse?.data ||
        scanResponse?.result ||
        scanResponse ||
        {};

      const reportData =
        reportResponse?.report ||
        reportResponse?.data ||
        reportResponse?.result ||
        reportResponse ||
        {};

      const mergedReport = {
        ...reportData,
      };

      const reportFindings =
        reportData?.findings ||
        reportData?.results ||
        reportData?.vulnerabilities ||
        reportData?.issues;

      const scanFindings =
        scanData?.findings ||
        scanData?.results ||
        scanData?.vulnerabilities ||
        scanData?.issues;

      if (
        Array.isArray(reportFindings)
      ) {
        mergedReport.findings =
          reportFindings;
      } else if (
        Array.isArray(scanFindings)
      ) {
        mergedReport.findings =
          scanFindings;
      }

      const activeProbes =
        reportData?.active_probes_log ||
        scanData?.active_probes_log ||
        reportData?.active_probes ||
        scanData?.active_probes;

      if (
        Array.isArray(activeProbes)
      ) {
        mergedReport.active_probes_log =
          activeProbes;
      }

      const selected = {
        ...scanData,
        id:
          scanData?.id ||
          scanData?.scan_id ||
          scanData?.uuid ||
          scanId,
        scan_id:
          scanData?.scan_id ||
          scanData?.id ||
          scanData?.uuid ||
          scanId,
        url:
          scanData?.url ||
          scanData?.target_url ||
          scanData?.target ||
          reportData?.url ||
          reportData?.target_url,
        risk_score:
          scanData?.risk_score ??
          scanData?.risk ??
          scanData?.score ??
          reportData?.risk_score ??
          reportData?.risk ??
          reportData?.score,
      };

      setSelectedScan(selected);
      setReport(mergedReport);
      setPage("report");
      setFindingFilter("all");
    } catch (error) {
      showToast(error.message);
    }
  }

  async function deleteScan(scanId) {
    if (!scanId) return;

    try {
      await api(
        "/scan/" + scanId,
        {
          method: "DELETE",
        }
      );

      showToast("Scan deleted.");

      setSelectedScan(null);
      setReport(null);

      await loadDashboard();
    } catch (error) {
      showToast(error.message);
    }
  }

  async function exportReport(scanId) {
    try {
      const response =
        await fetch(
          API_BASE +
            "/scan/" +
            scanId +
            "/export",
          {
            headers: {
              Authorization:
                "Bearer " + token,
            },
          }
        );

      if (!response.ok) {
        throw new Error(
          "Export failed (" +
            response.status +
            ")"
        );
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(
          blob
        );

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        "blindspot-" +
        scanId +
        ".json";

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);

      showToast(
        "Report exported."
      );
    } catch (error) {
      showToast(error.message);
    }
  }

  async function downloadAIReport(
    scanId
  ) {
    try {
      const response =
        await fetch(
          API_BASE +
            "/scan/" +
            scanId +
            "/ai-report",
          {
            headers: {
              Authorization:
                "Bearer " + token,
            },
          }
        );

      if (!response.ok) {
        throw new Error(
          "AI report failed (" +
            response.status +
            ")"
        );
      }

      const blob =
        await response.blob();

      const url =
        window.URL.createObjectURL(
          blob
        );

      const link =
        document.createElement("a");

      link.href = url;

      link.download =
        "blindspot-ai-report-" +
        scanId +
        ".pdf";

      document.body.appendChild(link);
      link.click();
      link.remove();

      window.URL.revokeObjectURL(url);

      showToast(
        "AI PDF downloaded."
      );
    } catch (error) {
      showToast(error.message);
    }
  }

  /* =====================================================
     FINDINGS
     ===================================================== */

  const findings = useMemo(() => {
    const raw =
      report?.findings ||
      report?.results ||
      [];

    const list =
      Array.isArray(raw)
        ? raw
        : [];

    const normalized =
      list.map((item) => ({
        ...item,
        severity:
          item?.severity ||
          item?.risk ||
          "info",
      }));

    return sortFindings(
      normalized
    );
  }, [report]);

  const filteredFindings =
    useMemo(() => {
      if (
        findingFilter === "all"
      ) {
        return findings;
      }

      return findings.filter(
        (finding) =>
          severityClass(
            finding.severity
          ) === findingFilter
      );
    }, [
      findings,
      findingFilter,
    ]);

  const severityCounts =
    useMemo(() => {
      const counts = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0,
      };

      findings.forEach(
        (finding) => {
          const severity =
            severityClass(
              finding.severity
            );

          if (
            severity ===
            "informational"
          ) {
            counts.info++;
          } else if (
            Object.prototype.hasOwnProperty.call(
              counts,
              severity
            )
          ) {
            counts[severity]++;
          } else {
            counts.info++;
          }
        }
      );

      return counts;
    }, [findings]);

  const riskScore = useMemo(() => {
    const possible =
      report?.risk_score ??
      report?.risk ??
      report?.score ??
      selectedScan?.risk_score ??
      selectedScan?.risk ??
      0;

    const number =
      Number(possible);

    return Number.isFinite(number)
      ? Math.max(
          0,
          Math.min(100, number)
        )
      : 0;
  }, [
    report,
    selectedScan,
  ]);

  const riskGrade =
    useMemo(
      () => getRiskGrade(riskScore),
      [riskScore]
    );

  /* =====================================================
     LOGIN
     ===================================================== */

  if (!token) {
    return (
      <div className="login-page">
        <div className="login-container">
          <div className="login-showcase">
            <div className="login-logo">
        <span>BlindSpot</span>
</div>

<div className="login-tagline">
  Website Vulnerability Scanner
</div>

            <h1>
              Stay ahead of every vulnerability.
            </h1>

            <p>
              A complete security assessment platform that maps attack surfaces, uncovers vulnerabilities, and delivers reports with clear remediation steps.
            </p>

            <div className="login-features">
              
            </div>
          </div>

          <div className="login-form-container">
            <form
              className="login-form"
              onSubmit={login}
            >
              <h2>
                Welcome back
              </h2>

              <p className="login-form-subtitle">
                Enter your details to sign in.
              </p>

              {loginError && (
                <div className="login-error">
                  {loginError}
                </div>
              )}

              <div className="login-form-group">
                <label>
                  Username
                </label>

                <input
                  className="login-input"
                  value={username}
                  onChange={(event) =>
                    setUsername(
                      event.target.value
                    )
                  }
                  autoComplete="username"
                  required
                />
              </div>

              <div className="login-form-group">
                <label>
                  Password
                </label>

                <div className="login-input-wrapper">
                  <input
                    className="login-input"
                    type={
                      showPassword
                        ? "text"
                        : "password"
                    }
                    value={password}
                    onChange={(event) =>
                      setPassword(
                        event.target.value
                      )
                    }
                    autoComplete="current-password"
                    required
                  />

                  <button
                    type="button"
                    className="login-password-toggle"
                    onClick={() =>
                      setShowPassword(
                        !showPassword
                      )
                    }
                  >
                    {showPassword
                      ? "Hide"
                      : "Show"}
                  </button>
                </div>
              </div>

              <button
                className="login-button"
                type="submit"
                disabled={loginLoading}
              >
                {loginLoading
                  ? "Signing in..."
                  : "Sign in"}
              </button>
            </form>
          </div>
        </div>
      </div>
    );
  }

  /* =====================================================
     LOADING
     ===================================================== */

  if (loading) {
    return (
      <div className="loading-screen">
        <div className="loading-spinner" />
      </div>
    );
  }

  /* =====================================================
     APP SHELL
     ===================================================== */

  return (
    <div className="app-shell">
      <Sidebar
        page={page}
        setPage={setPage}
        user={user}
        logout={logout}
        showLogoutConfirm={
          showLogoutConfirm
        }
        setShowLogoutConfirm={
          setShowLogoutConfirm
        }
      />

      <main className="main-content">
        <div className="page-container">
          {page === "overview" && (
            <Dashboard
              stats={stats}
              scans={scans}
              openScan={openScan}
              setPage={setPage}
            />
          )}

          {page === "new-scan" && (
            <NewScanPage
              scanForm={scanForm}
              setScanForm={
                setScanForm
              }
              startScan={startScan}
              scanProgress={
                scanProgress
              }
            />
          )}

          {page === "scans" && (
            <ScansPage
              scans={scans}
              openScan={openScan}
              deleteScan={deleteScan}
            />
          )}

          {page === "rules" && (
            <RulesPage
              rules={rules}
              reloadRules={
                reloadRules
              }
            />
          )}

          {page === "report" &&
            report && (
              <ReportPage
                report={report}
                selectedScan={
                  selectedScan
                }
                findings={
                  filteredFindings
                }
                allFindings={findings}
                severityCounts={
                  severityCounts
                }
                findingFilter={
                  findingFilter
                }
                setFindingFilter={
                  setFindingFilter
                }
                riskScore={riskScore}
                riskGrade={riskGrade}
                exportReport={
                  exportReport
                }
                downloadAIReport={
                  downloadAIReport
                }
                deleteScan={
                  deleteScan
                }
                setPage={setPage}
              />
            )}
        </div>
      </main>

      {toast && (
        <div className="toast">
          {toast}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   SIDEBAR
   ========================================================= */

function Sidebar({
  page,
  setPage,
  user,
  logout,
  showLogoutConfirm,
  setShowLogoutConfirm,
}) {
  const items = [
    {
      id: "overview",
      label: "Overview",
    },
    {
      id: "new-scan",
      label: "New Scan",
    },
    {
      id: "scans",
      label: "Scan History",
    },
    {
      id: "rules",
      label: "Detection Rules",
    },
    {
      id: "report",
      label: "Report",
    },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <span>
          BlindSpot
        </span>
      </div>

      <nav className="sidebar-nav">
        {items.map((item) => (
          <button
            key={item.id}
            className={`sidebar-item ${
              page === item.id
                ? "active"
                : ""
            }`}
            onClick={() => {
              if (
                item.id ===
                  "report" &&
                page !== "report"
              ) {
                return;
              }

              setPage(item.id);
            }}
            disabled={
              item.id === "report" &&
              page !== "report"
            }
          >
            <span>
              {item.icon}
            </span>

            <span>
              {item.label}
            </span>
          </button>
        ))}
      </nav>

      <div className="sidebar-spacer" />

      <div className="sidebar-status">
        <div className="sidebar-status-title">
          System Online
        </div>

        <div className="sidebar-status-text">
          BlindSpot is ready to scan
        </div>
      </div>

      <div className="sidebar-user">
        <div className="sidebar-avatar">
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <circle cx="12" cy="7" r="4"></circle>
            <path d="M6 21v-2a6 6 0 0 1 12 0v2"></path>
          </svg>
        </div>

        <div>
          <div className="sidebar-user-name">
            {user?.username ||
              user?.name ||
              "Admin"}
          </div>

          <div className="sidebar-user-role">
            Administrator
          </div>
        </div>

        <button
          type="button"
          className="sidebar-logout-btn"
          onClick={() => {
            setShowLogoutConfirm(
              true
            );
          }}
          title="Logout"
        >
          ↪
        </button>
      </div>

      {showLogoutConfirm && (
        <div
          className="logout-overlay"
          onClick={() =>
            setShowLogoutConfirm(
              false
            )
          }
        >
          <div
            className="logout-popup"
            onClick={(event) =>
              event.stopPropagation()
            }
          >
            <div className="logout-popup-title">
              Sign out?
            </div>

            <div className="logout-popup-text">
            </div>

            <div className="logout-popup-actions">
              <button
                type="button"
                className="logout-cancel"
                onClick={() =>
                  setShowLogoutConfirm(
                    false
                  )
                }
              >
                Cancel
              </button>

              <button
                type="button"
                className="logout-confirm"
                onClick={() => {
                  setShowLogoutConfirm(
                    false
                  );
                  logout();
                }}
              >
                Sign out
              </button>
            </div>
          </div>
        </div>
      )}
    </aside>
  );
}

/* =========================================================
   DASHBOARD
   ========================================================= */

function Dashboard({
  stats,
  scans,
  openScan,
  setPage,
}) {
  const totalScans =
    Number(
      stats?.total_scans ??
        stats?.scans_total ??
        scans.length
    ) || 0;

  const completedScans =
    Number(
      stats?.completed_scans ??
        stats?.completed ??
        scans.filter(
          (scan) =>
            String(
              scan.status
            ).toLowerCase() ===
            "completed"
        ).length
    ) || 0;

  const runningScans =
    Number(
      stats?.running_scans ??
        stats?.running ??
        scans.filter((scan) =>
          [
            "running",
            "pending",
            "scanning",
          ].includes(
            String(
              scan.status
            ).toLowerCase()
          )
        ).length
    ) || 0;

  const ruleCount =
    Number(
      stats?.rules_loaded ??
        stats?.detection_rules ??
        stats?.rules ??
        0
    ) || 0;

  const averageRisk =
    Number(
      stats?.average_risk ??
        stats?.avg_risk ??
        stats?.risk_score ??
        8
    ) || 0;

  const grade =
    getRiskGrade(
      averageRisk
    );

  return (
    <>
      <PageHeader
       
        title="Overview"
        action={
          <button
            className="primary-button"
            onClick={() =>
              setPage(
                "new-scan"
              )
            }
          >
            New scan
          </button>
        }
      />

      <section className="hero-grid">
        <div className="hero-card">
          <div className="hero-eyebrow">
            SECURITY PLATFORM
          </div>

          <h2 className="hero-title">
            Stay ahead of every{" "}
            <span>
             vulnerability.
            </span>
          </h2>

          <p className="hero-description">
            Continuous scanning across headers, endpoints, and known vulnerability signatures.
          </p>

          <div className="hero-status">
            <span className="status-dot" />
            Scanner operational
            &nbsp;.&nbsp;
            Active & Passive detection
          </div>
        </div>

        <div className="posture-card">
          <div className="posture-label">
            Average Risk
          </div>

          <div className="posture-value">
            {Math.round(
              averageRisk
            )}
          </div>

          <div className="posture-score">
            Security grade{" "}
            <strong>
              {grade}
            </strong>
          </div>

          <div className="posture-bar">
            <div
              className="posture-bar-fill"
              style={{
                width: `${Math.min(
                  100,
                  Math.max(
                    4,
                    averageRisk
                  )
                )}%`,
              }}
            />
          </div>
        </div>
      </section>

      <section className="metrics-grid">
        <MetricCard
          label="Total scans"
          value={totalScans}
          subtitle="Assessments performed"
        />

        <MetricCard
          label="Completed"
          value={completedScans}
          subtitle="Successfully finished"
        />

        <MetricCard
          label="Running"
          value={runningScans}
          subtitle="Currently active"
        />

        <MetricCard
          label="Detection rules"
          value={
            ruleCount || "—"
          }
          subtitle="Loaded security rules"
        />
      </section>

      <section className="section-card">
        <div className="section-card-header">
          <div>
           <div className="section-card-title">
              Recent scans <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>- Latest security assessments</span>
            </div>
          </div>

          <button
            className="secondary-button"
            onClick={() =>
              setPage("scans")
            }
          >
            View all
          </button>
        </div>

        <ScanTable
          scans={scans.slice(0, 8)}
          openScan={openScan}
        />
      </section>
    </>
  );
}

/* =========================================================
   METRIC CARD
   ========================================================= */

function MetricCard({
  label,
  value,
  subtitle,
}) {
  return (
    <div className="metric-card">
      <div className="metric-label">
        {label}
      </div>

      <div className="metric-value">
        {value}
      </div>

      <div className="metric-subtitle">
        {subtitle}
      </div>
    </div>
  );
}

/* =========================================================
   NEW SCAN PAGE
   ========================================================= */

function NewScanPage({
  scanForm,
  setScanForm,
  startScan,
  scanProgress,
}) {
  function update(key, value) {
    setScanForm(
      (previous) => ({
        ...previous,
        [key]: value,
      })
    );
  }

  return (
    <>
      <PageHeader
        title="New scan"
        description="Launch a security scan on an authorized target."
      />

      <form
        className="scan-form"
        onSubmit={startScan}
      >
        <div className="form-card">
          <div className="form-card-header">
            <div className="form-card-title">
              Target configuration
            </div>

            <div className="form-card-description">
              Provide the URL of the
              authorized application you
              want BlindSpot to assess.
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">
              Target URL
            </label>

            <input
              className="form-input"
              value={scanForm.url}
              onChange={(event) =>
                update(
                  "url",
                  event.target.value
                )
              }
              placeholder="https://example.com"
            />
          </div>

          <div className="authorization-box">
            <div>
              <div className="authorization-box-title">
                 Authorized target
              </div>

              <div className="authorization-box-text">
                Only scan systems you own
                or have explicit permission
                to assess.
              </div>
            </div>
          </div>
        </div>

        <div className="form-card">
          <div className="form-card-header">
            <div className="form-card-title">
              Scan options
            </div>

            <div className="form-card-description">
              Choose which analysis layers
              should run.
            </div>
          </div>

          <div className="scan-options">
            <OptionToggle
              title="Deep scan"
              active={
                scanForm.deep_scan
              }
              onClick={() =>
                update(
                  "deep_scan",
                  !scanForm.deep_scan
                )
              }
            />

            <OptionToggle
              title="Security headers"
              active={
                scanForm.security_headers
              }
              onClick={() =>
                update(
                  "security_headers",
                  !scanForm.security_headers
                )
              }
            />

            <OptionToggle
              title="TLS analysis"
              active={
                scanForm.tls_analysis
              }
              onClick={() =>
                update(
                  "tls_analysis",
                  !scanForm.tls_analysis
                )
              }
            />
          </div>
        </div>

        <div className="form-card">
          <div className="form-card-header">
            <div className="form-card-title">
              Detection intensity
            </div>

            <div className="form-card-description">
              Choose how deeply BlindSpot should analyze the target, from passive analysis to full active validation.
            </div>
          </div>

          <div className="mode-grid">
            <ModeCard
              title="Passive"
              description="Analyze responses without sending active validation probes."
              selected={
                scanForm.scan_mode ===
                "passive"
              }
              onClick={() =>
                update(
                  "scan_mode",
                  "passive"
                )
              }
              badge="LOW IMPACT"
            />

            <ModeCard
              title="Light active"
              description="Run a limited set of controlled validation probes.."
              selected={
                scanForm.scan_mode ===
                "light_active"
              }
              onClick={() =>
                update(
                  "scan_mode",
                  "light_active"
                )
              }
              badge="CONTROLLED"
            />

            <ModeCard
              title="Full active"
              description="Run the complete supported set of active validation probes."
              selected={
                scanForm.scan_mode ===
                "full_active"
              }
              onClick={() =>
                update(
                  "scan_mode",
                  "full_active"
                )
              }
              badge="MAX COVERAGE"
            />
          </div>
        </div>

        <div className="form-card">
          <div className="form-card-header">
            <div className="form-card-title">
              Optional request headers
            </div>

            <div className="form-card-description">
              Supply JSON headers when the
              authorized target requires them.
            </div>
          </div>

          <textarea
            className="form-textarea"
            value={
              scanForm.custom_headers
            }
            onChange={(event) =>
              update(
                "custom_headers",
                event.target.value
              )
            }
            placeholder='{"Authorization":"Bearer ..."}'
          />
        </div>

        <div className="warning-box">
          Active scanning performs controlled requests against the target. Run it only with explicit authorization.
        </div>

        {scanProgress && (
          <div className="progress-card">
            <div className="progress-header">
              <div className="progress-title">
                Scan progress
              </div>

              <div className="progress-value">
                {
                  scanProgress.percent
                }
                %
              </div>
            </div>

            <div className="progress-track">
              <div
                className="progress-fill"
                style={{
                  width: `${scanProgress.percent}%`,
                }}
              />
            </div>

            <div className="form-card-description">
              {
                scanProgress.status
              }
            </div>
          </div>
        )}

        <div>
          <button
            className="primary-button"
            type="submit"
            disabled={Boolean(
              scanProgress
            )}
          >
            {scanProgress
              ? "Scan in progress..."
              : "Start scan"}
          </button>
        </div>
      </form>
    </>
  );
}

/* =========================================================
   OPTION TOGGLE
   ========================================================= */

function OptionToggle({
  title,
  description,
  active,
  onClick,
}) {
  return (
    <button
      type="button"
      className={`option-toggle ${
        active ? "active" : ""
      }`}
      onClick={onClick}
    >
      <div>
        <div className="option-title">
          {title}
        </div>

        <div className="option-description">
          {description}
        </div>
      </div>

      <div
        className={`toggle ${
          active ? "active" : ""
        }`}
      />
    </button>
  );
}

/* =========================================================
   MODE CARD
   ========================================================= */

function ModeCard({
  title,
  description,
  selected,
  onClick,
  badge,
}) {
  return (
    <button
      type="button"
      className={`mode-card ${
        selected ? "selected" : ""
      }`}
      onClick={onClick}
    >
      <div className="mode-card-title">
        {title}
      </div>

      <div className="mode-card-description">
        {description}
      </div>

      <div className="mode-card-badge">
        {badge}
      </div>
    </button>
  );
}

/* =========================================================
   SCANS PAGE
   ========================================================= */

function ScansPage({
  scans,
  openScan,
  deleteScan,
}) {
  return (
    <>
      <PageHeader
        title="Scan history"
        description="View your past scans and their results."
      />

      <section className="section-card scan-history-card">
        <div className="section-card-header">
          <div>
            <div className="section-card-title">
  Recent scans <span style={{ fontWeight: 400, color: 'var(--text-muted)' }}>- Latest security assessments</span>
</div>

            <div className="section-card-subtitle">
              {scans.length} recorded
              assessment
              {scans.length === 1
                ? ""
                : "s"}
            </div>
          </div>
        </div>

        <ScanTable
          scans={scans}
          openScan={openScan}
          deleteScan={deleteScan}
        />
      </section>
    </>
  );
}

/* =========================================================
   SCAN TABLE
   ========================================================= */

function ScanTable({
  scans = [],
  openScan,
  deleteScan,
}) {
  if (!scans.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">
          No scans yet
        </div>

        <div className="empty-state-text">
          Start your first security
          assessment to see results here.
        </div>
      </div>
    );
  }

  const formatDuration = (seconds) => {
    if (!seconds && seconds !== 0) return "—";

    const totalSeconds = Math.round(Number(seconds));
    const hrs = Math.floor(totalSeconds / 3600);
    const mins = Math.floor((totalSeconds % 3600) / 60);
    const secs = totalSeconds % 60;

    if (hrs > 0) {
      return `${hrs}h ${mins}m ${secs}s`;
    }
    if (mins > 0) {
      return `${mins}m ${secs}s`;
    }
    return `${secs}s`;
  };

  return (
    <table className="scan-table">
      <thead>
        <tr>
          <th>Target</th>
          <th>Status</th>
          <th>Risk</th>
          <th>Findings</th>
          <th>Date</th>
          <th>Duration</th>

          {deleteScan && (
            <th />
          )}
        </tr>
      </thead>

      <tbody>
        {scans.map(
          (scan, index) => {
            const scanId =
              scan?.id ||
              scan?.scan_id ||
              scan?.uuid;

            const target =
              scan?.url ||
              scan?.target_url ||
              scan?.target ||
              scan?.targetUrl ||
              "Unknown target";

            const status =
              scan?.status ||
              scan?.scan_status ||
              "unknown";

            const risk =
              scan?.risk_score ??
              scan?.risk ??
              scan?.score ??
              0;

            const findings =
              scan?.findings_count ??
              scan?.finding_count ??
              scan?.findings ??
              0;

            const findingCount =
              Array.isArray(findings)
                ? findings.length
                : findings;

            let durationSeconds =
              scan?.duration_seconds ??
              scan?.duration ??
              null;

            if (
              durationSeconds == null &&
              scan?.started_at &&
              scan?.completed_at
            ) {
              durationSeconds =
                (new Date(scan.completed_at) -
                  new Date(scan.started_at)) /
                1000;
            }

            return (
              <tr
                key={
                  scanId ||
                  `${target}-${index}`
                }
              >
                <td>
                  <button
                    className="target-button"
                    onClick={() =>
                      scanId &&
                      openScan(scanId)
                    }
                  >
                    {target}

                    <span className="target-url">
                      {scanId}
                    </span>
                  </button>
                </td>

                <td>
                  <StatusBadge
                    status={status}
                  />
                </td>

                <td>
                  <span
                    className={`risk-mini ${
                      Number(risk) >= 70
                        ? "risk-high"
                        : Number(risk) >=
                          35
                        ? "risk-medium"
                        : "risk-low"
                    }`}
                  >
                    {Math.round(
                      Number(risk) || 0
                    )}
                  </span>
                </td>

                <td>
                  {findingCount}
                </td>

                <td>
                  {formatDate(
                    scan?.created_at ||
                      scan?.timestamp ||
                      scan?.started_at
                  )}
                </td>

                <td>
                  <span className="scan-duration">
                    {formatDuration(durationSeconds)}
                  </span>
                </td>

                {deleteScan && (
                  <td>
                    <button
                      className="secondary-button danger-button"
                      onClick={() =>
                        scanId &&
                        deleteScan(
                          scanId
                        )
                      }
                    >
                      Delete
                    </button>
                  </td>
                )}
              </tr>
            );
          }
        )}
      </tbody>
    </table>
  );
}

/* =========================================================
   STATUS BADGE
   ========================================================= */

function StatusBadge({
  status,
}) {
  const normalized =
    String(
      status || "unknown"
    ).toLowerCase();

  let className = "pending";

  if (
    normalized.includes(
      "complete"
    )
  ) {
    className = "completed";
  } else if (
    normalized.includes(
      "run"
    ) ||
    normalized.includes(
      "scan"
    )
  ) {
    className = "running";
  } else if (
    normalized.includes(
      "fail"
    ) ||
    normalized.includes(
      "error"
    )
  ) {
    className = "failed";
  }

  return (
    <span
      className={`status-badge ${className}`}
    >
      {status}
    </span>
  );
}

/* =========================================================
   RULES PAGE
   ========================================================= */

function RulesPage({
  rules,
  reloadRules,
}) {
  const [search, setSearch] =
    useState("");

  const filteredRules =
    useMemo(() => {
      const query =
        search.trim().toLowerCase();

      if (!query) return rules;

      return rules.filter((rule) =>
        JSON.stringify(rule)
          .toLowerCase()
          .includes(query)
      );
    }, [rules, search]);

  return (
    <>
      <PageHeader
        title="Detection rules"
        description="Security rules BlindSpot uses to detect threats."
        action={
          <button
            className="secondary-button"
            onClick={reloadRules}
          >
            Reload rules
          </button>
        }
      />

      <div className="rules-toolbar">
        <div className="rules-search-wrapper">
  <input
    className="rules-search"
    placeholder="Search rules..."
    value={search}
    onChange={(event) =>
      setSearch(
        event.target.value
      )
    }
  />

  {search && (
    <button
      type="button"
      className="rules-search-clear"
      onClick={() => setSearch("")}
    >
      ×
    </button>
  )}
</div>
      </div>

      <section className="section-card">
        {!filteredRules.length ? (
          <div className="empty-state">
            <div className="empty-state-title">
              No rules found
            </div>
          </div>
        ) : (
          <table className="rules-table">
            <thead>
              <tr>
                <th>Rule</th>
                <th>ID</th>
                <th>Severity</th>
                <th>Source</th>
                <th>OWASP</th>
              </tr>
            </thead>

            <tbody>
              {filteredRules
                .slice(0, 500)
                .map(
                  (
                    rule,
                    index
                  ) => (
                    <tr
                      key={
                        rule?.id ||
                        rule?.rule_id ||
                        index
                      }
                    >
                      <td>
                        <div className="rule-name">
                          {rule?.name ||
                            rule?.title ||
                            "Unnamed rule"}
                        </div>
                      </td>

                      <td>
                        <span className="rule-id">
                          {rule?.id ||
                            rule?.rule_id ||
                            "—"}
                        </span>
                      </td>

                      <td>
                        <span
                          className={`finding-severity ${severityClass(
                            rule?.severity
                          )}`}
                        >
                          {rule?.severity ||
                            "info"}
                        </span>
                      </td>

                      <td>
                        <span className="rule-source">
                          {rule?.source ||
                            rule?.source_tool ||
                            "BlindSpot"}
                        </span>
                      </td>

                      <td>
                        {rule?.owasp_category ||
                          rule?.owasp ||
                          "—"}
                      </td>
                    </tr>
                  )
                )}
            </tbody>
          </table>
        )}
      </section>
    </>
  );
}
/* =========================================================
   REPORT PAGE
   ========================================================= */

function ReportPage({
  report,
  selectedScan,
  findings,
  allFindings,
  severityCounts,
  findingFilter,
  setFindingFilter,
  riskScore,
  riskGrade,
  exportReport,
  downloadAIReport,
  deleteScan,
  setPage,
}) {
  const scanId =
    selectedScan?.id ||
    selectedScan?.scan_id;

  const target =
    selectedScan?.url ||
    selectedScan?.target_url ||
    selectedScan?.target ||
    report?.url ||
    report?.target_url ||
    "Unknown target";

  const activeProbes =
    Array.isArray(
      report?.active_probes_log
    )
      ? report.active_probes_log
      : [];

  return (
    <>
      <PageHeader
        title="Assessment report"
        description={target}
        action={
          <div className="report-actions">
            <button
              className="secondary-button"
              onClick={() =>
                setPage("scans")
              }
            >
              Back
            </button>

            {scanId && (
              <>
                <button
                  className="secondary-button"
                  onClick={() =>
                    exportReport(
                      scanId
                    )
                  }
                >
                  Export
                </button>

                <button
                  className="primary-button report-download-button"
                  onClick={() =>
                    downloadAIReport(
                      scanId
                    )
                  }
                >
                  Download PDF
                </button>
              </>
            )}
          </div>
        }
      />

      <section className="report-overview">
        <div className="risk-card">
          <div
            className="risk-ring"
            style={ringStyle(
              riskScore
            )}
          >
            <div>
              <div className="risk-score">
                {Math.round(
                  riskScore
                )}
              </div>

              <div className="risk-grade">
                Grade{" "}
                {riskGrade}
              </div>

              <div className="risk-caption">
                Risk score
              </div>
            </div>
          </div>
        </div>

        <div className="section-card">
          <div className="section-card-header">
            <div>
              <div className="section-card-title">
                Findings overview
              </div>

              <div className="section-card-subtitle">
                Evidence-backed security
                signals
              </div>
            </div>
          </div>

          <div
            className="finding-metrics"
            style={{
              padding: 18,
            }}
          >
            <FindingMetric
              label="Critical"
              value={
                severityCounts.critical
              }
              severity="critical"
            />

            <FindingMetric
              label="High"
              value={
                severityCounts.high
              }
              severity="high"
            />

            <FindingMetric
              label="Medium"
              value={
                severityCounts.medium
              }
              severity="medium"
            />

            <FindingMetric
              label="Low / Info"
              value={
                severityCounts.low +
                severityCounts.info
              }
              severity="low"
            />
          </div>
        </div>
      </section>

      <section className="section-card findings-section">
        <div className="section-card-header">
          <div>
            <div className="section-card-title">
              Security findings
            </div>

            <div className="section-card-subtitle">
              {allFindings.length} validated
              finding
              {allFindings.length ===
              1
                ? ""
                : "s"}
            </div>
          </div>

          <div className="finding-filter">
            {[
              "All",
              "Critical",
              "High",
              "Medium",
              "Low",
              "Info",
            ].map(
              (filter) => (
                <button
                  key={filter}
                  className={`filter-button ${
                    findingFilter ===
                    filter
                      ? "active"
                      : ""
                  }`}
                  onClick={() =>
                    setFindingFilter(
                      filter
                    )
                  }
                >
                  {filter}
                </button>
              )
            )}
          </div>
        </div>

        {findings.length ? (
          findings.map(
            (
              finding,
              index
            ) => (
              <FindingRow
                key={
                  finding?.id ||
                  `${finding?.title}-${index}`
                }
                finding={
                  finding
                }
              />
            )
          )
        ) : (
          <div className="empty-state">
            <div className="empty-state-title">
              No findings in this filter
            </div>
          </div>
        )}
      </section>

      <section
        className="section-card"
        style={{
          marginTop: 18,
        }}
      >
        <div className="section-card-header">
          <div>
            <div className="section-card-title">
              OWASP coverage
            </div>

            <div className="section-card-subtitle">
              Findings grouped by OWASP
              category
            </div>
          </div>
        </div>

        <OwaspChart
          findings={
            allFindings
          }
        />
      </section>

      <section
        className="section-card"
        style={{
          marginTop: 18,
        }}
      >
        <div className="section-card-header">
          <div>
            <div className="section-card-title">
              Active probe execution
            </div>

            <div className="section-card-subtitle">
              Actual probe → response
              validation
            </div>
          </div>

          <div className="rule-source">
            {activeProbes.length} probes
          </div>
        </div>

        <ProbeList
          probes={
            activeProbes
          }
        />
      </section>

      {scanId && (
        <div
          style={{
            marginTop: 18,
            display: "flex",
            justifyContent:
              "flex-end",
          }}
        >
          <button
            className="secondary-button danger-button"
            onClick={async () => {
              await deleteScan(
                scanId
              );
              setPage("scans");
            }}
          >
            Delete scan
          </button>
        </div>
      )}
    </>
  );
}

/* =========================================================
   FINDING METRIC
   ========================================================= */

function FindingMetric({
  label,
  value,
  severity,
}) {
  return (
    <div
      className={`finding-metric ${severity}`}
    >
      <div className="finding-metric-value">
        {value}
      </div>

      <div className="finding-metric-label">
        {label}
      </div>
    </div>
  );
}

/* =========================================================
   FINDING ROW
   ========================================================= */

function FindingRow({
  finding,
}) {
  const [
    expanded,
    setExpanded,
  ] = useState(false);

  const severity =
    severityClass(
      finding?.severity
    );

  return (
    <div className="finding-row">
      <div className="finding-row-main">
        <div
          className={`finding-severity-bar ${severity}`}
        />

        <div>
          <div className="finding-title">
            {finding?.title ||
              "Untitled finding"}
          </div>

          <div className="finding-description">
            {finding?.description ||
              "No description provided."}
          </div>

          <div className="finding-meta">
            <span
              className={`finding-severity ${severity}`}
            >
              {finding?.severity ||
                "info"}
            </span>

            {finding?.owasp_category && (
              <span className="finding-tag">
                {
                  finding.owasp_category
                }
              </span>
            )}

            {finding?.cwe && (
              <span className="finding-tag">
                {finding.cwe}
              </span>
            )}

            {finding?.source_tool && (
              <span className="finding-tag">
                {
                  finding.source_tool
                }
              </span>
            )}
          </div>
        </div>

        <button
          className="secondary-button"
          onClick={() =>
            setExpanded(
              !expanded
            )
          }
        >
          {expanded
            ? "Hide"
            : "Evidence"}
        </button>
      </div>

      {expanded && (
        <div className="finding-details">
          <div className="finding-details-card">
            <div className="finding-details-title">
              Evidence
            </div>

            <div className="finding-evidence">
              {finding?.evidence_snippet ||
                finding?.evidence ||
                finding?.evidence_location ||
                "No evidence snippet available."}
            </div>

            {finding?.remediation && (
              <>
                <div
                  className="finding-details-title"
                  style={{
                    marginTop: 15,
                  }}
                >
                  Remediation
                </div>

                <div className="finding-remediation">
                  {
                    finding.remediation
                  }
                </div>
              </>
            )}

            {finding?.target_url && (
              <>
                <div
                  className="finding-details-title"
                  style={{
                    marginTop: 15,
                  }}
                >
                  Target
                </div>

                <div className="finding-evidence">
                  {
                    finding.target_url
                  }
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* =========================================================
   OWASP CHART
   ========================================================= */

function OwaspChart({
  findings = [],
}) {
  const counts = {};

  findings.forEach(
    (finding) => {
      const category =
        finding?.owasp_category ||
        "Uncategorized";

      counts[category] =
        (counts[category] ||
          0) + 1;
    }
  );

  const entries =
    Object.entries(
      counts
    ).sort(
      (a, b) =>
        b[1] - a[1]
    );

  if (!entries.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">
          No OWASP data
        </div>
      </div>
    );
  }

  const max =
    Math.max(
      ...entries.map(
        ([, value]) =>
          value
      )
    );

  return (
    <div className="owasp-chart">
      {entries.map(
        ([category, count]) => (
          <div
            className="owasp-row"
            key={category}
          >
            <div className="owasp-label">
              {category}
            </div>

            <div className="owasp-bar">
              <div
                className="owasp-bar-fill"
                style={{
                  width: `${
                    (count /
                      max) *
                    100
                  }%`,
                }}
              />
            </div>

            <div className="owasp-count">
              {count}
            </div>
          </div>
        )
      )}
    </div>
  );
}

/* =========================================================
   ACTIVE PROBE LIST
   ========================================================= */

function ProbeList({
  probes = [],
}) {
  if (!probes.length) {
    return (
      <div className="empty-state">
        <div className="empty-state-title">
          No active probes recorded
        </div>

        <div className="empty-state-text">
          This scan did not expose
          active probe execution logs.
        </div>
      </div>
    );
  }

  return (
    <div className="probe-list">
      {probes.map(
        (
          probe,
          index
        ) => {
          const vulnerable =
            probe?.vulnerable ===
            true;

          const details =
            probe?.details ||
            probe?.result ||
            "No probe details.";

          const lowerDetails =
            String(
              details
            ).toLowerCase();

          const inconclusive =
            lowerDetails.includes(
              "inconclusive"
            );

          let status = "safe";

          if (vulnerable) {
            status =
              "vulnerable";
          } else if (
            inconclusive
          ) {
            status =
              "inconclusive";
          }

          return (
            <div
              className="probe-row"
              key={
                probe?.id ||
                `${probe?.probe_type}-${index}`
              }
            >
              <div>
                <div className="probe-type">
                  {probe?.probe_type ||
                    probe?.type ||
                    "Active probe"}
                </div>

                <div className="probe-param">
                  {probe?.param_name ||
                    "No parameter"}
                </div>
              </div>

              <div className="probe-details">
  {details}

  {probe?.target_url && (
    <div className="probe-target-url">
      {probe.target_url}
    </div>
  )}

                {probe?.status_code !== undefined &&
  probe?.status_code !== null && (
    <div className="probe-status-code">
      HTTP {probe.status_code}
    </div>
  )}
            
              </div>

              <div
                className={`probe-status ${status}`}
              >
                {vulnerable
                  ? "Vulnerable"
                  : inconclusive
                  ? "Inconclusive"
                  : "Safe"}
              </div>
            </div>
          );
        }
      )}
    </div>
  );
}

/* =========================================================
   PAGE HEADER
   ========================================================= */

function PageHeader({
  eyebrow,
  title,
  description,
  action,
}) {
  return (
    <div className="page-header">
      <div className="page-header-left">
        {eyebrow && (
          <div
            className="hero-eyebrow"
            style={{
              marginBottom: 7,
            }}
          >
            {eyebrow}
          </div>
        )}

        <h1>
          {title}
        </h1>

        {description && (
          <p>
            {description}
          </p>
        )}
      </div>

      {action && (
        <div className="page-header-actions">
          {action}
        </div>
      )}
    </div>
  );
}

/* =========================================================
   RISK HELPERS
   ========================================================= */

function getRiskGrade(score) {
  const value =
    Number(score) || 0;

  if (value <= 10)
    return "A";
  if (value <= 25)
    return "B";
  if (value <= 45)
    return "C";
  if (value <= 65)
    return "D";
  if (value <= 80)
    return "E";

  return "F";
}

function ringStyle(score) {
  const value = Math.max(
    0,
    Math.min(
      100,
      Number(score) || 0
    )
  );

  const angle = value * 3.6;
  const markerWidth = 2.5;

  const start = Math.max(
    0,
    angle - markerWidth
  );

  const end = Math.min(
    360,
    angle + markerWidth
  );

  return {
    background: `
      radial-gradient(
        circle,
        #0d121b 0%,
        #0d121b 56%,
        transparent 57%
      ),
      conic-gradient(
        from 0deg,
        #151c29 0deg ${start}deg,
        #22d3ee ${start}deg ${end}deg,
        #151c29 ${end}deg 360deg
      )
    `,
  };
}

/* =========================================================
   DATE
   ========================================================= */

function formatDate(value) {
  if (!value) return "—";

  try {
    const date =
      new Date(value);

    if (
      Number.isNaN(
        date.getTime()
      )
    ) {
      return "—";
    }

    return date.toLocaleDateString(
      undefined,
      {
        day: "2-digit",
        month: "short",
        year: "numeric",
      }
    );
  } catch {
    return "—";
  }
}

export default App;