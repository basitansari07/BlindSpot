// ============================================
// BlindSpot Chrome Extension
// ============================================

const API_BASE = "http://127.0.0.1:8000";

const MESSAGES = {

    ready: {
        title: "Ready to scan",
        detail: "Enter a URL to begin."
    },

    readyNoAuth: {
        title: "Ready",
        detail: "Click START SCAN to authenticate and scan."
    },

    urlRequired: {
        title: "URL required",
        detail: "Enter a website URL before starting the scan."
    },

    authenticating: {
        title: "Authenticating",
        detail: "Logging in to BlindSpot backend..."
    },

    connecting: {
        title: "Connecting",
        detail: "Submitting target to BlindSpot..."
    },

    scanSubmitted: {
        title: "Scan submitted",
        detail: "Scan ID: {scanId}..."
    },

    scanning: {
        title: "{status}",
        detail: "Scan progress: {progress}%"
    },

    collectingResults: {
        title: "Collecting results",
        detail: "Retrieving security findings..."
    },

    scanCompleted: {
        title: "Scan completed",
        detail: "{count} security finding(s) detected."
    },

    scanFailed: {
        title: "Scan failed",
        detail: "Something went wrong."
    },

    scanTimedOut: "Scan timed out.",

    generatingReport: {
        title: "Generating report",
        detail: "Creating your professional AI security assessment PDF..."
    },

    reportDownloaded: {
        title: "Report downloaded",
        detail: "AI security report saved to your Downloads folder."
    },

    reportFailed: {
        title: "Report failed",
        detail: "Could not generate or download the AI report."
    },

    reportButtonDefault: "Download AI Security Report",
    reportButtonLoading: "Generating AI Report...",

    scanButtonDefault: "START SCAN",
    scanButtonLoading: "SCANNING..."
};

const targetUrl = document.getElementById("targetUrl");
const scanBtn = document.getElementById("scanBtn");
const scanText = document.getElementById("scanText");
const spinner = document.getElementById("spinner");

const statusText = document.getElementById("statusText");
const statusDetail = document.getElementById("statusDetail");

const results = document.getElementById("results");
const findingCount = document.getElementById("findingCount");
const criticalCount = document.getElementById("criticalCount");
const highCount = document.getElementById("highCount");

const reportBtn = document.getElementById("reportBtn");

function fillTemplate(template, values = {}) {
    return template.replace(/\{(\w+)\}/g, (match, key) =>
        Object.prototype.hasOwnProperty.call(values, key)
            ? values[key]
            : match
    );
}

function setStatusFromMessage(message, values = {}) {
    setStatus(
        fillTemplate(message.title, values),
        fillTemplate(message.detail, values)
    );
}

function setStatus(title, detail) {
    statusText.textContent = title;
    statusDetail.textContent = detail;
}

function setScanning(scanning) {
    scanBtn.disabled = scanning;

    if (scanning) {
        scanText.textContent = MESSAGES.scanButtonLoading;
        spinner.classList.remove("hidden");
    } else {
        scanText.textContent = MESSAGES.scanButtonDefault;
        spinner.classList.add("hidden");
    }
}

function showResults() {
    results.classList.remove("hidden");
}

function hideResults() {
    results.classList.add("hidden");
}

function getSeverityCount(findings, severity) {
    return findings.filter(
        finding =>
            String(finding.severity || "").toLowerCase() === severity
    ).length;
}

async function getAuthToken() {
    const data = await chrome.storage.local.get(["authToken"]);
    return data.authToken || "";
}

async function saveAuth(data) {
    await chrome.storage.local.set({
        authToken: data.token,
        username: data.username || "",
        role: data.role || "user",
        tokenExpiresIn: data.expires_in || 0
    });
}

async function clearAuth() {
    await chrome.storage.local.remove([
        "authToken",
        "username",
        "role",
        "tokenExpiresIn"
    ]);
}

async function apiRequest(path, options = {}) {

    const token = await getAuthToken();

    const headers = {
        "Content-Type": "application/json",
        ...(options.headers || {})
    };

    if (token) {
        headers["Authorization"] = `Bearer ${token}`;
    }

    const response = await fetch(`${API_BASE}${path}`, {
        ...options,
        credentials: "include",
        headers
    });

    let data;

    try {
        data = await response.json();
    } catch {
        throw new Error(`Backend returned HTTP ${response.status}`);
    }

    if (!response.ok) {

        if (response.status === 401) {
            await clearAuth();
        }

        throw new Error(
            data.detail ||
            data.message ||
            `Request failed with HTTP ${response.status}`
        );
    }

    return data;
}

async function login(username, password) {

    const data = await apiRequest("/api/auth/login", {
        method: "POST",
        body: JSON.stringify({
            username,
            password
        })
    });

    if (!data.token) {
        throw new Error(
            "Login succeeded but no authentication token was returned."
        );
    }

    await saveAuth(data);

    return data;
}

async function ensureAuthenticated() {

    const existingToken = await getAuthToken();

    if (existingToken) {
        return true;
    }

    setStatusFromMessage(MESSAGES.authenticating);

    await login("admin", "admin123");

    return true;
}

async function getCurrentTabUrl() {

    try {

        const tabs = await chrome.tabs.query({
            active: true,
            currentWindow: true
        });

        if (tabs.length > 0 && tabs[0].url) {
            return tabs[0].url;
        }

    } catch (error) {

        console.warn(
            "Could not get current tab URL:",
            error
        );
    }

    return "";
}

async function submitScan(url) {

    return await apiRequest("/api/scan", {
        method: "POST",

        body: JSON.stringify({

            url: url,

            authorized: true,

            scan_mode: "full_active",

            deep_scan: true,
            check_headers: true,
            check_tls: true,

            rate_limit: 0
        })
    });
}

async function getScanStatus(scanId) {

    return await apiRequest(
        `/api/scan/${scanId}`
    );
}

async function getScanResults(scanId) {

    return await apiRequest(
        `/api/scan/${scanId}/results`
    );
}

async function waitForScan(scanId) {

    const maxAttempts = 180;
    const delay = 2000;

    for (
        let attempt = 0;
        attempt < maxAttempts;
        attempt++
    ) {

        const data = await getScanStatus(scanId);

        const scan = data.scan || {};

        const currentStatus =
            scan.status || "unknown";

        const progress =
            scan.progress ?? 0;

        setStatusFromMessage(MESSAGES.scanning, {
            status: currentStatus.toUpperCase(),
            progress: progress
        });

        if (currentStatus === "completed") {
            return true;
        }

        if (currentStatus === "failed") {

            throw new Error(
                scan.error ||
                "The security scan failed."
            );
        }

        await new Promise(resolve =>
            setTimeout(resolve, delay)
        );
    }

    throw new Error(MESSAGES.scanTimedOut);
}

function displayResults(data) {

    const findings = Array.isArray(data.findings)
        ? data.findings
        : [];

    const critical =
        getSeverityCount(
            findings,
            "critical"
        );

    const high =
        getSeverityCount(
            findings,
            "high"
        );

    findingCount.textContent =
        findings.length;

    criticalCount.textContent =
        critical;

    highCount.textContent =
        high;

    showResults();

    setStatusFromMessage(MESSAGES.scanCompleted, {
        count: findings.length
    });
}

reportBtn.addEventListener(
    "click",
    async () => {

        try {

            const stored =
                await chrome.storage.local.get([
                    "lastScanId",
                    "lastScanUrl"
                ]);

            const scanId =
                stored.lastScanId;

            if (!scanId) {

                throw new Error(
                    "No completed scan found. Please run a scan first."
                );
            }

            const token =
                await getAuthToken();

            if (!token) {

                throw new Error(
                    "Authentication required. Please run the scan again."
                );
            }

            reportBtn.disabled = true;

            reportBtn.textContent =
                MESSAGES.reportButtonLoading;

            setStatusFromMessage(MESSAGES.generatingReport);

            const response =
                await fetch(
                    `${API_BASE}/api/scan/${scanId}/ai-report`,
                    {
                        method: "GET",

                        headers: {
                            "Authorization":
                                `Bearer ${token}`
                        }
                    }
                );

            if (!response.ok) {

                let errorMessage =
                    `Report request failed with HTTP ${response.status}`;

                try {

                    const errorData =
                        await response.json();

                    errorMessage =
                        errorData.detail ||
                        errorData.message ||
                        errorMessage;

                } catch {
                    // Response was not JSON
                }

                if (response.status === 401) {
                    await clearAuth();
                }

                throw new Error(
                    errorMessage
                );
            }

            const contentType =
                response.headers.get(
                    "content-type"
                ) || "";

            if (
                !contentType
                    .toLowerCase()
                    .includes("application/pdf")
            ) {

                throw new Error(
                    "Backend did not return a PDF file."
                );
            }

            const pdfBlob =
                await response.blob();

            if (
                !pdfBlob ||
                pdfBlob.size === 0
            ) {

                throw new Error(
                    "Generated PDF is empty."
                );
            }

            const downloadUrl =
                URL.createObjectURL(
                    pdfBlob
                );

            await new Promise(
                (resolve, reject) => {

                    chrome.downloads.download(
                        {
                            url: downloadUrl,

                            filename:
                                `BlindSpot/blindspot-ai-report-${scanId.slice(0, 8)}.pdf`,

                            saveAs: false,

                            conflictAction:
                                "uniquify"
                        },

                        downloadId => {

                            if (
                                chrome.runtime.lastError
                            ) {

                                reject(
                                    new Error(
                                        chrome.runtime.lastError.message
                                    )
                                );

                                return;
                            }

                            if (
                                downloadId === undefined
                            ) {

                                reject(
                                    new Error(
                                        "Chrome could not start the PDF download."
                                    )
                                );

                                return;
                            }

                            resolve(
                                downloadId
                            );
                        }
                    );

                }
            );

            setTimeout(
                () => {
                    URL.revokeObjectURL(
                        downloadUrl
                    );
                },
                10000
            );

            setStatusFromMessage(MESSAGES.reportDownloaded);

            reportBtn.textContent =
                MESSAGES.reportButtonDefault;

        } catch (error) {

            console.error(
                "BlindSpot AI report error:",
                error
            );

            setStatus(
                MESSAGES.reportFailed.title,
                error.message ||
                MESSAGES.reportFailed.detail
            );

            reportBtn.textContent =
                MESSAGES.reportButtonDefault;

        } finally {

            reportBtn.disabled =
                false;
        }
    }
);

scanBtn.addEventListener(
    "click",
    async () => {

        hideResults();

        let url =
            targetUrl.value.trim();

        if (!url) {

            setStatusFromMessage(MESSAGES.urlRequired);

            targetUrl.focus();

            return;
        }

        if (!/^https?:\/\//i.test(url)) {
            url = "https://" + url;
        }

        targetUrl.value = url;

        setScanning(true);

        try {

            await ensureAuthenticated();

            setStatusFromMessage(MESSAGES.connecting);

            const scan =
                await submitScan(url);

            const scanId =
                scan.scan_id;

            if (!scanId) {

                throw new Error(
                    "Backend did not return a scan ID."
                );
            }

            await chrome.storage.local.set({

                lastScanId: scanId,

                lastScanUrl: url

            });

            setStatusFromMessage(MESSAGES.scanSubmitted, {
                scanId: scanId.substring(0, 8)
            });

            await waitForScan(scanId);

            setStatusFromMessage(MESSAGES.collectingResults);

            const resultData =
                await getScanResults(scanId);

            displayResults(
                resultData
            );

            await chrome.storage.local.set({

                lastScanId: scanId,

                lastScanUrl: url

            });

        } catch (error) {

            console.error(
                "BlindSpot scan error:",
                error
            );

            setStatus(
                MESSAGES.scanFailed.title,
                error.message ||
                MESSAGES.scanFailed.detail
            );

        } finally {

            setScanning(false);
        }
    }
);

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        hideResults();

        const currentUrl =
            await getCurrentTabUrl();

        if (
            currentUrl &&
            /^https?:\/\//i.test(currentUrl)
        ) {

            targetUrl.value =
                currentUrl;
        }

        const token =
            await getAuthToken();

        if (token) {

            setStatusFromMessage(MESSAGES.ready);

        } else {

            setStatusFromMessage(MESSAGES.readyNoAuth);
        }
    }
);
