// ============================================
// BlindSpot Chrome Extension
// ============================================

const API_BASE = "http://127.0.0.1:8000";


// ============================================
// DOM ELEMENTS
// ============================================

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


// ============================================
// HELPERS
// ============================================

function setStatus(title, detail) {
    statusText.textContent = title;
    statusDetail.textContent = detail;
}

function setScanning(scanning) {
    scanBtn.disabled = scanning;

    if (scanning) {
        scanText.textContent = "SCANNING...";
        spinner.classList.remove("hidden");
    } else {
        scanText.textContent = "START SCAN";
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


// ============================================
// AUTH STORAGE
// ============================================

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


// ============================================
// API REQUEST HELPER
// ============================================

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


// ============================================
// LOGIN
// ============================================

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


// ============================================
// ENSURE AUTHENTICATION
// ============================================

async function ensureAuthenticated() {

    const existingToken = await getAuthToken();

    if (existingToken) {
        return true;
    }

    setStatus(
        "Authenticating",
        "Logging in to BlindSpot backend..."
    );

    await login("admin", "admin123");

    return true;
}


// ============================================
// GET TARGET FROM CURRENT TAB
// ============================================

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


// ============================================
// SUBMIT SCAN
// ============================================

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


// ============================================
// CHECK SCAN STATUS
// ============================================

async function getScanStatus(scanId) {

    return await apiRequest(
        `/api/scan/${scanId}`
    );
}


// ============================================
// GET FINAL RESULTS
// ============================================

async function getScanResults(scanId) {

    return await apiRequest(
        `/api/scan/${scanId}/results`
    );
}


// ============================================
// WAIT FOR SCAN
// ============================================

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

        setStatus(
            currentStatus.toUpperCase(),
            `Scan progress: ${progress}%`
        );

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

    throw new Error("Scan timed out.");
}


// ============================================
// DISPLAY RESULTS
// ============================================

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

    setStatus(
        "Scan completed",
        `${findings.length} security finding(s) detected.`
    );
}


// ============================================
// DOWNLOAD AI PDF SECURITY REPORT
// ============================================

reportBtn.addEventListener(
    "click",
    async () => {

        try {

            // ----------------------------------------
            // Get last completed scan
            // ----------------------------------------

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


            // ----------------------------------------
            // Authentication
            // ----------------------------------------

            const token =
                await getAuthToken();

            if (!token) {

                throw new Error(
                    "Authentication required. Please run the scan again."
                );
            }


            // ----------------------------------------
            // UI state
            // ----------------------------------------

            reportBtn.disabled = true;

            const originalText =
                reportBtn.textContent;

            reportBtn.textContent =
                "Generating AI Report...";

            setStatus(
                "Generating report",
                "Creating your professional AI security assessment PDF..."
            );


            // ----------------------------------------
            // Request AI PDF from backend
            // ----------------------------------------

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


            // ----------------------------------------
            // Handle HTTP errors
            // ----------------------------------------

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


            // ----------------------------------------
            // Make sure backend returned PDF
            // ----------------------------------------

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


            // ----------------------------------------
            // Read PDF bytes
            // ----------------------------------------

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


            // ----------------------------------------
            // Create temporary browser URL
            // ----------------------------------------

            const downloadUrl =
                URL.createObjectURL(
                    pdfBlob
                );


            // ----------------------------------------
            // Download to Windows Downloads folder
            // ----------------------------------------

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


            // ----------------------------------------
            // Cleanup
            // ----------------------------------------

            setTimeout(
                () => {
                    URL.revokeObjectURL(
                        downloadUrl
                    );
                },
                10000
            );


            // ----------------------------------------
            // Success
            // ----------------------------------------

            setStatus(
                "Report downloaded",
                "AI security report saved to your Downloads folder."
            );


            reportBtn.textContent =
                "Download AI Security Report";


        } catch (error) {

            console.error(
                "BlindSpot AI report error:",
                error
            );

            setStatus(
                "Report failed",
                error.message ||
                "Could not generate or download the AI report."
            );

            reportBtn.textContent =
                "Download AI Security Report";

        } finally {

            reportBtn.disabled =
                false;
        }
    }
);


// ============================================
// MAIN SCAN FLOW
// ============================================

scanBtn.addEventListener(
    "click",
    async () => {

        hideResults();

        let url =
            targetUrl.value.trim();

        if (!url) {

            setStatus(
                "URL required",
                "Enter a website URL before starting the scan."
            );

            targetUrl.focus();

            return;
        }


        // ----------------------------------------
        // URL normalization
        // ----------------------------------------

        if (!/^https?:\/\//i.test(url)) {
            url = "https://" + url;
        }

        targetUrl.value = url;

        setScanning(true);


        try {

            // ----------------------------------------
            // Authentication
            // ----------------------------------------

            await ensureAuthenticated();


            // ----------------------------------------
            // Submit scan
            // ----------------------------------------

            setStatus(
                "Connecting",
                "Submitting target to BlindSpot..."
            );

            const scan =
                await submitScan(url);

            const scanId =
                scan.scan_id;

            if (!scanId) {

                throw new Error(
                    "Backend did not return a scan ID."
                );
            }


            // ----------------------------------------
            // Save scan immediately
            // ----------------------------------------

            await chrome.storage.local.set({

                lastScanId: scanId,

                lastScanUrl: url

            });


            setStatus(
                "Scan submitted",
                `Scan ID: ${scanId.substring(0, 8)}...`
            );


            // ----------------------------------------
            // Wait for completion
            // ----------------------------------------

            await waitForScan(scanId);


            // ----------------------------------------
            // Get final results
            // ----------------------------------------

            setStatus(
                "Collecting results",
                "Retrieving security findings..."
            );

            const resultData =
                await getScanResults(scanId);


            // ----------------------------------------
            // Display results
            // ----------------------------------------

            displayResults(
                resultData
            );


            // ----------------------------------------
            // Save completed scan
            // ----------------------------------------

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
                "Scan failed",
                error.message ||
                "Something went wrong."
            );

        } finally {

            setScanning(false);
        }
    }
);


// ============================================
// INITIALIZE POPUP
// ============================================

document.addEventListener(
    "DOMContentLoaded",
    async () => {

        hideResults();

        const currentUrl =
            await getCurrentTabUrl();

        // Automatically populate HTTP/HTTPS websites

        if (
            currentUrl &&
            /^https?:\/\//i.test(currentUrl)
        ) {

            targetUrl.value =
                currentUrl;
        }


        // Check authentication

        const token =
            await getAuthToken();

        if (token) {

            setStatus(
                "Ready",
                "Authenticated with BlindSpot backend."
            );

        } else {

            setStatus(
                "Ready",
                "Click START SCAN to authenticate and scan."
            );
        }
    }
);
