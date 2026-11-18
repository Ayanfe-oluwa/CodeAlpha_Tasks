
const API_BASE = "";

let authToken = sessionStorage.getItem("secureguard_token") || "";
let loggedInEmail = sessionStorage.getItem("secureguard_email") || "";

// DOM elements
const scannerForm = document.getElementById("scanner-form");
const scanInput = document.getElementById("scan-input");
const scanButton = document.getElementById("scan-button");
const scanResult = document.getElementById("scan-result");

const eventsTableBody = document.getElementById("events-table-body");
const refreshButton = document.getElementById("refresh-events");

const loginForm = document.getElementById("login-form");
const registerForm = document.getElementById("register-form");

const loginTab = document.getElementById("login-tab");
const registerTab = document.getElementById("register-tab");

const loginButton = document.getElementById("login-button");
const registerButton = document.getElementById("register-button");

const authMessage = document.getElementById("auth-message");
const accountStatus = document.getElementById("account-status");
const accountEmail = document.getElementById("account-email");
const logoutButton = document.getElementById("logout-button");


// Display authentication messages safely
function showAuthMessage(message, type = "error") {
    if (!authMessage) return;

    authMessage.textContent = message;
    authMessage.className = `auth-message ${type}`;
    authMessage.classList.remove("hidden");
}

function hideAuthMessage() {
    if (!authMessage) return;

    authMessage.textContent = "";
    authMessage.classList.add("hidden");
}


// Switch between login and registration
function showAuthTab(tab) {
    hideAuthMessage();

    const showLogin = tab === "login";

    loginForm?.classList.toggle("hidden", !showLogin);
    registerForm?.classList.toggle("hidden", showLogin);

    loginTab?.classList.toggle("active", showLogin);
    registerTab?.classList.toggle("active", !showLogin);
}

loginTab?.addEventListener("click", () => showAuthTab("login"));
registerTab?.addEventListener("click", () => showAuthTab("register"));


// Update account display
function updateAuthUI() {
    if (authToken && loggedInEmail) {
        loginForm?.classList.add("hidden");
        registerForm?.classList.add("hidden");
        loginTab?.classList.add("hidden");
        registerTab?.classList.add("hidden");

        accountStatus?.classList.remove("hidden");

        if (accountEmail) {
            accountEmail.textContent = loggedInEmail;
        }
    } else {
        accountStatus?.classList.add("hidden");
        loginTab?.classList.remove("hidden");
        registerTab?.classList.remove("hidden");

        showAuthTab("login");
    }
}


// Registration
registerForm?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("register-email").value.trim();
    const password = document.getElementById("register-password").value;
    const sensitiveData = document.getElementById("register-data").value.trim();

    registerButton.disabled = true;
    registerButton.textContent = "Creating account...";

    hideAuthMessage();

    try {
        const response = await fetch(`${API_BASE}/register`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password,
                sensitive_data: sensitiveData
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Registration failed.");
        }

        registerForm.reset();

        showAuthTab("login");
        showAuthMessage(
            "Account created successfully. You can now log in.",
            "success"
        );

        document.getElementById("login-email").value = email;

    } catch (error) {
        showAuthMessage(error.message);
    } finally {
        registerButton.disabled = false;
        registerButton.textContent = "Create Account";
    }
});


// Login
loginForm?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const email = document.getElementById("login-email").value.trim();
    const password = document.getElementById("login-password").value;

    loginButton.disabled = true;
    loginButton.textContent = "Signing in...";

    hideAuthMessage();

    try {
        const response = await fetch(`${API_BASE}/login`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                email: email,
                password: password
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Login failed.");
        }

        if (!data.access_token) {
            throw new Error("The server did not return an authentication token.");
        }

        authToken = data.access_token;
        loggedInEmail = email;

        sessionStorage.setItem("secureguard_token", authToken);
        sessionStorage.setItem("secureguard_email", loggedInEmail);

        loginForm.reset();

        updateAuthUI();

        showAuthMessage("Login successful. Your account is now active.", "success");

        await loadSecurityEvents();
        await loadDashboardSummary();

    } catch (error) {
        showAuthMessage(error.message);
    } finally {
        loginButton.disabled = false;
        loginButton.textContent = "Login";
    }
});


// Logout
logoutButton?.addEventListener("click", () => {
    authToken = "";
    loggedInEmail = "";

    sessionStorage.removeItem("secureguard_token");
    sessionStorage.removeItem("secureguard_email");

    updateAuthUI();

    if (eventsTableBody) {
        eventsTableBody.replaceChildren();
    }

    showAuthMessage("You have been logged out successfully.", "success");

    loadDashboardSummary();
});


// API health monitoring
async function checkSystemHealth() {
    const statusElement = document.getElementById("api-status");

    if (!statusElement) return;

    try {
        const response = await fetch(`${API_BASE}/health`);

        if (!response.ok) {
            throw new Error("API unavailable");
        }

        statusElement.textContent = "Online";
        statusElement.classList.add("online");
        statusElement.classList.remove("offline");

    } catch (error) {
        statusElement.textContent = "Offline";
        statusElement.classList.add("offline");
        statusElement.classList.remove("online");
    }
}


// Display scanner results
function showScanResult(message, isSuspicious) {
    if (!scanResult) return;

    scanResult.textContent = message;
    scanResult.classList.remove("hidden", "safe", "danger");

    scanResult.classList.add(isSuspicious ? "danger" : "safe");
}


// SQL injection scanner
scannerForm?.addEventListener("submit", async (event) => {
    event.preventDefault();

    const value = scanInput.value.trim();

    if (!value) {
        showScanResult("Enter text to scan.", true);
        return;
    }

    scanButton.disabled = true;
    scanButton.textContent = "Scanning...";

    try {
        const response = await fetch(`${API_BASE}/security-check`, {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                input: value
            })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.detail || "Security scan failed.");
        }

        showScanResult(
            `${data.message} Matched patterns: ${data.matched_patterns}.`,
            data.is_suspicious
        );

        if (authToken) {
            await loadSecurityEvents();
            await loadDashboardSummary();
        }

    } catch (error) {
        showScanResult(error.message, true);
    } finally {
        scanButton.disabled = false;
        scanButton.textContent = "Run Security Scan";
    }
});


// Retrieve authenticated security events
async function loadSecurityEvents() {
    if (!eventsTableBody) return;

    if (!authToken) {
        eventsTableBody.textContent = "Log in to view your security events.";
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/security-events`, {
            headers: {
                "Authorization": `Bearer ${authToken}`
            }
        });

        const data = await response.json();

        if (!response.ok) {
            if (response.status === 401 || response.status === 403) {
                handleExpiredSession();
                return;
            }

            throw new Error(data.detail || "Unable to retrieve security events.");
        }

        eventsTableBody.replaceChildren();

        if (!Array.isArray(data) || data.length === 0) {
            eventsTableBody.textContent = "No security events recorded yet.";
            return;
        }

        data.forEach((event) => {
            const row = document.createElement("tr");

            const values = [
                event.id,
                event.event_type,
                event.severity,
                event.description,
                event.created_at
                    ? new Date(event.created_at).toLocaleString()
                    : "Not available"
            ];

            values.forEach((value) => {
                const cell = document.createElement("td");
                cell.textContent = String(value ?? "");
                row.appendChild(cell);
            });

            eventsTableBody.appendChild(row);
        });

    } catch (error) {
        eventsTableBody.textContent = error.message;
    }
}


// Dashboard statistics
async function loadDashboardSummary() {
    const threatCount = document.getElementById("threat-count");
    const userCount = document.getElementById("user-count");
    const eventCount = document.getElementById("event-count");

    if (!authToken) {
        if (threatCount) threatCount.textContent = "--";
        if (userCount) userCount.textContent = "--";
        if (eventCount) eventCount.textContent = "--";
        return;
    }

    try {
        const response = await fetch(`${API_BASE}/dashboard/summary`, {
            headers: {
                "Authorization": `Bearer ${authToken}`
            }
        });

        if (!response.ok) {
            return;
        }

        const data = await response.json();

        if (threatCount) {
            threatCount.textContent = data.threats_detected ?? 0;
        }

        if (userCount) {
            userCount.textContent = data.account_count ?? 1;
        }

        if (eventCount) {
            eventCount.textContent = data.security_events ?? 0;
        }

    } catch (error) {
        console.error("Dashboard statistics unavailable.");
    }
}


// Handle expired login sessions
function handleExpiredSession() {
    authToken = "";
    loggedInEmail = "";

    sessionStorage.removeItem("secureguard_token");
    sessionStorage.removeItem("secureguard_email");

    updateAuthUI();
    showAuthMessage("Your session has expired. Please log in again.");
}


// Refresh security events
refreshButton?.addEventListener("click", loadSecurityEvents);


// Sidebar navigation
document.querySelectorAll(".nav-link").forEach((link) => {
    link.addEventListener("click", () => {
        document.querySelectorAll(".nav-link").forEach((item) => {
            item.classList.remove("active");
        });

        link.classList.add("active");
    });
});


// Initialize dashboard
document.addEventListener("DOMContentLoaded", () => {
    updateAuthUI();
    checkSystemHealth();
    loadSecurityEvents();
    loadDashboardSummary();
});
