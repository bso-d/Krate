/**
 * Krate Studio - Enterprise Single Page Application
 * 100% Offline / Zero Build Tooling / Pure Vanilla ES2022
 */
"use strict";

(function () {
  // --------------------------------------------------------------------------
  // Application State
  // --------------------------------------------------------------------------
  const state = {
    theme: localStorage.getItem("krate_theme") || "dark",
    csrfToken: null,
    authenticated: false,
    activeWorkspace: "kraft",
    workspaces: [],
    clusterStatus: null,
    doctorData: null,
    lagData: null,
    configData: null,
    usersData: null,
    activeView: "setup",
    activeJob: null, // { id, action, status }
    sseSource: null,
    lastEventId: 0,
    terminalLogs: [],
    autoScroll: true,
    terminalFilter: "",
    terminalExpanded: false,
    terminalMaximized: false,
    pendingSudoAction: null,
    tofuData: null,
  };

  // --------------------------------------------------------------------------
  // DOM Elements Cache
  // --------------------------------------------------------------------------
  const dom = {
    // Theme & Header
    html: document.documentElement,
    btnThemeToggle: document.getElementById("btn-theme-toggle"),
    selectWorkspace: document.getElementById("select-workspace"),
    badgeEdition: document.getElementById("badge-edition"),
    badgeClusterStatus: document.getElementById("badge-cluster-status"),
    badgeDoctorStatus: document.getElementById("badge-doctor-status"),
    textDoctorStatus: document.getElementById("text-doctor-status"),
    badgeDiskStatus: document.getElementById("badge-disk-status"),
    textDiskStatus: document.getElementById("text-disk-status"),
    badgeAuthStatus: document.getElementById("badge-auth-status"),
    textAuthStatus: document.getElementById("text-auth-status"),
    btnRemoteConnect: document.getElementById("btn-remote-connect"),
    btnToggleTerminal: document.getElementById("btn-toggle-terminal"),
    terminalBadgeStatus: document.getElementById("terminal-badge-status"),

    // Navigation
    navRail: document.getElementById("nav-rail"),
    navLinks: document.querySelectorAll(".nav-link"),
    viewPanels: document.querySelectorAll(".view-panel"),

    // View 1: Setup & Doctor
    btnRunDoctor: document.getElementById("btn-run-doctor"),
    btnQuickStart: document.getElementById("btn-quick-start"),
    tbodyDoctor: document.getElementById("tbody-doctor"),
    docBadgePassed: document.getElementById("doc-badge-passed"),
    docBadgeWarn: document.getElementById("doc-badge-warn"),
    docBadgeFailed: document.getElementById("doc-badge-failed"),
    btnStepDocker: document.getElementById("btn-step-docker"),
    btnStepCerts: document.getElementById("btn-step-certs"),
    btnStepImages: document.getElementById("btn-step-images"),
    btnStepStart: document.getElementById("btn-step-start"),

    // View 2: Cluster Services
    servicesGrid: document.getElementById("services-grid"),
    btnServicesHealth: document.getElementById("btn-services-health"),
    btnServicesRestart: document.getElementById("btn-services-restart"),
    btnServicesStop: document.getElementById("btn-services-stop"),
    btnServicesStart: document.getElementById("btn-services-start"),
    inputServicesSearch: document.getElementById("input-services-search"),
    pillFilters: document.querySelectorAll(".pill-filter"),

    // View 3: Lag Matrix
    btnRefreshLag: document.getElementById("btn-refresh-lag"),
    lagStatGroups: document.getElementById("lag-stat-groups"),
    lagStatGroupsSub: document.getElementById("lag-stat-groups-sub"),
    lagStatPartitions: document.getElementById("lag-stat-partitions"),
    lagStatMax: document.getElementById("lag-stat-max"),
    lagStatStatus: document.getElementById("lag-stat-status"),
    inputLagFilter: document.getElementById("input-lag-filter"),
    chkLagOnly: document.getElementById("chk-lag-only"),
    lagTreeContainer: document.getElementById("lag-tree-container"),

    // View 4: Config Editor
    configTabs: document.querySelectorAll(".config-tabs-bar .tab-btn"),
    configPanes: document.querySelectorAll(".config-pane"),
    configFieldsCluster: document.getElementById("config-fields-cluster"),
    configFieldsMonitoring: document.getElementById("config-fields-monitoring"),
    textareaRawConfig: document.getElementById("textarea-raw-config"),
    btnSaveConfig: document.getElementById("btn-save-config"),
    btnReloadConfig: document.getElementById("btn-reload-config"),

    // View 5: Identity & Users
    tbodyUsers: document.getElementById("tbody-users"),
    btnRefreshUsers: document.getElementById("btn-refresh-users"),
    btnOpenAddUser: document.getElementById("btn-open-add-user"),
    btnOpenRotateModal: document.getElementById("btn-open-rotate-modal"),
    btnBackupIdentity: document.getElementById("btn-backup-identity"),
    identityStatStatus: document.getElementById("identity-stat-status"),
    identityStatCount: document.getElementById("identity-stat-count"),

    // View 6: SSO Wizard
    btnRunSso: document.getElementById("btn-run-sso"),
    btnSsoFallback: document.getElementById("btn-sso-fallback"),
    selectSsoTarget: document.getElementById("select-sso-target"),
    selectSsoMode: document.getElementById("select-sso-mode"),
    ssoPipelineStatus: document.getElementById("sso-pipeline-status"),

    // View 7: Observability
    btnMonitorToggle: document.getElementById("btn-monitor-toggle"),

    // View 8: Release & Gates
    btnRunGates: document.getElementById("btn-run-gates"),
    formRemoteSsh: document.getElementById("form-remote-ssh"),
    inputRemoteHost: document.getElementById("input-remote-host"),
    inputRemoteUser: document.getElementById("input-remote-user"),
    inputRemotePort: document.getElementById("input-remote-port"),
    inputRemotePass: document.getElementById("input-remote-pass"),
    btnRemoteVerify: document.getElementById("btn-remote-verify"),

    // Terminal Drawer
    terminalDrawer: document.getElementById("terminal-drawer"),
    drawerHeader: document.getElementById("drawer-header"),
    btnToggleDrawerArrow: document.getElementById("btn-toggle-drawer-arrow"),
    terminalActionPill: document.getElementById("terminal-action-pill"),
    terminalConnStatus: document.getElementById("terminal-conn-status"),
    inputTerminalFilter: document.getElementById("input-terminal-filter"),
    chkTerminalAutoscroll: document.getElementById("chk-terminal-autoscroll"),
    btnTerminalClear: document.getElementById("btn-terminal-clear"),
    btnTerminalExpand: document.getElementById("btn-terminal-expand"),
    terminalPre: document.querySelector(".terminal-pre"),
    terminalCode: document.getElementById("terminal-code"),

    // Modals
    modalSudo: document.getElementById("modal-sudo"),
    inputSudoPassword: document.getElementById("input-sudo-password"),
    btnSudoCancel: document.getElementById("btn-sudo-cancel"),
    btnSudoSubmit: document.getElementById("btn-sudo-submit"),
    modalSudoActionDesc: document.getElementById("modal-sudo-action-desc"),

    modalOtp: document.getElementById("modal-otp"),
    otpUsername: document.getElementById("otp-username"),
    otpPassword: document.getElementById("otp-password"),
    btnOtpCopy: document.getElementById("btn-otp-copy"),
    textOtpCopy: document.getElementById("text-otp-copy"),
    btnOtpDone: document.getElementById("btn-otp-done"),

    modalPurge: document.getElementById("modal-purge"),
    inputPurgeConfirm: document.getElementById("input-purge-confirm"),
    chkPurgeConfirm: document.getElementById("chk-purge-confirm"),
    btnPurgeCancel: document.getElementById("btn-purge-cancel"),
    btnPurgeSubmit: document.getElementById("btn-purge-submit"),

    modalRotate: document.getElementById("modal-rotate"),
    selectRotateKey: document.getElementById("select-rotate-key"),
    inputRotateValue: document.getElementById("input-rotate-value"),
    btnGenerateSecret: document.getElementById("btn-generate-secret"),
    btnRotateCancel: document.getElementById("btn-rotate-cancel"),
    btnRotateSubmit: document.getElementById("btn-rotate-submit"),

    modalAddUser: document.getElementById("modal-add-user"),
    inputNewUsername: document.getElementById("input-new-username"),
    inputNewEmail: document.getElementById("input-new-email"),
    chkRoleAdmin: document.getElementById("chk-role-admin"),
    chkRoleViewer: document.getElementById("chk-role-viewer"),
    btnAddUserCancel: document.getElementById("btn-add-user-cancel"),
    btnAddUserSubmit: document.getElementById("btn-add-user-submit"),

    modalTofu: document.getElementById("modal-tofu"),
    tofuTargetHost: document.getElementById("tofu-target-host"),
    tofuKeyType: document.getElementById("tofu-key-type"),
    tofuFingerprint: document.getElementById("tofu-fingerprint"),
    btnTofuReject: document.getElementById("btn-tofu-reject"),
    btnTofuAccept: document.getElementById("btn-tofu-accept"),

    toastContainer: document.getElementById("toast-container"),
  };

  // --------------------------------------------------------------------------
  // Theme Management
  // --------------------------------------------------------------------------
  function applyTheme(theme) {
    state.theme = theme;
    dom.html.setAttribute("data-theme", theme);
    localStorage.setItem("krate_theme", theme);
  }

  function toggleTheme() {
    applyTheme(state.theme === "dark" ? "light" : "dark");
  }

  // --------------------------------------------------------------------------
  // Toast Notifications
  // --------------------------------------------------------------------------
  function showToast(message, type = "info", duration = 3500) {
    const toast = document.createElement("div");
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    dom.toastContainer.appendChild(toast);

    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateY(-8px)";
      toast.style.transition = "all 0.25s ease";
      setTimeout(() => toast.remove(), 250);
    }, duration);
  }

  // --------------------------------------------------------------------------
  // Modals Framework
  // --------------------------------------------------------------------------
  function openModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.add("open");
  }

  function closeModal(modalEl) {
    if (!modalEl) return;
    modalEl.classList.remove("open");
  }

  function setupModals() {
    // Backdrop clicks close modal (if not clicked inside dialog)
    document.querySelectorAll(".modal-backdrop").forEach((backdrop) => {
      backdrop.addEventListener("click", (e) => {
        if (e.target === backdrop) {
          closeModal(backdrop);
        }
      });
    });

    // Escape key closes open modals
    window.addEventListener("keydown", (e) => {
      if (e.key === "Escape") {
        document.querySelectorAll(".modal-backdrop.open").forEach((m) => closeModal(m));
      }
    });

    // Sudo Modal controls
    dom.btnSudoCancel?.addEventListener("click", () => {
      closeModal(dom.modalSudo);
      state.pendingSudoAction = null;
    });

    dom.btnSudoSubmit?.addEventListener("click", () => {
      const password = dom.inputSudoPassword.value;
      if (!password) {
        showToast("Please enter sudo password", "warning");
        return;
      }
      closeModal(dom.modalSudo);
      dom.inputSudoPassword.value = "";
      if (state.pendingSudoAction) {
        const { action, params, args } = state.pendingSudoAction;
        state.pendingSudoAction = null;
        triggerJob(action, params, args, password);
      }
    });

    // OTP Modal controls
    dom.btnOtpDone?.addEventListener("click", () => {
      closeModal(dom.modalOtp);
    });

    dom.btnOtpCopy?.addEventListener("click", async () => {
      const text = dom.otpPassword.textContent;
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(text);
        } else {
          const ta = document.createElement("textarea");
          ta.value = text;
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          ta.remove();
        }
        dom.textOtpCopy.textContent = "Copied!";
        setTimeout(() => {
          dom.textOtpCopy.textContent = "Copy to Clipboard";
        }, 2000);
        showToast("Password copied to clipboard!", "success");
      } catch (err) {
        showToast("Failed to copy automatically. Please copy manually.", "warning");
      }
    });

    // Purge Modal controls
    function validatePurge() {
      const textMatches = dom.inputPurgeConfirm.value.trim() === "PURGE";
      const checked = dom.chkPurgeConfirm.checked;
      dom.btnPurgeSubmit.disabled = !(textMatches && checked);
    }
    dom.inputPurgeConfirm?.addEventListener("input", validatePurge);
    dom.chkPurgeConfirm?.addEventListener("change", validatePurge);

    dom.btnPurgeCancel?.addEventListener("click", () => {
      closeModal(dom.modalPurge);
      dom.inputPurgeConfirm.value = "";
      dom.chkPurgeConfirm.checked = false;
      dom.btnPurgeSubmit.disabled = true;
    });

    dom.btnPurgeSubmit?.addEventListener("click", () => {
      closeModal(dom.modalPurge);
      dom.inputPurgeConfirm.value = "";
      dom.chkPurgeConfirm.checked = false;
      dom.btnPurgeSubmit.disabled = true;
      triggerJob("uninstall", { purge: true });
    });

    // Secret Rotate Modal controls
    dom.btnGenerateSecret?.addEventListener("click", () => {
      const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+";
      const array = new Uint8Array(24);
      window.crypto.getRandomValues(array);
      let res = "";
      for (let i = 0; i < array.length; i++) {
        res += charset[array[i] % charset.length];
      }
      dom.inputRotateValue.value = res;
    });

    dom.btnRotateCancel?.addEventListener("click", () => {
      closeModal(dom.modalRotate);
    });

    dom.btnRotateSubmit?.addEventListener("click", () => {
      const key = dom.selectRotateKey.value;
      const value = dom.inputRotateValue.value.trim();
      if (!value) {
        showToast("Secret value cannot be empty", "warning");
        return;
      }
      closeModal(dom.modalRotate);
      triggerJob("identity_rotate", { key, value });
    });

    // Add User Modal controls
    dom.btnAddUserCancel?.addEventListener("click", () => {
      closeModal(dom.modalAddUser);
    });

    dom.btnAddUserSubmit?.addEventListener("click", () => {
      const username = dom.inputNewUsername.value.trim();
      const email = dom.inputNewEmail.value.trim();
      const isAdmin = dom.chkRoleAdmin.checked;
      const isViewer = dom.chkRoleViewer.checked;

      if (!username) {
        showToast("Username is required", "warning");
        return;
      }

      closeModal(dom.modalAddUser);
      dom.inputNewUsername.value = "";
      dom.inputNewEmail.value = "";

      triggerJob("identity_users_add", {
        username,
        email,
        admin: isAdmin,
        viewer: isViewer,
      });
    });

    // TOFU Modal controls
    dom.btnTofuReject?.addEventListener("click", () => {
      closeModal(dom.modalTofu);
      state.tofuData = null;
      showToast("Remote host connection aborted", "info");
    });

    dom.btnTofuAccept?.addEventListener("click", async () => {
      if (!state.tofuData) return;
      closeModal(dom.modalTofu);
      try {
        showToast("Connecting to remote host...", "info");
        const res = await apiFetch("/api/v1/remote/connect", {
          method: "POST",
          body: {
            host: state.tofuData.host,
            port: state.tofuData.port,
            user: state.tofuData.user,
            password: state.tofuData.password,
            fingerprint_confirmed: true,
          },
        });
        showToast("Remote host connected successfully!", "success");
      } catch (err) {
        showToast(`Remote connection error: ${err.message}`, "danger");
      } finally {
        state.tofuData = null;
      }
    });
  }

  // --------------------------------------------------------------------------
  // REST API Client with CSRF Guard & Sudo Handling
  // --------------------------------------------------------------------------
  async function apiFetch(endpoint, options = {}) {
    const headers = options.headers ? { ...options.headers } : {};

    const method = (options.method || "GET").toUpperCase();
    if (["POST", "PUT", "DELETE"].includes(method)) {
      if (state.csrfToken) {
        headers["X-Krate-CSRF"] = state.csrfToken;
      }
    }

    if (options.body && typeof options.body === "object" && !(options.body instanceof FormData)) {
      headers["Content-Type"] = "application/json";
      options.body = JSON.stringify(options.body);
    }

    const fetchOptions = {
      ...options,
      headers,
      credentials: "same-origin",
    };

    let response;
    try {
      response = await fetch(endpoint, fetchOptions);
    } catch (netErr) {
      throw new Error(`Network failure connecting to ${endpoint}: ${netErr.message}`);
    }

    // Capture CSRF token if returned in header
    const respCsrf = response.headers.get("X-Krate-CSRF");
    if (respCsrf) {
      state.csrfToken = respCsrf;
    }

    let data;
    const contentType = response.headers.get("content-type");
    if (contentType && contentType.includes("application/json")) {
      data = await response.json();
    } else {
      data = await response.text();
    }

    // Handle Sudo Challenge
    if (response.status === 403 && data && data.needs_sudo) {
      dom.modalSudoActionDesc.textContent =
        data.message || "This operation requires root permissions on the host system (via sudo -A).";
      openModal(dom.modalSudo);
      throw new Error("Root privileges required");
    }

    if (!response.ok) {
      const errMsg = (data && (data.error || data.message)) || `HTTP ${response.status} ${response.statusText}`;
      const err = new Error(errMsg);
      err.status = response.status;
      err.data = data;
      throw err;
    }

    return data;
  }

  // --------------------------------------------------------------------------
  // Authentication & Bootstrap Flow
  // --------------------------------------------------------------------------
  async function initializeAuth() {
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get("token");

    if (token) {
      try {
        const res = await apiFetch("/api/v1/auth/bootstrap", {
          method: "POST",
          body: { token },
        });
        if (res.authenticated) {
          state.authenticated = true;
          state.csrfToken = res.csrf_token;
          showToast("Bootstrap authentication successful", "success");
        }
      } catch (err) {
        showToast(`Bootstrap token failed: ${err.message}`, "danger");
      } finally {
        // Strip token from browser address bar for security
        const cleanUrl = window.location.pathname + window.location.hash;
        window.history.replaceState({}, document.title, cleanUrl);
      }
    } else {
      // Check current session
      try {
        const res = await apiFetch("/api/v1/auth/session");
        if (res.authenticated) {
          state.authenticated = true;
          state.csrfToken = res.csrf_token;
        }
      } catch (err) {
        // Not authenticated yet
      }
    }

    updateAuthDisplay();
  }

  function updateAuthDisplay() {
    if (state.authenticated) {
      dom.badgeAuthStatus.className = "status-pill status-success";
      dom.textAuthStatus.textContent = "Session Active";
    } else {
      dom.badgeAuthStatus.className = "status-pill status-warning";
      dom.textAuthStatus.textContent = "Guest Mode";
    }
  }

  // --------------------------------------------------------------------------
  // ANSI Color Code Parser for Live Terminal
  // --------------------------------------------------------------------------
  function escapeHtml(text) {
    return text
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  const ANSI_COLOR_MAP = {
    "30": "ansi-black",
    "31": "ansi-red",
    "32": "ansi-green",
    "33": "ansi-yellow",
    "34": "ansi-blue",
    "35": "ansi-magenta",
    "36": "ansi-cyan",
    "37": "ansi-white",
    "90": "ansi-bright-black",
    "91": "ansi-bright-red",
    "92": "ansi-bright-green",
    "93": "ansi-bright-yellow",
    "94": "ansi-bright-blue",
    "95": "ansi-bright-magenta",
    "96": "ansi-bright-cyan",
    "97": "ansi-bright-white",
  };

  function parseAnsi(rawText) {
    if (!rawText) return "";

    const segments = rawText.split(/\u001b\[/);
    if (segments.length === 1) {
      return escapeHtml(rawText);
    }

    let result = escapeHtml(segments[0]);
    let activeClasses = [];

    for (let i = 1; i < segments.length; i++) {
      const seg = segments[i];
      const match = seg.match(/^([0-9;]*)m([\s\S]*)$/);
      if (!match) {
        result += escapeHtml(seg);
        continue;
      }

      const codes = match[1] ? match[1].split(";") : ["0"];
      const content = match[2];

      for (const code of codes) {
        if (code === "0" || code === "") {
          activeClasses = [];
        } else if (code === "1") {
          if (!activeClasses.includes("ansi-bold")) activeClasses.push("ansi-bold");
        } else if (code === "2") {
          if (!activeClasses.includes("ansi-dim")) activeClasses.push("ansi-dim");
        } else if (code === "3") {
          if (!activeClasses.includes("ansi-italic")) activeClasses.push("ansi-italic");
        } else if (code === "4") {
          if (!activeClasses.includes("ansi-underline")) activeClasses.push("ansi-underline");
        } else if (ANSI_COLOR_MAP[code]) {
          // Remove previous color
          activeClasses = activeClasses.filter((c) => !c.startsWith("ansi-"));
          activeClasses.push(ANSI_COLOR_MAP[code]);
        }
      }

      if (content) {
        if (activeClasses.length > 0) {
          result += `<span class="${activeClasses.join(" ")}">${escapeHtml(content)}</span>`;
        } else {
          result += escapeHtml(content);
        }
      }
    }

    return result;
  }

  // --------------------------------------------------------------------------
  // Live Terminal Drawer & SSE Client
  // --------------------------------------------------------------------------
  function openTerminalDrawer() {
    dom.terminalDrawer.classList.remove("collapsed");
    state.terminalExpanded = true;
    scrollTerminalToBottom();
  }

  function collapseTerminalDrawer() {
    dom.terminalDrawer.classList.add("collapsed");
    dom.terminalDrawer.classList.remove("maximized");
    state.terminalExpanded = false;
    state.terminalMaximized = false;
  }

  function toggleTerminalDrawer() {
    if (dom.terminalDrawer.classList.contains("collapsed")) {
      openTerminalDrawer();
    } else {
      collapseTerminalDrawer();
    }
  }

  function toggleTerminalMaximize() {
    if (dom.terminalDrawer.classList.contains("maximized")) {
      dom.terminalDrawer.classList.remove("maximized");
      state.terminalMaximized = false;
    } else {
      dom.terminalDrawer.classList.add("maximized");
      dom.terminalDrawer.classList.remove("collapsed");
      state.terminalMaximized = true;
      state.terminalExpanded = true;
    }
    scrollTerminalToBottom();
  }

  function appendTerminalLine(text, stream = "stdout") {
    state.terminalLogs.push({ text, stream });
    if (state.terminalLogs.length > 5000) {
      state.terminalLogs.shift();
    }

    const lineEl = document.createElement("span");
    lineEl.className = `terminal-line ${stream === "stderr" ? "stderr" : ""}`;
    lineEl.innerHTML = parseAnsi(text);

    // Apply live filter if active
    if (state.terminalFilter && !text.toLowerCase().includes(state.terminalFilter.toLowerCase())) {
      lineEl.style.display = "none";
    }

    dom.terminalCode.appendChild(lineEl);

    if (state.autoScroll) {
      scrollTerminalToBottom();
    }
  }

  function scrollTerminalToBottom() {
    if (dom.terminalPre) {
      dom.terminalPre.scrollTop = dom.terminalPre.scrollHeight;
    }
  }

  function clearTerminal() {
    state.terminalLogs = [];
    dom.terminalCode.innerHTML = "";
  }

  function filterTerminalLines() {
    const filter = dom.inputTerminalFilter.value.toLowerCase().trim();
    state.terminalFilter = filter;
    const lines = dom.terminalCode.querySelectorAll(".terminal-line");
    lines.forEach((line) => {
      if (!filter || line.textContent.toLowerCase().includes(filter)) {
        line.style.display = "block";
      } else {
        line.style.display = "none";
      }
    });
  }

  function connectJobStream(jobId) {
    if (state.sseSource) {
      state.sseSource.close();
    }

    openTerminalDrawer();
    dom.terminalConnStatus.textContent = "Connecting...";
    dom.terminalConnStatus.className = "terminal-conn";

    const sseUrl = `/api/v1/jobs/${jobId}/stream?last_event_id=${state.lastEventId}`;
    const source = new EventSource(sseUrl);
    state.sseSource = source;

    source.onopen = () => {
      dom.terminalConnStatus.textContent = "Connected (SSE)";
      dom.terminalConnStatus.className = "terminal-conn connected";
    };

    source.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (payload.seq) {
          state.lastEventId = payload.seq;
        }
        appendTerminalLine(payload.text || "", payload.stream || "stdout");
      } catch (e) {
        appendTerminalLine(event.data);
      }
    };

    source.addEventListener("done", (event) => {
      try {
        const payload = JSON.parse(event.data);
        const isSuccess = payload.status === "succeeded";
        appendTerminalLine(`\n[System] Job finished with status: ${payload.status} (exit code: ${payload.exit_code})`, isSuccess ? "stdout" : "stderr");

        // Handle ephemeral one-time credentials
        if (payload.ephemeral && payload.ephemeral.one_time_password) {
          showOtpRevealCard(payload.ephemeral.user || "admin", payload.ephemeral.one_time_password);
        }

        dom.terminalBadgeStatus.textContent = isSuccess ? "Done" : "Failed";
        dom.terminalBadgeStatus.className = isSuccess ? "badge-counter text-success" : "badge-counter text-danger";
        dom.terminalActionPill.textContent = "Idle";
        dom.terminalActionPill.className = "terminal-pill";

        showToast(`Job ${state.activeJob?.action || ""} ${payload.status}`, isSuccess ? "success" : "danger");
      } catch (e) {
        console.error("Error parsing done event:", e);
      } finally {
        source.close();
        state.sseSource = null;
        state.activeJob = null;
        fetchStatus();
      }
    });

    source.onerror = () => {
      dom.terminalConnStatus.textContent = "Reconnecting...";
      dom.terminalConnStatus.className = "terminal-conn";
    };
  }

  function showOtpRevealCard(username, password) {
    dom.otpUsername.textContent = username;
    dom.otpPassword.textContent = password;
    openModal(dom.modalOtp);
  }

  // --------------------------------------------------------------------------
  // Job Triggers & Supervisors
  // --------------------------------------------------------------------------
  async function triggerJob(action, params = {}, args = [], sudoPassword = null) {
    if (state.activeJob && state.activeJob.status === "running") {
      showToast("Another task is currently running", "warning");
      return;
    }

    try {
      dom.terminalBadgeStatus.textContent = "Running";
      dom.terminalBadgeStatus.className = "badge-counter text-warning";
      dom.terminalActionPill.textContent = `Running: ${action}`;
      dom.terminalActionPill.className = "terminal-pill running";

      const payload = { action, params, args };
      if (sudoPassword) {
        payload.sudo_password = sudoPassword;
      }

      const res = await apiFetch("/api/v1/jobs", {
        method: "POST",
        body: payload,
      });

      state.activeJob = { id: res.job_id, action, status: "running" };
      state.lastEventId = 0;
      appendTerminalLine(`\n[System] Initiated job '${action}' (ID: ${res.job_id})...\n`, "system");
      connectJobStream(res.job_id);
    } catch (err) {
      dom.terminalBadgeStatus.textContent = "Error";
      dom.terminalActionPill.textContent = "Idle";
      dom.terminalActionPill.className = "terminal-pill";

      if (err.message === "Root privileges required" || (err.data && err.data.needs_sudo)) {
        state.pendingSudoAction = { action, params, args };
      } else {
        showToast(`Failed to launch ${action}: ${err.message}`, "danger");
      }
    }
  }

  // --------------------------------------------------------------------------
  // Data Fetching & Rendering Engine
  // --------------------------------------------------------------------------

  // Status & Services
  async function fetchStatus() {
    try {
      const data = await apiFetch("/api/v1/status");
      state.clusterStatus = data;
      renderStatus(data);
    } catch (err) {
      dom.badgeClusterStatus.className = "status-pill status-danger";
      dom.badgeClusterStatus.querySelector(".status-label").innerHTML = "Cluster: <strong>Offline</strong>";
    }
  }

  function renderStatus(data) {
    if (!data) return;

    // Edition Tag
    if (data.edition) {
      state.activeWorkspace = data.edition;
      dom.badgeEdition.textContent = data.edition.toUpperCase() + (data.is_package ? " (Offline Bundle)" : " Mode");
      if (dom.selectWorkspace) dom.selectWorkspace.value = data.edition;
    }

    // Cluster State Badge
    const stateVal = (data.cluster_state || "stopped").toLowerCase();
    if (stateVal === "running" || stateVal === "healthy") {
      dom.badgeClusterStatus.className = "status-pill status-healthy";
      dom.badgeClusterStatus.querySelector(".status-label").innerHTML = "Cluster: <strong>Healthy</strong>";
    } else if (stateVal === "degraded" || stateVal === "starting") {
      dom.badgeClusterStatus.className = "status-pill status-warning";
      dom.badgeClusterStatus.querySelector(".status-label").innerHTML = `Cluster: <strong>${data.cluster_state}</strong>`;
    } else {
      dom.badgeClusterStatus.className = "status-pill status-danger";
      dom.badgeClusterStatus.querySelector(".status-label").innerHTML = "Cluster: <strong>Stopped</strong>";
    }

    // Disk Space
    if (data.disk) {
      dom.textDiskStatus.textContent = `Disk: ${data.disk.percent || 0}% (${data.disk.free_gb || 0} GB Free)`;
    }

    // Identity summary
    if (data.identity && dom.identityStatStatus) {
      dom.identityStatStatus.textContent = data.identity.state || "Active";
      dom.identityStatStatus.className = data.identity.state === "healthy" ? "metric-value text-success" : "metric-value text-warning";
    }

    // Services Grid
    renderServicesGrid(data.containers || []);
  }

  function renderServicesGrid(containers) {
    if (!dom.servicesGrid) return;
    if (!containers || containers.length === 0) {
      dom.servicesGrid.innerHTML = `
        <div class="card card-loading">
          <span>No active cluster containers reported. Click "Start All" to launch stack.</span>
        </div>`;
      return;
    }

    const search = (dom.inputServicesSearch?.value || "").toLowerCase().trim();
    const activeFilter = document.querySelector(".pill-filter.active")?.dataset.filter || "all";

    const filtered = containers.filter((c) => {
      const name = (c.name || "").toLowerCase();
      const ports = (c.ports || "").toLowerCase();
      if (search && !name.includes(search) && !ports.includes(search)) {
        return false;
      }
      if (activeFilter === "brokers") return name.includes("broker") || name.includes("kafka-");
      if (activeFilter === "ui-proxy") return name.includes("ui") || name.includes("proxy");
      if (activeFilter === "identity") return name.includes("keycloak") || name.includes("idp");
      if (activeFilter === "monitoring") return name.includes("prometheus") || name.includes("grafana") || name.includes("perses") || name.includes("loki") || name.includes("exporter");
      return true;
    });

    dom.servicesGrid.innerHTML = filtered
      .map((c) => {
        const isRunning = (c.status || "").toLowerCase().includes("up") || (c.status || "").toLowerCase().includes("running");
        const health = (c.health || "healthy").toLowerCase();
        let statusBadge = `<span class="badge badge-success">Running</span>`;
        if (!isRunning) {
          statusBadge = `<span class="badge badge-danger">Stopped</span>`;
        } else if (health.includes("unhealthy")) {
          statusBadge = `<span class="badge badge-danger">Unhealthy</span>`;
        } else if (health.includes("starting")) {
          statusBadge = `<span class="badge badge-warning">Starting</span>`;
        }

        return `
          <div class="service-card">
            <div>
              <div class="service-card-top">
                <div>
                  <div class="service-name">${escapeHtml(c.name || "Service")}</div>
                  <div class="service-container-tag">${escapeHtml(c.container_id || c.name || "")}</div>
                </div>
                ${statusBadge}
              </div>
              <div class="service-meta-grid">
                <div class="service-meta-item">
                  <span class="meta-label">Ports</span>
                  <span class="meta-value" title="${escapeHtml(c.ports || "Internal")}">${escapeHtml(c.ports || "None")}</span>
                </div>
                <div class="service-meta-item">
                  <span class="meta-label">Status</span>
                  <span class="meta-value">${escapeHtml(c.status || "Unknown")}</span>
                </div>
              </div>
            </div>
            <div class="service-card-actions">
              <button class="btn btn-xs btn-ghost btn-svc-logs" data-svc="${escapeHtml(c.name)}">Logs</button>
              <button class="btn btn-xs btn-secondary btn-svc-restart" data-svc="${escapeHtml(c.name)}">Restart</button>
              ${
                isRunning
                  ? `<button class="btn btn-xs btn-danger btn-svc-stop" data-svc="${escapeHtml(c.name)}">Stop</button>`
                  : `<button class="btn btn-xs btn-primary btn-svc-start" data-svc="${escapeHtml(c.name)}">Start</button>`
              }
            </div>
          </div>
        `;
      })
      .join("");

    // Wire service card actions
    dom.servicesGrid.querySelectorAll(".btn-svc-restart").forEach((btn) => {
      btn.addEventListener("click", () => triggerJob("restart", {}, [btn.dataset.svc]));
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-stop").forEach((btn) => {
      btn.addEventListener("click", () => triggerJob("stop", {}, [btn.dataset.svc]));
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-start").forEach((btn) => {
      btn.addEventListener("click", () => triggerJob("start", {}, [btn.dataset.svc]));
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-logs").forEach((btn) => {
      btn.addEventListener("click", () => {
        openTerminalDrawer();
        dom.inputTerminalFilter.value = btn.dataset.svc;
        filterTerminalLines();
      });
    });
  }

  // Doctor Diagnostics
  async function fetchDoctor() {
    try {
      const data = await apiFetch("/api/v1/doctor");
      state.doctorData = data;
      renderDoctor(data);
    } catch (err) {
      dom.textDoctorStatus.textContent = "Doctor: Offline";
    }
  }

  function renderDoctor(data) {
    if (!data) return;

    let passed = 0;
    let warnings = 0;
    let failed = 0;

    const checks = data.checks || [];
    checks.forEach((c) => {
      const s = (c.status || "").toLowerCase();
      if (s === "ok" || s === "pass" || s === "passed") passed++;
      else if (s === "warn" || s === "warning") warnings++;
      else failed++;
    });

    if (dom.docBadgePassed) dom.docBadgePassed.textContent = `${passed} Passing`;
    if (dom.docBadgeWarn) dom.docBadgeWarn.textContent = `${warnings} Warnings`;
    if (dom.docBadgeFailed) dom.docBadgeFailed.textContent = `${failed} Issues`;

    if (failed > 0) {
      dom.badgeDoctorStatus.className = "status-pill status-danger";
      dom.textDoctorStatus.textContent = `Doctor: ${failed} Issues`;
    } else if (warnings > 0) {
      dom.badgeDoctorStatus.className = "status-pill status-warning";
      dom.textDoctorStatus.textContent = `Doctor: ${warnings} Warn`;
    } else {
      dom.badgeDoctorStatus.className = "status-pill status-healthy";
      dom.textDoctorStatus.textContent = `Doctor: ${passed}/${checks.length} OK`;
    }

    if (dom.tbodyDoctor) {
      if (checks.length === 0) {
        dom.tbodyDoctor.innerHTML = `<tr><td colspan="4" class="text-center text-muted">No diagnostic checks registered.</td></tr>`;
        return;
      }

      dom.tbodyDoctor.innerHTML = checks
        .map((c) => {
          const s = (c.status || "").toLowerCase();
          let badge = `<span class="badge badge-success">PASS</span>`;
          if (s === "warn" || s === "warning") badge = `<span class="badge badge-warning">WARN</span>`;
          else if (s === "error" || s === "fail" || s === "failed") badge = `<span class="badge badge-danger">FAIL</span>`;

          return `
            <tr>
              <td><strong>${escapeHtml(c.name || "System Check")}</strong></td>
              <td>${badge}</td>
              <td>${escapeHtml(c.message || "OK")}</td>
              <td style="text-align: right;">
                ${
                  c.fix_action
                    ? `<button class="btn btn-xs btn-primary btn-doctor-fix" data-fix="${escapeHtml(c.fix_action)}">1-Click Fix</button>`
                    : `<span class="text-muted text-xs">No Fix Needed</span>`
                }
              </td>
            </tr>
          `;
        })
        .join("");

      dom.tbodyDoctor.querySelectorAll(".btn-doctor-fix").forEach((btn) => {
        btn.addEventListener("click", () => {
          triggerJob("doctor_fix", { fix: btn.dataset.fix });
        });
      });
    }
  }

  // Lag & Health Matrix
  async function fetchLag() {
    try {
      const data = await apiFetch("/api/v1/lag");
      state.lagData = data;
      renderLag(data);
    } catch (err) {
      if (dom.lagTreeContainer) {
        dom.lagTreeContainer.innerHTML = `<div class="text-center text-muted p-4">Lag metrics currently unavailable. Verify Kafka brokers are healthy.</div>`;
      }
    }
  }

  function renderLag(data) {
    if (!dom.lagTreeContainer) return;
    const groups = data.groups || [];

    let totalGroups = groups.length;
    let totalPartitions = 0;
    let maxLag = 0;

    groups.forEach((g) => {
      const parts = g.partitions || [];
      totalPartitions += parts.length;
      parts.forEach((p) => {
        const l = parseInt(p.lag || 0, 10);
        if (l > maxLag) maxLag = l;
      });
    });

    if (dom.lagStatGroups) dom.lagStatGroups.textContent = totalGroups;
    if (dom.lagStatGroupsSub) dom.lagStatGroupsSub.textContent = `${totalGroups} Active Consumer Groups`;
    if (dom.lagStatPartitions) dom.lagStatPartitions.textContent = totalPartitions;
    if (dom.lagStatMax) {
      dom.lagStatMax.textContent = maxLag.toLocaleString();
      dom.lagStatMax.className = maxLag > 1000 ? "metric-value text-danger" : maxLag > 100 ? "metric-value text-warning" : "metric-value text-success";
    }
    if (dom.lagStatStatus) {
      dom.lagStatStatus.textContent = maxLag > 1000 ? "Severe Lag" : maxLag > 100 ? "Lagging" : "Caught Up";
      dom.lagStatStatus.className = maxLag > 1000 ? "metric-value text-danger" : maxLag > 100 ? "metric-value text-warning" : "metric-value text-success";
    }

    if (groups.length === 0) {
      dom.lagTreeContainer.innerHTML = `<div class="text-center text-muted p-4">No active consumer groups detected. Start a consumer to view lag metrics.</div>`;
      return;
    }

    const filterText = (dom.inputLagFilter?.value || "").toLowerCase().trim();
    const lagOnly = dom.chkLagOnly?.checked || false;

    dom.lagTreeContainer.innerHTML = groups
      .filter((g) => {
        const name = (g.group || "").toLowerCase();
        if (filterText && !name.includes(filterText)) return false;
        if (lagOnly && (g.total_lag || 0) === 0) return false;
        return true;
      })
      .map((g) => {
        const parts = g.partitions || [];
        const isBehind = (g.total_lag || 0) > 0;
        const groupBadge = isBehind
          ? `<span class="badge badge-warning">${g.total_lag} Lag</span>`
          : `<span class="badge badge-success">Caught Up</span>`;

        return `
          <div class="lag-group-card">
            <div class="lag-group-header" data-group="${escapeHtml(g.group)}">
              <div class="lag-group-title">
                <svg viewBox="0 0 24 24" width="16" height="16" stroke="currentColor" fill="none" stroke-width="2"><polyline points="6 9 12 15 18 9"/></svg>
                <span>${escapeHtml(g.group)}</span>
                ${groupBadge}
              </div>
              <div class="lag-group-stats">
                <span>Partitions: <strong>${parts.length}</strong></span>
                <span>Total Lag: <strong>${g.total_lag || 0}</strong></span>
              </div>
            </div>
            <div class="lag-group-body">
              <table class="lag-partitions-table">
                <thead>
                  <tr>
                    <th>Topic</th>
                    <th>Partition</th>
                    <th>Current Offset</th>
                    <th>Log End Offset</th>
                    <th>Lag Depth</th>
                    <th>Consumer Host</th>
                  </tr>
                </thead>
                <tbody>
                  ${parts
                    .map((p) => {
                      const l = parseInt(p.lag || 0, 10);
                      const barClass = l > 1000 ? "lag-crit" : l > 100 ? "lag-warn" : "";
                      const barPercent = Math.min(100, Math.max(5, (l / 1000) * 100));

                      return `
                        <tr>
                          <td>${escapeHtml(p.topic || "")}</td>
                          <td>${escapeHtml(String(p.partition || 0))}</td>
                          <td>${escapeHtml(String(p.current_offset || 0))}</td>
                          <td>${escapeHtml(String(p.log_end_offset || 0))}</td>
                          <td>
                            <div class="lag-bar-wrap">
                              <div class="lag-bar-fill ${barClass}" style="width: ${barPercent}%"></div>
                            </div>
                            <span>${l}</span>
                          </td>
                          <td class="text-muted">${escapeHtml(p.consumer_id || "Unassigned")}</td>
                        </tr>
                      `;
                    })
                    .join("")}
                </tbody>
              </table>
            </div>
          </div>
        `;
      })
      .join("");

    // Toggle group accordion
    dom.lagTreeContainer.querySelectorAll(".lag-group-header").forEach((header) => {
      header.addEventListener("click", () => {
        const body = header.nextElementSibling;
        if (body.style.display === "none") {
          body.style.display = "block";
          header.querySelector("svg").style.transform = "rotate(0deg)";
        } else {
          body.style.display = "none";
          header.querySelector("svg").style.transform = "rotate(-90deg)";
        }
      });
    });
  }

  // Configuration Editor
  async function fetchConfig() {
    try {
      const data = await apiFetch("/api/v1/config");
      state.configData = data;
      renderConfig(data);
    } catch (err) {
      showToast("Failed to fetch configuration", "danger");
    }
  }

  function renderConfig(data) {
    if (!data) return;

    // Cluster env fields
    if (dom.configFieldsCluster && data.env) {
      dom.configFieldsCluster.innerHTML = Object.entries(data.env)
        .map(
          ([k, v]) => `
          <div class="config-item">
            <span class="config-key">${escapeHtml(k)}</span>
            <input type="text" class="text-input text-input-config" data-key="${escapeHtml(k)}" value="${escapeHtml(String(v))}">
          </div>
        `
        )
        .join("");
    }

    // Monitoring env fields
    if (dom.configFieldsMonitoring && data.monitoring_env) {
      dom.configFieldsMonitoring.innerHTML = Object.entries(data.monitoring_env)
        .map(
          ([k, v]) => `
          <div class="config-item">
            <span class="config-key">${escapeHtml(k)}</span>
            <input type="text" class="text-input text-input-config" data-key="${escapeHtml(k)}" value="${escapeHtml(String(v))}">
          </div>
        `
        )
        .join("");
    }

    // Raw editor
    if (dom.textareaRawConfig && data.env) {
      const lines = Object.entries(data.env).map(([k, v]) => `${k}=${v}`);
      dom.textareaRawConfig.value = lines.join("\n");
    }
  }

  // Identity & Users
  async function fetchUsers() {
    try {
      const data = await apiFetch("/api/v1/identity/users");
      state.usersData = data;
      renderUsers(data);
    } catch (err) {
      if (dom.tbodyUsers) {
        dom.tbodyUsers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">Identity directory currently unavailable.</td></tr>`;
      }
    }
  }

  function renderUsers(data) {
    if (!dom.tbodyUsers) return;
    const users = data.users || [];

    if (dom.identityStatCount) {
      dom.identityStatCount.textContent = users.length;
    }

    if (users.length === 0) {
      dom.tbodyUsers.innerHTML = `<tr><td colspan="5" class="text-center text-muted">No users found. Click "Add User" to create one.</td></tr>`;
      return;
    }

    dom.tbodyUsers.innerHTML = users
      .map((u) => {
        const isAdmin = (u.groups || []).includes("admin") || u.username === "admin";
        const roleBadge = isAdmin ? `<span class="badge badge-danger">Admin</span>` : `<span class="badge badge-info">Viewer</span>`;
        const statusBadge = u.enabled
          ? `<span class="badge badge-success">Active</span>`
          : `<span class="badge badge-warning">Disabled</span>`;

        return `
          <tr>
            <td><strong>${escapeHtml(u.username)}</strong></td>
            <td class="text-muted">${escapeHtml(u.email || "No email")}</td>
            <td>${roleBadge}</td>
            <td>${statusBadge}</td>
            <td style="text-align: right;">
              <button class="btn btn-xs btn-secondary btn-reset-pw" data-user="${escapeHtml(u.username)}">Reset Password</button>
              <button class="btn btn-xs btn-ghost btn-toggle-user" data-user="${escapeHtml(u.username)}" data-enabled="${u.enabled}">
                ${u.enabled ? "Disable" : "Enable"}
              </button>
            </td>
          </tr>
        `;
      })
      .join("");

    dom.tbodyUsers.querySelectorAll(".btn-reset-pw").forEach((btn) => {
      btn.addEventListener("click", () => {
        triggerJob("identity_users_reset_password", { username: btn.dataset.user });
      });
    });

    dom.tbodyUsers.querySelectorAll(".btn-toggle-user").forEach((btn) => {
      btn.addEventListener("click", () => {
        const isEnabled = btn.dataset.enabled === "true";
        triggerJob("identity_users_toggle", { username: btn.dataset.user, enable: !isEnabled });
      });
    });
  }

  // Workspaces
  async function fetchWorkspaces() {
    try {
      const data = await apiFetch("/api/v1/workspaces");
      state.workspaces = data.available_workspaces || [];
      if (data.active_workspace && dom.selectWorkspace) {
        state.activeWorkspace = data.active_workspace;
        dom.selectWorkspace.value = data.active_workspace;
      }
    } catch (err) {
      // ignore
    }
  }

  // --------------------------------------------------------------------------
  // Navigation & View Routing
  // --------------------------------------------------------------------------
  function switchView(viewName) {
    state.activeView = viewName;
    window.location.hash = viewName;

    dom.navLinks.forEach((link) => {
      if (link.dataset.view === viewName) {
        link.classList.add("active");
      } else {
        link.classList.remove("active");
      }
    });

    dom.viewPanels.forEach((panel) => {
      if (panel.id === `view-${viewName}`) {
        panel.classList.add("active");
      } else {
        panel.classList.remove("active");
      }
    });

    // View enter lifecycle triggers
    if (viewName === "setup") fetchDoctor();
    if (viewName === "services") fetchStatus();
    if (viewName === "lag") fetchLag();
    if (viewName === "config") fetchConfig();
    if (viewName === "identity") fetchUsers();
  }

  function setupNavigation() {
    dom.navLinks.forEach((link) => {
      link.addEventListener("click", () => {
        switchView(link.dataset.view);
      });
    });

    window.addEventListener("hashchange", () => {
      const hash = window.location.hash.replace("#", "");
      if (hash && document.getElementById(`view-${hash}`)) {
        switchView(hash);
      }
    });

    const initHash = window.location.hash.replace("#", "");
    if (initHash && document.getElementById(`view-${initHash}`)) {
      switchView(initHash);
    }
  }

  // --------------------------------------------------------------------------
  // Event Listeners & Action Bindings
  // --------------------------------------------------------------------------
  function setupActions() {
    // Theme toggle
    dom.btnThemeToggle?.addEventListener("click", toggleTheme);

    // Workspace switch
    dom.selectWorkspace?.addEventListener("change", async (e) => {
      const newWs = e.target.value;
      try {
        await apiFetch("/api/v1/workspaces/switch", {
          method: "POST",
          body: { workspace: newWs },
        });
        showToast(`Switched workspace to ${newWs}`, "success");
        fetchStatus();
        fetchDoctor();
      } catch (err) {
        showToast(`Failed to switch workspace: ${err.message}`, "danger");
      }
    });

    // Terminal Drawer controls
    dom.btnToggleTerminal?.addEventListener("click", toggleTerminalDrawer);
    dom.drawerHeader?.addEventListener("click", (e) => {
      // Don't toggle if clicking input or buttons inside drawer header
      if (["INPUT", "BUTTON", "LABEL", "SPAN"].includes(e.target.tagName)) return;
      toggleTerminalDrawer();
    });
    dom.btnToggleDrawerArrow?.addEventListener("click", toggleTerminalDrawer);
    dom.btnTerminalExpand?.addEventListener("click", toggleTerminalMaximize);
    dom.btnTerminalClear?.addEventListener("click", clearTerminal);
    dom.chkTerminalAutoscroll?.addEventListener("change", (e) => {
      state.autoScroll = e.target.checked;
    });
    dom.inputTerminalFilter?.addEventListener("input", filterTerminalLines);

    // Setup & Wizard actions
    dom.btnRunDoctor?.addEventListener("click", () => triggerJob("doctor"));
    dom.btnQuickStart?.addEventListener("click", () => triggerJob("start"));
    dom.btnStepDocker?.addEventListener("click", () => triggerJob("docker-install"));
    dom.btnStepCerts?.addEventListener("click", () => triggerJob("gen-cert"));
    dom.btnStepImages?.addEventListener("click", () => triggerJob("load-images"));
    dom.btnStepStart?.addEventListener("click", () => triggerJob("start"));

    // Services actions
    dom.btnServicesStart?.addEventListener("click", () => triggerJob("start"));
    dom.btnServicesStop?.addEventListener("click", () => triggerJob("stop"));
    dom.btnServicesRestart?.addEventListener("click", () => triggerJob("restart"));
    dom.btnServicesHealth?.addEventListener("click", () => triggerJob("health"));
    dom.inputServicesSearch?.addEventListener("input", () => renderServicesGrid(state.clusterStatus?.containers || []));

    dom.pillFilters.forEach((pill) => {
      pill.addEventListener("click", () => {
        dom.pillFilters.forEach((p) => p.classList.remove("active"));
        pill.classList.add("active");
        renderServicesGrid(state.clusterStatus?.containers || []);
      });
    });

    // Lag actions
    dom.btnRefreshLag?.addEventListener("click", fetchLag);
    dom.inputLagFilter?.addEventListener("input", () => renderLag(state.lagData || {}));
    dom.chkLagOnly?.addEventListener("change", () => renderLag(state.lagData || {}));

    // Config actions
    dom.configTabs.forEach((tab) => {
      tab.addEventListener("click", () => {
        dom.configTabs.forEach((t) => t.classList.remove("active"));
        dom.configPanes.forEach((p) => p.classList.remove("active"));
        tab.classList.add("active");
        const pane = document.getElementById(`pane-${tab.dataset.tab}`);
        if (pane) pane.classList.add("active");
      });
    });

    dom.btnReloadConfig?.addEventListener("click", fetchConfig);
    dom.btnSaveConfig?.addEventListener("click", async () => {
      showToast("Saving configuration...", "info");
      try {
        // Collect updated inputs
        const inputs = document.querySelectorAll(".text-input-config");
        for (const input of inputs) {
          await apiFetch("/api/v1/config", {
            method: "POST",
            body: { key: input.dataset.key, value: input.value },
          });
        }
        showToast("Configuration saved successfully", "success");
      } catch (err) {
        showToast(`Save failed: ${err.message}`, "danger");
      }
    });

    // Identity actions
    dom.btnRefreshUsers?.addEventListener("click", fetchUsers);
    dom.btnOpenAddUser?.addEventListener("click", () => openModal(dom.modalAddUser));
    dom.btnOpenRotateModal?.addEventListener("click", () => openModal(dom.modalRotate));
    dom.btnBackupIdentity?.addEventListener("click", () => triggerJob("identity_backup"));

    // SSO actions
    dom.btnRunSso?.addEventListener("click", async () => {
      const target = dom.selectSsoTarget.value;
      const mode = dom.selectSsoMode.value;
      try {
        showToast(`Starting SSO orchestration for ${target}...`, "info");
        dom.ssoPipelineStatus.textContent = "Orchestrating...";
        const res = await apiFetch("/api/v1/sso/orchestrate", {
          method: "POST",
          body: { target, mode },
        });
        state.activeJob = { id: res.job_id, action: "sso_orchestrate", status: "running" };
        connectJobStream(res.job_id);
      } catch (err) {
        showToast(`SSO orchestrator error: ${err.message}`, "danger");
      }
    });

    dom.btnSsoFallback?.addEventListener("click", () => {
      triggerJob("auth", {}, ["fallback"]);
    });

    // Observability actions
    dom.btnMonitorToggle?.addEventListener("click", () => {
      triggerJob("monitor_restart");
    });

    // Release & Gates actions
    dom.btnRunGates?.addEventListener("click", () => {
      triggerJob("doctor");
    });

    // Remote SSH Bootstrapper
    dom.btnRemoteConnect?.addEventListener("click", () => {
      switchView("release");
      dom.inputRemoteHost.focus();
    });

    dom.btnRemoteVerify?.addEventListener("click", async () => {
      const host = dom.inputRemoteHost.value.trim();
      const user = dom.inputRemoteUser.value.trim();
      const port = parseInt(dom.inputRemotePort.value, 10) || 22;
      const password = dom.inputRemotePass.value;

      if (!host) {
        showToast("Target host IP or hostname is required", "warning");
        return;
      }

      try {
        showToast("Probing remote host fingerprint...", "info");
        const res = await apiFetch("/api/v1/remote/verify-host", {
          method: "POST",
          body: { host, port, user },
        });

        state.tofuData = { host, port, user, password };
        dom.tofuTargetHost.textContent = `${user ? user + "@" : ""}${host}:${port}`;
        dom.tofuKeyType.textContent = res.key_type || "ssh-ed25519";
        dom.tofuFingerprint.textContent = res.fingerprint || "SHA256:unknown";
        openModal(dom.modalTofu);
      } catch (err) {
        showToast(`TOFU fingerprint probe failed: ${err.message}`, "danger");
      }
    });
  }

  // --------------------------------------------------------------------------
  // Periodic Polling Loop
  // --------------------------------------------------------------------------
  function startPolling() {
    setInterval(() => {
      if (document.hidden) return; // Save CPU when tab is hidden
      fetchStatus();
      if (state.activeView === "setup") fetchDoctor();
      if (state.activeView === "lag") fetchLag();
      if (state.activeView === "identity") fetchUsers();
    }, 4000);
  }

  // --------------------------------------------------------------------------
  // Bootstrap & Initialization
  // --------------------------------------------------------------------------
  async function init() {
    applyTheme(state.theme);
    setupNavigation();
    setupModals();
    setupActions();

    await initializeAuth();
    await fetchStatus();
    await fetchDoctor();
    await fetchWorkspaces();

    startPolling();
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
