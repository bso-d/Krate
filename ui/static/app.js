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
    gatesData: null,
    activeConfigTab: "cluster-env",
    rawConfigTarget: ".env",
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
    btnDrawerToggle: document.getElementById("btn-drawer-toggle"),
    btnRailCollapse: document.getElementById("btn-rail-collapse"),

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
    btnStepInstall: document.getElementById("btn-step-install"),
    btnStepStart: document.getElementById("btn-step-start"),
    stepInstallChip: document.getElementById("step-install-chip"),
    stepInstallDesc: document.getElementById("step-install-desc"),

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
    btnPreviewConfig: document.getElementById("btn-preview-config"),
    btnSaveDraft: document.getElementById("btn-save-draft"),
    btnDiscardDraft: document.getElementById("btn-discard-draft"),
    btnRecoverConfig: document.getElementById("btn-recover-config"),
    configEffectiveDir: document.getElementById("config-effective-dir"),
    configRevisionLabel: document.getElementById("config-revision-label"),
    configStateBadge: document.getElementById("config-state-badge"),
    configDraftBadge: document.getElementById("config-draft-badge"),
    configPendingBadge: document.getElementById("config-pending-badge"),
    configPlanPreview: document.getElementById("config-plan-preview"),

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
    linkPortalGrafana: document.getElementById("link-portal-grafana"),
    linkPortalKafbat: document.getElementById("link-portal-kafbat"),
    linkPortalPerses: document.getElementById("link-portal-perses"),
    linkPortalLoki: document.getElementById("link-portal-loki"),
    alertsSummaryBadge: document.getElementById("alerts-summary-badge"),
    tbodyAlerts: document.getElementById("tbody-alerts"),

    // View 8: Release & Gates
    btnRunGates: document.getElementById("btn-run-gates"),
    gatesSummaryBadge: document.getElementById("gates-summary-badge"),
    tbodyGates: document.getElementById("tbody-gates"),
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

    modalBackup: document.getElementById("modal-backup"),
    inputBackupFile: document.getElementById("input-backup-file"),
    inputBackupPassphrase: document.getElementById("input-backup-passphrase"),
    inputBackupPassphraseConfirm: document.getElementById("input-backup-passphrase-confirm"),
    btnBackupCancel: document.getElementById("btn-backup-cancel"),
    btnBackupSubmit: document.getElementById("btn-backup-submit"),

    modalClearImages: document.getElementById("modal-clear-images"),
    btnClearImagesCancel: document.getElementById("btn-clear-images-cancel"),
    btnClearImagesSubmit: document.getElementById("btn-clear-images-submit"),

    modalCredentialsReveal: document.getElementById("modal-credentials-reveal"),
    btnCredRevealDone: document.getElementById("btn-cred-reveal-done"),
    btnCopyAllCreds: document.getElementById("btn-copy-all-creds"),

    modalSetupWizard: document.getElementById("modal-setup-wizard"),
    btnOpenSetupWizard: document.getElementById("btn-open-setup-wizard"),
    btnWizardPrev: document.getElementById("btn-wizard-prev"),
    btnWizardNext: document.getElementById("btn-wizard-next"),
    btnWizardCancel: document.getElementById("btn-wizard-cancel"),
    btnWizardApply: document.getElementById("btn-wizard-apply"),
    btnWizardDiscoverIdp: document.getElementById("btn-wizard-discover-idp"),

    stepDockerChip: document.getElementById("step-docker-chip"),
    stepCertsChip: document.getElementById("step-certs-chip"),
    stepImagesChip: document.getElementById("step-images-chip"),
    stepStartChip: document.getElementById("step-start-chip"),

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
      triggerJob("clear_cluster", { purge: true });
    });

    document.getElementById("btn-services-purge")?.addEventListener("click", () => openModal(dom.modalPurge));
    document.getElementById("btn-setup-purge")?.addEventListener("click", () => openModal(dom.modalPurge));
    document.getElementById("btn-services-down")?.addEventListener("click", () => triggerJob("down"));
    document.getElementById("btn-setup-down")?.addEventListener("click", () => triggerJob("down"));

    // Clear Images Modal controls
    document.getElementById("btn-step-clear-images")?.addEventListener("click", () => openModal(dom.modalClearImages));
    document.getElementById("btn-setup-clear-images")?.addEventListener("click", () => openModal(dom.modalClearImages));
    dom.btnClearImagesCancel?.addEventListener("click", () => closeModal(dom.modalClearImages));
    dom.btnClearImagesSubmit?.addEventListener("click", () => {
      closeModal(dom.modalClearImages);
      triggerJob("clear_images");
    });

    // Credentials Modal & Reveal controls
    document.getElementById("btn-open-credentials-modal")?.addEventListener("click", () => {
      openModal(dom.modalCredentialsReveal);
      fetchCredentials();
    });
    dom.btnCredRevealDone?.addEventListener("click", () => closeModal(dom.modalCredentialsReveal));

    // Show/hide toggle for masked password inputs in modal
    document.querySelectorAll(".btn-reveal-toggle").forEach(btn => {
      btn.addEventListener("click", () => {
        const inputId = btn.getAttribute("data-input");
        const inp = document.getElementById(inputId);
        if (!inp) return;
        if (inp.type === "password") {
          inp.type = "text";
          btn.textContent = "Hide";
        } else {
          inp.type = "password";
          btn.textContent = "Show";
        }
      });
    });

    // Copy direct buttons in credentials modal and overview
    document.querySelectorAll(".btn-copy-direct").forEach(btn => {
      btn.addEventListener("click", async () => {
        const inputId = btn.getAttribute("data-target");
        const inp = document.getElementById(inputId);
        if (!inp || !inp.value) return;
        try {
          await navigator.clipboard.writeText(inp.value);
          const orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = orig; }, 2000);
          showToast("Password copied to clipboard!", "success");
        } catch (e) {
          showToast("Failed to copy. Please copy manually.", "warning");
        }
      });
    });

    document.querySelectorAll(".btn-cred-copy").forEach(btn => {
      btn.addEventListener("click", async () => {
        const targetId = btn.getAttribute("data-target");
        const el = document.getElementById(targetId);
        const secret = el ? el.dataset.secret : null;
        if (!secret) return;
        try {
          await navigator.clipboard.writeText(secret);
          const orig = btn.textContent;
          btn.textContent = "Copied!";
          setTimeout(() => { btn.textContent = orig; }, 2000);
          showToast("Password copied to clipboard!", "success");
        } catch (e) {
          showToast("Failed to copy. Please copy manually.", "warning");
        }
      });
    });

    dom.btnCopyAllCreds?.addEventListener("click", async () => {
      if (!state.credentials) await fetchCredentials();
      const creds = state.credentials;
      if (!creds) return;
      const text = [
        "Krate Cluster Credentials",
        "=========================",
        `Kafbat UI: ${creds.ui?.kafbat_url || "https://localhost/"}`,
        `Username: ${creds.ui?.KAFKA_UI_USER || "admin"}`,
        `Password: ${creds.ui?.KAFKA_UI_PASSWORD || ""}`,
        "",
        `Grafana: ${creds.monitoring?.grafana_url || "https://localhost/grafana/"}`,
        `Username: ${creds.monitoring?.GRAFANA_USER || "admin"}`,
        `Password: ${creds.monitoring?.GRAFANA_PASSWORD || ""}`,
        "",
        `Perses: ${creds.monitoring?.perses_url || "https://localhost:3443/"}`,
        `Username: ${creds.monitoring?.PERSES_ADMIN_USER || "admin"}`,
        `Password: ${creds.monitoring?.PERSES_ADMIN_PASSWORD || ""}`,
        "",
        `Keycloak Realm: ${creds.identity?.public_url || "https://localhost/identity"}`,
        `Admin: ${creds.identity?.KEYCLOAK_ADMIN_USER || "admin"}`,
        `Password: ${creds.identity?.KEYCLOAK_ADMIN_PASSWORD || ""}`,
      ].join("\n");
      try {
        await navigator.clipboard.writeText(text);
        showToast("All credentials copied to clipboard!", "success");
      } catch (e) {
        showToast("Could not copy to clipboard.", "warning");
      }
    });

    // Setup Wizard Controls
    let wizardCurrentStep = 1;
    const maxWizardStep = 4;

    function setWizardStep(s) {
      wizardCurrentStep = s;
      document.querySelectorAll(".wizard-tab").forEach(tab => {
        tab.classList.toggle("active", parseInt(tab.dataset.step, 10) === s);
      });
      for (let i = 1; i <= maxWizardStep; i++) {
        const el = document.getElementById(`wizard-step-${i}`);
        if (el) el.style.display = (i === s) ? "block" : "none";
      }
      if (dom.btnWizardPrev) dom.btnWizardPrev.style.display = (s > 1) ? "inline-flex" : "none";
      if (dom.btnWizardNext) dom.btnWizardNext.style.display = (s < maxWizardStep) ? "inline-flex" : "none";
      if (dom.btnWizardApply) dom.btnWizardApply.style.display = (s === maxWizardStep) ? "inline-flex" : "none";

      if (s === 4) {
        renderWizardPlan();
      }
    }

    function renderWizardPlan() {
      const presetRadio = document.querySelector('input[name="wizard-preset"]:checked');
      const preset = presetRadio ? presetRadio.value : "standalone";
      const fqdn = document.getElementById("wizard-input-fqdn")?.value.trim() || "localhost";
      const httpsPort = document.getElementById("wizard-input-https-port")?.value || "443";
      const planDiv = document.getElementById("wizard-plan-summary");
      if (!planDiv) return;

      let html = `
        <div class="summary-item mb-1"><strong>Selected Architecture:</strong> <code>${preset}</code></div>
        <div class="summary-item mb-1"><strong>Cluster FQDN / Domain:</strong> <code>${fqdn}</code></div>
        <div class="summary-item mb-1"><strong>Nginx HTTPS Port:</strong> <code>${httpsPort}</code></div>
      `;
      if (preset === "ping_federate") {
        const issuer = document.getElementById("wizard-input-idp-issuer")?.value.trim() || "(unconfigured)";
        const clientId = document.getElementById("wizard-input-idp-client-id")?.value.trim() || "krate-keycloak";
        html += `
          <div class="summary-item mb-1"><strong>PingFederate Issuer:</strong> <code>${issuer}</code></div>
          <div class="summary-item mb-1"><strong>OIDC Client ID:</strong> <code>${clientId}</code></div>
          <div class="summary-item mb-1"><strong>Dual-Run OIDC Watcher:</strong> <code>Enabled (idp-watch)</code></div>
        `;
      }
      planDiv.innerHTML = html;
    }

    dom.btnOpenSetupWizard?.addEventListener("click", async () => {
      setWizardStep(1);
      openModal(dom.modalSetupWizard);
      try {
        const host = await apiGet("/api/v1/host");
        if (host) {
          if (document.getElementById("pill-host-os")) document.getElementById("pill-host-os").textContent = `OS: ${host.os || "Linux"}`;
          if (document.getElementById("pill-host-arch")) document.getElementById("pill-host-arch").textContent = `Arch: ${host.arch || "amd64"}`;
          if (document.getElementById("pill-host-ip")) document.getElementById("pill-host-ip").textContent = `IP: ${host.primary_ip || "127.0.0.1"}`;
          if (document.getElementById("pill-host-fqdn")) document.getElementById("pill-host-fqdn").textContent = `FQDN: ${host.fqdn || host.hostname}`;
          if (document.getElementById("wizard-input-fqdn") && !document.getElementById("wizard-input-fqdn").value) {
            document.getElementById("wizard-input-fqdn").value = host.fqdn || host.primary_ip || "localhost";
          }
        }
      } catch (e) {
        console.warn("Host info fetch error:", e);
      }
    });

    dom.btnWizardPrev?.addEventListener("click", () => {
      if (wizardCurrentStep > 1) setWizardStep(wizardCurrentStep - 1);
    });
    dom.btnWizardNext?.addEventListener("click", () => {
      if (wizardCurrentStep < maxWizardStep) setWizardStep(wizardCurrentStep + 1);
    });
    dom.btnWizardCancel?.addEventListener("click", () => closeModal(dom.modalSetupWizard));

    document.querySelectorAll(".wizard-tab").forEach(tab => {
      tab.addEventListener("click", () => {
        const stepNum = parseInt(tab.dataset.step, 10);
        if (stepNum) setWizardStep(stepNum);
      });
    });

    dom.btnWizardDiscoverIdp?.addEventListener("click", async (e) => {
      e.preventDefault();
      const issuerInput = document.getElementById("wizard-input-idp-issuer");
      const issuerVal = issuerInput ? issuerInput.value.trim() : "";
      if (!issuerVal) {
        showToast("Please enter a PingFederate / IdP Issuer URL first", "warning");
        return;
      }
      const statusBox = document.getElementById("wizard-discovery-status");
      const detailsBox = document.getElementById("wizard-discovery-details");
      if (statusBox) statusBox.style.display = "block";
      if (detailsBox) detailsBox.innerHTML = '<span class="text-muted">Probing /.well-known/openid-configuration server-side...</span>';

      try {
        const res = await apiPost("/api/v1/auth/discover", { issuer_url: issuerVal });
        if (res && res.status === "ok") {
          showToast("OIDC Discovery successful!", "success");
          if (detailsBox) {
            detailsBox.innerHTML = `
              <div class="text-success font-semibold mb-1">✓ Discovered Endpoints:</div>
              <div class="text-xs"><strong>Auth:</strong> ${res.authorization_endpoint || "N/A"}</div>
              <div class="text-xs"><strong>Token:</strong> ${res.token_endpoint || "N/A"}</div>
              <div class="text-xs"><strong>JWKS:</strong> ${res.jwks_uri || "N/A"}</div>
            `;
          }
        } else {
          showToast(res?.error || "Discovery failed", "error");
          if (detailsBox) detailsBox.innerHTML = `<span class="text-danger">Discovery Error: ${res?.error || "Endpoint unreachable"}</span>`;
        }
      } catch (err) {
        showToast(`Discovery error: ${err.message}`, "error");
        if (detailsBox) detailsBox.innerHTML = `<span class="text-danger">Network Error: ${err.message}</span>`;
      }
    });

    dom.btnWizardApply?.addEventListener("click", async () => {
      const presetRadio = document.querySelector('input[name="wizard-preset"]:checked');
      const presetId = presetRadio ? presetRadio.value : "standalone";
      const fqdn = document.getElementById("wizard-input-fqdn")?.value.trim() || "";
      const uiPass = document.getElementById("wizard-input-ui-pass")?.value || "";
      const overrides = {};
      if (fqdn) overrides.fqdn = fqdn;
      if (uiPass) overrides.kafka_ui_password = uiPass;

      if (presetId === "ping_federate") {
        const secret = document.getElementById("wizard-input-idp-client-secret")?.value;
        if (secret) overrides.ping_client_secret = secret;
        const adminGroup = document.getElementById("wizard-input-idp-admin-group")?.value.trim();
        if (adminGroup) overrides.KEYCLOAK_ADMIN_GROUP = adminGroup;
        const viewerGroup = document.getElementById("wizard-input-idp-viewer-group")?.value.trim();
        if (viewerGroup) overrides.KEYCLOAK_VIEWER_GROUP = viewerGroup;
      }

      try {
        const payload = {
          preset_id: presetId,
          expected_revision: state.clusterStatus?.config_revision,
          overrides: overrides,
        };
        const res = await apiPost("/api/v1/presets/apply", payload);
        if (res && (res.status === "ok" || res.config_revision)) {
          closeModal(dom.modalSetupWizard);
          showToast("Configuration preset applied successfully!", "success");
          fetchStatus();
          fetchCredentials();
        } else {
          showToast(res?.error || "Failed to apply preset", "error");
        }
      } catch (err) {
        showToast(`Preset apply error: ${err.message}`, "error");
      }
    });

    // Secret Rotate Modal controls
    dom.btnGenerateSecret?.addEventListener("click", () => {
      const charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-";
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
      const tofuPayload = { ...state.tofuData };
      state.tofuData = null;
      closeModal(dom.modalTofu);
      try {
        showToast("Connecting to remote host...", "info");
        const res = await apiFetch("/api/v1/remote/connect", {
          method: "POST",
          body: {
            host: tofuPayload.host,
            port: tofuPayload.port,
            user: tofuPayload.user,
            password: tofuPayload.password,
            raw_key: tofuPayload.raw_key,
            fingerprint_confirmed: true,
          },
        });
        if (res && res.job_id) {
          state.activeJob = { id: res.job_id, action: res.action || "remote-ssh", status: "running" };
          state.lastEventId = 0;
          connectJobStream(res.job_id);
          const outcome = await waitForJobCompletion(res.job_id);
          if (outcome && outcome.status === "succeeded" && outcome.exit_code === 0) {
            showToast("Remote host connected successfully!", "success");
          } else {
            showToast(`Remote connection failed (exit code ${outcome?.exit_code ?? 1})`, "danger");
          }
        } else {
          showToast("Remote connection failed: no job ID returned", "danger");
        }
      } catch (err) {
        showToast(`Remote connection error: ${err.message}`, "danger");
      }
    });

    // Backup Identity Modal controls
    dom.btnBackupCancel?.addEventListener("click", () => {
      closeModal(dom.modalBackup);
    });

    dom.btnBackupSubmit?.addEventListener("click", () => {
      const file = (dom.inputBackupFile?.value || "").trim();
      const passphrase = dom.inputBackupPassphrase?.value || "";
      const confirmPass = dom.inputBackupPassphraseConfirm?.value || "";

      if (!file) {
        showToast("Backup destination file path is required", "warning");
        return;
      }
      if (passphrase.length < 8) {
        showToast("Backup passphrase must be at least 8 characters", "warning");
        return;
      }
      if (dom.inputBackupPassphraseConfirm && passphrase !== confirmPass) {
        showToast("Backup passphrases do not match", "warning");
        return;
      }

      closeModal(dom.modalBackup);
      if (dom.inputBackupPassphrase) dom.inputBackupPassphrase.value = "";
      if (dom.inputBackupPassphraseConfirm) dom.inputBackupPassphraseConfirm.value = "";
      triggerJob("identity_backup", { file, passphrase });
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
      if (dom.modalSudoActionDesc) {
        dom.modalSudoActionDesc.textContent =
          data.message || "This operation requires root permissions on the host system (via sudo -A).";
      }
      openModal(dom.modalSudo);
      const sudoErr = new Error("Root privileges required");
      sudoErr.status = 403;
      sudoErr.data = data;
      throw sudoErr;
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

  async function apiGet(endpoint) {
    return apiFetch(endpoint, { method: "GET" });
  }

  async function apiPost(endpoint, body = {}) {
    return apiFetch(endpoint, { method: "POST", body });
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
      dom.badgeAuthStatus.className = "mui-status-indicator status-success";
      dom.badgeAuthStatus.title = "Session: Active (Authenticated)";
      if (dom.textAuthStatus) dom.textAuthStatus.textContent = "Session Active";
    } else {
      dom.badgeAuthStatus.className = "mui-status-indicator status-neutral";
      dom.badgeAuthStatus.title = "Session: Guest / Token Required";
      if (dom.textAuthStatus) dom.textAuthStatus.textContent = "Guest Mode";
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

        if (dom.terminalBadgeStatus) {
          dom.terminalBadgeStatus.textContent = "";
          dom.terminalBadgeStatus.className = isSuccess
            ? "terminal-pulse-dot status-done"
            : "terminal-pulse-dot status-error";
        }
        dom.terminalActionPill.textContent = "Idle";
        dom.terminalActionPill.className = "terminal-pill";

        const finishedAction = state.activeJob?.action || "";
        if (!finishedAction.startsWith("remote-ssh")) {
          showToast(`Job ${finishedAction} ${payload.status}`, isSuccess ? "success" : "danger");
        }
      } catch (e) {
        console.error("Error parsing done event:", e);
      } finally {
        const finishedAction = state.activeJob?.action || "";
        source.close();
        state.sseSource = null;
        state.activeJob = null;
        updateWorkspaceSelectorLock(false);
        fetchStatus();
        if (finishedAction === "install" || finishedAction === "doctor_fix") {
          fetchWorkspaces();
          fetchDoctor();
          fetchConfig();
        }
        if (finishedAction === "gates") {
          fetchGates();
        }
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

  async function waitForJobCompletion(jobId, timeoutMs = 120000) {
    const start = Date.now();
    while (Date.now() - start < timeoutMs) {
      try {
        const j = await apiFetch(`/api/v1/jobs/${jobId}`);
        if (j && j.status && j.status !== "running") {
          return { status: j.status, exit_code: j.exit_code };
        }
      } catch (err) {
        return { status: "failed", exit_code: 1, error: err.message };
      }
      await new Promise((resolve) => setTimeout(resolve, 400));
    }
    return { status: "failed", exit_code: -1 };
  }

  function updateWorkspaceSelectorLock(mutationActive = false) {
    const isMutating = Boolean(
      mutationActive ||
        (state.activeJob && state.activeJob.status === "running" && state.activeJob.isMutation !== false)
    );
    if (dom.selectWorkspace) {
      dom.selectWorkspace.disabled = isMutating;
      dom.selectWorkspace.title = isMutating
        ? "Workspace switching is disabled while a mutation operation is running"
        : "Select active Krate workspace";
    }
  }

  // --------------------------------------------------------------------------
  // Job Triggers & Supervisors
  // --------------------------------------------------------------------------
  async function triggerJob(action, params = {}, args = [], sudoPassword = null) {
    if (state.activeJob && state.activeJob.status === "running") {
      showToast("Another task is currently running", "warning");
      return null;
    }

    try {
      if (dom.terminalBadgeStatus) {
        dom.terminalBadgeStatus.textContent = "";
        dom.terminalBadgeStatus.className = "terminal-pulse-dot active";
      }
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

      const isMutation =
        res.is_mutation !== undefined
          ? Boolean(res.is_mutation)
          : !["health", "credentials", "status", "logs", "doctor", "gates", "identity_status", "monitor_status", "monitor_logs", "monitor_ui"].includes(action);
      state.activeJob = {
        id: res.job_id,
        action,
        status: "running",
        isMutation,
        context: res.context || null,
      };
      updateWorkspaceSelectorLock(isMutation);
      state.lastEventId = 0;
      appendTerminalLine(`\n[System] Initiated job '${action}' (ID: ${res.job_id})...\n`, "system");
      connectJobStream(res.job_id);
      return res;
    } catch (err) {
      updateWorkspaceSelectorLock(false);
      if (dom.terminalBadgeStatus) {
        dom.terminalBadgeStatus.textContent = "";
        dom.terminalBadgeStatus.className = "terminal-pulse-dot status-error";
      }
      dom.terminalActionPill.textContent = "Idle";
      dom.terminalActionPill.className = "terminal-pill";

      if (err.message === "Root privileges required" || (err.data && err.data.needs_sudo)) {
        state.pendingSudoAction = { action, params, args };
      } else {
        showToast(`Failed to launch ${action}: ${err.message}`, "danger");
      }
      return null;
    }
  }

  // --------------------------------------------------------------------------
  // Data Fetching & Rendering Engine
  // --------------------------------------------------------------------------

  function updateStepperChips(statusData, doctorData) {
    if (!statusData) return;

    // 1. Docker Socket
    if (dom.stepDockerChip) {
      const dockerCheck = doctorData?.checks?.find((c) => (c.name || "").toLowerCase().includes("docker"));
      const isDockerUp = dockerCheck ? dockerCheck.status === "passed" : (statusData.cluster_state !== "unknown");
      dom.stepDockerChip.textContent = isDockerUp ? "Socket Ready" : "Daemon Down";
      dom.stepDockerChip.className = `step-status-chip ${isDockerUp ? "badge-success" : "badge-danger"}`;
    }

    // 2. TLS Certificates
    if (dom.stepCertsChip) {
      const certCheck = doctorData?.checks?.find((c) => (c.name || "").toLowerCase().includes("cert"));
      const certValid = certCheck ? certCheck.status === "passed" : true;
      dom.stepCertsChip.textContent = certValid ? "Valid SANs" : "Regen Required";
      dom.stepCertsChip.className = `step-status-chip ${certValid ? "badge-success" : "badge-warning"}`;
    }

    // 3. Offline Images
    if (dom.stepImagesChip) {
      const imgCheck = doctorData?.checks?.find((c) => (c.name || "").toLowerCase().includes("image"));
      const imgsLoaded = imgCheck ? imgCheck.status === "passed" : true;
      dom.stepImagesChip.textContent = imgsLoaded ? "Images Loaded" : "Load Required";
      dom.stepImagesChip.className = `step-status-chip ${imgsLoaded ? "badge-success" : "badge-warning"}`;
    }

    // 4. Installation
    if (dom.stepInstallChip) {
      if (statusData.is_package && !statusData.is_installed) {
        dom.stepInstallChip.textContent = "Install Required";
        dom.stepInstallChip.className = "step-status-chip badge-warning";
      } else if (statusData.is_package && statusData.is_installed) {
        dom.stepInstallChip.textContent = "Installed";
        dom.stepInstallChip.className = "step-status-chip badge-success";
      } else {
        dom.stepInstallChip.textContent = "Checkout Ready";
        dom.stepInstallChip.className = "step-status-chip badge-info";
      }
    }

    // 5. Start Cluster
    if (dom.stepStartChip) {
      const stateVal = (statusData.cluster_state || "stopped").toLowerCase();
      if (stateVal === "running" || stateVal === "healthy") {
        dom.stepStartChip.textContent = "Production Live";
        dom.stepStartChip.className = "step-status-chip badge-success";
      } else if (stateVal === "degraded" || stateVal === "starting") {
        dom.stepStartChip.textContent = "Starting...";
        dom.stepStartChip.className = "step-status-chip badge-warning";
      } else {
        dom.stepStartChip.textContent = "Cluster Stopped";
        dom.stepStartChip.className = "step-status-chip badge-neutral";
      }
    }
  }

  async function fetchCredentials() {
    try {
      const res = await apiFetch("/api/v1/credentials");
      if (!res) return;
      state.credentials = res;

      const uiUser = res.ui?.KAFKA_UI_USER || "admin";
      const uiPass = res.ui?.KAFKA_UI_PASSWORD || "(unconfigured)";
      const grafUser = res.monitoring?.GRAFANA_USER || "admin";
      const grafPass = res.monitoring?.GRAFANA_PASSWORD || "(unconfigured)";
      const persesUser = res.monitoring?.PERSES_ADMIN_USER || "admin";
      const persesPass = res.monitoring?.PERSES_ADMIN_PASSWORD || "(unconfigured)";
      const kcUser = res.identity?.KEYCLOAK_ADMIN_USER || "admin";
      const kcPass = res.identity?.KEYCLOAK_ADMIN_PASSWORD || "(unconfigured)";

      // Overview grid elements
      const elUiU = document.getElementById("cred-user-kafbat");
      if (elUiU) elUiU.textContent = uiUser;
      const elUiP = document.getElementById("cred-pass-kafbat");
      if (elUiP) { elUiP.dataset.secret = uiPass; elUiP.textContent = "••••••••••••••••"; }

      const elGrU = document.getElementById("cred-user-grafana");
      if (elGrU) elGrU.textContent = grafUser;
      const elGrP = document.getElementById("cred-pass-grafana");
      if (elGrP) { elGrP.dataset.secret = grafPass; elGrP.textContent = "••••••••••••••••"; }

      const elPeU = document.getElementById("cred-user-perses");
      if (elPeU) elPeU.textContent = persesUser;
      const elPeP = document.getElementById("cred-pass-perses");
      if (elPeP) { elPeP.dataset.secret = persesPass; elPeP.textContent = "••••••••••••••••"; }

      const elKcU = document.getElementById("cred-user-keycloak");
      if (elKcU) elKcU.textContent = kcUser;
      const elKcP = document.getElementById("cred-pass-keycloak");
      if (elKcP) { elKcP.dataset.secret = kcPass; elKcP.textContent = "••••••••••••••••"; }

      // Modal inputs
      const mUiU = document.getElementById("rev-user-kafbat");
      if (mUiU) mUiU.textContent = uiUser;
      const mUiP = document.getElementById("rev-pass-kafbat");
      if (mUiP) mUiP.value = uiPass;

      const mGrU = document.getElementById("rev-user-grafana");
      if (mGrU) mGrU.textContent = grafUser;
      const mGrP = document.getElementById("rev-pass-grafana");
      if (mGrP) mGrP.value = grafPass;

      const mPeU = document.getElementById("rev-user-perses");
      if (mPeU) mPeU.textContent = persesUser;
      const mPeP = document.getElementById("rev-pass-perses");
      if (mPeP) mPeP.value = persesPass;

      const mKcU = document.getElementById("rev-user-keycloak");
      if (mKcU) mKcU.textContent = kcUser;
      const mKcP = document.getElementById("rev-pass-keycloak");
      if (mKcP) mKcP.value = kcPass;

      if (res.ui?.kafbat_url && document.getElementById("rev-link-kafbat")) {
        document.getElementById("rev-link-kafbat").href = res.ui.kafbat_url;
        document.getElementById("rev-link-kafbat").textContent = res.ui.kafbat_url;
      }
      if (res.monitoring?.grafana_url && document.getElementById("rev-link-grafana")) {
        document.getElementById("rev-link-grafana").href = res.monitoring.grafana_url;
        document.getElementById("rev-link-grafana").textContent = res.monitoring.grafana_url;
      }
      if (res.monitoring?.perses_url && document.getElementById("rev-link-perses")) {
        document.getElementById("rev-link-perses").href = res.monitoring.perses_url;
        document.getElementById("rev-link-perses").textContent = res.monitoring.perses_url;
      }
    } catch (e) {
      console.warn("Could not fetch credentials:", e);
    }
  }

  // Status & Services
  async function fetchStatus() {
    try {
      const data = await apiFetch("/api/v1/status");
      state.clusterStatus = data;
      renderStatus(data);
    } catch (err) {
      dom.badgeClusterStatus.className = "mui-status-indicator status-stopped";
      dom.badgeClusterStatus.title = "Cluster: Offline / Unreachable";
      const lbl = dom.badgeClusterStatus.querySelector(".status-label");
      if (lbl) lbl.innerHTML = "Cluster: <strong>Offline</strong>";
    }
  }

  function renderStatus(data) {
    if (!data) return;

    // Dynamic Stepper State Synchronization
    updateStepperChips(data, state.doctorData);

    // Edition Tag & Active Workspace Path
    if (data.edition) {
      dom.badgeEdition.textContent = data.edition.toUpperCase() + (data.is_package ? " (Bundle)" : " Mode");
    }
    if (data.workspace) {
      state.activeWorkspace = data.workspace;
      if (dom.selectWorkspace) {
        const hasOption = Array.from(dom.selectWorkspace.options).some((opt) => opt.value === data.workspace);
        if (hasOption) {
          dom.selectWorkspace.value = data.workspace;
        }
      }
    }
    if (data.mutation_active !== undefined) {
      updateWorkspaceSelectorLock(Boolean(data.mutation_active));
    }

    // Update Package Install Wizard Step
    if (dom.stepInstallChip) {
      if (data.is_package && !data.is_installed) {
        dom.stepInstallChip.textContent = "Install Required";
      } else if (data.is_package && data.is_installed) {
        dom.stepInstallChip.textContent = "Installed";
      } else {
        dom.stepInstallChip.textContent = "Checkout Ready";
      }
    }

    // Cluster State Badge (Color-Changing Lucide Icon)
    const stateVal = (data.cluster_state || "stopped").toLowerCase();
    if (stateVal === "running" || stateVal === "healthy") {
      dom.badgeClusterStatus.className = "mui-status-indicator status-healthy";
      dom.badgeClusterStatus.title = "Cluster: Healthy & Running";
      const lbl = dom.badgeClusterStatus.querySelector(".status-label");
      if (lbl) lbl.innerHTML = "Cluster: <strong>Healthy</strong>";
    } else if (stateVal === "degraded" || stateVal === "starting") {
      dom.badgeClusterStatus.className = "mui-status-indicator status-warning";
      dom.badgeClusterStatus.title = `Cluster: ${data.cluster_state}`;
      const lbl = dom.badgeClusterStatus.querySelector(".status-label");
      if (lbl) lbl.innerHTML = `Cluster: <strong>${data.cluster_state}</strong>`;
    } else {
      dom.badgeClusterStatus.className = "mui-status-indicator status-stopped";
      dom.badgeClusterStatus.title = "Cluster: Stopped";
      const lbl = dom.badgeClusterStatus.querySelector(".status-label");
      if (lbl) lbl.innerHTML = "Cluster: <strong>Stopped</strong>";
    }

    // Disk Space (Color-Changing Icon & Tooltip)
    if (data.disk) {
      dom.badgeDiskStatus.title = `Host Disk: ${data.disk.percent || 0}% used (${data.disk.free_gb || 0} GB Free)`;
      if (data.disk.percent > 85) {
        dom.badgeDiskStatus.className = "mui-status-indicator status-warning";
      } else if (data.disk.percent > 95) {
        dom.badgeDiskStatus.className = "mui-status-indicator status-danger";
      } else {
        dom.badgeDiskStatus.className = "mui-status-indicator status-healthy";
      }
      if (dom.textDiskStatus) {
        dom.textDiskStatus.textContent = `Disk: ${data.disk.percent || 0}% (${data.disk.free_gb || 0} GB Free)`;
      }
    }

    // Identity summary
    if (data.identity && dom.identityStatStatus) {
      dom.identityStatStatus.textContent = data.identity.state || "Down";
      dom.identityStatStatus.className =
        data.identity.state === "healthy" ? "metric-value text-success" : "metric-value text-warning";
    }

    // Portals & Alerts
    if (data.portals) {
      renderPortals(data.portals);
    }
    renderAlerts(data.alerts);

    // Services Grid
    renderServicesGrid(data.containers || []);
  }

  function deriveComposeServiceName(name, serviceLabel = "") {
    if (serviceLabel && serviceLabel.trim()) {
      return serviceLabel.trim();
    }
    const clean = (name || "").trim();
    const mBroker = clean.match(/^(?:krate|epc)-broker-(\d+)$/);
    if (mBroker) {
      return `kafka-${mBroker[1]}`;
    }
    if (clean === "krate-kafbat" || clean === "epc-kafbat") {
      return "kafka-ui";
    }
    if (clean === "krate-proxy" || clean === "epc-proxy") {
      return "proxy";
    }
    const mCompose = clean.match(/^krate-(?:kraft|epc)(?:-monitoring)?-([a-zA-Z0-9_-]+)-\d+$/);
    if (mCompose) {
      return mCompose[1];
    }
    return clean;
  }

  function renderPortals(portals) {
    if (!portals) return;
    if (dom.linkPortalGrafana && portals.grafana_url) {
      dom.linkPortalGrafana.href = portals.grafana_url;
      dom.linkPortalGrafana.textContent = "Open Grafana";
    }
    if (dom.linkPortalKafbat && portals.kafbat_url) {
      dom.linkPortalKafbat.href = portals.kafbat_url;
      dom.linkPortalKafbat.textContent = "Open Kafbat UI";
    }
    if (dom.linkPortalPerses && portals.perses_url) {
      dom.linkPortalPerses.href = portals.perses_url;
      dom.linkPortalPerses.textContent = "Open Perses";
    }
    if (dom.linkPortalLoki && portals.loki_url) {
      dom.linkPortalLoki.href = portals.loki_url;
      dom.linkPortalLoki.textContent = "Explore Logs";
    }
  }

  function renderAlerts(alertsData) {
    if (dom.alertsSummaryBadge) {
      if (!alertsData || !alertsData.evaluated) {
        dom.alertsSummaryBadge.className = "badge badge-neutral";
        dom.alertsSummaryBadge.textContent = alertsData?.summary || "Unknown";
      } else if (alertsData.status === "firing") {
        dom.alertsSummaryBadge.className = "badge badge-danger";
        dom.alertsSummaryBadge.textContent = alertsData.summary || "Alerts Firing";
      } else if (alertsData.status === "pending") {
        dom.alertsSummaryBadge.className = "badge badge-warning";
        dom.alertsSummaryBadge.textContent = alertsData.summary || "Alerts Pending";
      } else {
        dom.alertsSummaryBadge.className = "badge badge-success";
        dom.alertsSummaryBadge.textContent = alertsData.summary || "All Alerts Clear";
      }
    }

    const tbodyAlerts = document.getElementById("tbody-alerts");
    const ruleList = Array.isArray(alertsData?.rule_list)
      ? alertsData.rule_list
      : Object.entries(alertsData?.rules || {}).map(([name, r]) => ({ name, ...r }));

    if (tbodyAlerts && ruleList.length > 0) {
      tbodyAlerts.innerHTML = ruleList
        .map((rule) => {
          const rName = rule.name || "";
          const sev = String(rule.severity || "warning").toLowerCase();
          const sevClass =
            sev === "critical" ? "badge-danger" : sev === "warning" ? "badge-warning" : "badge-info";
          const rState = alertsData?.evaluated ? rule.state || "unknown" : "unknown";
          let stBadge = `<span class="badge badge-neutral" data-alert-rule="${escapeHtml(rName)}">Unknown</span>`;
          if (rState === "firing") {
            stBadge = `<span class="badge badge-danger" data-alert-rule="${escapeHtml(rName)}">${escapeHtml(rule.label || "Firing")}</span>`;
          } else if (rState === "pending") {
            stBadge = `<span class="badge badge-warning" data-alert-rule="${escapeHtml(rName)}">${escapeHtml(rule.label || "Pending")}</span>`;
          } else if (rState === "ok") {
            stBadge = `<span class="badge badge-success" data-alert-rule="${escapeHtml(rName)}">${escapeHtml(rule.label || "OK (Clear)")}</span>`;
          }
          return `
            <tr>
              <td><strong>${escapeHtml(rName)}</strong></td>
              <td><span class="badge ${sevClass}">${escapeHtml(sev.toUpperCase())}</span></td>
              <td>${escapeHtml(rule.group || "krate")}</td>
              <td>${escapeHtml(rule.summary || rule.description || "")}</td>
              <td>${stBadge}</td>
            </tr>
          `;
        })
        .join("");
    } else {
      const ruleBadges = document.querySelectorAll("[data-alert-rule]");
      ruleBadges.forEach((badge) => {
        const ruleName = badge.dataset.alertRule;
        const ruleObj = alertsData?.evaluated && alertsData?.rules ? alertsData.rules[ruleName] : null;
        if (!ruleObj || ruleObj.state === "unknown") {
          badge.className = "badge badge-neutral";
          badge.textContent = "Unknown";
        } else if (ruleObj.state === "firing") {
          badge.className = "badge badge-danger";
          badge.textContent = ruleObj.label || "Firing";
        } else if (ruleObj.state === "pending") {
          badge.className = "badge badge-warning";
          badge.textContent = ruleObj.label || "Pending";
        } else {
          badge.className = "badge badge-success";
          badge.textContent = ruleObj.label || "OK";
        }
      });
    }
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

        const svcName = deriveComposeServiceName(c.name, c.service);
        const edition = state.clusterStatus?.edition || "kraft";
        const isMonSvc = [
          "prometheus",
          "grafana",
          "loki",
          "promtail",
          "alertmanager",
          "kafka-exporter",
          "node-exporter",
          "perses",
          "oauth2-proxy",
          "perses-sync",
        ].includes(svcName);
        const projName =
          c.project ||
          (isMonSvc
            ? state.clusterStatus?.projects?.monitoring || `krate-${edition}-monitoring`
            : state.clusterStatus?.projects?.cluster || `krate-${edition}`);
        const containerTag = c.name && c.name !== svcName ? c.name : c.container_id || c.name || "";

        return `
          <div class="service-card" data-project="${escapeHtml(projName)}" data-service="${escapeHtml(svcName)}">
            <div>
              <div class="service-card-top">
                <div>
                  <div class="service-name">${escapeHtml(svcName || c.name || "Service")}</div>
                  <div class="service-container-tag">${escapeHtml(projName)} &middot; ${escapeHtml(containerTag)}</div>
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
              <button class="btn btn-xs btn-ghost btn-svc-logs" data-project="${escapeHtml(projName)}" data-svc="${escapeHtml(svcName)}" data-container="${escapeHtml(c.name || "")}">Logs</button>
              <button class="btn btn-xs btn-secondary btn-svc-restart" data-project="${escapeHtml(projName)}" data-svc="${escapeHtml(svcName)}" data-container="${escapeHtml(c.name || "")}">Restart</button>
              ${
                isRunning
                  ? `<button class="btn btn-xs btn-danger btn-svc-stop" data-project="${escapeHtml(projName)}" data-svc="${escapeHtml(svcName)}" data-container="${escapeHtml(c.name || "")}">Stop</button>`
                  : `<button class="btn btn-xs btn-primary btn-svc-start" data-project="${escapeHtml(projName)}" data-svc="${escapeHtml(svcName)}" data-container="${escapeHtml(c.name || "")}">Start</button>`
              }
            </div>
          </div>
        `;
      })
      .join("");

    // Wire project-qualified service card actions
    dom.servicesGrid.querySelectorAll(".btn-svc-restart").forEach((btn) => {
      btn.addEventListener("click", () =>
        triggerJob("service_restart", { project: btn.dataset.project, service: btn.dataset.svc })
      );
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-stop").forEach((btn) => {
      btn.addEventListener("click", () =>
        triggerJob("service_stop", { project: btn.dataset.project, service: btn.dataset.svc })
      );
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-start").forEach((btn) => {
      btn.addEventListener("click", () =>
        triggerJob("service_start", { project: btn.dataset.project, service: btn.dataset.svc })
      );
    });
    dom.servicesGrid.querySelectorAll(".btn-svc-logs").forEach((btn) => {
      btn.addEventListener("click", () => {
        openTerminalDrawer();
        if (dom.inputTerminalFilter) {
          dom.inputTerminalFilter.value = "";
        }
        triggerJob("service_logs", { project: btn.dataset.project, service: btn.dataset.svc, tail: 100 });
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

    // Dynamic Stepper State Synchronization
    updateStepperChips(state.clusterStatus, data);

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
      dom.badgeDoctorStatus.className = "mui-status-indicator status-danger";
      dom.badgeDoctorStatus.title = `Doctor: ${failed} Issues Detected`;
      if (dom.textDoctorStatus) dom.textDoctorStatus.textContent = `Doctor: ${failed} Issues`;
    } else if (warnings > 0) {
      dom.badgeDoctorStatus.className = "mui-status-indicator status-warning";
      dom.badgeDoctorStatus.title = `Doctor: ${warnings} Warnings`;
      if (dom.textDoctorStatus) dom.textDoctorStatus.textContent = `Doctor: ${warnings} Warn`;
    } else {
      dom.badgeDoctorStatus.className = "mui-status-indicator status-healthy";
      dom.badgeDoctorStatus.title = `Doctor: ${passed}/${checks.length} All Checks Passing`;
      if (dom.textDoctorStatus) dom.textDoctorStatus.textContent = `Doctor: ${passed}/${checks.length} OK`;
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

    if (dom.configEffectiveDir) {
      dom.configEffectiveDir.textContent = data.effective_dir || "(Uninstalled Package — run Install first)";
    }
    if (dom.configRevisionLabel) {
      dom.configRevisionLabel.textContent = data.config_revision ? data.config_revision.slice(0, 12) : "—";
    }
    if (dom.configDraftBadge) {
      dom.configDraftBadge.style.display = data.has_draft ? "inline-flex" : "none";
    }
    if (dom.btnDiscardDraft) {
      dom.btnDiscardDraft.style.display = data.has_draft ? "inline-flex" : "none";
    }
    const pendingCount = Array.isArray(data.pending_services) ? data.pending_services.length : 0;
    if (dom.configPendingBadge) {
      dom.configPendingBadge.style.display = pendingCount > 0 ? "inline-flex" : "none";
      dom.configPendingBadge.textContent = `${pendingCount} Pending Service Reconcile`;
    }
    if (dom.btnRecoverConfig) {
      dom.btnRecoverConfig.style.display = data.recovery_required ? "inline-flex" : "none";
    }
    if (dom.configStateBadge) {
      if (data.recovery_required) {
        dom.configStateBadge.className = "badge badge-danger";
        dom.configStateBadge.textContent = "Recovery Required";
      } else if (pendingCount > 0) {
        dom.configStateBadge.className = "badge badge-warning";
        dom.configStateBadge.textContent = "Pending Apply";
      } else if (data.has_draft) {
        dom.configStateBadge.className = "badge badge-info";
        dom.configStateBadge.textContent = "Draft Staged";
      } else {
        dom.configStateBadge.className = "badge badge-success";
        dom.configStateBadge.textContent = "Applied";
      }
    }

    const draftTargets = (data.draft && data.draft.targets) || {};
    const clusterSource =
      (draftTargets[".env"] && draftTargets[".env"].entries) || data.env || {};
    const monitoringSource =
      (draftTargets["monitoring/.env"] && draftTargets["monitoring/.env"].entries) ||
      data.monitoring_env ||
      {};

    // Cluster env fields
    if (dom.configFieldsCluster) {
      dom.configFieldsCluster.innerHTML = Object.entries(clusterSource)
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
    if (dom.configFieldsMonitoring) {
      dom.configFieldsMonitoring.innerHTML = Object.entries(monitoringSource)
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
    updateRawEditorFromConfig(data);
  }

  function collectActiveConfigPayload() {
    const activeTab =
      document.querySelector(".config-tabs-bar .tab-btn.active")?.dataset.tab ||
      state.activeConfigTab ||
      "cluster-env";
    const expected_revision = state.configData?.config_revision || null;

    if (activeTab === "raw-editor") {
      const target = state.rawConfigTarget || ".env";
      const rawContent = dom.textareaRawConfig ? dom.textareaRawConfig.value : "";
      return { mode: "raw", raw: rawContent, target, expected_revision };
    }
    const isMonitoring = activeTab === "monitoring-env";
    const target = isMonitoring ? "monitoring/.env" : ".env";
    const container = isMonitoring ? dom.configFieldsMonitoring : dom.configFieldsCluster;
    const inputs = (container || document).querySelectorAll(".text-input-config");
    const entries = {};
    for (const input of inputs) {
      if (input.dataset.key) {
        entries[input.dataset.key] = input.value;
      }
    }
    return { mode: "entries", entries, target, expected_revision };
  }

  function renderConfigPlanPreview(result) {
    if (!dom.configPlanPreview || !result) return;
    const changes = result.changes || [];
    const services = result.affected_services || [];
    const steps = result.steps || [];
    dom.configPlanPreview.style.display = "block";

    const changesHtml =
      changes.length === 0
        ? `<div class="text-muted text-xs">No configuration changes detected.</div>`
        : `<ul style="margin: 0.25rem 0 0.5rem 1.25rem; font-size: 0.85rem;">` +
          changes
            .map(
              (c) =>
                `<li><code>${escapeHtml(c.key)}</code> (${escapeHtml(c.classification)}) &rarr; <strong>${escapeHtml(c.action)}</strong></li>`
            )
            .join("") +
          `</ul>`;
    const svcsHtml =
      services.length === 0
        ? `<span class="text-muted text-xs">None</span>`
        : services
            .map((s) => `<span class="badge badge-info" style="margin-right: 4px;">${escapeHtml(s.project)}/${escapeHtml(s.service)}</span>`)
            .join("");
    const stepsHtml =
      steps.length === 0
        ? ""
        : `<div style="margin-top: 0.35rem; font-size: 0.8rem;"><strong>Steps:</strong> ` +
          steps.map((s) => `${escapeHtml(s.step)} [${escapeHtml(s.status)}]`).join(" &rarr; ") +
          `</div>`;

    dom.configPlanPreview.innerHTML = `
      <div><strong>State:</strong> <code>${escapeHtml(result.state || "planned")}</code></div>
      <div style="margin-top: 0.25rem;"><strong>Planned Changes (${changes.length}):</strong> ${changesHtml}</div>
      <div><strong>Affected Services:</strong> ${svcsHtml}</div>
      ${stepsHtml}
    `;
  }

  function updateRawEditorFromConfig(data) {
    if (!dom.textareaRawConfig || !data) return;
    if (state.rawConfigTarget === "monitoring/.env") {
      if (typeof data.raw_monitoring_env === "string" && data.raw_monitoring_env.length > 0) {
        dom.textareaRawConfig.value = data.raw_monitoring_env;
      } else {
        const lines = Object.entries(data.monitoring_env || {}).map(([k, v]) => `${k}=${v}`);
        dom.textareaRawConfig.value = lines.join("\n");
      }
    } else {
      if (typeof data.raw_env === "string" && data.raw_env.length > 0) {
        dom.textareaRawConfig.value = data.raw_env;
      } else {
        const lines = Object.entries(data.env || {}).map(([k, v]) => `${k}=${v}`);
        dom.textareaRawConfig.value = lines.join("\n");
      }
    }
  }

  // Acceptance Gates
  async function fetchGates() {
    try {
      const data = await apiFetch("/api/v1/gates");
      state.gatesData = data;
      renderGates(data);
    } catch (err) {
      // keep default Not Run state
    }
  }

  function renderGates(data) {
    if (!data) return;
    const checks = data.checks || data.gates || [];
    const binding = data.binding || {};
    const bindingLabel = document.getElementById("gates-binding-label");
    if (bindingLabel && binding.installation_id) {
      const candShort = binding.candidate ? String(binding.candidate).slice(0, 12) : "—";
      const revShort = binding.config_revision ? String(binding.config_revision).slice(0, 12) : "—";
      bindingLabel.textContent = `Target: ${binding.installation_id} | Candidate: ${candShort} | Config Rev: ${revShort}`;
    }

    if (dom.gatesSummaryBadge) {
      if (data.status === "passed") {
        dom.gatesSummaryBadge.className = "badge badge-success";
        dom.gatesSummaryBadge.textContent = `Passed (${data.passed}/${checks.length})`;
      } else if (data.status === "failed") {
        dom.gatesSummaryBadge.className = "badge badge-danger";
        dom.gatesSummaryBadge.textContent = `Failed (${data.failed} failed)`;
      } else if (data.status === "partial") {
        dom.gatesSummaryBadge.className = "badge badge-info";
        dom.gatesSummaryBadge.textContent = `Partial (${data.passed} passed, ${data.not_run || 0} not run)`;
      } else {
        dom.gatesSummaryBadge.className = "badge badge-neutral";
        dom.gatesSummaryBadge.textContent = "Not Run";
      }
    }

    const tbodyGates = document.getElementById("tbody-gates");
    if (tbodyGates && checks.length > 0) {
      tbodyGates.innerHTML = checks
        .map((g) => {
          let badgeClass = "badge-neutral";
          let badgeText = "Not Run";
          if (g.status === "passed") {
            badgeClass = "badge-success";
            badgeText = "Passed";
          } else if (g.status === "failed") {
            badgeClass = "badge-danger";
            badgeText = "Failed";
          }
          return `
            <tr data-gate-id="${escapeHtml(g.id)}">
              <td><strong>${escapeHtml(g.id)}</strong></td>
              <td>${escapeHtml(g.category || "check")} &middot; <code>${escapeHtml(g.tool || "")}</code></td>
              <td><div>${escapeHtml(g.scope || "")}</div><div class="text-muted text-xs">${escapeHtml(g.detail || "")}</div></td>
              <td><span class="badge ${badgeClass}" data-gate-badge="${escapeHtml(g.id)}" title="${escapeHtml(g.detail || "")}">${badgeText}</span></td>
            </tr>
          `;
        })
        .join("");
    }

    const historyEl = document.getElementById("gates-history-container");
    const historyList = Array.isArray(data.history) ? data.history : [];
    if (historyEl) {
      if (historyList.length === 0) {
        historyEl.style.display = "none";
        historyEl.innerHTML = "";
      } else {
        historyEl.style.display = "block";
        historyEl.innerHTML =
          `<div class="text-xs text-muted"><strong>Historical / Invalidated Runs (${historyList.length}):</strong></div>` +
          `<ul style="margin: 0.25rem 0 0 1.25rem; font-size: 0.8rem;">` +
          historyList
            .slice(0, 5)
            .map((h) => {
              const hb = h.binding || {};
              return `<li><code>${escapeHtml(hb.installation_id || "")}</code> @ rev <code>${escapeHtml(String(hb.config_revision || "").slice(0, 12))}</code> &mdash; invalidated (${escapeHtml(h.invalidated_reason || "superseded")})</li>`;
            })
            .join("") +
          `</ul>`;
      }
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

    const adminGroup = data.admin_group || state.configData?.env?.KEYCLOAK_ADMIN_GROUP || "KRATE_ADMINS";
    const viewerGroup = data.viewer_group || state.configData?.env?.KEYCLOAK_VIEWER_GROUP || "KRATE_VIEWERS";

    dom.tbodyUsers.innerHTML = users
      .map((u) => {
        const groups = Array.isArray(u.groups)
          ? u.groups.map((g) => String(g).trim().replace(/^\/+/, ""))
          : [];
        const cleanAdmin = String(adminGroup).trim().replace(/^\/+/, "");
        const cleanViewer = String(viewerGroup).trim().replace(/^\/+/, "");
        const isAdmin = u.is_admin === true || u.role === "admin" || groups.includes(cleanAdmin);
        const isViewer = !isAdmin && (u.role === "viewer" || groups.includes(cleanViewer));
        const roleBadge = isAdmin
          ? `<span class="badge badge-danger">Admin</span>`
          : isViewer
          ? `<span class="badge badge-info">Viewer</span>`
          : `<span class="badge badge-neutral">No Group</span>`;
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
      if (dom.selectWorkspace && state.workspaces.length > 0) {
        dom.selectWorkspace.innerHTML = state.workspaces
          .map((ws) => {
            const editionLabel = (ws.variant || ws.name || "krate").toUpperCase();
            const suffix = ws.is_package ? " (Bundle)" : "";
            const label = `${editionLabel} — ${ws.path}${suffix}`;
            const isSelected = ws.path === data.active_workspace || ws.active ? " selected" : "";
            return `<option value="${escapeHtml(ws.path)}"${isSelected}>${escapeHtml(label)}</option>`;
          })
          .join("");
      }
      if (data.active_workspace && dom.selectWorkspace) {
        state.activeWorkspace = data.active_workspace;
        dom.selectWorkspace.value = data.active_workspace;
      }
      if (data.mutation_active !== undefined) {
        updateWorkspaceSelectorLock(Boolean(data.mutation_active));
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
    if (viewName === "observability") fetchStatus();
    if (viewName === "release") fetchGates();
  }

  function setupNavigation() {
    // Drawer mini-variant collapse toggle
    const isNavCollapsed = localStorage.getItem("krate_nav_collapsed") === "true";
    if (isNavCollapsed && dom.navRail) {
      dom.navRail.classList.add("collapsed");
    }
    const toggleNavRail = () => {
      if (!dom.navRail) return;
      const collapsed = dom.navRail.classList.toggle("collapsed");
      localStorage.setItem("krate_nav_collapsed", collapsed ? "true" : "false");
    };
    dom.btnDrawerToggle?.addEventListener("click", toggleNavRail);
    dom.btnRailCollapse?.addEventListener("click", toggleNavRail);

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
        await fetchWorkspaces();
        await fetchStatus();
        await fetchDoctor();
        await fetchConfig();
        await fetchGates();
      } catch (err) {
        if (dom.selectWorkspace && state.activeWorkspace) {
          dom.selectWorkspace.value = state.activeWorkspace;
        }
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
    dom.btnQuickStart?.addEventListener("click", () => {
      if (state.clusterStatus?.is_package && !state.clusterStatus?.is_installed) {
        triggerJob("install");
      } else {
        triggerJob("start");
      }
    });
    dom.btnStepDocker?.addEventListener("click", () => triggerJob("docker-install"));
    dom.btnStepCerts?.addEventListener("click", () => triggerJob("gen-cert"));
    dom.btnStepImages?.addEventListener("click", () => triggerJob("load-images"));
    dom.btnStepInstall?.addEventListener("click", () => triggerJob("install"));
    dom.btnStepStart?.addEventListener("click", () => {
      if (state.clusterStatus?.is_package && !state.clusterStatus?.is_installed) {
        triggerJob("install");
      } else {
        triggerJob("start");
      }
    });

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
        const tabId = tab.dataset.tab || "cluster-env";
        state.activeConfigTab = tabId;
        if (tabId === "cluster-env") {
          state.rawConfigTarget = ".env";
        } else if (tabId === "monitoring-env") {
          state.rawConfigTarget = "monitoring/.env";
        } else if (tabId === "raw-editor" && state.configData) {
          updateRawEditorFromConfig(state.configData);
        }
        const pane = document.getElementById(`pane-${tabId}`);
        if (pane) pane.classList.add("active");
      });
    });

    dom.btnReloadConfig?.addEventListener("click", fetchConfig);
    dom.btnPreviewConfig?.addEventListener("click", async () => {
      try {
        const payload = collectActiveConfigPayload();
        const res = await apiFetch("/api/v1/config/plan", {
          method: "POST",
          body: payload,
        });
        renderConfigPlanPreview(res);
        showToast(`Plan computed (${(res.changes || []).length} change(s))`, "info");
      } catch (err) {
        showToast(`Plan failed: ${err.message}`, "danger");
      }
    });

    dom.btnSaveDraft?.addEventListener("click", async () => {
      try {
        const payload = collectActiveConfigPayload();
        payload.action = "save";
        const res = await apiFetch("/api/v1/config/draft", {
          method: "POST",
          body: payload,
        });
        renderConfigPlanPreview(res);
        await fetchConfig();
        showToast("Staged draft saved (live .env untouched)", "success");
      } catch (err) {
        showToast(`Draft save failed: ${err.message}`, "danger");
      }
    });

    dom.btnDiscardDraft?.addEventListener("click", async () => {
      try {
        await apiFetch("/api/v1/config/draft", {
          method: "POST",
          body: { action: "discard", target: ".env" },
        });
        if (dom.configPlanPreview) dom.configPlanPreview.style.display = "none";
        await fetchConfig();
        showToast("Staged draft discarded", "info");
      } catch (err) {
        showToast(`Discard draft failed: ${err.message}`, "danger");
      }
    });

    dom.btnRecoverConfig?.addEventListener("click", async () => {
      try {
        if (dom.configStateBadge) {
          dom.configStateBadge.className = "badge badge-warning";
          dom.configStateBadge.textContent = "Recovering...";
        }
        const res = await apiFetch("/api/v1/config/recover", {
          method: "POST",
          body: {},
        });
        renderConfigPlanPreview(res);
        await fetchConfig();
        showToast("Configuration recovery completed and verified", "success");
      } catch (err) {
        await fetchConfig();
        showToast(`Recovery failed: ${err.message}`, "danger");
      }
    });

    dom.btnSaveConfig?.addEventListener("click", async () => {
      showToast("Applying and verifying configuration...", "info");
      if (dom.configStateBadge) {
        dom.configStateBadge.className = "badge badge-info";
        dom.configStateBadge.textContent = "Applying...";
      }
      updateWorkspaceSelectorLock(true);
      try {
        const payload = collectActiveConfigPayload();
        const res = await apiFetch("/api/v1/config/apply", {
          method: "POST",
          body: payload,
        });
        renderConfigPlanPreview(res);
        await fetchConfig();
        await fetchStatus();
        showToast("Configuration applied and verified", "success");
      } catch (err) {
        await fetchConfig();
        showToast(`Apply failed: ${err.message}`, "danger");
      } finally {
        updateWorkspaceSelectorLock(Boolean(state.activeJob && state.activeJob.status === "running" && state.activeJob.isMutation));
      }
    });

    // Identity actions
    dom.btnRefreshUsers?.addEventListener("click", fetchUsers);
    dom.btnOpenAddUser?.addEventListener("click", () => openModal(dom.modalAddUser));
    dom.btnOpenRotateModal?.addEventListener("click", () => openModal(dom.modalRotate));
    dom.btnBackupIdentity?.addEventListener("click", () => {
      if (dom.inputBackupFile && !dom.inputBackupFile.value.trim()) {
        const dateStamp = new Date().toISOString().slice(0, 10);
        dom.inputBackupFile.value = `identity-backup-${dateStamp}.enc`;
      }
      if (dom.inputBackupPassphrase) dom.inputBackupPassphrase.value = "";
      if (dom.inputBackupPassphraseConfirm) dom.inputBackupPassphraseConfirm.value = "";
      openModal(dom.modalBackup);
    });

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
        state.activeJob = {
          id: res.job_id,
          action: "sso_orchestrate",
          status: "running",
          isMutation: true,
          context: res.context || null,
        };
        updateWorkspaceSelectorLock(true);
        connectJobStream(res.job_id);
      } catch (err) {
        showToast(`SSO orchestrator error: ${err.message}`, "danger");
      }
    });

    dom.btnSsoFallback?.addEventListener("click", () => {
      const target = dom.selectSsoTarget?.value || "both";
      triggerJob("auth_fallback", { target, mode: "local" });
    });

    // Observability actions: single backend monitoring-restart job
    dom.btnMonitorToggle?.addEventListener("click", async () => {
      await triggerJob("monitor_restart");
    });

    // Release & Gates actions
    dom.btnRunGates?.addEventListener("click", async () => {
      const gateJob = await triggerJob("gates");
      if (gateJob && gateJob.job_id) {
        await waitForJobCompletion(gateJob.job_id);
        await fetchGates();
      }
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

        state.tofuData = { host, port, user, password, raw_key: res.raw_key };
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
    await fetchWorkspaces();
    await fetchStatus();
    await fetchCredentials();
    await fetchDoctor();
    await fetchGates();

    startPolling();
  }

  // Run on DOM ready
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
