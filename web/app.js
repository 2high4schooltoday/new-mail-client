const state = {
  user: null,
  mailbox: "INBOX",
  messages: [],
  selectedMessage: null,
  theme: "machine-dark",
  auth: {
    lastUnauthorizedAtMs: 0,
    lastUnauthorizedCode: "",
  },
  setup: {
    required: false,
    step: 0,
    baseDomain: "",
    defaultAdminEmail: "",
    authMode: "sql",
    passwordMinLength: 12,
    passwordMaxLength: 128,
    passwordClassMin: 3,
    submitting: false,
    adminEmailTouched: false,
    lastAutoAdminEmail: "",
    retryUntilMs: 0,
    retryTimer: 0,
    adminMailboxLogin: "",
  },
  update: {
    pollTimer: 0,
    checking: false,
    applying: false,
    lastStatus: null,
    apiMissing: false,
  },
  captcha: {
    config: null,
    token: "",
    scriptLoaded: false,
    scriptPromise: null,
    widgetActive: false,
    widgetBlocked: false,
    widgetError: "",
  },
  ui: {
    activeAuthPane: "login",
    composeOpen: false,
    composeLastTrigger: null,
    activeMailPane: "mailboxes",
    activeKeyboardPane: "mailboxes",
    activeAdminSection: "update",
  },
  admin: {
    registrations: {
      q: "",
      status: "pending",
      sort: "created_at",
      order: "desc",
      selected: new Set(),
    },
    users: {
      q: "",
      status: "all",
      role: "all",
      provision: "all",
      sort: "created_at",
      order: "desc",
      selected: new Set(),
    },
    audit: {
      q: "",
      action: "all",
      actor: "",
      target: "",
      from: "",
      to: "",
      sort: "created_at",
      order: "desc",
    },
  },
};

const el = {
  appShell: document.getElementById("app-shell"),
  status: document.getElementById("status-line"),
  btnTheme: document.getElementById("btn-theme"),
  tabSetup: document.getElementById("tab-setup"),
  tabAuth: document.getElementById("tab-auth"),
  tabMail: document.getElementById("tab-mail"),
  tabAdmin: document.getElementById("tab-admin"),
  btnLogout: document.getElementById("btn-logout"),
  viewSetup: document.getElementById("view-setup"),
  viewAuth: document.getElementById("view-auth"),
  viewMail: document.getElementById("view-mail"),
  viewAdmin: document.getElementById("view-admin"),
  mailPaneMailboxes: document.getElementById("mail-pane-mailboxes"),
  mailPaneMessages: document.getElementById("mail-pane-messages"),
  mailPaneReader: document.getElementById("mail-pane-reader"),
  mailMobileBack: document.getElementById("mail-mobile-back"),
  mailBackToMailboxes: document.getElementById("mail-back-to-mailboxes"),
  mailBackToMessages: document.getElementById("mail-back-to-messages"),
  authModeLogin: document.getElementById("auth-mode-login"),
  authModeRegister: document.getElementById("auth-mode-register"),
  authModeReset: document.getElementById("auth-mode-reset"),
  authPaneLogin: document.getElementById("auth-pane-login"),
  authPaneRegister: document.getElementById("auth-pane-register"),
  authPaneReset: document.getElementById("auth-pane-reset"),
  mailboxes: document.getElementById("mailboxes"),
  messages: document.getElementById("messages"),
  meta: document.getElementById("message-meta"),
  body: document.getElementById("message-body"),
  attachments: document.getElementById("attachment-list"),
  searchInput: document.getElementById("search-input"),
  btnSearch: document.getElementById("btn-search"),
  btnFlag: document.getElementById("btn-flag"),
  btnSeen: document.getElementById("btn-mark-seen"),
  btnTrash: document.getElementById("btn-trash"),
  btnComposeOpen: document.getElementById("btn-compose-open"),
  btnComposeClose: document.getElementById("btn-compose-close"),
  btnComposeCancel: document.getElementById("btn-compose-cancel"),
  composeOverlay: document.getElementById("compose-overlay"),
  composeDialog: document.getElementById("compose-dialog"),
  composeForm: document.getElementById("form-compose"),
  registerForm: document.getElementById("form-register"),
  registerSubmit: document.querySelector("#form-register button[type='submit']"),
  captchaShell: document.getElementById("captcha-shell"),
  captchaNote: document.getElementById("captcha-note"),
  captchaError: document.getElementById("captcha-error"),
  captchaWidgetContainer: document.getElementById("captcha-widget-container"),
  captchaManualWrap: document.getElementById("captcha-manual-wrap"),
  captchaManualInput: document.getElementById("captcha-token-manual"),
  captchaTokenHidden: document.getElementById("captcha-token-hidden"),
  adminRegs: document.getElementById("admin-registrations"),
  adminUsers: document.getElementById("admin-users"),
  adminAudit: document.getElementById("admin-audit"),
  adminNavUpdate: document.getElementById("admin-nav-update"),
  adminNavRegistrations: document.getElementById("admin-nav-registrations"),
  adminNavUsers: document.getElementById("admin-nav-users"),
  adminNavAudit: document.getElementById("admin-nav-audit"),
  adminSectionUpdate: document.getElementById("admin-section-update"),
  adminSectionRegistrations: document.getElementById("admin-section-registrations"),
  adminSectionUsers: document.getElementById("admin-section-users"),
  adminSectionAudit: document.getElementById("admin-section-audit"),
  adminRegQ: document.getElementById("admin-reg-q"),
  adminRegStatus: document.getElementById("admin-reg-status"),
  adminRegSort: document.getElementById("admin-reg-sort"),
  adminRegOrder: document.getElementById("admin-reg-order"),
  btnAdminRegApply: document.getElementById("btn-admin-reg-apply"),
  btnRegSelectAll: document.getElementById("btn-reg-select-all"),
  btnRegClear: document.getElementById("btn-reg-clear"),
  btnRegApprove: document.getElementById("btn-reg-approve"),
  btnRegReject: document.getElementById("btn-reg-reject"),
  adminRegCheckAll: document.getElementById("admin-reg-check-all"),
  adminUserQ: document.getElementById("admin-user-q"),
  adminUserStatus: document.getElementById("admin-user-status"),
  adminUserRole: document.getElementById("admin-user-role"),
  adminUserProvision: document.getElementById("admin-user-provision"),
  adminUserSort: document.getElementById("admin-user-sort"),
  adminUserOrder: document.getElementById("admin-user-order"),
  btnAdminUserApply: document.getElementById("btn-admin-user-apply"),
  btnUserSelectAll: document.getElementById("btn-user-select-all"),
  btnUserClear: document.getElementById("btn-user-clear"),
  btnUserSuspend: document.getElementById("btn-user-suspend"),
  btnUserUnsuspend: document.getElementById("btn-user-unsuspend"),
  adminUserCheckAll: document.getElementById("admin-user-check-all"),
  adminAuditQ: document.getElementById("admin-audit-q"),
  adminAuditAction: document.getElementById("admin-audit-action"),
  adminAuditActor: document.getElementById("admin-audit-actor"),
  adminAuditTarget: document.getElementById("admin-audit-target"),
  adminAuditFrom: document.getElementById("admin-audit-from"),
  adminAuditTo: document.getElementById("admin-audit-to"),
  adminAuditSort: document.getElementById("admin-audit-sort"),
  adminAuditOrder: document.getElementById("admin-audit-order"),
  btnAdminAuditApply: document.getElementById("btn-admin-audit-apply"),
  updateCurrentVersion: document.getElementById("update-current-version"),
  updateCurrentCommit: document.getElementById("update-current-commit"),
  updateLatestVersion: document.getElementById("update-latest-version"),
  updateAvailable: document.getElementById("update-available"),
  updateLastChecked: document.getElementById("update-last-checked"),
  updateApplyState: document.getElementById("update-apply-state"),
  updateNote: document.getElementById("update-note"),
  btnUpdateCheck: document.getElementById("btn-update-check"),
  btnUpdateApply: document.getElementById("btn-update-apply"),
  setupBackIcon: document.getElementById("setup-back-icon"),
  setupClose: document.getElementById("setup-close"),
  setupForm: document.getElementById("form-setup"),
  setupBack: document.getElementById("setup-back"),
  setupNext: document.getElementById("setup-next"),
  setupOpenMail: document.getElementById("setup-open-mail"),
  setupOpenAdmin: document.getElementById("setup-open-admin"),
  setupRegion: document.getElementById("setup-region"),
  setupDomain: document.getElementById("setup-domain"),
  setupAdminEmail: document.getElementById("setup-admin-email"),
  setupAdminMailboxLogin: document.getElementById("setup-admin-mailbox-login"),
  setupAdminMailboxLoginWrap: document.getElementById("setup-mailbox-login-wrap"),
  setupPassword: document.getElementById("setup-password"),
  setupPasswordConfirm: document.getElementById("setup-password-confirm"),
  setupSummaryRegion: document.getElementById("setup-summary-region"),
  setupSummaryDomain: document.getElementById("setup-summary-domain"),
  setupSummaryEmail: document.getElementById("setup-summary-email"),
  setupPasswordHint: document.getElementById("setup-password-hint"),
  setupInlineStatus: document.getElementById("setup-inline-status"),
  setupCompleteNote: document.getElementById("setup-complete-note"),
  setupModalOverlay: document.getElementById("setup-modal-overlay"),
  setupModalTitle: document.getElementById("setup-modal-title"),
  setupModalBody: document.getElementById("setup-modal-body"),
  setupModalCancel: document.getElementById("setup-modal-cancel"),
  setupModalConfirm: document.getElementById("setup-modal-confirm"),
};

const setupSteps = [
  document.getElementById("setup-step-0"),
  document.getElementById("setup-step-1"),
  document.getElementById("setup-step-2"),
  document.getElementById("setup-step-3"),
  document.getElementById("setup-step-4"),
  document.getElementById("setup-step-5"),
];

const setupDots = Array.from(document.querySelectorAll(".oobe-dot"));

const ThemeController = {
  getTheme() {
    return state.theme;
  },
  setTheme(themeName) {
    const next = themeName === "machine-dark" ? "machine-dark" : "paper-light";
    state.theme = next;
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("ui.theme", next);
    if (el.btnTheme) {
      el.btnTheme.textContent = next === "machine-dark" ? "Theme: Machine" : "Theme: Paper";
    }
  },
  initTheme() {
    const params = new URLSearchParams(window.location.search);
    const forced = params.get("theme");
    if (forced === "machine-dark" || forced === "paper-light") {
      this.setTheme(forced);
      return state.theme;
    }
    this.setTheme(localStorage.getItem("ui.theme") || "machine-dark");
    return state.theme;
  },
};

function setStatus(text, type = "info") {
  el.status.textContent = text;
  if (type === "error") el.status.style.color = "var(--sig-err)";
  else if (type === "ok") el.status.style.color = "var(--sig-ok)";
  else el.status.style.color = "var(--fg-0)";
}

function setSetupInlineStatus(text, type = "info") {
  if (!el.setupInlineStatus) return;
  el.setupInlineStatus.textContent = text || "";
  if (type === "error") el.setupInlineStatus.style.color = "var(--sig-err)";
  else if (type === "ok") el.setupInlineStatus.style.color = "var(--sig-ok)";
  else el.setupInlineStatus.style.color = "var(--fg-muted)";
}

function apiRequestRef(err) {
  return err && err.requestID ? ` (request ${err.requestID})` : "";
}

function formatAPIError(err, fallbackMessage = "Request failed") {
  const fallback = String(fallbackMessage || "Request failed");
  if (!err || typeof err !== "object") {
    return fallback;
  }
  if (err.code === "csrf_failed") {
    return `Action blocked by CSRF protection. Refresh the page and retry.${apiRequestRef(err)}`;
  }
  if (err.status === 401 && isSessionErrorCode(String(err.code || ""))) {
    return `${reauthMessageForCode(String(err.code || ""))}${apiRequestRef(err)}`;
  }
  const base = String(err.message || fallback).trim() || fallback;
  return `${base}${apiRequestRef(err)}`;
}

function presentAPIError(err, fallbackMessage) {
  setStatus(formatAPIError(err, fallbackMessage), "error");
}

function setActiveAuthPane(pane) {
  const next = ["login", "register", "reset"].includes(String(pane || "")) ? String(pane) : "login";
  state.ui.activeAuthPane = next;
  const modes = {
    login: el.authModeLogin,
    register: el.authModeRegister,
    reset: el.authModeReset,
  };
  const panes = {
    login: el.authPaneLogin,
    register: el.authPaneRegister,
    reset: el.authPaneReset,
  };
  Object.entries(modes).forEach(([key, button]) => {
    if (!button) return;
    const active = key === next;
    button.classList.toggle("is-active", active);
    button.setAttribute("aria-selected", active ? "true" : "false");
    button.setAttribute("tabindex", active ? "0" : "-1");
  });
  Object.entries(panes).forEach(([key, panel]) => {
    if (!panel) return;
    const hidden = key !== next;
    panel.classList.toggle("hidden", hidden);
    panel.setAttribute("aria-hidden", hidden ? "true" : "false");
  });
}

function safeDomID(prefix, raw, fallback = "item") {
  const stem = String(raw || "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "");
  return `${prefix}${stem || fallback}`;
}

function syncMailboxActiveDescendant() {
  if (!el.mailboxes) return;
  const buttons = mailboxesButtons();
  const active = buttons.find((node) => String(node.dataset.mailboxName || "") === state.mailbox) || null;
  for (const button of buttons) {
    const isActive = button === active;
    button.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", isActive ? "true" : "false");
    button.tabIndex = -1;
  }
  if (active) {
    if (!active.id) {
      active.id = safeDomID("mailbox-option-", active.dataset.mailboxName || "", `${buttons.indexOf(active)}`);
    }
    el.mailboxes.setAttribute("aria-activedescendant", active.id);
  } else {
    el.mailboxes.removeAttribute("aria-activedescendant");
  }
}

function syncMessageActiveDescendant() {
  if (!el.messages) return;
  const buttons = messageButtons();
  const selectedID = String(state.selectedMessage?.id || "");
  const active = buttons.find((node) => String(node.dataset.messageId || "") === selectedID) || null;
  for (const button of buttons) {
    const isActive = button === active;
    const row = button.closest(".message-row");
    if (row) row.classList.toggle("active", isActive);
    button.setAttribute("aria-selected", isActive ? "true" : "false");
    button.tabIndex = -1;
  }
  if (active) {
    if (!active.id) {
      active.id = safeDomID("message-option-", active.dataset.messageId || "", `${buttons.indexOf(active)}`);
    }
    el.messages.setAttribute("aria-activedescendant", active.id);
  } else {
    el.messages.removeAttribute("aria-activedescendant");
  }
}

function getCookie(name) {
  const m = document.cookie.match(new RegExp("(^| )" + name + "=([^;]+)"));
  return m ? decodeURIComponent(m[2]) : "";
}

function isProtectedAPIPath(path) {
  return path.startsWith("/api/v1/me")
    || path.startsWith("/api/v1/mailboxes")
    || path.startsWith("/api/v1/messages")
    || path.startsWith("/api/v1/search")
    || path.startsWith("/api/v1/attachments")
    || path.startsWith("/api/v1/admin/");
}

function isSessionErrorCode(code) {
  return code === "session_missing" || code === "session_invalid" || code === "unauthorized";
}

function reauthMessageForCode(code) {
  if (code === "session_missing") {
    return "Session cookie is missing. Check HTTP/HTTPS cookie policy, then sign in again.";
  }
  return "Session is invalid or expired. Sign in again.";
}

function routeToAuthWithMessage(message, code = "") {
  const now = Date.now();
  const shouldAnnounce = now - state.auth.lastUnauthorizedAtMs > 1800 || state.auth.lastUnauthorizedCode !== code;
  state.auth.lastUnauthorizedAtMs = now;
  state.auth.lastUnauthorizedCode = code;
  state.user = null;
  closeComposeOverlay(false);
  applyNavVisibility();
  if (!state.setup.required) {
    setActiveTab(el.tabAuth);
    showView("auth");
    setActiveAuthPane("login");
    void initCaptchaUI();
  }
  if (shouldAnnounce) {
    setStatus(message, "error");
  }
}

function composeDraftKey() {
  return "despatch.compose.draft.v1";
}

function saveComposeDraft(form) {
  if (!form) return;
  const fd = new FormData(form);
  const payload = {
    to: String(fd.get("to") || ""),
    subject: String(fd.get("subject") || ""),
    body: String(fd.get("body") || ""),
  };
  localStorage.setItem(composeDraftKey(), JSON.stringify(payload));
}

function clearComposeDraft() {
  localStorage.removeItem(composeDraftKey());
}

function restoreComposeDraft(form) {
  if (!form) return;
  const raw = localStorage.getItem(composeDraftKey());
  if (!raw) return;
  try {
    const draft = JSON.parse(raw);
    if (typeof draft.to === "string") form.elements.to.value = draft.to;
    if (typeof draft.subject === "string") form.elements.subject.value = draft.subject;
    if (typeof draft.body === "string") form.elements.body.value = draft.body;
  } catch {
    localStorage.removeItem(composeDraftKey());
  }
}

function composeFocusableElements() {
  if (!el.composeDialog) return [];
  return Array.from(el.composeDialog.querySelectorAll("button, [href], input, textarea, select, [tabindex]:not([tabindex='-1'])"))
    .filter((node) => !node.disabled && node.offsetParent !== null);
}

function openComposeOverlay(trigger = null) {
  if (!el.composeOverlay) return;
  state.ui.composeOpen = true;
  state.ui.composeLastTrigger = trigger || document.activeElement || null;
  el.composeOverlay.classList.remove("hidden");
  el.composeOverlay.setAttribute("aria-hidden", "false");
  document.body.style.overflow = "hidden";
  if (el.composeForm) {
    restoreComposeDraft(el.composeForm);
    const toInput = el.composeForm.elements.to;
    if (toInput && typeof toInput.focus === "function") {
      toInput.focus();
    }
  }
}

function closeComposeOverlay(restoreFocus = true) {
  if (!el.composeOverlay) return;
  state.ui.composeOpen = false;
  el.composeOverlay.classList.add("hidden");
  el.composeOverlay.setAttribute("aria-hidden", "true");
  document.body.style.overflow = "";
  if (restoreFocus && state.ui.composeLastTrigger && typeof state.ui.composeLastTrigger.focus === "function") {
    state.ui.composeLastTrigger.focus();
  }
  state.ui.composeLastTrigger = null;
}

function handleComposeOverlayKeydown(event) {
  if (!state.ui.composeOpen) return;
  if (event.key === "Escape") {
    event.preventDefault();
    closeComposeOverlay(true);
    return;
  }
  if (event.key !== "Tab") return;
  const focusables = composeFocusableElements();
  if (focusables.length === 0) return;
  const first = focusables[0];
  const last = focusables[focusables.length - 1];
  if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  } else if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  }
}

async function api(path, opts = {}) {
  const method = opts.method || "GET";
  const headers = Object.assign({}, opts.headers || {});
  const init = { method, credentials: "include", headers };

  if (opts.json !== undefined) {
    headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.json);
  } else if (opts.body !== undefined) {
    init.body = opts.body;
  }

  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const csrf = getCookie("mailclient_csrf");
    if (csrf) headers["X-CSRF-Token"] = csrf;
  }

  const res = await fetch(path, init);
  const text = await res.text();
  const payload = text ? (() => {
    try { return JSON.parse(text); } catch { return {}; }
  })() : {};

  if (!res.ok) {
    const error = new Error(payload.message || payload.code || `HTTP ${res.status}`);
    error.code = payload.code || "request_failed";
    error.retryAfterSec = Number(res.headers.get("Retry-After") || "0");
    error.status = res.status;
    error.requestID = payload.request_id || res.headers.get("X-Request-ID") || "";
    if (opts.logErrors !== false && window && window.console && typeof window.console.error === "function") {
      console.error("API request failed", {
        path,
        method,
        status: error.status,
        code: error.code,
        message: error.message,
        request_id: error.requestID,
      });
    }
    const shouldHandleUnauthorized = error.status === 401
      && isSessionErrorCode(error.code)
      && isProtectedAPIPath(path)
      && !opts.skipUnauthorizedHandling
      && !state.setup.required
      && !!state.user;
    if (shouldHandleUnauthorized) {
      routeToAuthWithMessage(reauthMessageForCode(error.code), error.code);
    }
    throw error;
  }
  return payload;
}

function ensureSlashSuffix(v) {
  const value = String(v || "").trim();
  if (!value) return "";
  if (value.endsWith("/")) return value;
  return `${value}/`;
}

function setCaptchaToken(token) {
  state.captcha.token = String(token || "").trim();
  if (el.captchaTokenHidden) {
    el.captchaTokenHidden.value = state.captcha.token;
  }
  if (el.captchaManualInput && document.activeElement !== el.captchaManualInput) {
    el.captchaManualInput.value = state.captcha.token;
  }
  syncRegisterSubmitState();
}

function setCaptchaNote(text, type = "info") {
  if (!el.captchaNote) return;
  el.captchaNote.textContent = text || "";
  if (type === "error") el.captchaNote.style.color = "var(--sig-err)";
  else if (type === "ok") el.captchaNote.style.color = "var(--sig-ok)";
  else el.captchaNote.style.color = "var(--fg-muted)";
}

function setCaptchaError(text) {
  state.captcha.widgetError = String(text || "");
  if (!el.captchaError) return;
  el.captchaError.textContent = state.captcha.widgetError;
  el.captchaError.style.color = state.captcha.widgetError ? "var(--sig-err)" : "var(--fg-muted)";
}

function syncRegisterSubmitState() {
  if (!el.registerSubmit) return;
  const cfg = state.captcha.config;
  if (!cfg || !cfg.enabled) {
    el.registerSubmit.disabled = false;
    return;
  }
  const provider = String(cfg.provider || "").toLowerCase();
  if (provider !== "cap") {
    el.registerSubmit.disabled = state.captcha.token.length === 0;
    return;
  }
  if (state.captcha.widgetBlocked) {
    el.registerSubmit.disabled = true;
    return;
  }
  el.registerSubmit.disabled = state.captcha.token.length === 0;
}

function renderCaptchaShell(show) {
  if (!el.captchaShell) return;
  el.captchaShell.classList.toggle("hidden", !show);
}

function showCaptchaManualInput(show) {
  if (!el.captchaManualWrap) return;
  el.captchaManualWrap.classList.toggle("hidden", !show);
}

function clearCaptchaWidget() {
  if (!el.captchaWidgetContainer) return;
  el.captchaWidgetContainer.replaceChildren();
}

function capWidgetPaths(cfg) {
  const endpoint = ensureSlashSuffix(cfg?.widget_api_url || "");
  if (!endpoint) {
    throw new Error("CAPTCHA_WIDGET_API_URL is not set");
  }
  const siteKey = String(cfg?.site_key || "").trim();
  const parsed = new URL(endpoint, window.location.origin);
  let path = parsed.pathname.replace(/\/+$/, "");
  if (siteKey) {
    const suffix = `/${siteKey}`.toLowerCase();
    if (path.toLowerCase().endsWith(suffix)) {
      path = path.slice(0, path.length - suffix.length);
    }
  }
  if (!path) path = "/";
  const assetBase = `${parsed.origin}${path}`.replace(/\/$/, "");
  return {
    endpoint: parsed.toString(),
    scriptURL: `${assetBase}/assets/widget.js`,
    wasmURL: `${assetBase}/assets/cap_wasm_bg.wasm`,
    hashesURL: `${assetBase}/assets/wasm-hashes.min.js`,
  };
}

async function fetchCapAsset(url, expectsBinary) {
  const res = await fetch(url, {
    method: "GET",
    cache: "no-store",
    credentials: "omit",
  });
  if (!res.ok) {
    throw new Error(`asset ${url} returned HTTP ${res.status}`);
  }
  if (expectsBinary) {
    const ctype = String(res.headers.get("content-type") || "").toLowerCase();
    if (ctype.includes("text/html") || ctype.startsWith("text/")) {
      throw new Error(`asset ${url} returned non-binary content-type ${ctype || "<empty>"}`);
    }
    await res.arrayBuffer();
    return;
  }
  const body = await res.text();
  if (!body || body.includes("Failed to resolve the requested file")) {
    throw new Error(`asset ${url} is unresolved in CAP runtime`);
  }
}

async function preflightCapAssets(paths) {
  await fetchCapAsset(paths.scriptURL, false);
  await fetchCapAsset(paths.wasmURL, true);
  let hashesURL = "";
  try {
    await fetchCapAsset(paths.hashesURL, false);
    hashesURL = paths.hashesURL;
  } catch {
    hashesURL = "";
  }
  return { hashesURL };
}

function loadCapWidgetScript(paths, preflight = null) {
  if (state.captcha.scriptLoaded && window.customElements && window.customElements.get("cap-widget")) {
    return Promise.resolve();
  }
  if (state.captcha.scriptPromise) {
    return state.captcha.scriptPromise;
  }
  state.captcha.scriptPromise = new Promise((resolve, reject) => {
    window.CAP_CUSTOM_WASM_URL = paths.wasmURL;
    if (preflight?.hashesURL) {
      window.CAP_CUSTOM_HASHES_URL = preflight.hashesURL;
    } else {
      delete window.CAP_CUSTOM_HASHES_URL;
    }
    const existing = document.querySelector("script[data-cap-widget-script='1']");
    if (existing) {
      existing.addEventListener("load", () => {
        state.captcha.scriptLoaded = true;
        resolve();
      }, { once: true });
      existing.addEventListener("error", () => reject(new Error(`failed to load cap widget script: ${paths.scriptURL}`)), { once: true });
      return;
    }
    const script = document.createElement("script");
    script.src = paths.scriptURL;
    script.defer = true;
    script.dataset.capWidgetScript = "1";
    script.onload = () => {
      state.captcha.scriptLoaded = true;
      resolve();
    };
    script.onerror = () => {
      reject(new Error(`failed to load cap widget script: ${paths.scriptURL}`));
    };
    document.head.appendChild(script);
  }).finally(() => {
    state.captcha.scriptPromise = null;
  });
  return state.captcha.scriptPromise;
}

function mountCapWidget(paths) {
  clearCaptchaWidget();
  if (!el.captchaWidgetContainer) return;
  const widget = document.createElement("cap-widget");
  // cap-widget versions in standalone runtime read `cap-api-endpoint` directly.
  // Keep the data-* attribute for forward compatibility.
  widget.setAttribute("cap-api-endpoint", paths.endpoint);
  widget.setAttribute("data-cap-api-endpoint", paths.endpoint);
  widget.setAttribute("data-cap-hidden-field-name", "cap_internal_token");
  widget.setAttribute("data-cap-language", "en");
  widget.setAttribute("data-cap-max-retries", "3");
  widget.addEventListener("solve", (event) => {
    const detailToken = String(event?.detail?.token || "").trim();
    if (detailToken) {
      setCaptchaToken(detailToken);
      setCaptchaError("");
      setCaptchaNote("Challenge solved. You can submit registration.", "ok");
      return;
    }
    const hidden = el.captchaWidgetContainer.querySelector("input[name='cap_internal_token'], input[name='cap-token']");
    setCaptchaToken(hidden ? hidden.value : "");
    if (state.captcha.token) {
      setCaptchaError("");
      setCaptchaNote("Challenge solved. You can submit registration.", "ok");
    }
  });
  widget.addEventListener("error", () => {
    setCaptchaToken("");
    setCaptchaError("Captcha challenge failed. Retry the challenge.");
    setCaptchaNote("Captcha challenge not solved yet.", "error");
  });
  widget.addEventListener("reset", () => {
    setCaptchaToken("");
    setCaptchaError("");
    setCaptchaNote("Complete the challenge to continue registration.", "info");
  });
  el.captchaWidgetContainer.appendChild(widget);
  state.captcha.widgetActive = true;
  setCaptchaToken("");
}

async function loadCaptchaConfig() {
  try {
    const cfg = await api("/api/v1/public/captcha/config", { logErrors: false });
    state.captcha.config = cfg || null;
  } catch {
    state.captcha.config = null;
  }
  return state.captcha.config;
}

async function initCaptchaUI() {
  const cfg = await loadCaptchaConfig();
  if (!cfg || !cfg.enabled) {
    renderCaptchaShell(false);
    showCaptchaManualInput(false);
    setCaptchaToken("");
    state.captcha.widgetBlocked = false;
    state.captcha.widgetActive = false;
    setCaptchaError("");
    return;
  }

  renderCaptchaShell(true);
  state.captcha.widgetBlocked = false;
  state.captcha.widgetActive = false;
  setCaptchaToken("");
  setCaptchaError("");

  const provider = String(cfg.provider || "").toLowerCase();
  if (provider !== "cap") {
    showCaptchaManualInput(true);
    setCaptchaNote("Captcha is enabled. Provide token from configured provider.", "info");
    syncRegisterSubmitState();
    return;
  }

  showCaptchaManualInput(false);
  setCaptchaNote("Complete the challenge to continue registration.", "info");
  let paths = null;
  try {
    paths = capWidgetPaths(cfg);
    const preflight = await preflightCapAssets(paths);
    await loadCapWidgetScript(paths, preflight);
    mountCapWidget(paths);
  } catch (err) {
    state.captcha.widgetBlocked = true;
    setCaptchaToken("");
    const assetHint = paths
      ? `Check self-hosted CAP assets: ${paths.scriptURL} and ${paths.wasmURL}.`
      : "Check CAPTCHA_WIDGET_API_URL and CAP standalone route.";
    const secureHint = !window.isSecureContext
      ? " Browser context is not secure; CAPTCHA worker hashing requires HTTPS."
      : "";
    setCaptchaError("Captcha widget failed to load from self-hosted CAP assets.");
    setCaptchaNote(`CAP asset server unavailable. ${assetHint}${secureHint} (${err.message})`, "error");
  }
  syncRegisterSubmitState();
}

async function resetCaptchaChallenge() {
  if (!state.captcha.config || !state.captcha.config.enabled) {
    setCaptchaToken("");
    return;
  }
  const provider = String(state.captcha.config.provider || "").toLowerCase();
  if (provider !== "cap") {
    setCaptchaToken("");
    return;
  }
  try {
    const paths = capWidgetPaths(state.captcha.config);
    const preflight = await preflightCapAssets(paths);
    if (!state.captcha.scriptLoaded) {
      await loadCapWidgetScript(paths, preflight);
    } else if (preflight?.hashesURL) {
      window.CAP_CUSTOM_HASHES_URL = preflight.hashesURL;
    } else {
      delete window.CAP_CUSTOM_HASHES_URL;
    }
    mountCapWidget(paths);
    setCaptchaError("");
    setCaptchaNote("Complete the challenge to continue registration.", "info");
  } catch {
    state.captcha.widgetBlocked = true;
    setCaptchaToken("");
    setCaptchaError("Captcha widget failed to reset from self-hosted CAP assets.");
  }
  syncRegisterSubmitState();
}

function legacyUpdaterStatus() {
  return {
    enabled: false,
    configured: false,
    current: {
      version: "unknown",
      commit: "",
      build_time: "",
      source_repo: "",
    },
    latest: null,
    last_checked_at: "",
    last_check_error: "",
    update_available: false,
    apply: {
      state: "unsupported",
    },
    legacy_backend: true,
  };
}

function setupRetrySecondsRemaining() {
  const ms = Number(state.setup.retryUntilMs || 0) - Date.now();
  if (ms <= 0) return 0;
  return Math.ceil(ms / 1000);
}

function setSetupCooldown(waitSec) {
  const secs = Math.max(1, Number(waitSec || 1));
  state.setup.retryUntilMs = Date.now() + secs * 1000;
  if (state.setup.retryTimer) {
    clearInterval(state.setup.retryTimer);
    state.setup.retryTimer = 0;
  }
  state.setup.retryTimer = window.setInterval(() => {
    const remaining = setupRetrySecondsRemaining();
    if (remaining <= 0) {
      clearInterval(state.setup.retryTimer);
      state.setup.retryTimer = 0;
      state.setup.retryUntilMs = 0;
      setSetupInlineStatus("You can retry initialization now.", "info");
      OOBEController.refreshNavState();
      return;
    }
    setSetupInlineStatus(`Too many attempts. Retry in ${remaining}s.`, "error");
    OOBEController.refreshNavState();
  }, 250);
}

function setActiveTab(tab) {
  [el.tabSetup, el.tabAuth, el.tabMail, el.tabAdmin]
    .filter(Boolean)
    .forEach((btn) => btn.classList.remove("active"));
  if (tab) tab.classList.add("active");
}

function showView(name) {
  el.viewSetup.classList.add("hidden");
  el.viewAuth.classList.add("hidden");
  el.viewMail.classList.add("hidden");
  el.viewAdmin.classList.add("hidden");
  if (name === "setup") el.viewSetup.classList.remove("hidden");
  if (name === "auth") el.viewAuth.classList.remove("hidden");
  if (name === "mail") el.viewMail.classList.remove("hidden");
  if (name === "admin") el.viewAdmin.classList.remove("hidden");

  if (!el.appShell) return;
  el.appShell.classList.remove("page-office", "page-machine", "page-oobe-assistant");
  if (name === "setup") {
    el.appShell.classList.add("page-oobe-assistant");
    return;
  }
  if (state.theme === "machine-dark" && (name === "mail" || name === "admin")) {
    el.appShell.classList.add("page-machine");
    return;
  }
  el.appShell.classList.add("page-office");
}

function isMobileLayout() {
  return window.matchMedia("(max-width: 980px)").matches;
}

function paneElement(name) {
  if (name === "mailboxes") return el.mailPaneMailboxes;
  if (name === "messages") return el.mailPaneMessages;
  return el.mailPaneReader;
}

function paneFocusElement(name) {
  if (name === "mailboxes") return el.mailboxes || paneElement(name);
  if (name === "messages") return el.messages || paneElement(name);
  return paneElement(name);
}

function focusMailPane(name) {
  const next = ["mailboxes", "messages", "reader"].includes(String(name || "")) ? String(name) : "mailboxes";
  state.ui.activeKeyboardPane = next;
  [el.mailPaneMailboxes, el.mailPaneMessages, el.mailPaneReader]
    .filter(Boolean)
    .forEach((node) => node.classList.remove("is-keyboard-pane"));
  const pane = paneElement(next);
  const focusTarget = paneFocusElement(next);
  if (pane) {
    pane.classList.add("is-keyboard-pane");
  }
  if (focusTarget && typeof focusTarget.focus === "function") {
    focusTarget.focus({ preventScroll: true });
  }
}

function setActiveMailPane(name, opts = {}) {
  if (!el.viewMail) return;
  const next = ["mailboxes", "messages", "reader"].includes(String(name || "")) ? String(name) : "mailboxes";
  state.ui.activeMailPane = next;
  el.viewMail.dataset.mobilePane = next;
  if (el.mailMobileBack) {
    el.mailMobileBack.classList.toggle("hidden", !isMobileLayout() || next === "mailboxes");
  }
  if (el.mailBackToMailboxes) {
    el.mailBackToMailboxes.classList.toggle("hidden", !isMobileLayout() || next !== "messages");
  }
  if (el.mailBackToMessages) {
    el.mailBackToMessages.classList.toggle("hidden", !isMobileLayout() || next !== "reader");
  }
  syncMailboxActiveDescendant();
  syncMessageActiveDescendant();
  if (opts.focus !== false) {
    focusMailPane(next);
  }
}

function cycleMailPane(delta = 1) {
  const panes = ["mailboxes", "messages", "reader"];
  const current = panes.indexOf(state.ui.activeKeyboardPane || "mailboxes");
  const nextIndex = (current + delta + panes.length) % panes.length;
  focusMailPane(panes[nextIndex]);
}

function setActiveAdminSection(name) {
  const next = ["update", "registrations", "users", "audit"].includes(String(name || "")) ? String(name) : "update";
  state.ui.activeAdminSection = next;
  const sections = {
    update: el.adminSectionUpdate,
    registrations: el.adminSectionRegistrations,
    users: el.adminSectionUsers,
    audit: el.adminSectionAudit,
  };
  const nav = {
    update: el.adminNavUpdate,
    registrations: el.adminNavRegistrations,
    users: el.adminNavUsers,
    audit: el.adminNavAudit,
  };
  Object.entries(sections).forEach(([key, node]) => {
    if (!node) return;
    node.classList.toggle("hidden", key !== next);
  });
  Object.entries(nav).forEach(([key, node]) => {
    if (!node) return;
    node.classList.toggle("is-active", key === next);
  });
}

function applyNavVisibility() {
  if (state.setup.required) {
    el.tabSetup.style.display = "inline-block";
    el.tabAuth.style.display = "none";
    el.tabMail.style.display = "none";
    el.tabAdmin.style.display = "none";
    el.btnLogout.style.display = "none";
    return;
  }

  el.tabSetup.style.display = "none";
  el.tabAuth.style.display = "inline-block";
  el.tabMail.style.display = "inline-block";
  el.tabAdmin.style.display = state.user && state.user.role === "admin" ? "inline-block" : "none";
  el.btnLogout.style.display = state.user ? "inline-block" : "none";
}

function requireSelectedMessage() {
  if (!state.selectedMessage) {
    throw new Error("Select a message first");
  }
}

function normalizeDomain(v) {
  return String(v || "")
    .trim()
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/\/$/, "")
    .replace(/\.$/, "");
}

function domainToDefaultEmail(domain) {
  const d = normalizeDomain(domain);
  if (!d) return "webmaster@example.com";
  return `webmaster@${d}`;
}

function validDomain(domain) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(domain);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(email || "").trim());
}

function passwordClassCount(password) {
  let classes = 0;
  if (/[a-z]/.test(password)) classes += 1;
  if (/[A-Z]/.test(password)) classes += 1;
  if (/[0-9]/.test(password)) classes += 1;
  if (/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(password)) classes += 1;
  return classes;
}

async function loadSetupStatus() {
  const data = await api("/api/v1/setup/status");
  state.setup.required = !!data.required;
  state.setup.baseDomain = normalizeDomain(data.base_domain || "example.com");
  state.setup.defaultAdminEmail = String(data.default_admin_email || domainToDefaultEmail(state.setup.baseDomain)).toLowerCase();
  state.setup.authMode = String(data.auth_mode || "sql").toLowerCase();
  state.setup.passwordMinLength = Number(data.password_min_length || 12);
  state.setup.passwordMaxLength = Number(data.password_max_length || 128);
  state.setup.passwordClassMin = Number(data.password_class_min || 3);
  return data;
}

async function completeSetup() {
  const domain = normalizeDomain(el.setupDomain.value);
  const email = String(el.setupAdminEmail.value || "").trim().toLowerCase();
  const region = String(el.setupRegion.value || "us-east").trim();
  const password = el.setupPassword.value;
  const mailboxLogin = String(el.setupAdminMailboxLogin?.value || "").trim();

  await api("/api/v1/setup/complete", {
    method: "POST",
    json: {
      base_domain: domain,
      admin_email: email,
      admin_mailbox_login: mailboxLogin,
      admin_password: password,
      region,
    },
  });

  const session = await refreshSession({ throwOnFail: true, skipUnauthorizedHandling: true });
  if (!session.ok) {
    throw new Error("Setup completed, but browser session was not established. Check HTTP/HTTPS cookie policy and sign in.");
  }
  state.setup.required = false;
  applyNavVisibility();
  showView("setup");
  setStatus("SETUP COMPLETE. SIGNED IN AS WEBMASTER.", "ok");
}

const OOBEController = {
  init() {
    const domain = state.setup.baseDomain || "example.com";
    const email = state.setup.defaultAdminEmail || domainToDefaultEmail(domain);
    el.setupDomain.value = domain;
    el.setupAdminEmail.value = email;
    el.setupPassword.value = "";
    el.setupPasswordConfirm.value = "";
    if (el.setupAdminMailboxLogin) el.setupAdminMailboxLogin.value = "";
    el.setupRegion.value = el.setupRegion.value || "us-east";
    if (el.setupCompleteNote) {
      el.setupCompleteNote.textContent = "Auto opening mail in 3 seconds.";
    }
    state.setup.adminEmailTouched = false;
    state.setup.lastAutoAdminEmail = email;
    state.setup.retryUntilMs = 0;
    if (state.setup.retryTimer) {
      clearInterval(state.setup.retryTimer);
      state.setup.retryTimer = 0;
    }
    state.setup.modalType = "";
    state.setup.submitting = false;
    if (state.setup.autoOpenTimer) {
      clearTimeout(state.setup.autoOpenTimer);
      state.setup.autoOpenTimer = 0;
    }
    setSetupInlineStatus("");
    this.updatePasswordHint();
    this.setStep(0);
    this.updateSummary();
  },

  setStep(step) {
    state.setup.step = Math.max(0, Math.min(step, setupSteps.length - 1));
    for (let i = 0; i < setupSteps.length; i += 1) {
      setupSteps[i].classList.toggle("hidden", i !== state.setup.step);
    }
    setupDots.forEach((dot, index) => dot.classList.toggle("active", index <= state.setup.step));
    const isFirst = state.setup.step === 0;
    const isReview = state.setup.step === 4;
    const isComplete = state.setup.step === 5;

    el.setupBack.disabled = isFirst || isComplete || state.setup.submitting;
    el.setupBackIcon.disabled = isFirst || isComplete || state.setup.submitting;
    el.setupNext.disabled = isComplete || state.setup.submitting;
    const retryRemaining = setupRetrySecondsRemaining();
    if (retryRemaining > 0) {
      el.setupNext.textContent = `Retry in ${retryRemaining}s`;
    } else {
      el.setupNext.textContent = state.setup.submitting ? "Initializing..." : isReview ? "Initialize" : "Continue";
    }
    if (!isComplete) setSetupInlineStatus("");
    this.refreshNavState();
  },

  updateSummary() {
    el.setupSummaryRegion.textContent = el.setupRegion.options[el.setupRegion.selectedIndex]?.text || "-";
    el.setupSummaryDomain.textContent = normalizeDomain(el.setupDomain.value) || "-";
    el.setupSummaryEmail.textContent = String(el.setupAdminEmail.value || "-").trim().toLowerCase();
  },

  validateStep(stepId) {
    if (stepId === 2) {
      const domain = normalizeDomain(el.setupDomain.value);
      const email = String(el.setupAdminEmail.value || "").trim().toLowerCase();
      if (!validDomain(domain)) {
        throw new Error("Enter a valid domain (example: mail.example.com or example.com)");
      }
      if (!validEmail(email)) {
        throw new Error("Enter a valid admin email");
      }
      if (!email.endsWith(`@${domain}`)) {
        throw new Error(`Admin email must use @${domain}`);
      }
    }

    if (stepId === 3) {
      const p1 = el.setupPassword.value;
      const p2 = el.setupPasswordConfirm.value;
      if (p1.length === 0) {
        throw new Error("Admin password is required");
      }
      if (p1 !== p2) {
        throw new Error("Password and verify password must match");
      }
      if (state.setup.authMode !== "pam") {
        const minLen = Number(state.setup.passwordMinLength || 12);
        const maxLen = Number(state.setup.passwordMaxLength || 128);
        const classMin = Number(state.setup.passwordClassMin || 3);
        if (p1.length < minLen) {
          throw new Error(`Admin password must be at least ${minLen} characters`);
        }
        if (p1.length > maxLen) {
          throw new Error(`Admin password must be at most ${maxLen} characters`);
        }
        if (passwordClassCount(p1) < classMin) {
          throw new Error(`Password must include at least ${classMin} character classes (lower/upper/number/symbol)`);
        }
      }
    }
  },

  isStepValid(stepId) {
    try {
      this.validateStep(stepId);
      return true;
    } catch {
      return false;
    }
  },

  refreshNavState() {
    if (state.setup.step === 5) {
      el.setupNext.disabled = true;
      return;
    }
    if (setupRetrySecondsRemaining() > 0) {
      el.setupNext.disabled = true;
      el.setupBack.disabled = true;
      return;
    }
    if (state.setup.submitting) {
      el.setupNext.disabled = true;
      el.setupBack.disabled = true;
      return;
    }
    el.setupNext.disabled = !this.isStepValid(state.setup.step);
  },

  async next() {
    if (state.setup.submitting) return;
    if (setupRetrySecondsRemaining() > 0) return;
    this.validateStep(state.setup.step);
    if (state.setup.step < 4) {
      this.setStep(state.setup.step + 1);
      this.updateSummary();
      return;
    }
    if (state.setup.step === 4) {
      state.setup.submitting = true;
      this.refreshNavState();
      setSetupInlineStatus("Initializing setup...", "info");
      try {
        await completeSetup();
        state.setup.submitting = false;
        this.setStep(5);
        this.scheduleAutoOpenMail();
        setSetupInlineStatus("");
      } catch (err) {
        state.setup.submitting = false;
        this.refreshNavState();
        if (err.code === "rate_limited") {
          const wait = Number(err.retryAfterSec || 60);
          setSetupCooldown(wait);
          const wrapped = new Error(`Too many setup attempts. Wait about ${wait} seconds and try again.`);
          wrapped.code = "rate_limited";
          wrapped.requestID = err.requestID || "";
          throw wrapped;
        }
        throw err;
      }
      return;
    }
  },

  updatePasswordHint() {
    if (!el.setupPasswordHint) return;
    if (state.setup.authMode === "pam") {
      el.setupPasswordHint.textContent = "PAM mode: enter the current mailbox password. If login differs from email, provide Mailbox Login.";
      if (el.setupAdminMailboxLoginWrap) {
        el.setupAdminMailboxLoginWrap.classList.remove("hidden");
      }
      return;
    }
    if (el.setupAdminMailboxLoginWrap) {
      el.setupAdminMailboxLoginWrap.classList.add("hidden");
    }
    if (el.setupAdminMailboxLogin) {
      el.setupAdminMailboxLogin.value = "";
    }
    const minLen = Number(state.setup.passwordMinLength || 12);
    const classMin = Number(state.setup.passwordClassMin || 3);
    el.setupPasswordHint.textContent = `Use at least ${minLen} characters and ${classMin} character classes (lower/upper/number/symbol).`;
  },

  back() {
    if (state.setup.step <= 0 || state.setup.step === 5) return;
    this.setStep(state.setup.step - 1);
    this.updateSummary();
  },

  scheduleAutoOpenMail() {
    if (state.setup.autoOpenTimer) clearTimeout(state.setup.autoOpenTimer);
    let ticks = 3;
    if (el.setupCompleteNote) {
      el.setupCompleteNote.textContent = `Auto opening mail in ${ticks} seconds.`;
    }
    const interval = setInterval(() => {
      ticks -= 1;
      if (ticks > 0 && el.setupCompleteNote) {
        el.setupCompleteNote.textContent = `Auto opening mail in ${ticks} seconds.`;
      }
    }, 1000);
    state.setup.autoOpenTimer = window.setTimeout(async () => {
      clearInterval(interval);
      await this.openMail();
    }, 3000);
  },

  async openMail() {
    if (state.setup.autoOpenTimer) {
      clearTimeout(state.setup.autoOpenTimer);
      state.setup.autoOpenTimer = 0;
    }
    setActiveTab(el.tabMail);
    showView("mail");
    setActiveMailPane("messages");
    if (!state.user) {
      routeToAuthWithMessage("Sign in required before opening mailbox.", "session_missing");
      return;
    }
    await loadMailboxes();
    await loadMessages();
  },

  async openAdmin() {
    if (!state.user || state.user.role !== "admin") {
      await this.openMail();
      return;
    }
    if (state.setup.autoOpenTimer) {
      clearTimeout(state.setup.autoOpenTimer);
      state.setup.autoOpenTimer = 0;
    }
    setActiveTab(el.tabAdmin);
    showView("admin");
    setActiveAdminSection(state.ui.activeAdminSection || "update");
    await loadAdmin();
  },

  openConfirm(type) {
    state.setup.modalType = type;
    if (type === "cancel") {
      el.setupModalTitle.textContent = "Discard Setup Progress?";
      el.setupModalBody.textContent = "If you close setup now, initialization stays incomplete and login remains blocked.";
      el.setupModalConfirm.textContent = "Discard";
    } else {
      el.setupModalTitle.textContent = "Reset Entered Values?";
      el.setupModalBody.textContent = "This removes all values entered in the assistant and returns to the welcome step.";
      el.setupModalConfirm.textContent = "Reset";
    }
    el.setupModalOverlay.classList.remove("hidden");
    el.setupModalOverlay.setAttribute("aria-hidden", "false");
    el.setupModalCancel.focus();
  },

  closeConfirm() {
    el.setupModalOverlay.classList.add("hidden");
    el.setupModalOverlay.setAttribute("aria-hidden", "true");
    if (!el.setupNext.disabled) {
      el.setupNext.focus();
    } else {
      el.setupBack.focus();
    }
  },

  async confirm() {
    const type = state.setup.modalType || "cancel";
    this.closeConfirm();
    if (type === "cancel") {
      setStatus("SETUP CANCELLED. COMPLETE SETUP TO LOG IN.", "info");
      return;
    }
    this.init();
    setStatus("SETUP FORM RESET", "info");
  },
};

async function enterSetupIfRequired() {
  const status = await loadSetupStatus();
  if (!status.required) return false;
  state.setup.required = true;
  OOBEController.init();
  applyNavVisibility();
  setActiveTab(el.tabSetup);
  showView("setup");
  setStatus("FIRST-RUN SETUP REQUIRED", "info");
  return true;
}

async function refreshSession(opts = {}) {
  try {
    const me = await api("/api/v1/me", {
      skipUnauthorizedHandling: !!opts.skipUnauthorizedHandling,
      logErrors: !opts.skipUnauthorizedHandling,
    });
    state.user = me;
    setStatus(`Signed in as ${me.email}.`, "ok");
    applyNavVisibility();
    return { ok: true, user: me };
  } catch (err) {
    state.user = null;
    applyNavVisibility();
    if (opts.throwOnFail) throw err;
    return { ok: false, error: err };
  }
}

async function loadMailboxes() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const data = await api("/api/v1/mailboxes");
  el.mailboxes.innerHTML = "";
  for (const [index, mb] of data.entries()) {
    const li = document.createElement("li");
    li.className = "mailbox-row";
    const btn = document.createElement("button");
    btn.innerHTML = `<span class="mailbox-name">${escapeHtml(mb.name)}</span><span class="mailbox-count">${Number(mb.unread || 0)}/${Number(mb.messages || 0)}</span>`;
    btn.className = mb.name === state.mailbox ? "active" : "";
    btn.dataset.mailboxName = mb.name;
    btn.id = safeDomID("mailbox-option-", mb.name, `${index}`);
    btn.type = "button";
    btn.setAttribute("role", "option");
    btn.setAttribute("aria-selected", mb.name === state.mailbox ? "true" : "false");
    btn.tabIndex = -1;
    btn.onclick = async () => {
      state.mailbox = mb.name;
      state.selectedMessage = null;
      el.body.textContent = "Select a message.";
      el.meta.innerHTML = "";
      el.attachments.textContent = "";
      await loadMessages();
      await loadMailboxes();
      setActiveMailPane("messages");
    };
    li.appendChild(btn);
    el.mailboxes.appendChild(li);
  }
  syncMailboxActiveDescendant();
}

function renderMessages(items) {
  el.messages.innerHTML = "";
  state.messages = items;
  if (!Array.isArray(items) || items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "message-empty";
    empty.textContent = "No messages to display.";
    el.messages.appendChild(empty);
    return;
  }
  for (const m of items) {
    const li = document.createElement("li");
    const isActive = state.selectedMessage && state.selectedMessage.id === m.id;
    li.className = "message-row";
    if (isActive) li.classList.add("active");
    if (!m.seen) li.classList.add("is-unread");
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "message-row-btn";
    btn.dataset.messageId = m.id;
    btn.id = safeDomID("message-option-", m.id, "message");
    btn.setAttribute("role", "option");
    btn.setAttribute("aria-selected", isActive ? "true" : "false");
    btn.tabIndex = -1;
    btn.innerHTML = `<span class="message-mark" aria-hidden="true"></span>
      <span class="message-from">${escapeHtml(m.from || "(unknown sender)")}</span>
      <span class="message-subject">${escapeHtml(m.subject || "(no subject)")}</span>
      <span class="message-date">${escapeHtml(formatDate(m.date))}</span>`;
    btn.onclick = () => openMessage(m.id);
    li.appendChild(btn);
    el.messages.appendChild(li);
  }
  syncMessageActiveDescendant();
}

async function loadMessages() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const data = await api(`/api/v1/messages?mailbox=${encodeURIComponent(state.mailbox)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`Mailbox ${state.mailbox} loaded.`, "ok");
}

function renderMessageMeta(rows) {
  el.meta.innerHTML = "";
  for (const [label, rawValue] of rows) {
    const row = document.createElement("div");
    const labelNode = document.createElement("span");
    labelNode.className = "meta-label";
    labelNode.textContent = String(label || "-");

    const valueNode = document.createElement("span");
    valueNode.className = "meta-value";
    const valueText = String(rawValue || "-");
    valueNode.textContent = valueText;
    valueNode.title = valueText;

    row.appendChild(labelNode);
    row.appendChild(valueNode);
    el.meta.appendChild(row);
  }
}

async function openMessage(id) {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const m = await api(`/api/v1/messages/${encodeURIComponent(id)}`);
  state.selectedMessage = m;
  const metaRows = [
    ["From", m.from || "-"],
    ["To", (m.to || []).join(", ") || "-"],
    ["Subject", m.subject || "-"],
    ["Date", formatDate(m.date) || "-"],
  ];
  renderMessageMeta(metaRows);
  el.body.textContent = m.body || "(empty)";

  el.attachments.innerHTML = "";
  for (const a of (m.attachments || [])) {
    const link = document.createElement("a");
    link.href = `/api/v1/attachments/${encodeURIComponent(a.id)}`;
    link.textContent = `${a.filename || "attachment"} (${Math.round((a.size || 0) / 1024)} KB)`;
    link.target = "_blank";
    el.attachments.appendChild(link);
  }
  renderMessages(state.messages);
  syncMessageActiveDescendant();
  setActiveMailPane("reader");
}

async function searchMessages() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const q = el.searchInput.value.trim();
  const data = await api(`/api/v1/search?mailbox=${encodeURIComponent(state.mailbox)}&q=${encodeURIComponent(q)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`Search complete (${(data.items || []).length} results).`, "ok");
  setActiveMailPane("messages");
}

async function sendCompose(form) {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  saveComposeDraft(form);
  const fd = new FormData(form);
  const files = form.querySelector("input[name='attachments']").files;

  if (files && files.length > 0) {
    const mp = new FormData();
    mp.append("to", fd.get("to"));
    mp.append("subject", fd.get("subject"));
    mp.append("body", fd.get("body"));
    for (const f of files) mp.append("attachments", f);
    await api("/api/v1/messages/send", { method: "POST", body: mp });
  } else {
    await api("/api/v1/messages/send", {
      method: "POST",
      json: {
        to: String(fd.get("to")).split(",").map((s) => s.trim()).filter(Boolean),
        subject: String(fd.get("subject") || ""),
        body: String(fd.get("body") || ""),
      },
    });
  }
  clearComposeDraft();
}

function setUpdateNote(text, type = "info") {
  if (!el.updateNote) return;
  el.updateNote.textContent = text || "";
  if (type === "error") el.updateNote.style.color = "var(--sig-err)";
  else if (type === "ok") el.updateNote.style.color = "var(--sig-ok)";
  else el.updateNote.style.color = "var(--fg-muted)";
}

function applyUpdateControls(status) {
  if (!el.btnUpdateCheck || !el.btnUpdateApply) return;
  const st = status || state.update.lastStatus || {};
  const applyState = String(st.apply?.state || "idle");
  const busy = applyState === "queued" || applyState === "in_progress";
  const checkSupported = !st.legacy_backend;
  const assetMissing = String(st.last_check_error || "").toLowerCase().includes("release asset");
  el.btnUpdateCheck.disabled = state.update.checking || !checkSupported;
  const canApply = !!st.enabled && !!st.configured && !!st.update_available && !busy && !state.update.applying && !assetMissing;
  el.btnUpdateApply.disabled = !canApply;
}

function renderUpdateStatus(status) {
  state.update.lastStatus = status || null;
  if (!status) {
    if (el.updateCurrentVersion) el.updateCurrentVersion.textContent = "-";
    if (el.updateCurrentCommit) el.updateCurrentCommit.textContent = "-";
    if (el.updateLatestVersion) el.updateLatestVersion.textContent = "-";
    if (el.updateAvailable) el.updateAvailable.textContent = "-";
    if (el.updateLastChecked) el.updateLastChecked.textContent = "-";
    if (el.updateApplyState) el.updateApplyState.textContent = "idle";
    setUpdateNote("Update status unavailable.", "error");
    applyUpdateControls();
    return;
  }
  if (el.updateCurrentVersion) el.updateCurrentVersion.textContent = status.current?.version || "-";
  if (el.updateCurrentCommit) el.updateCurrentCommit.textContent = status.current?.commit || "-";
  if (el.updateLatestVersion) el.updateLatestVersion.textContent = status.latest?.tag_name || "-";
  if (el.updateAvailable) el.updateAvailable.textContent = status.update_available ? "YES" : "NO";
  if (el.updateLastChecked) el.updateLastChecked.textContent = formatDate(status.last_checked_at) || "-";
  if (el.updateApplyState) el.updateApplyState.textContent = String(status.apply?.state || "idle");

  if (status.legacy_backend) {
    setUpdateNote("This server build does not expose updater API endpoints yet (HTTP 404). Upgrade backend binary manually to a newer release, then reopen Admin.", "error");
  } else if (!status.enabled) {
    setUpdateNote("Software update feature is disabled in configuration (UPDATE_ENABLED=false).", "info");
  } else if (!status.configured) {
    setUpdateNote("Updater is not configured on this host. Install mailclient-updater systemd units to enable one-click updates.", "error");
  } else if (status.last_check_error) {
    if (String(status.last_check_error).toLowerCase().includes("release asset")) {
      setUpdateNote(`Release packaging issue detected for this CPU architecture: ${status.last_check_error}`, "error");
    } else {
      setUpdateNote(`Latest check failed: ${status.last_check_error}`, "error");
    }
  } else if (status.update_available && status.latest?.tag_name) {
    setUpdateNote(`New release available: ${status.latest.tag_name}`, "ok");
  } else {
    setUpdateNote("No update currently available.", "info");
  }
  applyUpdateControls(status);
}

function isUpdateStateBusy(status) {
  const stateName = String(status?.apply?.state || "");
  return stateName === "queued" || stateName === "in_progress";
}

function stopUpdatePolling() {
  if (!state.update.pollTimer) return;
  clearInterval(state.update.pollTimer);
  state.update.pollTimer = 0;
}

function startUpdatePolling() {
  stopUpdatePolling();
  state.update.pollTimer = window.setInterval(async () => {
    try {
      const status = await api("/api/v1/admin/system/update/status", { logErrors: false });
      renderUpdateStatus(status);
      if (!isUpdateStateBusy(status)) {
        stopUpdatePolling();
        if (status.apply?.state === "completed") {
          setStatus(`UPDATE COMPLETED: ${status.apply?.to_version || "new version active"}`, "ok");
        } else if (status.apply?.state === "rolled_back" || status.apply?.state === "failed") {
          setStatus(`UPDATE FAILED: ${status.apply?.error || "rolled back"}`, "error");
        }
      }
    } catch (err) {
      if (err.status === 404) {
        state.update.apiMissing = true;
        stopUpdatePolling();
        renderUpdateStatus(legacyUpdaterStatus());
        return;
      }
      setUpdateNote(`Failed to refresh update status: ${err.message}`, "error");
    }
  }, 2500);
}

async function loadUpdateStatus(forceCheck = false) {
  if (!state.user || state.user.role !== "admin") {
    throw new Error("admin role required");
  }
  if (state.update.apiMissing) {
    const legacy = legacyUpdaterStatus();
    renderUpdateStatus(legacy);
    return legacy;
  }
  let status;
  try {
    status = forceCheck
      ? await api("/api/v1/admin/system/update/check", { method: "POST", json: {}, logErrors: false })
      : await api("/api/v1/admin/system/update/status", { logErrors: false });
  } catch (err) {
    if (err.status === 404) {
      state.update.apiMissing = true;
      const legacy = legacyUpdaterStatus();
      renderUpdateStatus(legacy);
      return legacy;
    }
    throw err;
  }
  renderUpdateStatus(status);
  if (isUpdateStateBusy(status)) {
    startUpdatePolling();
  } else {
    stopUpdatePolling();
  }
  return status;
}

async function loadAdmin() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  try {
    await loadUpdateStatus(false);
  } catch (err) {
    renderUpdateStatus(null);
    setUpdateNote(`Unable to load updater status: ${err.message}`, "error");
  }
  await loadActiveAdminSection();
}

async function loadActiveAdminSection() {
  if (state.ui.activeAdminSection === "registrations") {
    await loadAdminRegistrations();
    return;
  }
  if (state.ui.activeAdminSection === "users") {
    await loadAdminUsers();
    return;
  }
  if (state.ui.activeAdminSection === "audit") {
    await loadAdminAudit();
  }
}

function adminQuery(params) {
  const query = new URLSearchParams();
  Object.entries(params).forEach(([key, value]) => {
    const v = String(value ?? "").trim();
    if (!v) return;
    query.set(key, v);
  });
  return query.toString();
}

function syncAdminCheckAll() {
  if (el.adminRegCheckAll) {
    const boxes = Array.from(document.querySelectorAll(".admin-reg-check"));
    el.adminRegCheckAll.checked = boxes.length > 0 && boxes.every((node) => node.checked);
  }
  if (el.adminUserCheckAll) {
    const boxes = Array.from(document.querySelectorAll(".admin-user-check"));
    el.adminUserCheckAll.checked = boxes.length > 0 && boxes.every((node) => node.checked);
  }
}

async function loadAdminRegistrations() {
  const f = state.admin.registrations;
  const query = adminQuery({
    status: f.status,
    q: f.q,
    sort: f.sort,
    order: f.order,
    page: 1,
    page_size: 100,
  });
  const regs = await api(`/api/v1/admin/registrations?${query}`);
  el.adminRegs.innerHTML = "";
  for (const r of regs.items || []) {
    const regID = String(r.id || r.ID || "").trim();
    const regEmail = String(r.email || r.Email || "").trim();
    const regCreatedAt = r.created_at || r.CreatedAt || "";
    const checked = state.admin.registrations.selected.has(regID);
    const tr = document.createElement("tr");
    tr.dataset.regId = regID;
    tr.innerHTML = `<td class="num"><input class="admin-reg-check" data-id="${escapeHtml(regID)}" type="checkbox" ${checked ? "checked" : ""} aria-label="Select ${escapeHtml(regEmail)}"></td>
      <td>${escapeHtml(regEmail)}</td>
      <td><span class="status-chip status-chip--${escapeHtml(String(r.status || "pending").toLowerCase())}">${escapeHtml(r.status || "pending")}</span></td>
      <td class="num">${formatDate(regCreatedAt)}</td>
      <td></td>`;
    const td = tr.children[4];
    const check = tr.querySelector(".admin-reg-check");
    if (check) {
      check.addEventListener("change", () => {
        if (check.checked) state.admin.registrations.selected.add(regID);
        else state.admin.registrations.selected.delete(regID);
        syncAdminCheckAll();
      });
    }
    const menu = document.createElement("details");
    menu.className = "row-menu";
    menu.innerHTML = `<summary>Actions</summary>`;
    const menuBody = document.createElement("div");
    menuBody.className = "row-menu-body";
    const approve = document.createElement("button");
    approve.className = "cmd-btn cmd-btn--dense cmd-btn--primary";
    approve.textContent = "Approve";
    approve.onclick = async () => {
      try {
        if (!regID) {
          throw new Error("registration id missing from API response");
        }
        await api(`/api/v1/admin/registrations/${encodeURIComponent(regID)}/approve`, { method: "POST", json: {} });
        state.admin.registrations.selected.delete(regID);
        await loadAdminRegistrations();
        setStatus(`Approved ${regEmail}.`, "ok");
      } catch (err) {
        presentAPIError(err, "Failed to approve registration");
      }
    };
    const reject = document.createElement("button");
    reject.className = "cmd-btn cmd-btn--dense cmd-btn--danger";
    reject.textContent = "Reject";
    reject.onclick = async () => {
      try {
        if (!regID) {
          throw new Error("registration id missing from API response");
        }
        const reason = prompt("Reject reason:", "Rejected by admin") || "Rejected";
        await api(`/api/v1/admin/registrations/${encodeURIComponent(regID)}/reject`, { method: "POST", json: { reason } });
        state.admin.registrations.selected.delete(regID);
        await loadAdminRegistrations();
        setStatus(`Rejected ${regEmail}.`, "ok");
      } catch (err) {
        presentAPIError(err, "Failed to reject registration");
      }
    };
    if (!regID) {
      approve.disabled = true;
      reject.disabled = true;
      approve.title = "Registration ID missing in API response";
      reject.title = "Registration ID missing in API response";
    }
    menuBody.appendChild(approve);
    menuBody.appendChild(reject);
    menu.appendChild(menuBody);
    td.appendChild(menu);
    el.adminRegs.appendChild(tr);
  }
  if ((regs.items || []).length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="5">No registrations match the current filters.</td>`;
    el.adminRegs.appendChild(tr);
  }
  syncAdminCheckAll();
}

async function loadAdminUsers() {
  const f = state.admin.users;
  const query = adminQuery({
    q: f.q,
    status: f.status,
    role: f.role,
    provision_state: f.provision,
    sort: f.sort,
    order: f.order,
    page: 1,
    page_size: 100,
  });
  const users = await api(`/api/v1/admin/users?${query}`);
  el.adminUsers.innerHTML = "";
  const visibleUsers = (users.items || []).filter((u) => String(u.status || "").trim().toLowerCase() !== "rejected");
  for (const u of visibleUsers) {
    const userID = String(u.id || "").trim();
    const checked = state.admin.users.selected.has(userID);
    const userStatus = String(u.status || "").trim().toLowerCase();
    const tr = document.createElement("tr");
    tr.dataset.userId = userID;
    tr.innerHTML = `<td class="num"><input class="admin-user-check" data-id="${escapeHtml(userID)}" type="checkbox" ${checked ? "checked" : ""} aria-label="Select ${escapeHtml(String(u.email || ""))}"></td>
      <td>${escapeHtml(u.email)}</td>
      <td>${escapeHtml(u.role)}</td>
      <td><span class="status-chip status-chip--${escapeHtml(userStatus)}">${escapeHtml(u.status)}</span></td>
      <td><span class="status-chip">${escapeHtml(u.provision_state || "-")}</span></td>
      <td></td>`;
    const td = tr.children[5];
    const check = tr.querySelector(".admin-user-check");
    if (check) {
      check.addEventListener("change", () => {
        if (check.checked) state.admin.users.selected.add(userID);
        else state.admin.users.selected.delete(userID);
        syncAdminCheckAll();
      });
    }
    const menu = document.createElement("details");
    menu.className = "row-menu";
    menu.innerHTML = `<summary>Actions</summary>`;
    const menuBody = document.createElement("div");
    menuBody.className = "row-menu-body";
    if (userStatus === "active") {
      const btn = document.createElement("button");
      btn.className = "cmd-btn cmd-btn--dense cmd-btn--danger";
      btn.textContent = "Suspend";
      btn.onclick = async () => {
        try {
          await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/suspend`, { method: "POST", json: {} });
          state.admin.users.selected.delete(userID);
          await loadAdminUsers();
          setStatus(`Suspended ${u.email}.`, "ok");
        } catch (err) {
          presentAPIError(err, "Failed to suspend user");
        }
      };
      menuBody.appendChild(btn);
    } else if (userStatus === "suspended") {
      const btn = document.createElement("button");
      btn.className = "cmd-btn cmd-btn--dense cmd-btn--primary";
      btn.textContent = "Unsuspend";
      btn.onclick = async () => {
        try {
          await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/unsuspend`, { method: "POST", json: {} });
          state.admin.users.selected.delete(userID);
          await loadAdminUsers();
          setStatus(`Unsuspended ${u.email}.`, "ok");
        } catch (err) {
          presentAPIError(err, "Failed to unsuspend user");
        }
      };
      menuBody.appendChild(btn);
    }

    const reset = document.createElement("button");
    reset.className = "cmd-btn cmd-btn--dense";
    reset.textContent = "Reset Password";
    reset.onclick = async () => {
      try {
        const pw = prompt(`New password for ${u.email}:`);
        if (!pw) return;
        await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/reset-password`, { method: "POST", json: { new_password: pw } });
        setStatus(`Password reset for ${u.email}.`, "ok");
      } catch (err) {
        presentAPIError(err, "Failed to reset password");
      }
    };
    menuBody.appendChild(reset);

    menu.appendChild(menuBody);
    td.appendChild(menu);
    el.adminUsers.appendChild(tr);
  }
  if (visibleUsers.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="6">No users match the current filters.</td>`;
    el.adminUsers.appendChild(tr);
  }
  syncAdminCheckAll();
}

async function loadAdminAudit() {
  const f = state.admin.audit;
  const query = adminQuery({
    q: f.q,
    action: f.action,
    actor: f.actor,
    target: f.target,
    from: f.from,
    to: f.to,
    sort: f.sort,
    order: f.order,
    page: 1,
    page_size: 100,
  });
  const audit = await api(`/api/v1/admin/audit-log?${query}`);
  el.adminAudit.innerHTML = "";
  for (const a of audit.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td class="num">${escapeHtml(formatDate(a.created_at))}</td>
      <td><span class="status-chip status-chip--${escapeHtml(String(a.severity || "info").toLowerCase())}">${escapeHtml(String(a.severity || "info").toUpperCase())}</span></td>
      <td>${escapeHtml(a.summary_text || a.action || "-")}</td>
      <td>${escapeHtml(a.actor_email || "-")}</td>
      <td>${escapeHtml(a.target_label || a.target || "-")}</td>`;
    el.adminAudit.appendChild(tr);
  }
  if ((audit.items || []).length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td colspan="5">No audit entries match the current filters.</td>`;
    el.adminAudit.appendChild(tr);
  }
}

async function runBulkRegistrationDecision(decision) {
  const ids = Array.from(state.admin.registrations.selected);
  if (ids.length === 0) {
    setStatus("Select at least one registration.", "error");
    return;
  }
  let reason = "";
  if (decision === "reject") {
    reason = prompt("Reject reason:", "Rejected by admin") || "Rejected";
  }
  const payload = {
    ids,
    decision,
    reason,
  };
  const out = await api("/api/v1/admin/registrations/bulk/decision", { method: "POST", json: payload });
  state.admin.registrations.selected.clear();
  await loadAdminRegistrations();
  const appliedCount = Array.isArray(out.applied) ? out.applied.length : 0;
  const failedCount = Array.isArray(out.failed) ? out.failed.length : 0;
  setStatus(`${decision === "approve" ? "Approved" : "Rejected"} ${appliedCount} registration(s)${failedCount ? `, ${failedCount} failed` : ""}.`, failedCount ? "error" : "ok");
}

async function runBulkUserAction(action) {
  const ids = Array.from(state.admin.users.selected);
  if (ids.length === 0) {
    setStatus("Select at least one user.", "error");
    return;
  }
  const out = await api("/api/v1/admin/users/bulk/action", {
    method: "POST",
    json: { ids, action },
  });
  state.admin.users.selected.clear();
  await loadAdminUsers();
  const appliedCount = Array.isArray(out.applied) ? out.applied.length : 0;
  const failedCount = Array.isArray(out.failed) ? out.failed.length : 0;
  setStatus(`${action === "suspend" ? "Suspended" : "Unsuspended"} ${appliedCount} user(s)${failedCount ? `, ${failedCount} failed` : ""}.`, failedCount ? "error" : "ok");
}

function mailboxesButtons() {
  return Array.from(el.mailboxes.querySelectorAll("button[role='option']"));
}

function messageButtons() {
  return Array.from(el.messages.querySelectorAll(".message-row-btn[role='option']"));
}

async function moveMailboxSelection(delta) {
  const buttons = mailboxesButtons();
  if (buttons.length === 0) return;
  const index = Math.max(0, buttons.findIndex((node) => String(node.dataset.mailboxName || "") === state.mailbox));
  const next = Math.max(0, Math.min(buttons.length - 1, index + delta));
  const nextBtn = buttons[next];
  if (nextBtn) {
    if (el.mailboxes && typeof el.mailboxes.focus === "function") {
      el.mailboxes.focus({ preventScroll: true });
    }
    nextBtn.click();
    syncMailboxActiveDescendant();
  }
}

async function moveMessageSelection(delta) {
  const buttons = messageButtons();
  if (buttons.length === 0) return;
  const currentID = String(state.selectedMessage?.id || "");
  let index = buttons.findIndex((node) => String(node.dataset.messageId || "") === currentID);
  if (index < 0) index = 0;
  const next = Math.max(0, Math.min(buttons.length - 1, index + delta));
  const nextBtn = buttons[next];
  if (nextBtn) {
    if (el.messages && typeof el.messages.focus === "function") {
      el.messages.focus({ preventScroll: true });
    }
    nextBtn.click();
    syncMessageActiveDescendant();
  }
}

async function handleMailKeyboard(event) {
  if (el.viewMail.classList.contains("hidden")) return;
  if (state.ui.composeOpen) return;
  const target = event.target;
  const isEditable = target && (
    target.tagName === "INPUT"
    || target.tagName === "TEXTAREA"
    || target.tagName === "SELECT"
    || target.isContentEditable
  );
  if (isEditable && event.key !== "Escape") return;

  if (event.key === "Tab") {
    event.preventDefault();
    cycleMailPane(event.shiftKey ? -1 : 1);
    return;
  }

  if (event.key === "/" && !event.shiftKey) {
    event.preventDefault();
    el.searchInput.focus();
    return;
  }

  if (event.key.toLowerCase() === "c") {
    event.preventDefault();
    openComposeOverlay(el.btnComposeOpen);
    return;
  }

  if (event.key.toLowerCase() === "f") {
    event.preventDefault();
    if (state.selectedMessage) el.btnFlag.click();
    return;
  }

  if (event.key.toLowerCase() === "s") {
    event.preventDefault();
    if (state.selectedMessage) el.btnSeen.click();
    return;
  }

  if (event.key === "Delete") {
    event.preventDefault();
    if (state.selectedMessage) el.btnTrash.click();
    return;
  }

  if (event.key === "Enter") {
    if (state.ui.activeKeyboardPane === "mailboxes") {
      event.preventDefault();
      const activeID = el.mailboxes?.getAttribute("aria-activedescendant") || "";
      const active = activeID ? document.getElementById(activeID) : null;
      const current = active || mailboxesButtons().find((node) => String(node.dataset.mailboxName || "") === state.mailbox);
      if (current) current.click();
      return;
    }
    if (state.ui.activeKeyboardPane === "messages") {
      event.preventDefault();
      const activeID = el.messages?.getAttribute("aria-activedescendant") || "";
      const active = activeID ? document.getElementById(activeID) : null;
      const current = active || messageButtons().find((node) => String(node.dataset.messageId || "") === String(state.selectedMessage?.id || ""));
      if (current) current.click();
    }
  }

  if (event.key === "Escape") {
    if (isMobileLayout() && state.ui.activeMailPane === "reader") {
      event.preventDefault();
      setActiveMailPane("messages");
      return;
    }
    if (isMobileLayout() && state.ui.activeMailPane === "messages") {
      event.preventDefault();
      setActiveMailPane("mailboxes");
    }
    return;
  }

  const k = event.key.toLowerCase();
  if (state.ui.activeKeyboardPane === "mailboxes" && (k === "j" || event.key === "ArrowDown")) {
    event.preventDefault();
    await moveMailboxSelection(1);
    return;
  }
  if (state.ui.activeKeyboardPane === "mailboxes" && (k === "k" || event.key === "ArrowUp")) {
    event.preventDefault();
    await moveMailboxSelection(-1);
    return;
  }
  if (state.ui.activeKeyboardPane === "messages" && (k === "j" || event.key === "ArrowDown")) {
    event.preventDefault();
    await moveMessageSelection(1);
    return;
  }
  if (state.ui.activeKeyboardPane === "messages" && (k === "k" || event.key === "ArrowUp")) {
    event.preventDefault();
    await moveMessageSelection(-1);
    return;
  }
}

function formatDate(value) {
  if (!value) return "";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function escapeHtml(s) {
  return String(s || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function bindSetupUI() {
  el.setupBack.onclick = () => OOBEController.back();
  el.setupBackIcon.onclick = () => OOBEController.back();
  el.setupClose.onclick = async () => {
    if (state.setup.step === 5 && !state.setup.required) {
      await OOBEController.openMail();
      return;
    }
    OOBEController.openConfirm("cancel");
  };

  el.setupForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (state.setup.step >= 5) return;
    try {
      await OOBEController.next();
      setSetupInlineStatus("");
    } catch (err) {
      if (err.code === "setup_already_complete") {
        try {
          const status = await loadSetupStatus();
          if (!status.required) {
            state.setup.required = false;
            applyNavVisibility();
            setActiveTab(el.tabAuth);
            showView("auth");
            setActiveAuthPane("login");
            setStatus("SETUP ALREADY COMPLETED. SIGN IN WITH ADMIN ACCOUNT.", "info");
            setSetupInlineStatus("");
            return;
          }
        } catch {
          // fallback to normal error rendering below
        }
      }
      if (err.code === "pam_credentials_invalid") {
        if (!/attempted logins:/i.test(String(err.message || ""))) {
          err.message = "PAM mode is enabled. The password or mailbox login identity is invalid. Try the optional Mailbox Login field if IMAP login differs from email.";
        }
      } else if (err.code === "pam_verifier_unavailable") {
        err.message = "Cannot validate PAM credentials right now because IMAP connectivity failed. Check IMAP host/port/TLS and try again.";
      } else if (isSessionErrorCode(err.code)) {
        err.message = "Setup was accepted, but browser session cookie was not established. Check HTTP/HTTPS cookie policy and then sign in from Login.";
      }
      const requestRef = err.requestID ? ` (request ${err.requestID})` : "";
      const detail = err.code && err.code !== "request_failed" ? `${err.message} [${err.code}]${requestRef}` : `${err.message}${requestRef}`;
      setStatus(detail, "error");
      setSetupInlineStatus(detail, "error");
    }
  });

  el.setupOpenMail.onclick = async () => {
    try {
      await OOBEController.openMail();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.setupOpenAdmin.onclick = async () => {
    try {
      await OOBEController.openAdmin();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.setupModalCancel.onclick = () => OOBEController.closeConfirm();
  el.setupModalConfirm.onclick = async () => {
    try {
      await OOBEController.confirm();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.setupModalOverlay.addEventListener("click", (event) => {
    if (event.target === el.setupModalOverlay) {
      OOBEController.closeConfirm();
    }
  });

  el.setupDomain.addEventListener("input", () => {
    const domain = normalizeDomain(el.setupDomain.value);
    const autoEmail = domainToDefaultEmail(domain);
    if (!state.setup.adminEmailTouched || String(el.setupAdminEmail.value).trim().toLowerCase() === state.setup.lastAutoAdminEmail) {
      el.setupAdminEmail.value = autoEmail;
      state.setup.lastAutoAdminEmail = autoEmail;
    }
    OOBEController.updateSummary();
    OOBEController.refreshNavState();
  });

  el.setupAdminEmail.addEventListener("input", () => {
    const email = String(el.setupAdminEmail.value || "").trim().toLowerCase();
    state.setup.adminEmailTouched = email !== state.setup.lastAutoAdminEmail;
    OOBEController.updateSummary();
    OOBEController.refreshNavState();
  });

  el.setupRegion.addEventListener("change", () => {
    OOBEController.updateSummary();
    OOBEController.refreshNavState();
  });
  el.setupPassword.addEventListener("input", () => OOBEController.refreshNavState());
  el.setupPasswordConfirm.addEventListener("input", () => OOBEController.refreshNavState());

  document.addEventListener("keydown", async (event) => {
    if (!state.setup.required || el.viewSetup.classList.contains("hidden")) return;
    if (!el.setupModalOverlay.classList.contains("hidden")) {
      if (event.key === "Tab") {
        event.preventDefault();
        const focusables = [el.setupModalCancel, el.setupModalConfirm];
        const currentIndex = focusables.findIndex((node) => node === document.activeElement);
        const nextIndex = (currentIndex + (event.shiftKey ? -1 : 1) + focusables.length) % focusables.length;
        focusables[nextIndex].focus();
      }
      if (event.key === "Escape") {
        event.preventDefault();
        OOBEController.closeConfirm();
      }
      if (event.key === "Enter") {
        event.preventDefault();
        await OOBEController.confirm();
      }
      return;
    }

    if (event.key === "Escape" && state.setup.step > 0 && state.setup.step < 5) {
      event.preventDefault();
      OOBEController.openConfirm("cancel");
    }
  });
}

function bindUI() {
  bindSetupUI();
  setActiveAuthPane("login");
  setActiveAdminSection(state.ui.activeAdminSection || "update");
  setActiveMailPane(state.ui.activeMailPane || "mailboxes", { focus: false });
  if (el.authModeLogin) {
    el.authModeLogin.onclick = () => setActiveAuthPane("login");
  }
  if (el.authModeRegister) {
    el.authModeRegister.onclick = () => {
      setActiveAuthPane("register");
      void initCaptchaUI();
    };
  }
  if (el.authModeReset) {
    el.authModeReset.onclick = () => setActiveAuthPane("reset");
  }
  const authModeButtons = [el.authModeLogin, el.authModeRegister, el.authModeReset].filter(Boolean);
  authModeButtons.forEach((button, index) => {
    button.addEventListener("keydown", (event) => {
      if (event.key !== "ArrowRight" && event.key !== "ArrowLeft") return;
      event.preventDefault();
      const delta = event.key === "ArrowRight" ? 1 : -1;
      const nextIndex = (index + delta + authModeButtons.length) % authModeButtons.length;
      authModeButtons[nextIndex].focus();
      authModeButtons[nextIndex].click();
    });
  });
  if (el.captchaManualInput) {
    el.captchaManualInput.addEventListener("input", () => {
      setCaptchaToken(el.captchaManualInput.value);
      if (state.captcha.token) {
        setCaptchaError("");
        setCaptchaNote("Captcha token captured.", "ok");
      } else {
        setCaptchaNote("Captcha is enabled. Provide token from configured provider.", "info");
      }
    });
  }
  if (el.btnTheme) {
    el.btnTheme.onclick = () => {
      const next = ThemeController.getTheme() === "paper-light" ? "machine-dark" : "paper-light";
      ThemeController.setTheme(next);
      if (state.setup.required) {
        showView("setup");
      } else if (!state.user) {
        showView("auth");
        setActiveAuthPane(state.ui.activeAuthPane || "login");
      } else if (!el.viewAdmin.classList.contains("hidden")) {
        showView("admin");
      } else {
        showView("mail");
      }
    };
  }

  const loadCurrentAdminSection = async () => {
    if (el.viewAdmin.classList.contains("hidden")) return;
    try {
      await loadActiveAdminSection();
    } catch (err) {
      presentAPIError(err, "Failed to load admin data");
    }
  };

  if (el.adminNavUpdate) {
    el.adminNavUpdate.onclick = async () => {
      setActiveAdminSection("update");
      await loadCurrentAdminSection();
    };
  }
  if (el.adminNavRegistrations) {
    el.adminNavRegistrations.onclick = async () => {
      setActiveAdminSection("registrations");
      await loadCurrentAdminSection();
    };
  }
  if (el.adminNavUsers) {
    el.adminNavUsers.onclick = async () => {
      setActiveAdminSection("users");
      await loadCurrentAdminSection();
    };
  }
  if (el.adminNavAudit) {
    el.adminNavAudit.onclick = async () => {
      setActiveAdminSection("audit");
      await loadCurrentAdminSection();
    };
  }

  if (el.btnAdminRegApply) {
    el.btnAdminRegApply.onclick = async () => {
      state.admin.registrations.q = String(el.adminRegQ?.value || "").trim();
      state.admin.registrations.status = String(el.adminRegStatus?.value || "pending").trim();
      state.admin.registrations.sort = String(el.adminRegSort?.value || "created_at").trim();
      state.admin.registrations.order = String(el.adminRegOrder?.value || "desc").trim();
      await loadCurrentAdminSection();
    };
  }
  if (el.btnAdminUserApply) {
    el.btnAdminUserApply.onclick = async () => {
      state.admin.users.q = String(el.adminUserQ?.value || "").trim();
      state.admin.users.status = String(el.adminUserStatus?.value || "all").trim();
      state.admin.users.role = String(el.adminUserRole?.value || "all").trim();
      state.admin.users.provision = String(el.adminUserProvision?.value || "all").trim();
      state.admin.users.sort = String(el.adminUserSort?.value || "created_at").trim();
      state.admin.users.order = String(el.adminUserOrder?.value || "desc").trim();
      await loadCurrentAdminSection();
    };
  }
  if (el.btnAdminAuditApply) {
    el.btnAdminAuditApply.onclick = async () => {
      state.admin.audit.q = String(el.adminAuditQ?.value || "").trim();
      state.admin.audit.action = String(el.adminAuditAction?.value || "all").trim();
      state.admin.audit.actor = String(el.adminAuditActor?.value || "").trim();
      state.admin.audit.target = String(el.adminAuditTarget?.value || "").trim();
      state.admin.audit.from = String(el.adminAuditFrom?.value || "").trim();
      state.admin.audit.to = String(el.adminAuditTo?.value || "").trim();
      state.admin.audit.sort = String(el.adminAuditSort?.value || "created_at").trim();
      state.admin.audit.order = String(el.adminAuditOrder?.value || "desc").trim();
      await loadCurrentAdminSection();
    };
  }

  if (el.btnRegSelectAll) {
    el.btnRegSelectAll.onclick = () => {
      Array.from(document.querySelectorAll(".admin-reg-check")).forEach((node) => {
        node.checked = true;
        const regID = String(node.dataset.id || "");
        if (regID) state.admin.registrations.selected.add(regID);
      });
      syncAdminCheckAll();
    };
  }
  if (el.btnRegClear) {
    el.btnRegClear.onclick = () => {
      state.admin.registrations.selected.clear();
      Array.from(document.querySelectorAll(".admin-reg-check")).forEach((node) => {
        node.checked = false;
      });
      syncAdminCheckAll();
    };
  }
  if (el.btnRegApprove) {
    el.btnRegApprove.onclick = async () => {
      try {
        await runBulkRegistrationDecision("approve");
      } catch (err) {
        presentAPIError(err, "Failed to approve selected registrations");
      }
    };
  }
  if (el.btnRegReject) {
    el.btnRegReject.onclick = async () => {
      try {
        await runBulkRegistrationDecision("reject");
      } catch (err) {
        presentAPIError(err, "Failed to reject selected registrations");
      }
    };
  }
  if (el.adminRegCheckAll) {
    el.adminRegCheckAll.addEventListener("change", () => {
      const checked = el.adminRegCheckAll.checked;
      Array.from(document.querySelectorAll(".admin-reg-check")).forEach((node) => {
        node.checked = checked;
        const id = String(node.dataset.id || "");
        if (!id) return;
        if (checked) state.admin.registrations.selected.add(id);
        else state.admin.registrations.selected.delete(id);
      });
      syncAdminCheckAll();
    });
  }

  if (el.btnUserSelectAll) {
    el.btnUserSelectAll.onclick = () => {
      Array.from(document.querySelectorAll(".admin-user-check")).forEach((node) => {
        node.checked = true;
        const id = String(node.dataset.id || "");
        if (id) state.admin.users.selected.add(id);
      });
      syncAdminCheckAll();
    };
  }
  if (el.btnUserClear) {
    el.btnUserClear.onclick = () => {
      state.admin.users.selected.clear();
      Array.from(document.querySelectorAll(".admin-user-check")).forEach((node) => {
        node.checked = false;
      });
      syncAdminCheckAll();
    };
  }
  if (el.btnUserSuspend) {
    el.btnUserSuspend.onclick = async () => {
      try {
        await runBulkUserAction("suspend");
      } catch (err) {
        presentAPIError(err, "Failed to suspend selected users");
      }
    };
  }
  if (el.btnUserUnsuspend) {
    el.btnUserUnsuspend.onclick = async () => {
      try {
        await runBulkUserAction("unsuspend");
      } catch (err) {
        presentAPIError(err, "Failed to unsuspend selected users");
      }
    };
  }
  if (el.adminUserCheckAll) {
    el.adminUserCheckAll.addEventListener("change", () => {
      const checked = el.adminUserCheckAll.checked;
      Array.from(document.querySelectorAll(".admin-user-check")).forEach((node) => {
        node.checked = checked;
        const id = String(node.dataset.id || "");
        if (!id) return;
        if (checked) state.admin.users.selected.add(id);
        else state.admin.users.selected.delete(id);
      });
      syncAdminCheckAll();
    });
  }

  if (el.mailMobileBack) {
    el.mailMobileBack.onclick = () => {
      if (state.ui.activeMailPane === "reader") setActiveMailPane("messages");
      else if (state.ui.activeMailPane === "messages") setActiveMailPane("mailboxes");
    };
  }
  if (el.mailBackToMailboxes) {
    el.mailBackToMailboxes.onclick = () => setActiveMailPane("mailboxes");
  }
  if (el.mailBackToMessages) {
    el.mailBackToMessages.onclick = () => setActiveMailPane("messages");
  }
  [el.mailPaneMailboxes, el.mailPaneMessages, el.mailPaneReader].forEach((pane) => {
    if (!pane) return;
    pane.addEventListener("focus", () => {
      if (pane === el.mailPaneMailboxes) focusMailPane("mailboxes");
      if (pane === el.mailPaneMessages) focusMailPane("messages");
      if (pane === el.mailPaneReader) focusMailPane("reader");
    });
    pane.addEventListener("click", () => {
      if (pane === el.mailPaneMailboxes) focusMailPane("mailboxes");
      if (pane === el.mailPaneMessages) focusMailPane("messages");
      if (pane === el.mailPaneReader) focusMailPane("reader");
    });
  });
  [el.mailboxes, el.messages].forEach((list) => {
    if (!list) return;
    list.addEventListener("focus", () => {
      if (list === el.mailboxes) focusMailPane("mailboxes");
      if (list === el.messages) focusMailPane("messages");
    });
    list.addEventListener("click", () => {
      if (list === el.mailboxes) focusMailPane("mailboxes");
      if (list === el.messages) focusMailPane("messages");
    });
  });
  window.addEventListener("resize", () => setActiveMailPane(state.ui.activeMailPane, { focus: false }));
  document.addEventListener("keydown", (event) => {
    void handleMailKeyboard(event);
  });

  document.getElementById("form-login").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/v1/login", { method: "POST", json: { email: fd.get("email"), password: fd.get("password") } });
      try {
        await refreshSession({ throwOnFail: true, skipUnauthorizedHandling: true });
      } catch (err) {
        if (isSessionErrorCode(err.code)) {
          routeToAuthWithMessage("Login accepted but browser session cookie was not established. Check HTTP/HTTPS cookie policy.", err.code);
          return;
        }
        throw err;
      }
      await loadMailboxes();
      await loadMessages();
      setActiveTab(el.tabMail);
      showView("mail");
      setActiveMailPane("messages");
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
        return;
      }
      if (err.code === "pam_verifier_unavailable") {
        const requestRef = err.requestID ? ` (request ${err.requestID})` : "";
        setStatus(`PAM/IMAP auth backend is unreachable. Check IMAP connectivity or switch local dev to SQL auth mode.${requestRef}`, "error");
        return;
      }
      setStatus(err.message, "error");
    }
  });

  document.getElementById("form-register").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    const captchaToken = String(fd.get("captcha_token") || "").trim();
    const captchaEnabled = !!state.captcha.config?.enabled;
    if (captchaEnabled && !captchaToken) {
      setCaptchaError("Complete captcha challenge before submitting registration.");
      setCaptchaNote("Captcha challenge not solved yet.", "error");
      setStatus("Complete captcha challenge before submitting registration.", "error");
      syncRegisterSubmitState();
      return;
    }
    try {
      await api("/api/v1/register", {
        method: "POST",
        json: { email: fd.get("email"), password: fd.get("password"), captcha_token: captchaToken },
      });
      setStatus("Registration submitted. Wait for approval.", "ok");
      e.target.reset();
      await resetCaptchaChallenge();
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
        return;
      }
      if (err.code === "captcha_required") {
        setCaptchaError("Captcha validation failed. Please solve a fresh challenge and retry.");
        setCaptchaNote("Captcha challenge failed verification.", "error");
        setStatus("Captcha validation failed. Solve challenge again and retry.", "error");
        await resetCaptchaChallenge();
        return;
      }
      if (err.code === "captcha_unavailable") {
        const requestRef = err.requestID ? ` (request ${err.requestID})` : "";
        setCaptchaError("Captcha verification service is currently unavailable.");
        setCaptchaNote(`Verification service unavailable${requestRef}.`, "error");
        setStatus(`Captcha verification service is unavailable. Please retry shortly.${requestRef}`, "error");
        await resetCaptchaChallenge();
        return;
      }
      setStatus(err.message, "error");
      if (captchaEnabled) {
        await resetCaptchaChallenge();
      }
    }
  });

  document.getElementById("form-reset-request").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/v1/password/reset/request", { method: "POST", json: { email: fd.get("email") } });
      setStatus("If the account exists, reset instructions were sent.", "ok");
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
        return;
      }
      setStatus(err.message, "error");
    }
  });

  document.getElementById("form-reset-confirm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const fd = new FormData(e.target);
    try {
      await api("/api/v1/password/reset/confirm", { method: "POST", json: { token: fd.get("token"), new_password: fd.get("new_password") } });
      setStatus("Password updated.", "ok");
      e.target.reset();
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
        return;
      }
      setStatus(err.message, "error");
    }
  });

  document.getElementById("form-compose").addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await sendCompose(e.target);
      setStatus("Message sent.", "ok");
      e.target.reset();
      clearComposeDraft();
      closeComposeOverlay(true);
      await loadMessages();
    } catch (err) {
      if (err.code === "smtp_sender_rejected") {
        const requestRef = err.requestID ? ` (request ${err.requestID})` : "";
        setStatus(`SMTP sender policy rejected this message. On Ubuntu, check Postfix sender-login policy and users.mail_login mapping.${requestRef}`, "error");
        return;
      }
      setStatus(err.message, "error");
    }
  });

  if (el.btnUpdateCheck) {
    el.btnUpdateCheck.onclick = async () => {
      if (!state.user || state.user.role !== "admin") return;
      state.update.checking = true;
      applyUpdateControls();
      try {
        await loadUpdateStatus(true);
        setStatus("Update check complete.", "ok");
      } catch (err) {
        setUpdateNote(`Update check failed: ${err.message}`, "error");
        setStatus(err.message, "error");
      } finally {
        state.update.checking = false;
        applyUpdateControls();
      }
    };
  }

  if (el.btnUpdateApply) {
    el.btnUpdateApply.onclick = async () => {
      if (!state.user || state.user.role !== "admin") return;
      state.update.applying = true;
      applyUpdateControls();
      try {
        const targetVersion = state.update.lastStatus?.latest?.tag_name || "";
        await api("/api/v1/admin/system/update/apply", {
          method: "POST",
          json: targetVersion ? { target_version: targetVersion } : {},
        });
        setStatus(`UPDATE QUEUED${targetVersion ? ` (${targetVersion})` : ""}`, "info");
        await loadUpdateStatus(false);
        startUpdatePolling();
      } catch (err) {
        if (err.code === "updater_not_configured") {
          setUpdateNote("Updater is not configured on this host. Install mailclient-updater units first.", "error");
        } else if (err.code === "update_in_progress") {
          setUpdateNote("An update is already running. Waiting for completion.", "info");
          startUpdatePolling();
        } else {
          setUpdateNote(`Update request failed: ${err.message}`, "error");
        }
        setStatus(err.message, "error");
      } finally {
        state.update.applying = false;
        applyUpdateControls();
      }
    };
  }

  if (el.composeForm) {
    restoreComposeDraft(el.composeForm);
    const persistDraft = () => saveComposeDraft(el.composeForm);
    el.composeForm.addEventListener("input", persistDraft);
    el.composeForm.addEventListener("change", persistDraft);
  }

  if (el.btnComposeOpen) {
    el.btnComposeOpen.onclick = () => {
      if (!state.user || state.setup.required) return;
      openComposeOverlay(el.btnComposeOpen);
    };
  }
  if (el.btnComposeClose) {
    el.btnComposeClose.onclick = () => closeComposeOverlay(true);
  }
  if (el.btnComposeCancel) {
    el.btnComposeCancel.onclick = () => closeComposeOverlay(true);
  }
  if (el.composeOverlay) {
    el.composeOverlay.addEventListener("click", (event) => {
      if (event.target === el.composeOverlay) {
        closeComposeOverlay(true);
      }
    });
  }
  document.addEventListener("keydown", handleComposeOverlayKeydown);

  el.tabSetup.onclick = () => {
    if (!state.setup.required) return;
    setActiveTab(el.tabSetup);
    showView("setup");
  };

  el.tabAuth.onclick = () => {
    if (state.setup.required) return;
    closeComposeOverlay(false);
    setActiveTab(el.tabAuth);
    showView("auth");
    setActiveAuthPane("login");
    void initCaptchaUI();
  };

  el.tabMail.onclick = async () => {
    if (!state.user || state.setup.required) return;
    closeComposeOverlay(false);
    setActiveTab(el.tabMail);
    showView("mail");
    setActiveMailPane(state.selectedMessage ? "reader" : "messages");
    try {
      await loadMailboxes();
      await loadMessages();
    } catch (err) {
      presentAPIError(err, "Failed to load mail");
    }
  };

  el.tabAdmin.onclick = async () => {
    if (!state.user || state.user.role !== "admin" || state.setup.required) return;
    closeComposeOverlay(false);
    setActiveTab(el.tabAdmin);
    showView("admin");
    setActiveAdminSection(state.ui.activeAdminSection || "update");
    try {
      await loadAdmin();
    } catch (err) {
      presentAPIError(err, "Failed to load admin data");
    }
  };

  el.btnLogout.onclick = async () => {
    try {
      await api("/api/v1/logout", { method: "POST", json: {} });
    } catch {
      // ignore
    }
    stopUpdatePolling();
    state.user = null;
    state.selectedMessage = null;
    closeComposeOverlay(false);
    applyNavVisibility();
    setActiveTab(el.tabAuth);
    showView("auth");
    setActiveAuthPane("login");
    void initCaptchaUI();
    setStatus("Signed out.", "ok");
  };

  el.btnSearch.onclick = async () => {
    try {
      await searchMessages();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.btnFlag.onclick = async () => {
    try {
      requireSelectedMessage();
      await api(`/api/v1/messages/${encodeURIComponent(state.selectedMessage.id)}/flags`, { method: "POST", json: { flags: ["\\Flagged", "\\Seen"] } });
      await loadMessages();
      setStatus("Message flagged.", "ok");
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.btnSeen.onclick = async () => {
    try {
      requireSelectedMessage();
      await api(`/api/v1/messages/${encodeURIComponent(state.selectedMessage.id)}/flags`, { method: "POST", json: { flags: ["\\Seen"] } });
      await loadMessages();
      setStatus("Message marked seen.", "ok");
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.btnTrash.onclick = async () => {
    try {
      requireSelectedMessage();
      await api(`/api/v1/messages/${encodeURIComponent(state.selectedMessage.id)}/move`, { method: "POST", json: { mailbox: "Trash" } });
      state.selectedMessage = null;
      el.body.textContent = "Select a message.";
      await loadMessages();
      setStatus("Message moved to trash.", "ok");
      setActiveMailPane("messages");
    } catch (err) {
      setStatus(err.message, "error");
    }
  };
}

async function bootstrap() {
  ThemeController.initTheme();
  bindUI();
  await initCaptchaUI();

  try {
    if (await enterSetupIfRequired()) {
      return;
    }
  } catch (err) {
    setStatus(err.message, "error");
    return;
  }

  const session = await refreshSession({ skipUnauthorizedHandling: true });
  if (!session.ok) {
    setActiveTab(el.tabAuth);
    showView("auth");
    setActiveAuthPane("login");
    await initCaptchaUI();
    setStatus("Authentication required.");
    return;
  }

  setActiveTab(el.tabMail);
  showView("mail");
  setActiveMailPane("messages", { focus: false });
  try {
    await loadMailboxes();
    await loadMessages();
  } catch (err) {
    setStatus(err.message, "error");
  }
}

bootstrap();
