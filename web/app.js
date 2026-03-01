const state = {
  user: null,
  mailbox: "INBOX",
  messages: [],
  selectedMessage: null,
  theme: "paper-light",
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
};

const el = {
  appShell: document.getElementById("app-shell"),
  status: document.getElementById("status-line"),
  btnTheme: document.getElementById("btn-theme"),
  tabSetup: document.getElementById("tab-setup"),
  tabAuth: document.getElementById("tab-auth"),
  tabMail: document.getElementById("tab-mail"),
  tabCompose: document.getElementById("tab-compose"),
  tabAdmin: document.getElementById("tab-admin"),
  btnLogout: document.getElementById("btn-logout"),
  viewSetup: document.getElementById("view-setup"),
  viewAuth: document.getElementById("view-auth"),
  viewMail: document.getElementById("view-mail"),
  viewCompose: document.getElementById("view-compose"),
  viewAdmin: document.getElementById("view-admin"),
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
  composeForm: document.getElementById("form-compose"),
  adminRegs: document.getElementById("admin-registrations"),
  adminUsers: document.getElementById("admin-users"),
  adminAudit: document.getElementById("admin-audit"),
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
    this.setTheme(localStorage.getItem("ui.theme") || "paper-light");
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
  applyNavVisibility();
  if (!state.setup.required) {
    setActiveTab(el.tabAuth);
    showView("auth");
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
    if (window && window.console && typeof window.console.error === "function") {
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
  [el.tabSetup, el.tabAuth, el.tabMail, el.tabCompose, el.tabAdmin]
    .filter(Boolean)
    .forEach((btn) => btn.classList.remove("active"));
  if (tab) tab.classList.add("active");
}

function showView(name) {
  el.viewSetup.classList.add("hidden");
  el.viewAuth.classList.add("hidden");
  el.viewMail.classList.add("hidden");
  el.viewCompose.classList.add("hidden");
  el.viewAdmin.classList.add("hidden");
  if (name === "setup") el.viewSetup.classList.remove("hidden");
  if (name === "auth") el.viewAuth.classList.remove("hidden");
  if (name === "mail") el.viewMail.classList.remove("hidden");
  if (name === "compose") el.viewCompose.classList.remove("hidden");
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

function applyNavVisibility() {
  if (state.setup.required) {
    el.tabSetup.style.display = "inline-block";
    el.tabAuth.style.display = "none";
    el.tabMail.style.display = "none";
    el.tabCompose.style.display = "none";
    el.tabAdmin.style.display = "none";
    el.btnLogout.style.display = "none";
    return;
  }

  el.tabSetup.style.display = "none";
  el.tabAuth.style.display = "inline-block";
  el.tabMail.style.display = "inline-block";
  el.tabCompose.style.display = "inline-block";
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
    const me = await api("/api/v1/me", { skipUnauthorizedHandling: !!opts.skipUnauthorizedHandling });
    state.user = me;
    setStatus(`SIGNED IN AS ${me.email.toUpperCase()}`, "ok");
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
  for (const mb of data) {
    const li = document.createElement("li");
    const btn = document.createElement("button");
    btn.textContent = `${mb.name} (${mb.unread || 0}/${mb.messages || 0})`;
    btn.className = mb.name === state.mailbox ? "active" : "";
    btn.onclick = async () => {
      state.mailbox = mb.name;
      state.selectedMessage = null;
      await loadMessages();
      await loadMailboxes();
    };
    li.appendChild(btn);
    el.mailboxes.appendChild(li);
  }
}

function renderMessages(items) {
  el.messages.innerHTML = "";
  state.messages = items;
  for (const m of items) {
    const tr = document.createElement("tr");
    if (state.selectedMessage && state.selectedMessage.id === m.id) tr.classList.add("active");
    tr.innerHTML = `<td>${escapeHtml(m.from || "")}</td><td>${escapeHtml(m.subject || "")}</td><td>${formatDate(m.date)}</td>`;
    tr.onclick = () => openMessage(m.id);
    el.messages.appendChild(tr);
  }
}

async function loadMessages() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const data = await api(`/api/v1/messages?mailbox=${encodeURIComponent(state.mailbox)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`MAILBOX ${state.mailbox} LOADED`, "ok");
}

async function openMessage(id) {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const m = await api(`/api/v1/messages/${encodeURIComponent(id)}`);
  state.selectedMessage = m;
  el.meta.innerHTML = `<div><b>From:</b> ${escapeHtml(m.from || "")}</div>
    <div><b>To:</b> ${escapeHtml((m.to || []).join(", "))}</div>
    <div><b>Subject:</b> ${escapeHtml(m.subject || "")}</div>
    <div><b>Date:</b> ${formatDate(m.date)}</div>`;
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
}

async function searchMessages() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const q = el.searchInput.value.trim();
  const data = await api(`/api/v1/search?mailbox=${encodeURIComponent(state.mailbox)}&q=${encodeURIComponent(q)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`SEARCH COMPLETE (${(data.items || []).length} RESULTS)`, "ok");
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

async function loadAdmin() {
  if (!state.user) {
    throw new Error("Sign in required");
  }
  const [regs, users, audit] = await Promise.all([
    api("/api/v1/admin/registrations?status=pending&page=1&page_size=50"),
    api("/api/v1/admin/users?page=1&page_size=100"),
    api("/api/v1/admin/audit-log?page=1&page_size=100"),
  ]);

  el.adminRegs.innerHTML = "";
  for (const r of regs.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escapeHtml(r.email)}</td><td>${formatDate(r.created_at)}</td><td><span class="status-chip">pending</span></td><td></td>`;
    const td = tr.children[3];
    const approve = document.createElement("button");
    approve.className = "cmd-btn cmd-btn--primary";
    approve.textContent = "Approve";
    approve.onclick = async () => {
      await api(`/api/v1/admin/registrations/${encodeURIComponent(r.id)}/approve`, { method: "POST", json: {} });
      await loadAdmin();
    };
    const reject = document.createElement("button");
    reject.className = "cmd-btn";
    reject.textContent = "Reject";
    reject.onclick = async () => {
      const reason = prompt("Reject reason:", "Rejected by admin") || "Rejected";
      await api(`/api/v1/admin/registrations/${encodeURIComponent(r.id)}/reject`, { method: "POST", json: { reason } });
      await loadAdmin();
    };
    td.appendChild(approve);
    td.appendChild(reject);
    el.adminRegs.appendChild(tr);
  }

  el.adminUsers.innerHTML = "";
  for (const u of users.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${escapeHtml(u.email)}</td><td>${escapeHtml(u.role)}</td><td><span class="status-chip">${escapeHtml(u.status)}</span></td><td></td>`;
    const td = tr.children[3];
    if (u.status === "active") {
      const btn = document.createElement("button");
      btn.className = "cmd-btn";
      btn.textContent = "Suspend";
      btn.onclick = async () => {
        await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/suspend`, { method: "POST", json: {} });
        await loadAdmin();
      };
      td.appendChild(btn);
    } else if (u.status === "suspended") {
      const btn = document.createElement("button");
      btn.className = "cmd-btn";
      btn.textContent = "Unsuspend";
      btn.onclick = async () => {
        await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/unsuspend`, { method: "POST", json: {} });
        await loadAdmin();
      };
      td.appendChild(btn);
    }

    const reset = document.createElement("button");
    reset.className = "cmd-btn";
    reset.textContent = "Reset Password";
    reset.onclick = async () => {
      const pw = prompt(`New password for ${u.email}:`);
      if (!pw) return;
      await api(`/api/v1/admin/users/${encodeURIComponent(u.id)}/reset-password`, { method: "POST", json: { new_password: pw } });
      setStatus(`PASSWORD RESET FOR ${u.email}`, "ok");
    };
    td.appendChild(reset);

    el.adminUsers.appendChild(tr);
  }

  el.adminAudit.innerHTML = "";
  for (const a of audit.items || []) {
    const tr = document.createElement("tr");
    tr.innerHTML = `<td>${formatDate(a.created_at)}</td><td>${escapeHtml(a.action)}</td><td>${escapeHtml(a.target || "")}</td>`;
    el.adminAudit.appendChild(tr);
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
  if (el.btnTheme) {
    el.btnTheme.onclick = () => {
      const next = ThemeController.getTheme() === "paper-light" ? "machine-dark" : "paper-light";
      ThemeController.setTheme(next);
      if (state.setup.required) {
        showView("setup");
      } else if (!state.user) {
        showView("auth");
      } else if (!el.viewAdmin.classList.contains("hidden")) {
        showView("admin");
      } else if (!el.viewCompose.classList.contains("hidden")) {
        showView("compose");
      } else {
        showView("mail");
      }
    };
  }

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
    try {
      await api("/api/v1/register", {
        method: "POST",
        json: { email: fd.get("email"), password: fd.get("password"), captcha_token: fd.get("captcha_token") },
      });
      setStatus("REGISTRATION SUBMITTED. WAIT FOR APPROVAL.", "ok");
      e.target.reset();
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
        return;
      }
      setStatus(err.message, "error");
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
      setStatus("PASSWORD UPDATED", "ok");
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
      setStatus("MESSAGE SENT", "ok");
      e.target.reset();
      clearComposeDraft();
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

  if (el.composeForm) {
    restoreComposeDraft(el.composeForm);
    const persistDraft = () => saveComposeDraft(el.composeForm);
    el.composeForm.addEventListener("input", persistDraft);
    el.composeForm.addEventListener("change", persistDraft);
  }

  el.tabSetup.onclick = () => {
    if (!state.setup.required) return;
    setActiveTab(el.tabSetup);
    showView("setup");
  };

  el.tabAuth.onclick = () => {
    if (state.setup.required) return;
    setActiveTab(el.tabAuth);
    showView("auth");
  };

  el.tabMail.onclick = async () => {
    if (!state.user || state.setup.required) return;
    setActiveTab(el.tabMail);
    showView("mail");
    try {
      await loadMailboxes();
      await loadMessages();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.tabCompose.onclick = () => {
    if (!state.user || state.setup.required) return;
    setActiveTab(el.tabCompose);
    showView("compose");
    restoreComposeDraft(el.composeForm);
  };

  el.tabAdmin.onclick = async () => {
    if (!state.user || state.user.role !== "admin" || state.setup.required) return;
    setActiveTab(el.tabAdmin);
    showView("admin");
    try {
      await loadAdmin();
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.btnLogout.onclick = async () => {
    try {
      await api("/api/v1/logout", { method: "POST", json: {} });
    } catch {
      // ignore
    }
    state.user = null;
    state.selectedMessage = null;
    applyNavVisibility();
    setActiveTab(el.tabAuth);
    showView("auth");
    setStatus("SIGNED OUT", "ok");
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
      setStatus("MESSAGE FLAGGED", "ok");
    } catch (err) {
      setStatus(err.message, "error");
    }
  };

  el.btnSeen.onclick = async () => {
    try {
      requireSelectedMessage();
      await api(`/api/v1/messages/${encodeURIComponent(state.selectedMessage.id)}/flags`, { method: "POST", json: { flags: ["\\Seen"] } });
      await loadMessages();
      setStatus("MESSAGE MARKED SEEN", "ok");
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
      setStatus("MESSAGE MOVED TO TRASH", "ok");
    } catch (err) {
      setStatus(err.message, "error");
    }
  };
}

async function bootstrap() {
  ThemeController.initTheme();
  bindUI();

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
    setStatus("AUTH REQUIRED");
    return;
  }

  setActiveTab(el.tabMail);
  showView("mail");
  try {
    await loadMailboxes();
    await loadMessages();
  } catch (err) {
    setStatus(err.message, "error");
  }
}

bootstrap();
