const state = {
  user: null,
  mailbox: "INBOX",
  messages: [],
  selectedMessage: null,
  theme: "paper-light",
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
    throw error;
  }
  return payload;
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

  await api("/api/v1/setup/complete", {
    method: "POST",
    json: {
      base_domain: domain,
      admin_email: email,
      admin_password: password,
      region,
    },
  });

  state.setup.required = false;
  applyNavVisibility();
  await refreshSession();
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
    el.setupRegion.value = el.setupRegion.value || "us-east";
    if (el.setupCompleteNote) {
      el.setupCompleteNote.textContent = "Auto opening mail in 3 seconds.";
    }
    state.setup.adminEmailTouched = false;
    state.setup.lastAutoAdminEmail = email;
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
    el.setupNext.textContent = state.setup.submitting ? "Initializing..." : isReview ? "Initialize" : "Continue";
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
    if (state.setup.submitting) {
      el.setupNext.disabled = true;
      el.setupBack.disabled = true;
      return;
    }
    el.setupNext.disabled = !this.isStepValid(state.setup.step);
  },

  async next() {
    if (state.setup.submitting) return;
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
          const wrapped = new Error(`Too many setup attempts. Wait about ${wait} seconds and try again.`);
          wrapped.code = "rate_limited";
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
      el.setupPasswordHint.textContent = "PAM mode: enter the current password for the selected mailbox account.";
      return;
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

async function refreshSession() {
  try {
    const me = await api("/api/v1/me");
    state.user = me;
    setStatus(`SIGNED IN AS ${me.email.toUpperCase()}`, "ok");
    applyNavVisibility();
    return true;
  } catch {
    state.user = null;
    applyNavVisibility();
    return false;
  }
}

async function loadMailboxes() {
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
  const data = await api(`/api/v1/messages?mailbox=${encodeURIComponent(state.mailbox)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`MAILBOX ${state.mailbox} LOADED`, "ok");
}

async function openMessage(id) {
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
  const q = el.searchInput.value.trim();
  const data = await api(`/api/v1/search?mailbox=${encodeURIComponent(state.mailbox)}&q=${encodeURIComponent(q)}&page=1&page_size=40`);
  renderMessages(data.items || []);
  setStatus(`SEARCH COMPLETE (${(data.items || []).length} RESULTS)`, "ok");
}

async function sendCompose(form) {
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
}

async function loadAdmin() {
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
        err.message = "PAM mode is enabled. Use an existing mailbox account and its current password.";
      }
      setStatus(err.message, "error");
      setSetupInlineStatus(err.message, "error");
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
      await refreshSession();
      await loadMailboxes();
      await loadMessages();
      setActiveTab(el.tabMail);
      showView("mail");
    } catch (err) {
      if (err.code === "setup_required") {
        await enterSetupIfRequired();
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
      const out = await api("/api/v1/password/reset/request", { method: "POST", json: { email: fd.get("email") } });
      setStatus(`RESET TOKEN: ${out.reset_token || "(check logs/email)"}`, "ok");
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
      await loadMessages();
    } catch (err) {
      setStatus(err.message, "error");
    }
  });

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

  const ok = await refreshSession();
  if (!ok) {
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
