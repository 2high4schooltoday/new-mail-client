const steps = Array.from(document.querySelectorAll('.oobe-step'));
const dots = Array.from(document.querySelectorAll('.oobe-dot'));
const statusLine = document.getElementById('mk-status');

const back = document.getElementById('mk-back');
const backIcon = document.getElementById('mk-back-icon');
const closeBtn = document.getElementById('mk-close');
const next = document.getElementById('mk-next');
const setupForm = document.getElementById('mk-form-setup');
const themeBtn = document.getElementById('mk-theme');

const openMailBtn = document.getElementById('mk-open-mail');
const openAdminBtn = document.getElementById('mk-open-admin');
const completeNote = document.getElementById('mk-complete-note');

const modal = document.getElementById('mk-modal');
const modalTitle = document.getElementById('mk-modal-title');
const modalBody = document.getElementById('mk-modal-body');
const modalCancel = document.getElementById('mk-modal-cancel');
const modalConfirm = document.getElementById('mk-modal-confirm');

const region = document.getElementById('mk-region');
const domain = document.getElementById('mk-domain');
const email = document.getElementById('mk-email');
const pass = document.getElementById('mk-pass');
const pass2 = document.getElementById('mk-pass2');
const sRegion = document.getElementById('mk-summary-region');
const sDomain = document.getElementById('mk-summary-domain');
const sEmail = document.getElementById('mk-summary-email');
const inlineStatus = document.getElementById('mk-inline-status');

const state = {
  step: 0,
  theme: 'paper-light',
  autoOpenTimer: 0,
  modalType: '',
  lastAutoEmail: 'webmaster@example.com',
  adminEmailTouched: false,
};

function setStatus(text, kind = 'info') {
  statusLine.textContent = text;
  if (kind === 'error') statusLine.style.color = 'var(--sig-err)';
  else if (kind === 'ok') statusLine.style.color = 'var(--sig-ok)';
  else statusLine.style.color = 'var(--fg-0)';
}

function setInlineStatus(text, kind = 'info') {
  inlineStatus.textContent = text || '';
  if (kind === 'error') inlineStatus.style.color = 'var(--sig-err)';
  else if (kind === 'ok') inlineStatus.style.color = 'var(--sig-ok)';
  else inlineStatus.style.color = 'var(--fg-muted)';
}

function normDomain(v) {
  return String(v || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/$/, '').replace(/\.$/, '');
}

function validDomain(value) {
  return /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/.test(value);
}

function validEmail(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(String(value || '').trim());
}

function passwordClassCount(password) {
  let classes = 0;
  if (/[a-z]/.test(password)) classes += 1;
  if (/[A-Z]/.test(password)) classes += 1;
  if (/[0-9]/.test(password)) classes += 1;
  if (/[!"#$%&'()*+,\-./:;<=>?@[\\\]^_`{|}~]/.test(password)) classes += 1;
  return classes;
}

function domainToDefaultEmail(v) {
  const d = normDomain(v);
  return d ? `webmaster@${d}` : 'webmaster@example.com';
}

function updateSummary() {
  sRegion.textContent = region.options[region.selectedIndex]?.text || '-';
  sDomain.textContent = normDomain(domain.value) || '-';
  sEmail.textContent = String(email.value || '').trim().toLowerCase();
}

function setTheme(name) {
  state.theme = name === 'machine-dark' ? 'machine-dark' : 'paper-light';
  document.documentElement.setAttribute('data-theme', state.theme);
  localStorage.setItem('ui.theme', state.theme);
  themeBtn.textContent = state.theme === 'machine-dark' ? 'Theme: Machine' : 'Theme: Paper';
}

function initTheme() {
  const queryTheme = new URLSearchParams(window.location.search).get('theme');
  if (queryTheme === 'machine-dark' || queryTheme === 'paper-light') {
    setTheme(queryTheme);
    return;
  }
  setTheme(localStorage.getItem('ui.theme') || 'paper-light');
}

function validateStep(step) {
  if (step === 2) {
    const d = normDomain(domain.value);
    const e = String(email.value || '').trim().toLowerCase();
    if (!validDomain(d)) throw new Error('Enter a valid domain (example.com).');
    if (!validEmail(e)) throw new Error('Enter a valid admin email.');
    if (!e.endsWith(`@${d}`)) throw new Error(`Admin email must use @${d}.`);
  }
  if (step === 3) {
    if ((pass.value || '').length < 12) throw new Error('Password must be at least 12 characters.');
    if (passwordClassCount(pass.value || '') < 3) throw new Error('Password must include lower/upper/number/symbol classes.');
    if (pass.value !== pass2.value) throw new Error('Password and verify password must match.');
  }
}

function isStepValid(step) {
  try {
    validateStep(step);
    return true;
  } catch {
    return false;
  }
}

function refreshNavState() {
  const isFirst = state.step === 0;
  const isComplete = state.step === 5;
  const isReview = state.step === 4;

  back.disabled = isFirst || isComplete;
  backIcon.disabled = isFirst || isComplete;
  next.disabled = isComplete ? true : !isStepValid(state.step);
  next.textContent = isReview ? 'Initialize' : 'Continue';
}

function setStep(step) {
  state.step = Math.max(0, Math.min(step, steps.length - 1));
  steps.forEach((node, i) => node.classList.toggle('hidden', i !== state.step));
  dots.forEach((node, i) => node.classList.toggle('active', i <= state.step));
  updateSummary();
  setInlineStatus('');
  refreshNavState();
}

function openConfirm(type) {
  state.modalType = type;
  if (type === 'cancel') {
    modalTitle.textContent = 'Discard Setup Progress?';
    modalBody.textContent = 'If you close setup now, initialization stays incomplete and login remains blocked.';
    modalConfirm.textContent = 'Discard';
  } else {
    modalTitle.textContent = 'Reset Entered Values?';
    modalBody.textContent = 'This removes all values entered in the mock setup and restarts at welcome.';
    modalConfirm.textContent = 'Reset';
  }
  modal.classList.remove('hidden');
  modal.setAttribute('aria-hidden', 'false');
  modalCancel.focus();
}

function closeConfirm() {
  modal.classList.add('hidden');
  modal.setAttribute('aria-hidden', 'true');
  if (!next.disabled) next.focus();
  else back.focus();
}

function resetFlow() {
  domain.value = 'example.com';
  email.value = 'webmaster@example.com';
  pass.value = '';
  pass2.value = '';
  region.value = 'us-east';
  state.lastAutoEmail = 'webmaster@example.com';
  state.adminEmailTouched = false;
  if (state.autoOpenTimer) {
    clearTimeout(state.autoOpenTimer);
    state.autoOpenTimer = 0;
  }
  completeNote.textContent = 'Auto opening mail in 3 seconds.';
  setStep(0);
  setStatus('MOCKUP MODE - NO BACKEND CALLS');
  setInlineStatus('');
}

function confirmModal() {
  const type = state.modalType || 'cancel';
  closeConfirm();
  if (type === 'cancel') {
    resetFlow();
    setStatus('SETUP CANCELLED (MOCK). FLOW RESET.', 'info');
  } else {
    resetFlow();
    setStatus('SETUP FORM RESET (MOCK).', 'info');
  }
}

function openMailPreview() {
  if (state.autoOpenTimer) {
    clearTimeout(state.autoOpenTimer);
    state.autoOpenTimer = 0;
  }
  completeNote.textContent = 'Mail opened.';
  setStatus('MOCK: OPENING MAIL VIEW', 'ok');
}

function openAdminPreview() {
  if (state.autoOpenTimer) {
    clearTimeout(state.autoOpenTimer);
    state.autoOpenTimer = 0;
  }
  completeNote.textContent = 'Admin opened.';
  setStatus('MOCK: OPENING ADMIN VIEW', 'ok');
}

function scheduleAutoOpen() {
  if (state.autoOpenTimer) clearTimeout(state.autoOpenTimer);
  let ticks = 3;
  completeNote.textContent = `Auto opening mail in ${ticks} seconds.`;
  const interval = setInterval(() => {
    ticks -= 1;
    if (ticks > 0) completeNote.textContent = `Auto opening mail in ${ticks} seconds.`;
  }, 1000);

  state.autoOpenTimer = window.setTimeout(() => {
    clearInterval(interval);
    openMailPreview();
  }, 3000);
}

async function nextStep() {
  validateStep(state.step);
  if (state.step < 4) {
    setStep(state.step + 1);
    return;
  }
  if (state.step === 4) {
    setStatus('SETUP COMPLETE (MOCK)', 'ok');
    setStep(5);
    scheduleAutoOpen();
  }
}

function bind() {
  back.addEventListener('click', () => setStep(state.step - 1));
  backIcon.addEventListener('click', () => setStep(state.step - 1));
  closeBtn.addEventListener('click', () => {
    if (state.step === 5) {
      openMailPreview();
      return;
    }
    openConfirm('cancel');
  });
  setupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    try {
      await nextStep();
      setInlineStatus('');
    } catch (err) {
      setStatus(err.message, 'error');
      setInlineStatus(err.message, 'error');
    }
  });

  region.addEventListener('change', () => {
    updateSummary();
    refreshNavState();
  });

  domain.addEventListener('input', () => {
    const d = normDomain(domain.value);
    const autoEmail = domainToDefaultEmail(d);
    if (!state.adminEmailTouched || String(email.value).trim().toLowerCase() === state.lastAutoEmail) {
      email.value = autoEmail;
      state.lastAutoEmail = autoEmail;
    }
    updateSummary();
    refreshNavState();
  });

  email.addEventListener('input', () => {
    const value = String(email.value || '').trim().toLowerCase();
    state.adminEmailTouched = value !== state.lastAutoEmail;
    updateSummary();
    refreshNavState();
  });

  pass.addEventListener('input', refreshNavState);
  pass2.addEventListener('input', refreshNavState);

  modalCancel.addEventListener('click', closeConfirm);
  modalConfirm.addEventListener('click', confirmModal);
  modal.addEventListener('click', (event) => {
    if (event.target === modal) closeConfirm();
  });

  openMailBtn.addEventListener('click', openMailPreview);
  openAdminBtn.addEventListener('click', openAdminPreview);

  themeBtn.addEventListener('click', () => {
    setTheme(state.theme === 'paper-light' ? 'machine-dark' : 'paper-light');
  });

  document.addEventListener('keydown', async (event) => {
    if (!modal.classList.contains('hidden')) {
      if (event.key === 'Escape') {
        event.preventDefault();
        closeConfirm();
      }
      if (event.key === 'Enter') {
        event.preventDefault();
        confirmModal();
      }
      if (event.key === 'Tab') {
        event.preventDefault();
        const focusables = [modalCancel, modalConfirm];
        const idx = focusables.findIndex((f) => f === document.activeElement);
        const nextIdx = (idx + (event.shiftKey ? -1 : 1) + focusables.length) % focusables.length;
        focusables[nextIdx].focus();
      }
      return;
    }

    if (event.key === 'Escape' && state.step > 0 && state.step < 5) {
      event.preventDefault();
      openConfirm('cancel');
    }
  });
}

initTheme();
resetFlow();
bind();
