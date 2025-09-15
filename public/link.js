// /public/link.js  (module)

// --- Imports (unchanged) ---
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys from '/src/passkeys.js';
import { SignatureShare } from '/src/signature-share.js';

// --- Constants ---
const VERIFY_URL = 'https://verify.dpop.fun/device';
const MOBILE_START_URL = '/link/mobile/start';
const ISSUE_BC_URL = '/link/mobile/issue-bc';
const CANCEL_BC_URL = '/link/mobile/cancel';
const POLL_STATE_URL = '/link/state';

const BC_TTL_FALLBACK = 60;   // seconds
const BC_REGEN_ENABLE_AT = 10; // enable regenerate in last N seconds

// --- Logging UI ---
const log = (msg, level = 'info') => {
  const out = document.getElementById('out');
  const timestamp = new Date().toLocaleTimeString();
  const levelClass = level || 'info';
  const levelIcon = { info:'ℹ️', success:'✅', warn:'⚠️', error:'❌' }[level] || 'ℹ️';
  const entry = document.createElement('div');
  entry.className = `log-entry ${levelClass}`;
  entry.innerHTML = `<span style="color:#a0aec0;">[${timestamp}]</span> ${levelIcon} ${msg}`;
  out.appendChild(entry);
  out.scrollTop = out.scrollHeight;
  console.log(`[${level.toUpperCase()}] ${msg}`);
};

// --- Progress UI (uses your existing .progress-step blocks) ---
const getDefaultMessage = (status) => (
  status === 'pending' ? 'Waiting...' :
  status === 'active'  ? 'In progress...' :
  status === 'completed' ? 'Completed' :
  status === 'error' ? 'Failed' : ''
);

const updateStep = (stepNumber, status, message = '') => {
  const step = document.getElementById(`step-${stepNumber}`);
  if (!step) return;
  const statusDiv = step.querySelector('.step-status');
  const stepNumberDiv = step.querySelector('.step-number');
  step.classList.remove('pending','active','completed','error');
  step.classList.add(status);
  if (statusDiv) statusDiv.textContent = message || getDefaultMessage(status);

  if (status === 'active') {
    if (!step.querySelector('.loading-spinner')) {
      const spinner = document.createElement('div');
      spinner.className = 'loading-spinner';
      step.appendChild(spinner);
    }
  } else {
    step.querySelector('.loading-spinner')?.remove();
  }
  stepNumberDiv.innerHTML = (status === 'completed') ? '✓' : (status === 'error') ? '✗' : stepNumber;
};

// --- BC UI (created on the fly if not present) ---
let bcCard, bcCodeEl, bcTimerEl, bcRegenerateBtn, bcCancelBtn;

function ensureBcCard() {
  bcCard = document.getElementById('bcCard');
  if (!bcCard) {
    const container = document.querySelector('.mobile-container') || document.body;
    bcCard = document.createElement('section');
    bcCard.id = 'bcCard';
    bcCard.className = 'bc-card';
    bcCard.style.display = 'none';
    bcCard.innerHTML = `
      <div class="bc-url">Enter only at <code>${VERIFY_URL}</code></div>
      <div class="bc-code" id="bcCode">----</div>
      <div class="bc-timer"><span id="bcTimer">${BC_TTL_FALLBACK}</span>s left</div>
      <div class="bc-actions" style="display:flex; gap:.5rem; margin-top:.5rem;">
        <button id="bcRegenerate" class="btn-secondary" disabled>Regenerate</button>
        <button id="bcCancel" class="btn-danger">Cancel</button>
      </div>
      <p class="bc-hint">Open <strong>${new URL(VERIFY_URL).host}</strong> on your computer and type the code exactly.</p>
    `;
    container.appendChild(bcCard);
  }
  bcCodeEl = document.getElementById('bcCode');
  bcTimerEl = document.getElementById('bcTimer');
  bcRegenerateBtn = document.getElementById('bcRegenerate');
  bcCancelBtn = document.getElementById('bcCancel');
}

const formatBC = (raw) =>
  raw.toUpperCase()
     .replace(/[^A-Z2-9]/g,'')
     .replace(/[ILOU]/g,(c)=>({I:'1',L:'1',O:'0',U:'V'}[c]))
     .replace(/(.{4})/g,'$1-')
     .replace(/-$/,'');

// --- Signature sharing (start only after confirmed) ---
let signatureShare = new SignatureShare();
function initSignatureSharing(linkId) {
  try {
    signatureShare.initMobile(linkId);
    log('Scribble sharing initialized ✓', 'success');
  } catch (e) {
    log(`Scribble init failed: ${e.message}`, 'warn');
  }
}

// --- UUID polyfill (for odd webviews) ---
if (typeof crypto !== 'undefined' && !crypto.randomUUID && crypto.getRandomValues) {
  crypto.randomUUID = () => {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map(x => x.toString(16).padStart(2,'0'));
    return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10,16).join('')}`;
  };
}

// --- Link ID extraction ---
function getLinkIdFromURL() {
  const url = new URL(location.href);
  const q = url.searchParams.get('lid');
  if (q) return q;
  const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  if (!hash) return null;
  return new URLSearchParams(hash).get('lid');
}

// --- BC lifecycle ---
let currentLid = null;
let bcExpireAt = 0;
let bcInterval = null;
let pollTimer = null;

function startBcTimer(ttlSec) {
  if (bcInterval) clearInterval(bcInterval);
  bcExpireAt = Date.now() + ttlSec * 1000;
  bcInterval = setInterval(() => {
    const rem = Math.max(0, Math.ceil((bcExpireAt - Date.now()) / 1000));
    if (bcTimerEl) bcTimerEl.textContent = String(rem);
    if (bcRegenerateBtn) bcRegenerateBtn.disabled = rem > BC_REGEN_ENABLE_AT;
    if (rem === 0) {
      clearInterval(bcInterval);
      log('Code expired — you can regenerate a new one.', 'warn');
    }
  }, 250);
}

async function issueBC(lid) {
  // Use strongholdFetch so the request is DPoP-bound (we’ve already bound on this mobile)
  const r = await Stronghold.strongholdFetch(ISSUE_BC_URL, {
    method: 'POST',
    body: { lid }
  });
  if (!r.ok) throw new Error(`issue-bc failed: ${r.status}`);
  const { bc, expires_in } = await r.json();
  const ttl = Math.max(10, Math.min(60, Number(expires_in) || BC_TTL_FALLBACK));
  ensureBcCard();
  bcCard.style.display = '';
  bcCodeEl.textContent = formatBC(bc);
  startBcTimer(ttl);
  updateStep(4, 'active', 'Waiting for desktop to enter the code…');
  log(`BC issued (TTL ~${ttl}s)`, 'success');
}

async function cancelBC() {
  if (!currentLid) return;
  try {
    await Stronghold.strongholdFetch(CANCEL_BC_URL, {
      method: 'POST',
      body: { lid: currentLid }
    });
    log('Link canceled.', 'info');
  } catch (e) {
    log(`Cancel failed: ${e.message}`, 'error');
  } finally {
    if (bcInterval) clearInterval(bcInterval);
    bcCard && (bcCard.style.display = 'none');
    updateStep(4, 'error', 'Canceled');
  }
}

async function regenerateBC() {
  if (!currentLid) return;
  bcRegenerateBtn.disabled = true;
  try {
    await issueBC(currentLid);
  } catch (e) {
    log(`Regenerate failed: ${e.message}`, 'error');
  }
}

function startPollingConfirmation(lid) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const u = new URL(POLL_STATE_URL, location.origin);
      u.searchParams.set('lid', lid);
      const r = await fetch(u, { method: 'GET', cache: 'no-store' });
      if (!r.ok) return;
      const { status } = await r.json();
      if (status === 'confirmed') {
        clearInterval(pollTimer);
        updateStep(4, 'completed', 'Desktop confirmed');
        log('Desktop session confirmed ✓', 'success');
        // Optional: start scribble after confirmation
        initSignatureSharing(lid);
      } else if (status === 'killed') {
        clearInterval(pollTimer);
        updateStep(4, 'error', 'Session terminated');
        log('Desktop session was killed', 'warn');
      }
    } catch { /* ignore transient errors */ }
  }, 1500);
}

// --- Main linking flow (mobile) ---
async function link(lid) {
  try {
    // Step 1: Initialize session
    updateStep(1, 'active', 'Initializing session…');
    await Stronghold.sessionInit({ sessionInitUrl: '/session/init' });
    updateStep(1, 'completed', 'Session initialized');
    log('Session initialized ✓', 'success');

    // Step 2: BIK register + DPoP bind
    updateStep(2, 'active', 'Setting up security…');
    await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
    await Stronghold.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
    updateStep(2, 'completed', 'Security configured');
    log('Security setup completed ✓', 'success');

    // Step 3: Passkey UV (register if needed, then authenticate)
    updateStep(3, 'active', 'Verifying passkey…');
    let hasCreds = false;
    let authOptions = null;
    try {
      authOptions = await Passkeys.getAuthOptions();
      hasCreds = !!(authOptions.allowCredentials && authOptions.allowCredentials.length);
      log(`[link] auth options: hasCreds=${hasCreds} rpId=${authOptions?.rpId}`, 'info');
    } catch (e) {
      log(`[link] getAuthOptions failed; will register: ${e.message || e}`, 'warn');
      hasCreds = false;
    }

    if (!hasCreds) {
      updateStep(3, 'active', 'Creating new passkey…');
      await Passkeys.registerPasskey();
      log('Passkey registered ✓', 'success');
    }
    await Passkeys.authenticatePasskey(hasCreds ? authOptions : undefined);
    updateStep(3, 'completed', 'Passkey verified');
    log('Passkey authenticated ✓', 'success');

    // Step 4: Issue BC and wait for desktop
    currentLid = lid;
    updateStep(4, 'active', 'Issuing verification code…');
    await issueBC(lid);
    startPollingConfirmation(lid);

  } catch (error) {
    log(`Linking failed: ${error.message}`, 'error');
    const currentStep = document.querySelector('.progress-step.active');
    if (currentStep) {
      currentStep.classList.remove('active');
      currentStep.classList.add('error');
      currentStep.querySelector('.step-status')?.textContent = 'Failed';
    }
  }
}

// --- Bootstrap: extract link_id and start ---
function attachBcButtons() {
  ensureBcCard();
  bcRegenerateBtn?.addEventListener('click', regenerateBC);
  bcCancelBtn?.addEventListener('click', cancelBC);
}

(async function bootstrap(){
  attachBcButtons();

  const linkId = getLinkIdFromURL();
  if (!linkId) {
    log('No link ID provided in URL', 'error');
    updateStep(1, 'error', 'Missing link ID');
    return;
  }
  log(`Link ID: ${linkId}`, 'info');

  // Tell server we scanned the QR (no DPoP required yet)
  try {
    const r = await fetch(MOBILE_START_URL, {
      method: 'POST',
      headers: { 'Content-Type':'application/json' },
      body: JSON.stringify({ lid: linkId })
    });
    if (!r.ok) throw new Error(`start failed: ${r.status}`);
    const { link_id } = await r.json();
    if (!link_id) throw new Error('start failed (no link_id)');
    log('QR accepted ✓', 'success');

    // Proceed with the main flow
    await link(link_id);

  } catch (e) {
    log(`Error starting link: ${e.message || String(e)}`, 'error');
    updateStep(1, 'error', 'Failed to start link');
  }
})();
