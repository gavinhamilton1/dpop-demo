// /public/link.js  (module)

// --- Imports (unchanged) ---
import * as DpopFun from '/src/dpop-fun.js';
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

// --- Mobile Fingerprint Collection ---
async function collectMobileFingerprint() {
  console.log('🔍 MOBILE FINGERPRINT COLLECTION STARTED');
  try {
    log('Collecting mobile device fingerprint...', 'info');
    
    // Use the centralized FingerprintService
    const result = await FingerprintService.collectAndSendFingerprint('mobile');
    
    log('Mobile fingerprint collection completed successfully', 'success');
    console.log('✅ Mobile fingerprint collection completed successfully');
    return result;
    
  } catch (error) {
    log(`Mobile fingerprint collection failed: ${error.message}`, 'error');
    log(`Mobile fingerprint error details: ${error.stack}`, 'error');
    console.log('❌ MOBILE FINGERPRINT COLLECTION FAILED:', error.message);
    // Don't throw - fingerprinting failure shouldn't break the linking flow
    return null;
  }
}



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
let bcCard, bcCodeEl, bcTimerEl, bcRegenerateBtn, bcCancelBtn, bcQREl;

function ensureBcCard() {
  bcCard = document.getElementById('bcCard');
  if (!bcCard) {
    const container = document.querySelector('.mobile-container') || document.body;
    bcCard = document.createElement('section');
    bcCard.id = 'bcCard';
    bcCard.className = 'bc-card';
    bcCard.style.display = 'none';
    bcCard.innerHTML = `
      <div class="bc-url">Enter only at <code>https://dpop.fun/verify</code></div>
      <div class="bc-security">⚠️ Verify the URL is correct on your desktop browser before entering your code</div>
      <div class="bc-code" id="bcCode">----</div>
      <div class="bc-qr-container">
        <div class="bc-qr" id="bcQR"></div>
        <p class="bc-qr-hint">Scan this QR code with your desktop verify page</p>
      </div>
      <div class="bc-timer"><span id="bcTimer">${BC_TTL_FALLBACK}</span>s left</div>
      <div class="bc-actions" style="display:flex; gap:.5rem; margin-top:.5rem;">
        <button id="bcRegenerate" class="btn-secondary" disabled>Regenerate</button>
        <button id="bcCancel" class="btn-danger">Cancel</button>
      </div>
      <p class="bc-hint">Open <strong>https://dpop.fun/verify</strong> on your computer and scan the QR code or type the code exactly.</p>
    `;
    container.appendChild(bcCard);
  }
  bcCodeEl = document.getElementById('bcCode');
  bcTimerEl = document.getElementById('bcTimer');
  bcRegenerateBtn = document.getElementById('bcRegenerate');
  bcCancelBtn = document.getElementById('bcCancel');
  bcQREl = document.getElementById('bcQR');
}

const formatBC = (raw) =>
  raw.toUpperCase()
     .replace(/[^A-Z2-9]/g,'')
     .replace(/[ILOU]/g,(c)=>({I:'1',L:'1',O:'0',U:'V'}[c]))
     .replace(/(.{4})/g,'$1-')
     .replace(/-$/,'');

function generateBCQR(bc) {
  if (!bcQREl) return;
  
  // Clear any existing QR code
  bcQREl.innerHTML = '';
  
  // Create QR code URL that the desktop verify page can scan
  const qrUrl = `${window.location.origin}/verify/device?bc=${bc}`;
  
  try {
    // Generate QR code using the qrcode library
    new QRCode(bcQREl, {
      text: qrUrl,
      width: 200,
      height: 200,
      colorDark: '#000000',
      colorLight: '#FFFFFF',
      correctLevel: QRCode.CorrectLevel.M
    });
    
    console.log('QR code generated successfully for:', qrUrl);
  } catch (error) {
    console.error('QR code generation error:', error);
    bcQREl.innerHTML = '<p style="color: red;">QR code generation error</p>';
  }
}

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
    if (bcRegenerateBtn) {
      bcRegenerateBtn.disabled = rem > BC_REGEN_ENABLE_AT;
      // Make button green when timer expires
      if (rem === 0) {
        bcRegenerateBtn.classList.add('btn-success');
        bcRegenerateBtn.classList.remove('btn-secondary');
      } else {
        bcRegenerateBtn.classList.remove('btn-success');
        bcRegenerateBtn.classList.add('btn-secondary');
      }
    }
    if (rem === 0) {
      clearInterval(bcInterval);
      log('Code expired — you can regenerate a new one.', 'warn');
    }
  }, 250);
}

async function issueBC(lid) {
  try {
    // Use dpopFunFetch so the request is DPoP-bound (we've already bound on this mobile)
    const data = await DpopFun.dpopFunFetch(ISSUE_BC_URL, {
      method: 'POST',
      body: { lid }
    });
    const { bc, expires_in } = data;
    const ttl = Math.max(10, Math.min(60, Number(expires_in) || BC_TTL_FALLBACK));
    ensureBcCard();
    bcCard.style.display = '';
    bcCodeEl.textContent = formatBC(bc);
    
    // Generate QR code for the BC
    generateBCQR(bc);
    
    startBcTimer(ttl);
    updateStep(4, 'active', 'Waiting for desktop to scan QR code or enter the code…');
    log(`BC issued (TTL ~${ttl}s)`, 'success');
  } catch (error) {
    log(`issue-bc failed: ${error.message}`, 'error');
    throw new Error(`issue-bc failed: ${error.message}`);
  }
}

async function cancelBC() {
  if (!currentLid) return;
  try {
    await DpopFun.dpopFunFetch(CANCEL_BC_URL, {
      method: 'POST',
      body: { lid: currentLid }
    });
    log('Link canceled.', 'info');
  } catch (e) {
    log(`Cancel failed: ${e.message}`, 'error');
  } finally {
    if (bcInterval) clearInterval(bcInterval);
    if (bcCard) bcCard.style.display = 'none';
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
  // Try SSE first, fallback to polling
  startSSEConfirmation(lid);
}

function startSSEConfirmation(lid) {
  if (pollTimer) clearInterval(pollTimer);
  
  try {
    console.log('Starting SSE for mobile confirmation...');
    const response = fetch(`/link/events/${lid}`, {
      method: 'GET',
      credentials: 'include',
      headers: {
        'Accept': 'text/event-stream',
        'Cache-Control': 'no-cache'
      }
    });
    
    response.then(async (res) => {
      if (!res.ok) {
        console.warn('SSE failed, falling back to polling');
        startPollingFallback(lid);
        return;
      }
      
      console.log('SSE connection opened for mobile confirmation');
      
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = '';
      
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        
        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';
        
        for (const line of lines) {
          if (line.trim() === '') continue;
          
          if (line.startsWith('data: ')) {
            try {
              const data = JSON.parse(line.slice(6));
              handleStatusUpdate(data, lid);
            } catch (error) {
              console.error('Failed to parse SSE data:', error);
            }
          }
        }
      }
    }).catch((error) => {
      console.warn('SSE error, falling back to polling:', error);
      startPollingFallback(lid);
    });
    
  } catch (error) {
    console.warn('Failed to start SSE, falling back to polling:', error);
    startPollingFallback(lid);
  }
}

function startPollingFallback(lid) {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const u = new URL(POLL_STATE_URL, location.origin);
      u.searchParams.set('lid', lid);
      const r = await fetch(u, { method: 'GET', cache: 'no-store' });
      if (!r.ok) return;
      const { status } = await r.json();
      handleStatusUpdate({ status }, lid);
    } catch { /* ignore transient errors */ }
  }, 1500);
}

function handleStatusUpdate(data, lid) {
  const status = data.status;
  if (status === 'confirmed') {
    if (pollTimer) clearInterval(pollTimer);
    // Cancel the BC countdown timer since linking is complete
    if (bcInterval) clearInterval(bcInterval);
    updateStep(4, 'completed', 'Desktop confirmed');
    log('Desktop session confirmed ✓', 'success');
    // Hide the BC card since linking is complete
    if (bcCard) bcCard.style.display = 'none';
    
    // Show success section and load fingerprint data
    showSuccessSection(lid);
    
    // Optional: start scribble after confirmation
    initSignatureSharing(lid);
  } else if (status === 'killed') {
    if (pollTimer) clearInterval(pollTimer);
    // Cancel the BC countdown timer since session was killed
    if (bcInterval) clearInterval(bcInterval);
    updateStep(4, 'error', 'Session terminated');
    log('Desktop session was killed', 'warn');
  }
}

// --- Main linking flow (mobile) ---
async function link(lid) {
  console.log('🚀 MOBILE LINKING FLOW STARTED with lid:', lid);
  console.log('📱 Mobile link function called - this should appear in mobile logs');
  try {
    // Step 1: Initialize session
    updateStep(1, 'active', 'Initializing session…');
    await DpopFun.sessionInit({ sessionInitUrl: '/session/init' });
    updateStep(1, 'completed', 'Session initialized');
    log('Session initialized ✓', 'success');
    
    // Collect mobile device fingerprint (with small delay to ensure session is established)
    log('Starting mobile fingerprint collection...', 'info');
    log(`Available cookies before fingerprint collection: ${document.cookie}`, 'info');
    console.log('🍪 Cookies before fingerprint collection:', document.cookie);
    await new Promise(resolve => setTimeout(resolve, 100)); // Small delay
    console.log('⏰ About to call collectMobileFingerprint()');
    try {
      await collectMobileFingerprint();
      log('Mobile fingerprint collection completed successfully', 'success');
      console.log('✅ Mobile fingerprint collection completed successfully');
    } catch (error) {
      log(`Mobile fingerprint collection failed: ${error.message}`, 'error');
      console.log('❌ Mobile fingerprint collection failed:', error.message);
      // Continue with linking flow even if fingerprinting fails
    }

    // Step 2: BIK register + DPoP bind
    updateStep(2, 'active', 'Setting up security…');
    await DpopFun.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
    await DpopFun.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
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

    // Step 4: Complete mobile linking and issue BC
    currentLid = lid;
    updateStep(4, 'active', 'Completing mobile link…');
    
    // Complete the mobile linking process
    const completeData = await DpopFun.dpopFunFetch('/link/mobile/complete', {
      method: 'POST',
      body: { link_id: lid }
    });
    log('Mobile link completed ✓', 'success');
    log(`Complete response: ${JSON.stringify(completeData)}`, 'info');
    
    // Add a small delay to ensure session is properly established
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Debug: Check if we have a session cookie
    log(`Document cookies: ${document.cookie}`, 'info');
    
    // Now issue BC for desktop to enter
    updateStep(4, 'active', 'Issuing verification code…');
    await issueBC(lid);
    startPollingConfirmation(lid);

  } catch (error) {
    log(`Linking failed: ${error.message}`, 'error');
    const currentStep = document.querySelector('.progress-step.active');
    if (currentStep) {
      currentStep.classList.remove('active');
      currentStep.classList.add('error');
      const statusEl = currentStep.querySelector('.step-status');
      if (statusEl) statusEl.textContent = 'Failed';
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

// --- Success Section Functions ---
async function showSuccessSection(linkId) {
  try {
    log('Showing success section and loading fingerprint data...', 'info');
    
    // Show the success section
    const successSection = document.getElementById('successSection');
    if (successSection) {
      successSection.style.display = 'block';
    }
    
    // Load fingerprint data
    await loadFingerprintData();
    
    // Setup button event listeners
    setupSuccessButtons();
    
  } catch (error) {
    log(`Error showing success section: ${error.message}`, 'error');
  }
}


async function loadFingerprintData() {
  try {
    log('Loading fingerprint data for both desktop and mobile...', 'info');
    
    const response = await fetch('/session/fingerprint-data', {
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new Error(`Failed to load fingerprint data: ${response.status}`);
    }
    
    const data = await response.json();
    log('Fingerprint data received:', 'info');
    
    // Load mobile fingerprint
    const mobileFingerprint = data.mobile.fingerprint;
    const mobileDeviceType = data.mobile.device_type || 'unknown';
    const mobileLinked = data.mobile.linked;
    
    log(`Mobile fingerprint data: ${JSON.stringify(mobileFingerprint)}`, 'info');
    log(`Mobile device type: ${mobileDeviceType}`, 'info');
    log(`Mobile linked: ${mobileLinked}`, 'info');
    
    if (!mobileFingerprint || Object.keys(mobileFingerprint).length === 0) {
      document.getElementById('mobileFingerprintSummary').innerHTML = 
        '<div class="fingerprint-loading">No mobile fingerprint data available</div>';
    } else {
      displayFingerprintData(mobileFingerprint, mobileDeviceType, 'mobileFingerprintSummary');
    }
    
    // Load desktop fingerprint
    const desktopFingerprint = data.desktop.fingerprint;
    const desktopDeviceType = data.desktop.device_type || 'unknown';
    const desktopLinked = data.desktop.linked;
    
    if (!desktopLinked) {
      document.getElementById('desktopFingerprintSummary').innerHTML = 
        '<div class="fingerprint-loading">No desktop session linked yet</div>';
    } else if (!desktopFingerprint || Object.keys(desktopFingerprint).length === 0) {
      document.getElementById('desktopFingerprintSummary').innerHTML = 
        '<div class="fingerprint-loading">No desktop fingerprint data available</div>';
    } else {
      displayFingerprintData(desktopFingerprint, desktopDeviceType, 'desktopFingerprintSummary');
    }
    
  } catch (error) {
    log(`Failed to load fingerprint data: ${error.message}`, 'error');
    document.getElementById('mobileFingerprintSummary').innerHTML = 
      '<div class="fingerprint-loading">Failed to load mobile fingerprint data: ' + error.message + '</div>';
    document.getElementById('desktopFingerprintSummary').innerHTML = 
      '<div class="fingerprint-loading">Failed to load desktop fingerprint data: ' + error.message + '</div>';
  }
}

function displayFingerprintData(fingerprint, deviceType = 'unknown', targetElementId = 'fingerprintSummary') {
  const summaryEl = document.getElementById(targetElementId);
  
  const deviceInfo = {
    'Device Type': deviceType.charAt(0).toUpperCase() + deviceType.slice(1),
    'User Agent': fingerprint.userAgent || 'Unknown',
    'Screen Resolution': fingerprint.screenResolution || 'Unknown',
    'Color Depth': fingerprint.colorDepth || 'Unknown',
    'Platform': fingerprint.platform || 'Unknown',
    'Language': fingerprint.language || 'Unknown',
    'Timezone': fingerprint.timezone || 'Unknown',
    'Hardware Concurrency': fingerprint.hardwareConcurrency || 'Unknown',
    'Device Memory': fingerprint.deviceMemory || 'Unknown',
    'Cookie Enabled': fingerprint.cookieEnabled ? 'Yes' : 'No',
    'Do Not Track': fingerprint.doNotTrack || 'Unknown'
  };
  
  const graphicsInfo = {
    'WebGL Vendor': fingerprint.webglVendor || 'Unknown',
    'WebGL Renderer': fingerprint.webglRenderer || 'Unknown'
  };
  
  const uaChInfo = fingerprint.ua_ch ? {
    'Mobile Device': fingerprint.ua_ch.mobile ? 'Yes' : 'No',
    'Platform': fingerprint.ua_ch.platform || 'Unknown',
    'Platform Version': fingerprint.ua_ch.platformVersion || 'Unknown',
    'Architecture': fingerprint.ua_ch.architecture || 'Unknown',
    'Model': fingerprint.ua_ch.model || 'Unknown',
    'Browser Version': fingerprint.ua_ch.uaFullVersion || 'Unknown',
    'Bitness': fingerprint.ua_ch.bitness || 'Unknown',
    'Full Version List': fingerprint.ua_ch.fullVersionList ? fingerprint.ua_ch.fullVersionList.map(v => `${v.brand}:${v.version}`).join(', ') : 'Unknown'
  } : {
    'User Agent Client Hints': 'Not Available'
  };
  
  const automationInfo = fingerprint.automation ? {
    'WebDriver Present': fingerprint.automation.webdriver ? 'Yes' : 'No',
    'Headless Chrome': fingerprint.automation.headlessUA ? 'Yes' : 'No',
    'Plugins Count': fingerprint.automation.pluginsLength || 'Unknown',
    'MIME Types Count': fingerprint.automation.mimeTypesLength || 'Unknown',
    'Visibility State': fingerprint.automation.visibilityState || 'Unknown',
    'Has Focus': fingerprint.automation.hasFocus ? 'Yes' : 'No',
    'Permissions': fingerprint.automation.permissionsAnomalies ? 
      Object.entries(fingerprint.automation.permissionsAnomalies).map(([k,v]) => `${k}: ${v}`).join(', ') : 'Unknown'
  } : {
    'Automation Detection': 'Not Available'
  };
  
  const networkInfo = {
    'IP Address': fingerprint.ip_address || 'Unknown',
    'Collection Time': fingerprint.timestamp ? new Date(fingerprint.timestamp).toLocaleString() : 'Unknown'
  };
  
  const geolocationInfo = fingerprint.geolocation ? {
    'City': fingerprint.geolocation.city || 'Unknown',
    'Region': fingerprint.geolocation.region || 'Unknown',
    'Country': fingerprint.geolocation.country || 'Unknown',
    'Country Code': fingerprint.geolocation.country_code || 'Unknown',
    'Postal Code': fingerprint.geolocation.postal || 'Unknown',
    'Coordinates': `${fingerprint.geolocation.latitude}, ${fingerprint.geolocation.longitude}`,
    'Timezone': fingerprint.geolocation.timezone || 'Unknown',
    'Organization': fingerprint.geolocation.org || 'Unknown',
    'ASN': fingerprint.geolocation.asn || 'Unknown'
  } : {
    'Geolocation': 'Not Available'
  };
  
  let html = '';
  
  // Device Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">Device Information</div>';
  for (const [label, value] of Object.entries(deviceInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  // Graphics Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">Graphics</div>';
  for (const [label, value] of Object.entries(graphicsInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  // User Agent Client Hints Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">User Agent Client Hints</div>';
  for (const [label, value] of Object.entries(uaChInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  // Automation Detection Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">Automation Detection</div>';
  for (const [label, value] of Object.entries(automationInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  // Network Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">Network Information</div>';
  for (const [label, value] of Object.entries(networkInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  // Geolocation Information
  html += '<div class="fingerprint-category">';
  html += '<div class="fingerprint-category-title">Geolocation</div>';
  for (const [label, value] of Object.entries(geolocationInfo)) {
    html += `<div class="fingerprint-item">
      <span class="fingerprint-label">${label}:</span>
      <span class="fingerprint-value">${value}</span>
    </div>`;
  }
  html += '</div>';
  
  summaryEl.innerHTML = html;
}

function setupSuccessButtons() {
  // Kill Session Button
  const killSessionBtn = document.getElementById('killSessionBtn');
  if (killSessionBtn) {
    killSessionBtn.addEventListener('click', async () => {
      if (confirm('Are you sure you want to kill this session? This will terminate the connection completely.')) {
        try {
          log('Killing session...', 'info');
          const response = await fetch('/session/kill', {
            method: 'POST',
            credentials: 'include'
          });
          
          if (response.ok) {
            log('Session killed successfully', 'success');
            // Hide success section and show message
            const successSection = document.getElementById('successSection');
            if (successSection) {
              successSection.style.display = 'none';
            }
            log('Session terminated. Please refresh the page to start a new session.', 'warn');
          } else {
            throw new Error(`Failed to kill session: ${response.status}`);
          }
        } catch (error) {
          log(`Failed to kill session: ${error.message}`, 'error');
        }
      }
    });
  }
  
  // Refresh Fingerprints Button
  const refreshFingerprintsBtn = document.getElementById('refreshFingerprintsBtn');
  if (refreshFingerprintsBtn) {
    refreshFingerprintsBtn.addEventListener('click', async () => {
      log('Refreshing fingerprint data...', 'info');
      await loadFingerprintData();
      log('Fingerprint data refreshed', 'success');
    });
  }
}
