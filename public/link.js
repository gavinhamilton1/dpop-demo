// Mobile linking page
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys from '/src/passkeys.js';
import { SignatureShare } from '/src/signature-share.js';

const log = (msg, level = 'info') => {
  const out = document.getElementById('out');
  const timestamp = new Date().toLocaleTimeString();
  const levelClass = level || 'info';
  const levelIcon = {
    'info': 'ℹ️',
    'success': '✅',
    'warn': '⚠️',
    'error': '❌'
  }[level] || 'ℹ️';
  
  const entry = document.createElement('div');
  entry.className = `log-entry ${levelClass}`;
  entry.innerHTML = `<span style="color: #a0aec0;">[${timestamp}]</span> ${levelIcon} ${msg}`;
  out.appendChild(entry);
  out.scrollTop = out.scrollHeight;
  
  // Also log to console for debugging
  console.log(`[${level.toUpperCase()}] ${msg}`);
};

// Progress step management
const updateStep = (stepNumber, status, message = '') => {
  const step = document.getElementById(`step-${stepNumber}`);
  if (!step) return;
  
  const statusDiv = step.querySelector('.step-status');
  const stepNumberDiv = step.querySelector('.step-number');
  
  // Remove all status classes
  step.classList.remove('pending', 'active', 'completed', 'error');
  
  // Add new status class
  step.classList.add(status);
  
  // Update status message
  if (statusDiv) {
    statusDiv.textContent = message || getDefaultMessage(status);
  }
  
  // Add loading spinner for active state
  if (status === 'active') {
    if (!step.querySelector('.loading-spinner')) {
      const spinner = document.createElement('div');
      spinner.className = 'loading-spinner';
      step.appendChild(spinner);
    }
  } else {
    const spinner = step.querySelector('.loading-spinner');
    if (spinner) spinner.remove();
  }
  
  // Add success/error icons
  if (status === 'completed') {
    stepNumberDiv.innerHTML = '✓';
  } else if (status === 'error') {
    stepNumberDiv.innerHTML = '✗';
  } else {
    stepNumberDiv.innerHTML = stepNumber;
  }
};

const getDefaultMessage = (status) => {
  switch (status) {
    case 'pending': return 'Waiting...';
    case 'active': return 'In progress...';
    case 'completed': return 'Completed';
    case 'error': return 'Failed';
    default: return '';
  }
};

// Initialize signature sharing
const initSignatureSharing = (linkId) => {
  try {
    signatureShare.initMobile(linkId);
    
    log('Scribble sharing initialized successfully!', 'success');
    log('You can now scribble on the canvas and it will appear on the desktop device in real-time.', 'info');
    
  } catch (error) {
    log(`Failed to initialize signature sharing: ${error.message}`, 'error');
  }
};

// Global signature share instance
let signatureShare = new SignatureShare();

// Polyfill randomUUID for odd webviews
if (typeof crypto !== 'undefined' && !crypto.randomUUID && crypto.getRandomValues) {
  crypto.randomUUID = () => {
    const b = new Uint8Array(16);
    crypto.getRandomValues(b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    const h = [...b].map(x => x.toString(16).padStart(2, '0'));
    return `${h.slice(0,4).join('')}-${h.slice(4,6).join('')}-${h.slice(6,8).join('')}-${h.slice(8,10).join('')}-${h.slice(10,16).join('')}`;
  };
}

function getLinkIdFromURL() {
  const url = new URL(location.href);
  const fromQuery = url.searchParams.get('lid');
  if (fromQuery) return fromQuery;
  const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  if (!hash) return null;
  return new URLSearchParams(hash).get('lid');
}

// Main linking process
async function link(linkId) {
  try {
    log('Starting cross-device linking process...', 'info');
    
    // Step 1: Initialize session
    updateStep(1, 'active', 'Initializing session...');
    await Stronghold.sessionInit({ sessionInitUrl: '/session/init' });
    updateStep(1, 'completed', 'Session initialized');
    log('Session initialized ✓', 'success');
    
    // Step 2: Setup security (BIK + DPoP)
    updateStep(2, 'active', 'Setting up security...');
    await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
    await Stronghold.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
    updateStep(2, 'completed', 'Security configured');
    log('Security setup completed ✓', 'success');

    // Step 3: Now that we have a valid session, check for existing passkeys
    updateStep(3, 'active', 'Checking for existing passkeys...');
    let hasCreds = false;
    let authOptions = null;
    
    try {
      // Try to get authentication options to see if there are existing passkeys
      authOptions = await Passkeys.getAuthOptions();
      hasCreds = authOptions.allowCredentials && authOptions.allowCredentials.length > 0;
      log(`[link] auth options check - hasCredentials: ${hasCreds}, count: ${authOptions.allowCredentials?.length || 0}, rpId: ${authOptions.rpId}`, 'info');
      
      // Log the full auth options for debugging
      log(`[link] full auth options: ${JSON.stringify(authOptions)}`, 'info');
      
    } catch (e) {
      // If getting auth options fails, assume no existing passkeys
      log(`[link] auth options check failed; will register new passkey: ${e.message || String(e)}`, 'warn');
      hasCreds = false;
    }

    // Step 4: Handle passkey flow
    if (!hasCreds) {
      log('No existing passkeys found for this domain — registering one now…');
      updateStep(3, 'active', 'Creating new passkey...');
      try {
        await Passkeys.registerPasskey();
        log('Passkey registered on mobile ✓', 'success');
        updateStep(3, 'completed', 'Passkey created');
      } catch (error) {
        log(`Passkey registration failed: ${error.message}`, 'error');
        updateStep(3, 'error', 'Passkey creation failed');
        throw error;
      }
    } else {
      log('Existing passkeys found for this domain — authenticating…');
      updateStep(3, 'active', 'Authenticating with existing passkey...');
    }

    // Step 5: Always authenticate (either with newly created or existing passkey)
    try {
      // If we have existing credentials, use them; otherwise let the browser choose
      if (hasCreds && authOptions) {
        await Passkeys.authenticatePasskey(authOptions);
      } else {
        await Passkeys.authenticatePasskey();
      }
      log('Passkey authenticated ✓', 'success');
      updateStep(3, 'completed', 'Passkey verified');
    } catch (error) {
      log(`Passkey authentication failed: ${error.message}`, 'error');
      
      // If authentication failed but we thought we had credentials, 
      // the credentials might be stale. Try registering a new passkey.
      if (hasCreds) {
        log('Authentication failed with existing credentials - trying to register new passkey...', 'warn');
        updateStep(3, 'active', 'Creating new passkey (fallback)...');
        try {
          await Passkeys.registerPasskey();
          log('New passkey registered after auth failure ✓', 'success');
          
          // Try authentication again with the new passkey
          await Passkeys.authenticatePasskey();
          log('Passkey authenticated with new credential ✓', 'success');
          updateStep(3, 'completed', 'Passkey verified (new)');
        } catch (regError) {
          log(`Registration fallback also failed: ${regError.message}`, 'error');
          updateStep(3, 'error', 'Passkey verification failed');
          throw error; // Throw the original error
        }
      } else {
        updateStep(3, 'error', 'Passkey verification failed');
        throw error;
      }
    }

    // Step 6: Complete link — MUST be DPoP-signed (use strongholdFetch)
    updateStep(4, 'active', 'Completing link...');
    await Stronghold.strongholdFetch('/link/mobile/complete', {
      method: 'POST',
      body: { link_id: linkId }
    });
    updateStep(4, 'completed', 'Link completed');
    log('Linked ✓', 'success');
    
    // 7) Initialize signature sharing after successful linking
    log('Starting Scribble sharing feature...', 'info');
    initSignatureSharing(linkId);
    
  } catch (error) {
    log(`Linking failed: ${error.message}`, 'error');
    // Mark the current step as failed
    const currentStep = document.querySelector('.progress-step.active');
    if (currentStep) {
      currentStep.classList.remove('active');
      currentStep.classList.add('error');
      const statusDiv = currentStep.querySelector('.step-status');
      if (statusDiv) {
        statusDiv.textContent = 'Failed';
      }
    }
  }
}

// Extract link ID from URL
const linkId = getLinkIdFromURL();
if (!linkId) {
  log('No link ID provided in URL', 'error');
  updateStep(1, 'error', 'Missing link ID');
} else {
  log(`Link ID found: ${linkId}`, 'info');
  
  // Start the linking process
  (async () => {
    try {
      // 1) Tell server we scanned the QR (no DPoP required yet)
      let r = await fetch('/link/mobile/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lid: linkId })
      });
      if (!r.ok) throw new Error(`start failed: ${r.status}`);
      const { link_id } = await r.json();
      if (!link_id) throw new Error('start failed (no link_id)');
      log(`QR accepted - Link ID: ${link_id}`, 'info');
      
      // Now start the main linking process
      link(link_id);
      
    } catch (e) {
      log(`Error starting link: ${e.message || String(e)}`, 'error');
      updateStep(1, 'error', 'Failed to start link');
    }
  })();
}
