// public/link.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';
import { SignatureShare } from '/src/signature-share.js';

const outEl = document.getElementById('out');
const log = (m, o) => {
  if (!outEl) return console.log(m, o ?? '');
  outEl.textContent += m + (o ? ' ' + JSON.stringify(o, null, 2) : '') + '\n';
};

// Global signature share instance
let signatureShare = null;

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

function getTokenFromURL() {
  const url = new URL(location.href);
  const fromQuery = url.searchParams.get('token');
  if (fromQuery) return fromQuery;
  const hash = url.hash.startsWith('#') ? url.hash.slice(1) : url.hash;
  if (!hash) return null;
  return new URLSearchParams(hash).get('token');
}

// Initialize signature sharing after successful linking
function initSignatureSharing(linkId) {
  log('Initializing signature sharing...', 'info');
  
  try {
    // Clean up any existing signature share
    if (signatureShare) {
      signatureShare.destroy();
    }
    
    // Initialize signature sharing for mobile device
    signatureShare = new SignatureShare();
    signatureShare.initMobile(linkId);
    
    log('Signature sharing initialized successfully!', 'success');
    log('You can now scribble on the canvas and it will appear on the desktop device in real-time.', 'info');
    
  } catch (error) {
    log(`Failed to initialize signature sharing: ${error.message}`, 'error');
  }
}

(async () => {
  log('Linking…');
  try {
    const token = getTokenFromURL();
    if (!token) throw new Error('missing token in URL');

    // 1) Tell server we scanned the QR (no DPoP required yet)
    let r = await fetch('/link/mobile/start', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token })
    });
    if (!r.ok) throw new Error(`start failed: ${r.status}`);
    const { link_id } = await r.json();
    if (!link_id) throw new Error('start failed (no link_id)');
    log('QR accepted', { link_id });

    // 2) Mobile session → BIK → DPoP
    await Stronghold.sessionInit({ sessionInitUrl: '/session/init' });
    await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
    await Stronghold.dpopBindStep({ dpopBindUrl: '/dpop/bind' });

    // 3) Now that we have a valid session, check for existing passkeys
    let hasCreds = false;
    let authOptions = null;
    
    try {
      // Try to get authentication options to see if there are existing passkeys
      authOptions = await Passkeys.getAuthOptions();
      hasCreds = authOptions.allowCredentials && authOptions.allowCredentials.length > 0;
      log('[link] auth options check', { 
        hasCredentials: hasCreds, 
        allowCredentialsCount: authOptions.allowCredentials?.length || 0,
        allowCredentials: authOptions.allowCredentials || [],
        rpId: authOptions.rpId,
        userVerification: authOptions.userVerification,
        _meta: authOptions._meta || {}
      });
      
      // Log the full auth options for debugging
      log('[link] full auth options', authOptions);
      
    } catch (e) {
      // If getting auth options fails, assume no existing passkeys
      log('[link] auth options check failed; will register new passkey', { message: e.message || String(e) });
      hasCreds = false;
    }

    // 4) Handle passkey flow
    if (!hasCreds) {
      log('No existing passkeys found for this domain — registering one now…');
      try {
        await Passkeys.registerPasskey();
        log('Passkey registered on mobile ✓');
      } catch (error) {
        log(`Passkey registration failed: ${error.message}`, 'error');
        throw error;
      }
    } else {
      log('Existing passkeys found for this domain — authenticating…');
    }

    // 5) Always authenticate (either with newly created or existing passkey)
    try {
      // If we have existing credentials, use them; otherwise let the browser choose
      if (hasCreds && authOptions) {
        await Passkeys.authenticatePasskey(authOptions);
      } else {
        await Passkeys.authenticatePasskey();
      }
      log('Passkey authenticated ✓');
    } catch (error) {
      log(`Passkey authentication failed: ${error.message}`, 'error');
      
      // If authentication failed but we thought we had credentials, 
      // the credentials might be stale. Try registering a new passkey.
      if (hasCreds) {
        log('Authentication failed with existing credentials - trying to register new passkey...', 'warn');
        try {
          await Passkeys.registerPasskey();
          log('New passkey registered after auth failure ✓');
          
          // Try authentication again with the new passkey
          await Passkeys.authenticatePasskey();
          log('Passkey authenticated with new credential ✓');
        } catch (regError) {
          log(`Registration fallback also failed: ${regError.message}`, 'error');
          throw error; // Throw the original error
        }
      } else {
        throw error;
      }
    }

    // 6) Complete link — MUST be DPoP-signed (use strongholdFetch)
    await Stronghold.strongholdFetch('/link/mobile/complete', {
      method: 'POST',
      body: { link_id }
    });
    log('Linked ✓');
    
    // 7) Initialize signature sharing after successful linking
    log('Starting signature sharing feature...', 'info');
    initSignatureSharing(link_id);
    
  } catch (e) {
    log('Error', { message: e.message || String(e) });
  }
})();
