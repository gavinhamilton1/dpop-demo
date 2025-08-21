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

async function preflightAuthOptions() {
  // Ask the server which creds it knows for THIS session's principal
  const opts = await Stronghold.strongholdFetch('/webauthn/authentication/options', { method: 'POST' });

  // Always normalize allowCredentials to an array
  const allow = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];

  // Be robust: if server didn't include _meta, synthesize it here
  const meta = opts._meta ?? {
    hasCredentials: allow.length > 0,
    registeredCount: allow.length,
    hasPlatform: allow.some(c => (c.transports || []).includes('internal')),
  };

  return { opts, allow, meta };
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

    // 3) Check if this session already has stored passkeys for the principal
    let hasCreds = false;
    try {
      const { allow, meta } = await preflightAuthOptions();
      hasCreds = !!meta.hasCredentials; // safe even if _meta missing on server
      log('[link] preflight', { allowCount: allow.length, meta });
    } catch (e) {
      // If preflight itself failed (network/DPoP/nonce), we'll fall back to trying auth
      log('[link] preflight failed; will continue', { message: e.message || String(e) });
    }

    // 4) If none, register a mobile passkey first; otherwise go straight to auth
    if (!hasCreds) {
      log('No stored mobile passkey for this session — registering one now…');
      await Passkeys.registerPasskey();  // will call /webauthn/registration/options + navigator.credentials.create
      log('Passkey registered on mobile ✓');
    } else {
      log('Stored passkey found for this session — authenticating…');
    }

    // Always authenticate after registration or when creds already exist
    await Passkeys.authenticatePasskey(); // /webauthn/authentication/options + navigator.credentials.get
    log('Passkey authenticated ✓');

    // 5) Complete link — MUST be DPoP-signed (use strongholdFetch)
    await Stronghold.strongholdFetch('/link/mobile/complete', {
      method: 'POST',
      body: { link_id }
    });
    log('Linked ✓');
    
    // 6) Initialize signature sharing after successful linking
    log('Starting signature sharing feature...', 'info');
    initSignatureSharing(link_id);
    
  } catch (e) {
    log('Error', { message: e.message || String(e) });
  }
})();
