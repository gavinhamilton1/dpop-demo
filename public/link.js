// public/link.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys   from '/src/passkeys.js';

const outEl = document.getElementById('out');
const log = (m, o) => {
  if (!outEl) return console.log(m, o ?? '');
  outEl.textContent += m + (o ? ' ' + JSON.stringify(o, null, 2) : '') + '\n';
};

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

function isUserCancelOrNoCreds(err) {
  const msg = String(err?.message || err || '');
  // Browsers vary: NotAllowedError/AbortError on cancel or on “no available credentials”
  return /NotAllowedError|AbortError|denied|cancel/i.test(msg);
}

(async () => {
  log('Linking…');
  try {
    const token = getTokenFromURL();
    if (!token) throw new Error('missing token in URL');

    // 1) Tell server we scanned the QR (no DPoP required)
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

    // 3) Authenticate first (RP-first discoverable; server may omit allowCredentials)
    const sup = await Passkeys.checkSupport();
    if (!sup.hasAPI) throw new Error('WebAuthn unsupported on this device');

    let authed = false;
    try {
      log('Attempting passkey authentication…');
      await Passkeys.authenticatePasskey({ discoverablePreferred: true });
      authed = true;
      log('Passkey authenticated ✓');
    } catch (e) {
      if (isUserCancelOrNoCreds(e)) {
        log('Authentication cancelled or no discoverable credential on this device.');
        // Optional: offer registration path instead of auto-registering.
        // If you want *silent* behavior with no prompt, flip this to false.
        const shouldRegister = confirm('No passkey was used. Create a mobile passkey for this account on this device now?');
        if (shouldRegister) {
          log('Registering a new passkey on mobile…');
          await Passkeys.registerPasskey();
          log('Passkey registered on mobile ✓');
          await Passkeys.authenticatePasskey();
          authed = true;
          log('Passkey authenticated ✓');
        }
      } else {
        throw e;
      }
    }

    if (!authed) throw new Error('Authentication required to complete linking.');

    // 4) Complete link — MUST be DPoP-signed (use strongholdFetch)
    await Stronghold.strongholdFetch('/link/mobile/complete', {
      method: 'POST',
      body: { link_id }
    });
    log('Linked ✓');
  } catch (e) {
    log('Error', { message: e.message || String(e) });
  }
})();
