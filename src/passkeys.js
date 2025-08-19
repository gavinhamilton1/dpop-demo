// src/passkeys.js
import { strongholdFetch } from '/src/stronghold.js';

const enc = new TextEncoder();

// --- add this guard block ---
let _wa = { busy: false, ctl: null };
function _beginWebAuthnOp() {
  if (_wa.busy) {
    // Abort any lingering native sheet before starting a new one.
    try { _wa.ctl?.abort(); } catch {}
  }
  _wa.ctl = new AbortController();
  _wa.busy = true;
  return _wa.ctl.signal;
}
function _endWebAuthnOp() {
  _wa.busy = false;
  _wa.ctl = null;
}

// small helpers (unchanged)
const b64u = (buf) => {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  return btoa(String.fromCharCode(...u8)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
};
const b64uDec = (s) => {
  s = s.replace(/-/g,'+').replace(/_/g,'/'); const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s + pad); const out = new Uint8Array(bin.length);
  for (let i=0;i<bin.length;i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
};

export async function checkSupport() {
  const hasAPI = !!window.PublicKeyCredential;
  let uvp = false, cond = false;
  try { uvp = await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable(); } catch {}
  try { cond = !!(PublicKeyCredential.isConditionalMediationAvailable && await PublicKeyCredential.isConditionalMediationAvailable()); } catch {}
  return { hasAPI, uvp, conditional: cond };
}

export async function registerPasskey() {
  const opts = await strongholdFetch('/webauthn/registration/options', { method: 'POST' });
  const publicKey = {
    rp: opts.rp,
    user: { id: b64uDec(opts.user.id), name: opts.user.name, displayName: opts.user.displayName },
    challenge: b64uDec(opts.challenge),
    pubKeyCredParams: opts.pubKeyCredParams,
    authenticatorSelection: opts.authenticatorSelection,
    attestation: opts.attestation,
    excludeCredentials: (opts.excludeCredentials || []).map(e => ({ ...e, id: b64uDec(e.id) })),
  };

  const signal = _beginWebAuthnOp();
  let cred;
  try {
    cred = await navigator.credentials.create({ publicKey, signal });
  } catch (e) {
    _endWebAuthnOp();
    // Normalize the common browser error string so your UI logs are stable.
    if (e && /already pending/i.test(String(e.message || e))) {
      throw new Error('WebAuthn operation already pending; wait for the native sheet to close.');
    }
    throw e;
  }
  _endWebAuthnOp();

  if (!cred) throw new Error('credential create returned null');

  let publicKeyJwk = null;
  try {
    if (cred.response.getPublicKey) {
      const spki = cred.response.getPublicKey();
      const key = await crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, true, ['verify']);
      publicKeyJwk = await crypto.subtle.exportKey('jwk', key);
      publicKeyJwk.alg = publicKeyJwk.alg || 'ES256';
    }
  } catch {}

  const payload = {
    id: cred.id,
    rawId: b64u(cred.rawId),
    type: cred.type,
    transports: (cred.response.getTransports && cred.response.getTransports()) || ['internal'],
    response: {
      clientDataJSON: b64u(cred.response.clientDataJSON),
      attestationObject: b64u(cred.response.attestationObject),
      ...(publicKeyJwk ? { publicKeyJwk } : {}),
    }
  };
  return strongholdFetch('/webauthn/registration/verify', { method: 'POST', body: payload });
}

export async function authenticatePasskey() {
  const opts = await strongholdFetch('/webauthn/authentication/options', { method: 'POST' });
  const publicKey = {
    rpId: opts.rpId,
    challenge: b64uDec(opts.challenge),
    // allowCredentials may be omitted → discoverable credentials flow
    ...(Array.isArray(opts.allowCredentials) && opts.allowCredentials.length
      ? { allowCredentials: opts.allowCredentials.map(c => ({ ...c, id: b64uDec(c.id) })) }
      : {}),
    userVerification: opts.userVerification || 'preferred',
  };

  const signal = _beginWebAuthnOp();
  let cred;
  try {
    cred = await navigator.credentials.get({ publicKey, signal });
  } catch (e) {
    _endWebAuthnOp();
    if (e && /already pending/i.test(String(e.message || e))) {
      throw new Error('WebAuthn operation already pending; dismiss the existing prompt.');
    }
    throw e;
  }
  _endWebAuthnOp();

  if (!cred) throw new Error('credential get returned null');

  const payload = {
    id: cred.id,
    rawId: b64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: b64u(cred.response.clientDataJSON),
      authenticatorData: b64u(cred.response.authenticatorData),
      signature: b64u(cred.response.signature),
      userHandle: cred.response.userHandle ? b64u(cred.response.userHandle) : null,
    }
  };
  return strongholdFetch('/webauthn/authentication/verify', { method: 'POST', body: payload });
}

// optional: give callers a way to cancel on route changes/unload
export function cancelWebAuthn() { try { _wa.ctl?.abort(); } catch {} finally { _endWebAuthnOp(); } }
