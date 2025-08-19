// /src/passkeys.js
import * as Stronghold from '/src/stronghold.js';

// -------- helpers --------
const b64u = (buf) =>
  typeof buf === 'string'
    ? buf
    : btoa(String.fromCharCode(...new Uint8Array(buf)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');

const deb64u = (s) => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b64 = (s + pad).replace(/-/g, '+').replace(/_/g, '/');
  const bin = atob(b64);
  const u8 = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
  return u8.buffer;
};

async function isUVPA() {
  try {
    if (!('PublicKeyCredential' in window)) return false;
    if (!PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable) return false;
    return await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch { return false; }
}

export async function checkSupport() {
  const hasAPI = 'PublicKeyCredential' in window;
  return {
    hasAPI,
    uvp: hasAPI ? await isUVPA() : false
  };
}

// -------- registration --------
export async function registerPasskey() {
  // 1) Get options from server
  const options = await Stronghold.strongholdFetch('/webauthn/registration/options', { method: 'POST' });

  // Convert to browser format
  const pubKey = {
    ...options,
    challenge: deb64u(options.challenge),
    user: {
      ...options.user,
      id: deb64u(options.user.id),
    },
    // (Optional nudge) Prefer platform authenticators:
    authenticatorSelection: {
      ...(options.authenticatorSelection || {}),
      // authenticatorAttachment: 'platform', // uncomment if you want a stronger nudge
    },
  };

  // 2) Create
  const cred = await navigator.credentials.create({ publicKey: pubKey });
  if (!cred) throw new Error('registration cancelled');

  // 3) Send back to server
  const att = cred.response;
  const transports = (att.getTransports && att.getTransports()) || [];

  const body = {
    id:       cred.id,
    rawId:    b64u(cred.rawId),
    type:     cred.type,
    transports,
    response: {
      clientDataJSON:     b64u(att.clientDataJSON),
      attestationObject:  b64u(att.attestationObject),
    },
  };

  return await Stronghold.strongholdFetch('/webauthn/registration/verify', {
    method: 'POST',
    body,
  });
}

// -------- authentication --------
/**
 * authenticatePasskey({ discoverablePreferred })
 * - If discoverablePreferred === true, we delete allowCredentials to enable local password manager / account picker,
 *   even if the server provided a list.
 * - If the server sends allowCredentials: [], we always delete it (empty array disables discoverable UX).
 */
export async function authenticatePasskey(params = {}) {
  // 1) Options from server
  const options = await Stronghold.strongholdFetch('/webauthn/authentication/options', { method: 'POST' });

  // Convert to browser format
  const pubKey = {
    ...options,
    challenge: deb64u(options.challenge),
  };

  // Normalize allowCredentials
  const list = Array.isArray(options.allowCredentials) ? options.allowCredentials : null;
  if (params.discoverablePreferred === true) {
    // Force discoverable flow regardless of server hint
    delete pubKey.allowCredentials;
  } else if (!list || list.length === 0) {
    // Critical: omit empty array to allow discoverable credentials
    delete pubKey.allowCredentials;
  } else {
    // Convert each id to ArrayBuffer and pass transports hint through
    pubKey.allowCredentials = list.map((c) => ({
      type: c.type || 'public-key',
      id: deb64u(c.id),
      transports: c.transports || ['internal'],
    }));
  }

  // 2) Get
  const cred = await navigator.credentials.get({
    publicKey: pubKey,
    // mediation: 'optional', // keep default; 'conditional' requires extra UX + HTTPS
  });
  if (!cred) throw new Error('authentication cancelled');

  // 3) Send to server
  const res = cred.response;
  const body = {
    id:       cred.id,
    rawId:    b64u(cred.rawId),
    type:     cred.type,
    response: {
      clientDataJSON:     b64u(res.clientDataJSON),
      authenticatorData:  b64u(res.authenticatorData),
      signature:          b64u(res.signature),
      userHandle:         res.userHandle ? b64u(res.userHandle) : null,
    },
  };

  return await Stronghold.strongholdFetch('/webauthn/authentication/verify', {
    method: 'POST',
    body,
  });
}
