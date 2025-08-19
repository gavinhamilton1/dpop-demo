// /src/passkeys.js
import * as Stronghold from '/src/stronghold.js';

// --- base64url helpers ---
const b64uToBuf = (s) => {
  const pad = '='.repeat((4 - (s.length % 4)) % 4);
  const b = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
  const buf = new Uint8Array(b.length);
  for (let i = 0; i < b.length; i++) buf[i] = b.charCodeAt(i);
  return buf.buffer;
};
const bufToB64u = (buf) => {
  const b = new Uint8Array(buf);
  let s = ''; for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
};

export async function checkSupport() {
  const hasAPI = !!(window.PublicKeyCredential && navigator.credentials);
  const uvp = hasAPI && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().catch(()=>false);
  return { hasAPI, uvp: !!uvp };
}

// ----- Registration -----
export async function registerPasskey() {
  // 1) get options
  const opts = await Stronghold.strongholdFetch('/webauthn/registration/options', { method: 'POST' });

  const pub = {
    rp: opts.rp,
    user: {
      ...opts.user,
      id: b64uToBuf(opts.user.id),
    },
    pubKeyCredParams: opts.pubKeyCredParams,
    challenge: b64uToBuf(opts.challenge),
    attestation: opts.attestation || 'none',
    authenticatorSelection: opts.authenticatorSelection || {},
  };

  // 2) create
  const cred = await navigator.credentials.create({ publicKey: pub });
  if (!cred) throw new Error('registration cancelled');

  // 3) send to server
  const att = {
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      clientDataJSON: bufToB64u(cred.response.clientDataJSON),
      attestationObject: bufToB64u(cred.response.attestationObject),
    },
    transports: cred.response.getTransports?.() || ['internal'],
  };

  return await Stronghold.strongholdFetch('/webauthn/registration/verify', {
    method: 'POST',
    body: att,
  });
}

// ----- Authentication (preflight-able) -----

export async function getAuthOptions() {
  return await Stronghold.strongholdFetch('/webauthn/authentication/options', { method: 'POST' });
}

export async function authenticatePasskey(passedOpts) {
  // allow caller to pass pre-fetched options
  const opts = passedOpts || await getAuthOptions();

  const allow = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];
  // If you want to avoid “external device” chooser when none are local,
  // handle that in the page logic before calling this function.

  const pub = {
    rpId: opts.rpId,
    challenge: b64uToBuf(opts.challenge),
    userVerification: opts.userVerification || 'preferred',
  };

  if (allow.length) {
    pub.allowCredentials = allow.map(c => ({
      type: 'public-key',
      id: b64uToBuf(c.id),
      transports: c.transports || ['internal'],
    }));
  }

  const assertion = await navigator.credentials.get({ publicKey: pub });
  if (!assertion) throw new Error('authentication cancelled');

  const payload = {
    id: assertion.id,
    rawId: bufToB64u(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
      authenticatorData: bufToB64u(assertion.response.authenticatorData),
      signature: bufToB64u(assertion.response.signature),
      userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : undefined,
    },
  };

  return await Stronghold.strongholdFetch('/webauthn/authentication/verify', {
    method: 'POST',
    body: payload,
  });
}
