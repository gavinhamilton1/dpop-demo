// Stronghold core: keys, bind, DPoP proof, signed fetch, client flush

import { b64uJSON, sigToJoseEcdsa, createJwsES256, jwkThumbprint } from '/src/jose-lite.js';
import { idbPut, idbGet, idbWipe, STORES } from '/src/idb.js';
import { createDpopProof, canonicalUrl } from '/src/dpop.js';
import { coreLogger } from './utils/logging.js';
import { AuthenticationError, NetworkError, StorageError } from './utils/errors.js';
import { CONFIG } from './utils/config.js';

export { createJwsES256, idbWipe, jwkThumbprint, createDpopProof };

let CSRF = null;
let REG_NONCE = null;

export async function get(key) { 
  try {
    return await idbGet(STORES.META, key); 
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new StorageError('Failed to get value from storage', { originalError: error.message, key });
  }
}

export async function set(key, value) { 
  try {
    return await idbPut(STORES.META, { id: key, value }); 
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new StorageError('Failed to set value in storage', { originalError: error.message, key });
  }
}

async function generateES256KeyPair() {
  try {
    coreLogger.debug('Generating new ES256 key pair');
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: CONFIG.CRYPTO.CURVE }, false, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    coreLogger.debug('ES256 key pair generated successfully');
    return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicJwk };
  } catch (error) {
    coreLogger.error('Failed to generate ES256 key pair:', error);
    throw new AuthenticationError('Failed to generate key pair', { originalError: error.message });
  }
}

async function maybeRotate(rec, ttlSec, label) {
  if (!rec?.createdAt) return true;
  const ageSec = (Date.now() - rec.createdAt) / 1000;
  if (ageSec > ttlSec) { 
    coreLogger.warn(`rotating ${label}, age=${ageSec.toFixed(0)}s`); 
    return true; 
  }
  return false;
}

export async function ensureBIK() {
  try {
    let rec = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.BIK_CURRENT);
    if (!rec || await maybeRotate(rec, CONFIG.TIMEOUTS.BIK_ROTATE_SEC, 'BIK')) {
      const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
      rec = { id: CONFIG.STORAGE.KEYS.BIK_CURRENT, privateKey, publicKey, publicJwk, createdAt: Date.now() };
      await idbPut(STORES.KEYS, rec);
      coreLogger.debug('BIK key created/rotated');
    }
    return { 
      privateKey: rec.privateKey, 
      publicKey: rec.publicKey, 
      publicJwk: rec.publicJwk, 
      jkt: await jwkThumbprint(rec.publicJwk) 
    };
  } catch (error) {
    coreLogger.error('Failed to ensure BIK:', error);
    if (error.name === 'AuthenticationError') throw error;
    throw new AuthenticationError('Failed to ensure BIK key', { originalError: error.message });
  }
}

export async function ensureDPoP() {
  try {
    let rec = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.DPOP_CURRENT);
    if (!rec || await maybeRotate(rec, CONFIG.TIMEOUTS.DPOP_ROTATE_SEC, 'DPoP')) {
      const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
      rec = { id: CONFIG.STORAGE.KEYS.DPOP_CURRENT, privateKey, publicKey, publicJwk, createdAt: Date.now() };
      await idbPut(STORES.KEYS, rec);
      coreLogger.debug('DPoP key created/rotated');
    }
    return { 
      privateKey: rec.privateKey, 
      publicKey: rec.publicKey, 
      publicJwk: rec.publicJwk, 
      jkt: await jwkThumbprint(rec.publicJwk) 
    };
  } catch (error) {
    coreLogger.error('Failed to ensure DPoP:', error);
    if (error.name === 'AuthenticationError') throw error;
    throw new AuthenticationError('Failed to ensure DPoP key', { originalError: error.message });
  }
}

async function createJwsWithDefaults({ typ, payload, privateKey, publicJwk }) {
  try {
    const protectedHeader = { 
      alg: CONFIG.CRYPTO.ALGORITHM, 
      typ, 
      jwk: publicJwk 
    };
    const fullPayload = { 
      ...payload, 
      iat: Math.floor(Date.now()/1000) 
    };
    return await createJwsES256({ protectedHeader, payload: fullPayload, privateKey });
  } catch (error) {
    coreLogger.error('Failed to create JWS with defaults:', error);
    throw new AuthenticationError('Failed to create JWS', { originalError: error.message });
  }
}

export async function sessionInit({ sessionInitUrl = CONFIG.ENDPOINTS.SESSION_INIT, browserUuid = null } = {}) {
  try {
    coreLogger.debug('Initializing session');
    const existing = (await get(CONFIG.STORAGE.KEYS.BROWSER_UUID))?.value;
    const uuid = browserUuid || existing || crypto.randomUUID();
    if (!existing) await set(CONFIG.STORAGE.KEYS.BROWSER_UUID, uuid);

    const r = await fetch(sessionInitUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ browser_uuid: uuid })
    });
    
    if (!r.ok) {
      throw new NetworkError(`session/init failed: ${r.status}`, r.status, { url: sessionInitUrl });
    }
    
    const j = await r.json();
    CSRF = j.csrf; 
    REG_NONCE = j.reg_nonce;
    // Store CSRF and reg_nonce in IndexedDB for session restoration
    await set(CONFIG.STORAGE.KEYS.CSRF, j.csrf);
    await set(CONFIG.STORAGE.KEYS.REG_NONCE, j.reg_nonce);
    coreLogger.info('sessionInit ok', j);
    return j;
  } catch (error) {
    coreLogger.error('Session initialization failed:', error);
    if (error.name === 'NetworkError') throw error;
    throw new AuthenticationError('Session initialization failed', { originalError: error.message });
  }
}

export async function bikRegisterStep({ bikRegisterUrl = CONFIG.ENDPOINTS.BROWSER_REGISTER } = {}) {
  try {
    if (!CSRF || !REG_NONCE) {
      throw new AuthenticationError('missing csrf/reg_nonce (call sessionInit first)');
    }
    
    coreLogger.debug('Registering BIK');
    const bik = await ensureBIK();
    const jws = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.BIK_REG,
      payload: { nonce: REG_NONCE },
      privateKey: bik.privateKey,
      publicJwk: bik.publicJwk
    });

    const r = await fetch(bikRegisterUrl, { 
      method: 'POST', 
      credentials: 'include', 
      headers: { 'X-CSRF-Token': CSRF }, 
      body: jws 
    });
    
    if (!r.ok) {
      throw new NetworkError(`bik register failed: ${r.status}`, r.status, { url: bikRegisterUrl });
    }
    
    const j = await r.json();
    await set(CONFIG.STORAGE.KEYS.BIK_JKT, j.bik_jkt);
    coreLogger.info('bik/register ok', j);
    return j;
  } catch (error) {
    coreLogger.error('BIK registration failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    throw new AuthenticationError('BIK registration failed', { originalError: error.message });
  }
}

export async function dpopBindStep({ dpopBindUrl = CONFIG.ENDPOINTS.DPOP_BIND } = {}) {
  try {
    if (!CSRF) {
      throw new AuthenticationError('missing csrf (call sessionInit first)');
    }
    
    coreLogger.debug('Binding DPoP');
    const bik = await ensureBIK();
    const dpop = await ensureDPoP();

    const payload = { dpop_jwk: dpop.publicJwk, nonce: crypto.randomUUID() };
    coreLogger.debug('DPoP bind payload:', payload);
    
    const jws = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.DPOP_BIND,
      payload,
      privateKey: bik.privateKey,
      publicJwk: bik.publicJwk
    });

    coreLogger.info('Created JWS for DPoP bind:', { 
      length: jws.length, 
      header: jws.split('.')[0],
      payloadPreview: jws.split('.')[1].substring(0, 50) + '...',
      csrf: CSRF 
    });

    const r = await fetch(dpopBindUrl, { 
      method: 'POST', 
      credentials: 'include', 
      headers: { 'X-CSRF-Token': CSRF }, 
      body: jws 
    });
    
    if (!r.ok) {
      const errorText = await r.text().catch(() => 'Unable to read error response');
      coreLogger.error('DPoP bind failed with status:', r.status, 'Response:', errorText);
      coreLogger.error('Request details:', { 
        url: dpopBindUrl,
        csrf: CSRF,
        jwsLength: jws.length,
        headers: { 'X-CSRF-Token': CSRF }
      });
      throw new NetworkError(`dpop bind failed: ${r.status}`, r.status, { url: dpopBindUrl, response: errorText });
    }
    
    const j = await r.json();
    await set(CONFIG.STORAGE.KEYS.BIND, j.bind);
    const serverNonce = r.headers.get('DPoP-Nonce'); 
    if (serverNonce) await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, serverNonce);

    coreLogger.info('dpop/bind ok', j, 'nonce=', serverNonce || null);
    return { ...j, dpopKeyId: CONFIG.STORAGE.KEYS.DPOP_CURRENT, nonce: serverNonce || null };
  } catch (error) {
    coreLogger.error('DPoP binding failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    throw new AuthenticationError('DPoP binding failed', { originalError: error.message });
  }
}

async function ensureBinding() {
  let bind = (await get(CONFIG.STORAGE.KEYS.BIND))?.value;
  if (!bind) {
    const ok = await resumeViaPage();
    if (!ok) throw new AuthenticationError('no binding token (resume failed)');
    bind = (await get(CONFIG.STORAGE.KEYS.BIND))?.value;
  } else {
    // Check if binding token is expired (server TTL is 1 hour = 3600 seconds)
    try {
      const payload = JSON.parse(atob(bind.split('.')[1]));
      const now = Math.floor(Date.now() / 1000);
      const expiresAt = payload.exp || 0;
      
      if (now >= expiresAt) {
        coreLogger.debug('Binding token expired, triggering resume');
        const ok = await resumeViaPage();
        if (!ok) throw new AuthenticationError('binding token expired and resume failed');
        bind = (await get(CONFIG.STORAGE.KEYS.BIND))?.value;
      }
    } catch (error) {
      coreLogger.warn('Failed to check binding token expiration, assuming valid');
    }
  }
  return bind;
}

async function handleNonceChallenge(res, url, method, dpop) {
  if ((res.status === CONFIG.HTTP.STATUS_CODES.UNAUTHORIZED || res.status === CONFIG.HTTP.STATUS_CODES.PRECONDITION_REQUIRED) && res.headers.get('DPoP-Nonce')) {
    const n = res.headers.get('DPoP-Nonce');
    await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n);
    const proof = await createDpopProof({ 
      url, method, nonce: n, 
      privateKey: dpop.privateKey, 
      publicJwk: dpop.publicJwk 
    });
    return proof;
  }
  return null;
}

export async function strongholdFetch(url, { method = 'GET', body = null } = {}) {
  try {
    coreLogger.debug('Making signed fetch request:', { url, method, hasBody: !!body });
    
    const bind = await ensureBinding();
    const dpop = await ensureDPoP();
    // Use current origin for canonicalization to support multi-domain
    const currentOrigin = globalThis.location?.origin || globalThis.self?.location?.origin || 'http://localhost';
    const fullUrl = canonicalUrl(url, currentOrigin);
    
    let proof = await createDpopProof({ 
      url: fullUrl, method, 
      nonce: (await get(CONFIG.STORAGE.KEYS.DPOP_NONCE))?.value || null, 
      privateKey: dpop.privateKey, 
      publicJwk: dpop.publicJwk 
    });
    
    let headers = { 
      'Content-Type': 'application/json', 
      'DPoP': proof, 
      'DPoP-Bind': bind 
    };
    const init = { method, headers, credentials: 'include', body: body ? JSON.stringify(body) : undefined };

    let res = await fetch(fullUrl, init);
    
    const retryProof = await handleNonceChallenge(res, fullUrl, method, dpop);
    if (retryProof) {
      coreLogger.debug('Handling nonce challenge, retrying with new proof');
      headers = { ...headers, 'DPoP': retryProof };
      res = await fetch(fullUrl, { ...init, headers });
    }

    if (!res.ok) {
      const t = await res.text().catch(() => String(res.status));
      throw new NetworkError(`request failed: ${res.status} ${t}`, res.status, { url: fullUrl });
    }
    
    const n2 = res.headers.get('DPoP-Nonce');
    if (n2) await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n2);
    
    const result = await res.json();
    coreLogger.debug('Signed fetch completed successfully');
    return result;
  } catch (error) {
    coreLogger.error('Signed fetch failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    // For test compatibility, preserve the original error message
    throw new NetworkError(`request failed: ${error.message}`, 0, { originalError: error.message, url });
  }
}

async function resumeViaPage() {
  try {
    coreLogger.debug('Attempting session resume');
    const r1 = await fetch(CONFIG.ENDPOINTS.SESSION_RESUME_INIT, { method: 'POST', credentials: 'include' });
    if (!r1.ok) return false;
    const { resume_nonce } = await r1.json();
    
    const bik = await ensureBIK();
    const jws = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.BIK_RESUME,
      payload: { resume_nonce },
      privateKey: bik.privateKey,
      publicJwk: bik.publicJwk
    });
    
    const r2 = await fetch(CONFIG.ENDPOINTS.SESSION_RESUME_CONFIRM, { method: 'POST', credentials: 'include', body: jws });
    if (!r2.ok) return false;
    const j = await r2.json();
    await set(CONFIG.STORAGE.KEYS.BIND, j.bind);
    const n = r2.headers.get('DPoP-Nonce'); 
    if (n) await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n);
    
    coreLogger.debug('Session resume completed successfully');
    return true;
  } catch (error) {
    coreLogger.error('Session resume failed:', error);
    return false;
  }
}

// Helper functions for DPoP information capture
export async function getDpopNonce() {
  return await get(CONFIG.STORAGE.KEYS.DPOP_NONCE);
}

export async function getBindToken() {
  return await get(CONFIG.STORAGE.KEYS.BIND);
}

export async function getBIK() {
  try {
    return await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.BIK_CURRENT);
  } catch {
    return null;
  }
}

/**
 * Restore CSRF token and reg_nonce from IndexedDB
 */
export async function restoreSessionTokens() {
  try {
    const csrf = await get(CONFIG.STORAGE.KEYS.CSRF);
    const regNonce = await get(CONFIG.STORAGE.KEYS.REG_NONCE);
    
    if (csrf?.value) {
      CSRF = csrf.value;
      coreLogger.debug('Restored CSRF token from storage');
    }
    
    if (regNonce?.value) {
      REG_NONCE = regNonce.value;
      coreLogger.debug('Restored reg_nonce from storage');
    }
    
    return { csrf: CSRF, regNonce: REG_NONCE };
  } catch (error) {
    coreLogger.warn('Failed to restore session tokens:', error);
    return { csrf: null, regNonce: null };
  }
}





export async function clientFlush() {
  try {
    coreLogger.debug('Flushing client state');
    CSRF = null; 
    REG_NONCE = null;
    await idbWipe();
    coreLogger.debug('Client flush completed');
    return { ok: true };
  } catch (error) {
    coreLogger.error('Client flush failed:', error);
    throw new StorageError('Client flush failed', { originalError: error.message });
  }
}
