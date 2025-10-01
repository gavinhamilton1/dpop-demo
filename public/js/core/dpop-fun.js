// DPop-Fun core: keys, bind, DPoP proof, signed fetch, client flush

import { b64uJSON, sigToJoseEcdsa, createJwsES256, jwkThumbprint } from '../utils/jose-lite.js';
import { idbPut, idbGet, idbWipe, STORES } from '../utils/idb.js';
import { logger } from '../utils/logging.js';
import { AuthenticationError, NetworkError, StorageError, CryptoError } from '../utils/errors.js';
import { CONFIG } from '../utils/config.js';
import { validateUrl, validateMethod, validateKeyPair, validateNonce } from '../utils/validation.js';
import { FingerprintService } from '../services/FingerprintService.js';

export { createJwsES256, idbWipe, jwkThumbprint };

let CSRF = null;
let REG_NONCE = null;

/**
 * Create a session state object with default values
 * @param {Object} overrides - Values to override defaults
 * @returns {Object} Session state object
 */
function createSessionState(overrides = {}) {
  const defaults = {
    hasSession: false,
    hasBIK: false,
    hasDPoP: false,
    hasUsername: false,
    username: null,
    sessionStatus: null,
    details: {
      serverSession: false,
      localBIK: false,
      localDPoP: false,
      serverBIK: false,
      serverDPoP: false,
      bikMatch: false,
      dpopMatch: false,
      dpopWorking: false,
        sessionType: SESSION_TYPES.NONE,
        bikType: KEY_TYPES.NONE,
        dpopType: KEY_TYPES.NONE
    }
  };
  
  return { ...defaults, ...overrides };
}



/**
 * Configuration constants for session and key types
 */
const SESSION_TYPES = {
  NONE: 'none',
  NEW: 'new',
  RESTORED: 'restored'
};

const KEY_TYPES = {
  NONE: 'none',
  NEW: 'new',
  RESTORED: 'restored',
  MISMATCH: 'mismatch',
  LOCAL_ONLY: 'local-only',
  SERVER_ONLY: 'server-only'
};

/**
 * Get current origin with fallback
 */
function getCurrentOrigin() {
  return globalThis.location?.origin || globalThis.self?.location?.origin || 'http://localhost';
}

/**
 * Session restoration helper functions
 */
const SessionRestore = {
  /**
   * Check local BIK and JKT from IndexedDB
   */
  async checkLocalBIK() {
    let localBIK = false;
    let localBikJkt = null;
    try {
      logger.debug('Checking for BIK with key:', CONFIG.STORAGE.KEYS.BIK_CURRENT);
      const bikRecord = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.BIK_CURRENT);
      logger.debug('BIK record from IndexedDB:', bikRecord);
      
      const bikJktRecord = await get(CONFIG.STORAGE.KEYS.BIK_JKT);
      logger.debug('BIK JKT record:', bikJktRecord);
      
      localBIK = !!bikRecord;
      localBikJkt = bikJktRecord?.value || null;
      
      logger.info('Local BIK detection result:', { localBIK, localBikJkt: localBikJkt ? 'present' : 'missing' });
    } catch (error) {
      logger.error('Error checking local BIK:', error);
      localBIK = false;
    }
    
    return { localBIK, localBikJkt };
  },
  
  /**
   * Check local DPoP from IndexedDB
   */
  async checkLocalDPoP() {
    let localDPoP = false;
    try {
      logger.debug('Checking for DPoP with key:', CONFIG.STORAGE.KEYS.DPOP_CURRENT);
      const dpopRecord = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.DPOP_CURRENT);
      logger.debug('DPoP record from IndexedDB:', dpopRecord);
      
      localDPoP = !!dpopRecord;
      logger.info('Local DPoP detection result:', { localDPoP });
    } catch (error) {
      logger.error('Error checking local DPoP:', error);
    }
    
    return { localDPoP };
  },
  
  /**
   * Test DPoP binding functionality
   */
  async testDPoPBinding() {
    let dpopWorking = false;
    try {
      // Test DPoP binding by making a request to session status
      await dpopFunFetch('/session/status');
      dpopWorking = true;
      logger.info('DPoP binding is working and matches');
    } catch (error) {
      logger.warn('DPoP binding test failed:', error.message);
      dpopWorking = false;
    }
    
    return { dpopWorking };
  },
  
  /**
   * Check for client/server mismatches and handle them
   */
  async checkAndHandleMismatches(localBIK, localDPoP, serverBIK, serverDPoP) {
    logger.info('Checking for mismatches:', { localBIK, localDPoP, serverBIK, serverDPoP });
    
    const bikMatch = localBIK && serverBIK && localBIK;
    const dpopMatch = localDPoP && serverDPoP;
    
    // Check for mismatches (server has keys but client doesn't, or vice versa)
    const hasMismatch = (serverBIK && !localBIK) || (serverDPoP && !localDPoP) || 
                       (!serverBIK && localBIK) || (!serverDPoP && localDPoP);
    
    logger.info('Mismatch detection result:', { hasMismatch, bikMatch, dpopMatch });
    
    if (hasMismatch) {
      logger.warn('Client/server mismatch detected, clearing server session');
      try {
        await clearServerSession();
        logger.info('Server session cleared due to mismatch');
        
        // Return fresh session state
        return createSessionState({
          details: {
            localBIK,
            localDPoP,
            serverBIK: false,
            serverDPoP: false,
            bikMatch: false,
            dpopMatch: false,
            dpopWorking: false
          }
        });
      } catch (error) {
        logger.error('Failed to clear server session:', error);
        // Continue with mismatched state if clearing fails
      }
    }
    
    return null; // No mismatch handled
  },
  
  /**
   * Get current username from server
   */
  async getCurrentUsername() {
    try {
      const username = await getCurrentUsername();
      return { hasUsername: !!username, username };
    } catch (error) {
      logger.debug('Failed to get current username:', error.message);
      return { hasUsername: false, username: null };
    }
  },

  /**
   * Store signal data for restored BIK to build historical baseline
   */
  async storeSignalDataForRestoredBIK() {
    try {
      logger.info('Storing signal data for restored BIK...');
      
      // Get current session status to get BIK JKT
      const sessionStatus = await getSessionStatus();
      if (!sessionStatus || !sessionStatus.bik_jkt) {
        logger.warn('No BIK JKT available for signal data storage');
        return;
      }

      logger.info(`BIK JKT found: ${sessionStatus.bik_jkt.substring(0, 8)}...`);

      // Check if we already have signal data for this BIK
      const response = await dpopFunFetch('/session/signal-data', { method: 'GET' });
      if (response && response.historical_signal) {
        logger.info('Signal data already exists for this BIK, skipping duplicate collection');
        return; // Don't collect fingerprint again if signal data already exists
      } else {
        logger.info('No historical signal data found, this will be the baseline');
      }

      // Collect and send current fingerprint data only if no signal data exists
      const fingerprint = await FingerprintService.collectFingerprint('desktop');
      if (fingerprint && Object.keys(fingerprint).length > 0) {
        await FingerprintService.sendFingerprintToServer(fingerprint);
        logger.info('Signal data stored for restored BIK');
      } else {
        logger.warn('No fingerprint data available for restored BIK');
      }
    } catch (error) {
      logger.error('Failed to store signal data for restored BIK:', error);
    }
  }
};


export function canonicalUrl(inputUrl, base) {
  try {
    logger.debug('Canonicalizing URL:', { inputUrl, base });
    validateUrl(inputUrl);
    
    // If no base is provided, use the current origin
    if (!base) {
      base = getCurrentOrigin();
    }
    
    logger.debug('Using base URL:', base);
    const u = new URL(inputUrl, base);
    const scheme = u.protocol.toLowerCase();
    const host = u.hostname.toLowerCase();
    let port = u.port;
    if ((scheme === 'https:' && port === '443') || (scheme === 'http:' && port === '80')) port = '';
    const netloc = port ? `${host}:${port}` : host;
    const canonical = `${scheme}//${netloc}${u.pathname || '/'}${u.search || ''}`;
    logger.debug('Canonicalized URL:', { input: inputUrl, output: canonical, base });
    return canonical;
  } catch (error) {
    logger.error('Canonicalization error:', { error: error.message, inputUrl, base });
    if (error.name === 'DPopFunError') throw error;
    throw new CryptoError('Failed to canonicalize URL', { originalError: error.message, url: inputUrl });
  }
}

export async function createDpopProof({ url, method, nonce, privateKey, publicJwk }) {
  try {
    validateUrl(url);
    const validatedMethod = validateMethod(method);
    validateNonce(nonce);
    validateKeyPair({ privateKey, publicKey: null, publicJwk });

    logger.debug('Creating DPoP proof:', { url, method: validatedMethod, hasNonce: !!nonce });

    const h = b64uJSON({ alg: CONFIG.CRYPTO.ALGORITHM, typ: CONFIG.CRYPTO.JWT_TYPES.DPOP, jwk: publicJwk });
    const p = b64uJSON({ 
      htu: canonicalUrl(url), 
      htm: validatedMethod, 
      iat: Math.floor(Date.now()/1000), 
      jti: crypto.randomUUID(), 
      ...(nonce ? { nonce } : {}) 
    });
    const input = new TextEncoder().encode(`${h}.${p}`);
    const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, input);
    const raw = sigToJoseEcdsa(sig, CONFIG.CRYPTO.KEY_SIZE);
    const s = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
    const proof = `${h}.${p}.${s}`;
    
    logger.debug('DPoP proof created successfully');
    return proof;
  } catch (error) {
    logger.error('Failed to create DPoP proof:', error);
    if (error.name === 'DPopFunError') throw error;
    throw new CryptoError('Failed to create DPoP proof', { 
      originalError: error.message, 
      url, 
      method, 
      hasNonce: !!nonce 
    });
  }
}


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
    logger.debug('Generating new ES256 key pair');
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: CONFIG.CRYPTO.CURVE }, false, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    logger.debug('ES256 key pair generated successfully');
    return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicJwk };
  } catch (error) {
    logger.error('Failed to generate ES256 key pair:', error);
    throw new AuthenticationError('Failed to generate key pair', { originalError: error.message });
  }
}

async function maybeRotate(rec, ttlSec, label) {
  if (!rec?.createdAt) return true;
  const ageSec = (Date.now() - rec.createdAt) / 1000;
  if (ageSec > ttlSec) { 
    logger.warn(`rotating ${label}, age=${ageSec.toFixed(0)}s`); 
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
      logger.debug('BIK key created/rotated');
    }
    return { 
      privateKey: rec.privateKey, 
      publicKey: rec.publicKey, 
      publicJwk: rec.publicJwk, 
      jkt: await jwkThumbprint(rec.publicJwk) 
    };
  } catch (error) {
    logger.error('Failed to ensure BIK:', error);
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
      logger.debug('DPoP key created/rotated');
    }
    return { 
      privateKey: rec.privateKey, 
      publicKey: rec.publicKey, 
      publicJwk: rec.publicJwk, 
      jkt: await jwkThumbprint(rec.publicJwk) 
    };
  } catch (error) {
    logger.error('Failed to ensure DPoP:', error);
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
    logger.error('Failed to create JWS with defaults:', error);
    throw new AuthenticationError('Failed to create JWS', { originalError: error.message });
  }
}

export async function sessionInit({ sessionInitUrl = CONFIG.ENDPOINTS.SESSION_INIT, browserUuid = null } = {}) {
  try {
    logger.debug('Initializing session');
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
    logger.info('sessionInit ok', j);
    return j;
  } catch (error) {
    logger.error('Session initialization failed:', error);
    if (error.name === 'NetworkError') throw error;
    throw new AuthenticationError('Session initialization failed', { originalError: error.message });
  }
}

export async function bikRegisterStep({ bikRegisterUrl = CONFIG.ENDPOINTS.BROWSER_REGISTER } = {}) {
  try {
    if (!CSRF || !REG_NONCE) {
      throw new AuthenticationError('missing csrf/reg_nonce (call sessionInit first)');
    }
    
    logger.debug('Registering BIK');
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
    logger.info('bik/register ok', j);
    return j;
  } catch (error) {
    logger.error('BIK registration failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    throw new AuthenticationError('BIK registration failed', { originalError: error.message });
  }
}

export async function dpopBindStep({ dpopBindUrl = CONFIG.ENDPOINTS.DPOP_BIND } = {}) {
  try {
    if (!CSRF) {
      throw new AuthenticationError('missing csrf (call sessionInit first)');
    }
    
    logger.debug('Binding DPoP');
    const bik = await ensureBIK();
    const dpop = await ensureDPoP();

    const payload = { dpop_jwk: dpop.publicJwk, nonce: crypto.randomUUID() };
    logger.debug('DPoP bind payload:', payload);
    
    const jws = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.DPOP_BIND,
      payload,
      privateKey: bik.privateKey,
      publicJwk: bik.publicJwk
    });

    logger.info('Created JWS for DPoP bind:', { 
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
      logger.error('DPoP bind failed with status:', r.status, 'Response:', errorText);
      logger.error('Request details:', { 
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

    logger.info('dpop/bind ok', j, 'nonce=', serverNonce || null);
    return { ...j, dpopKeyId: CONFIG.STORAGE.KEYS.DPOP_CURRENT, nonce: serverNonce || null };
  } catch (error) {
    logger.error('DPoP binding failed:', error);
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
        logger.debug('Binding token expired, triggering resume');
        const ok = await resumeViaPage();
        if (!ok) throw new AuthenticationError('binding token expired and resume failed');
        bind = (await get(CONFIG.STORAGE.KEYS.BIND))?.value;
      }
    } catch (error) {
      logger.warn('Failed to check binding token expiration, assuming valid');
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

export async function dpopFunFetch(url, { method = 'GET', body = null } = {}) {
  try {
    logger.debug('Making signed fetch request:', { url, method, hasBody: !!body });
    
    const bind = await ensureBinding();
    const dpop = await ensureDPoP();
    // Use current origin for canonicalization to support multi-domain
    const currentOrigin = getCurrentOrigin();
    const fullUrl = canonicalUrl(url, currentOrigin);
    
    const storedNonce = (await get(CONFIG.STORAGE.KEYS.DPOP_NONCE))?.value || null;
    logger.debug('Using DPoP nonce for request:', storedNonce);
    
    let proof = await createDpopProof({ 
      url: fullUrl, method, 
      nonce: storedNonce, 
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
      logger.debug('Handling nonce challenge, retrying with new proof');
      headers = { ...headers, 'DPoP': retryProof };
      res = await fetch(fullUrl, { ...init, headers });
    }

    if (!res.ok) {
      const t = await res.text().catch(() => String(res.status));
      
      // Handle binding token failures specifically
      if (res.status === 401 && t.includes('bind token invalid')) {
        logger.warn('Binding token invalid, clearing stored token and retrying');
        // Clear the stored binding token
        await set(CONFIG.STORAGE.KEYS.BIND, null);
        // Try to get a fresh binding token
        const freshBind = await ensureBinding();
        if (freshBind) {
          // Retry the request with fresh binding token
          headers = { ...headers, 'DPoP-Bind': freshBind };
          const retryRes = await fetch(fullUrl, { ...init, headers });
          if (retryRes.ok) {
            const n2 = retryRes.headers.get('DPoP-Nonce');
            if (n2) await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n2);
            const result = await retryRes.json();
            logger.debug('Request succeeded after binding token refresh');
            return result;
          }
        }
      }
      
      throw new NetworkError(`request failed: ${res.status} ${t}`, res.status, { url: fullUrl });
    }
    
    const n2 = res.headers.get('DPoP-Nonce');
    if (n2) await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n2);
    
    const result = await res.json();
    logger.debug('Signed fetch completed successfully');
    return result;
  } catch (error) {
    logger.error('Signed fetch failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    // For test compatibility, preserve the original error message
    throw new NetworkError(`request failed: ${error.message}`, 0, { originalError: error.message, url });
  }
}

export async function resumeViaPage() {
  try {
    logger.debug('Attempting session resume');
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
    if (n) {
      await set(CONFIG.STORAGE.KEYS.DPOP_NONCE, n);
      logger.info('Fresh DPoP nonce received and stored:', n);
    } else {
      logger.warn('No DPoP nonce received from session resume - this may cause authentication issues');
    }
    
    logger.debug('Session resume completed successfully');
    return true;
  } catch (error) {
    logger.error('Session resume failed:', error);
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
      logger.debug('Restored CSRF token from storage');
    }
    
    if (regNonce?.value) {
      REG_NONCE = regNonce.value;
      logger.debug('Restored reg_nonce from storage');
    }
    
    return { csrf: CSRF, regNonce: REG_NONCE };
  } catch (error) {
    logger.warn('Failed to restore session tokens:', error);
    return { csrf: null, regNonce: null };
  }
}





export async function clientFlush() {
  try {
    logger.debug('Flushing client state');
    CSRF = null; 
    REG_NONCE = null;
    await idbWipe();
    logger.debug('Client flush completed');
    return { ok: true };
  } catch (error) {
    logger.error('Client flush failed:', error);
    throw new StorageError('Client flush failed', { originalError: error.message });
  }
}

// ============================================================================
// SESSION MANAGEMENT
// ============================================================================

/**
 * Get comprehensive session status from server
 */
export async function getSessionStatus() {
  try {
    const response = await fetch('/session/status', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (!response.ok) {
      throw new NetworkError(`Session status failed: ${response.status}`, response.status);
    }
    
    const status = await response.json();
    logger.debug('Session status retrieved:', status);
    return status;
  } catch (error) {
    logger.error('Failed to get session status:', error);
    throw error;
  }
}

/**
 * Get current username from server
 */
export async function getCurrentUsername() {
  try {
    const response = await fetch('/onboarding/current-user', {
      method: 'GET',
      credentials: 'include'
    });
    
    if (response.ok) {
      const userData = await response.json();
      logger.debug('Current username retrieved:', userData.username);
      return userData;
    } else {
      logger.debug('No username found (status:', response.status, ')');
      return null;
    }
  } catch (error) {
    logger.debug('Failed to get current username:', error.message);
    return null;
  }
}

/**
 * Comprehensive session restoration with detailed state information
 */
export async function restoreSession() {
  try {
    logger.info('Starting comprehensive session restoration');
    
    // Step 1: Get server session status
    const sessionStatus = await getSessionStatus();
    
    if (!sessionStatus || !sessionStatus.valid) {
      logger.info('No valid session found');
      return createSessionState();
    }
    
    logger.info('Valid session found, restoring state');
    
    // Step 2: Restore session tokens from IndexedDB
    await restoreSessionTokens();
    
    // Step 3: Check local keys and server status
    const { localBIK, localBikJkt } = await SessionRestore.checkLocalBIK();
    const { localDPoP } = await SessionRestore.checkLocalDPoP();
    
    // Step 5: Check server BIK status
    const serverBIK = sessionStatus.bik_registered;
    const serverDPoP = sessionStatus.dpop_bound;
    
    // Step 4: Test DPoP binding functionality
    const { dpopWorking } = await SessionRestore.testDPoPBinding();
    
    // Step 5: Check BIK match (if both exist)
    let bikMatch = false;
    if (serverBIK && localBIK && localBikJkt) {
      // We have both server BIK and local BIK with JKT
      // For now, assume match if we have a stored JKT
      // In a real implementation, we'd compare with server's JKT
      bikMatch = true;
      logger.info('BIK exists on both server and client with stored JKT');
    } else if (serverBIK && localBIK && !localBikJkt) {
      // We have both but no JKT stored - this is a mismatch
      bikMatch = false;
      logger.warn('BIK exists locally but no JKT stored - mismatch');
    } else {
      // Not both present or no JKT
      bikMatch = false;
    }
    
    const dpopMatch = localDPoP && serverDPoP && dpopWorking;
    
    // Step 6: Store signal data for restored BIK if available
    if (bikMatch && serverBIK) {
      await SessionRestore.storeSignalDataForRestoredBIK();
    }
    
    // Step 7: Get current username
    const { hasUsername, username } = await SessionRestore.getCurrentUsername();
    
    // Step 7: Check for mismatches and handle them
    const mismatchResult = await SessionRestore.checkAndHandleMismatches(localBIK, localDPoP, serverBIK, serverDPoP);
    if (mismatchResult) {
      return mismatchResult;
    }

    const result = createSessionState({
      hasSession: true,
      hasBIK: serverBIK,
      hasDPoP: dpopWorking,
      hasUsername,
      username,
      bik_jkt: sessionStatus.bik_jkt, // Include BIK JKT for signal matching
      sessionStatus,
      details: {
        serverSession: true,
        localBIK,
        localDPoP,
        serverBIK,
        serverDPoP,
        bikMatch,
        dpopMatch,
        dpopWorking,
        sessionType: SESSION_TYPES.RESTORED,
        bikType: localBIK && serverBIK ? (bikMatch ? KEY_TYPES.RESTORED : KEY_TYPES.MISMATCH) : (localBIK ? KEY_TYPES.LOCAL_ONLY : KEY_TYPES.SERVER_ONLY),
        dpopType: localDPoP && serverDPoP ? (dpopWorking ? KEY_TYPES.RESTORED : KEY_TYPES.MISMATCH) : (localDPoP ? KEY_TYPES.LOCAL_ONLY : KEY_TYPES.SERVER_ONLY)
      }
    });
    
    logger.info('Session restoration completed:', result);
    return result;
    
  } catch (error) {
    logger.error('Session restoration failed:', error);
    throw error;
  }
}

/**
 * Initialize a fresh session (when no existing session)
 */
export async function initializeFreshSession() {
  try {
    logger.info('Initializing fresh session');
    
    // Step 1: Initialize session
    await sessionInit();
    
    // Step 2: Register BIK
    await bikRegisterStep();
    
    // Step 3: Bind DPoP
    await dpopBindStep();
    
    logger.info('Fresh session initialization completed');
    
    return createSessionState({
      hasSession: true,
      hasBIK: true,
      hasDPoP: true,
      hasUsername: false,
      username: null,
      sessionStatus: { valid: true, bik_registered: true, dpop_bound: true },
      details: {
        serverSession: true,
        localBIK: true,
        localDPoP: true,
        serverBIK: true,
        serverDPoP: true,
        bikMatch: true,
        dpopMatch: true,
        dpopWorking: true,
        sessionType: SESSION_TYPES.NEW,
        bikType: KEY_TYPES.NEW,
        dpopType: KEY_TYPES.NEW
      }
    });
    
  } catch (error) {
    logger.error('Fresh session initialization failed:', error);
    throw error;
  }
}

/**
 * Complete session setup (restore existing or initialize fresh)
 */
export async function setupSession() {
  try {
    logger.info('Setting up session');
    
    // Try to restore existing session first
    const restoredSession = await restoreSession();
    
    if (restoredSession.hasSession && restoredSession.hasDPoP) {
      // We have a working session
      logger.info('Using restored session');
      return restoredSession;
    } else {
      // No session or DPoP not working, initialize fresh
      logger.info('Initializing fresh session');
      return await initializeFreshSession();
    }
    
  } catch (error) {
    logger.error('Session setup failed:', error);
    throw error;
  }
}

/**
 * Clear server session (preserves user data)
 */
export async function clearServerSession() {
  try {
    logger.info('Clearing server session');
    const response = await fetch('/session/clear', {
      method: 'POST',
      credentials: 'include'
    });
    
    if (response.ok) {
      logger.info('Server session cleared successfully');
      return true;
    } else {
      logger.warn('Server session clear failed with status:', response.status);
      return false;
    }
  } catch (error) {
    logger.error('Failed to clear server session:', error);
    return false;
  }
}

/**
 * Complete session reset (client + server)
 */
export async function resetSession() {
  try {
    logger.info('Performing complete session reset');
    
    // Clear client state
    await clientFlush();
    
    // Clear server state
    await clearServerSession();
    
    logger.info('Complete session reset completed');
    return true;
  } catch (error) {
    logger.error('Session reset failed:', error);
    throw error;
  }
}


/**
 * Resume session with fresh binding token
 */
export async function resumeSession() {
  try {
    // First restore CSRF token and reg_nonce from IndexedDB
    await restoreSessionTokens();
    
    // Verify we have the necessary tokens
    const csrf = await get(CONFIG.STORAGE.KEYS.CSRF);
    const bind = await get(CONFIG.STORAGE.KEYS.BIND);
    
    if (!csrf?.value) {
      throw new AuthenticationError('CSRF token not found in storage');
    }
    
    if (!bind?.value) {
      throw new AuthenticationError('Binding token not found in storage');
    }
    
    // Now call the server-side resume process to get fresh DPoP nonce
    const resumeSuccess = await resumeViaPage();
    if (!resumeSuccess) {
      throw new AuthenticationError('Server-side session resume failed');
    }
    
    logger.info('Session restoration completed successfully');
    return true;
  } catch (error) {
    logger.error('Session restoration failed:', error);
    throw error;
  }
}

/**
 * Perform a full session resume when binding token is expired
 */
export async function performFullResume() {
  try {
    // Call the resume endpoints directly to get a fresh binding token
    const r1 = await fetch('/session/resume-init', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    
    if (!r1.ok) {
      throw new NetworkError(`Resume init failed: ${r1.status}`, r1.status);
    }
    
    const { resume_nonce } = await r1.json();
    
    // Get the BIK from storage
    const bik = await getBIK();
    if (!bik) {
      throw new AuthenticationError('BIK not found in storage');
    }
    
    // Create the resume JWS manually
    const jws = await createResumeJws(resume_nonce, bik);
    
    // Confirm the resume
    const r2 = await fetch('/session/resume-confirm', {
      method: 'POST',
      credentials: 'include',
      headers: { 'Content-Type': 'application/jose+json' },
      body: jws
    });
    
    if (!r2.ok) {
      throw new NetworkError(`Resume confirm failed: ${r2.status}`, r2.status);
    }
    
    const { bind } = await r2.json();
    
    // Store the binding token
    await set(CONFIG.STORAGE.KEYS.BIND, bind);
    
    logger.info('Full session resume completed successfully');
    return true;
  } catch (error) {
    logger.error('Full session resume failed:', error);
    throw error;
  }
}

/**
 * Create a resume JWS manually
 */
export async function createResumeJws(resume_nonce, bik) {
  try {
    // Import the necessary crypto functions from the jose-lite module
    const { jose } = await import('../vendor/jose-lite.js');
    
    // Create the JWS payload
    const payload = {
      resume_nonce,
      iat: Math.floor(Date.now() / 1000)
    };
    
    // Create the JWS header
    const header = {
      alg: 'ES256',
      typ: 'bik-resume+jws',
      jwk: bik.publicJwk
    };
    
    // Sign the JWS
    const jws = await jose.sign(header, payload, bik.privateKey);
    
    logger.debug('Created resume JWS:', { length: jws.length });
    return jws;
  } catch (error) {
    logger.error('Failed to create resume JWS:', error);
    throw error;
  }
}

