// DPop-Fun core: keys, bind, DPoP proof, signed fetch, client flush

import { b64uJSON, sigToJoseEcdsa, createJwsES256, jwkThumbprint } from '../utils/jose-lite.js';
import { idbPut, idbGet, idbWipe, STORES } from '../utils/idb.js';
import { logger } from '../utils/logging.js';
import { AuthenticationError, NetworkError, StorageError, CryptoError } from '../utils/errors.js';
import { CONFIG } from '../utils/config.js';
import { validateUrl, validateMethod, validateKeyPair, validateNonce } from '../utils/validation.js';
import { FingerprintService } from '../services/FingerprintService.js';

export { createJwsES256, idbWipe, jwkThumbprint };

//enum for session states
const SessionState = {
  PENDING_DPOP_BIND: "pending_dpop_bind",
  BOUND_BIK: "bound_bik", 
  BOUND_DPOP: "bound_dpop",
  AUTHENTICATED: "authenticated",
  USER_TERMINATED: "user_terminated",
  SYSTEM_TERMINATED: "system_terminated",
  EXPIRED: "expired"
}

let CSRF = null;
let REG_NONCE = null;

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

let DPOP_SESSION = {
  device_id: null,
  bik: null, 
  dpop: null,
  dpop_nonce: null,         
  auth_method: null,
  auth_status: null,
  auth_username: null,
  signal_data: null,
  csrf: null,
  state: SessionState.pending_dpop_bind,
  server_bind: null,
  server_bind_expires_at: null,
  lastusername: null,
  created_at: null,
  updated_at: null
}


//Main entry point for session setup
export async function setupSession() {
  let newSession = false;
  try {
    logger.info('Setting up session');

    logger.debug('STEP 1. Check for device ID');
    const deviceIdRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DEVICE_ID);
    const deviceId = deviceIdRecord?.value || null;
    if (deviceId) {
      DPOP_SESSION.device_id = deviceId;
      logger.info('Device ID found: ', deviceId);
    } else {
      newSession = true;
      DPOP_SESSION.device_id = crypto.randomUUID();
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DEVICE_ID, value: DPOP_SESSION.device_id });
      logger.info('Device ID not found, created new one: ', DPOP_SESSION.device_id);
    }

    logger.debug('STEP 2. Check for BIK key');
    const {localBIK, localBikJkt} = await checkLocalBIK();
    if (localBIK && localBikJkt && !newSession) {
      DPOP_SESSION.bik = localBIK;
      DPOP_SESSION.bik_jkt = localBikJkt;
      logger.info('Local BIK found: ', localBIK);
    } else {
      if (!await createBIK()) {
        logger.error('Failed to create session');
        return;
      }
    }

    logger.debug('STEP 3. Check for DPoP key');
    const {localDPoP, localDpopJkt} = await checkLocalDPoP();
    if (localDPoP && localDpopJkt && !newSession) {
      DPOP_SESSION.dpop = localDPoP;
      DPOP_SESSION.dpop_jkt = localDpopJkt;
      logger.info('Local DPoP found: ', localDPoP);
    } else {
      if (!await createDPoP()) {
        logger.error('Failed to create session');
        return;
      }
    }

    logger.debug('STEP 4. Collect signal data');
    DPOP_SESSION.signal_data = await FingerprintService.collectFingerprint('desktop');
    logger.info('Signal data collected: ', DPOP_SESSION.signal_data);


    logger.debug('STEP 5. Create new server session');
    if (!newSession) {
      // Get dpop_nonce for BIK registration
      const dpopNonceRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_NONCE);
      const dpopNonce = dpopNonceRecord?.value || null;
      
      const bikJws = await createJwsWithDefaults({
        typ: CONFIG.CRYPTO.JWT_TYPES.BIK_REG,
        payload: { 
          device_id: DPOP_SESSION.device_id,
        },
        privateKey: DPOP_SESSION.bik.privateKey,
        publicJwk: DPOP_SESSION.bik.publicJwk
      });

      const dpopJws = await createJwsWithDefaults({
        typ: CONFIG.CRYPTO.JWT_TYPES.DPOP_BIND,
        payload: { 
          htm: "POST",
          htu: window.location.origin + "/session/init",
          iat: Math.floor(Date.now() / 1000),
          jti: crypto.randomUUID(),
          nonce: DPOP_SESSION.dpop_nonce
        },
        privateKey: DPOP_SESSION.dpop.privateKey,
        publicJwk: DPOP_SESSION.dpop.publicJwk
      });

      const body = JSON.stringify({
        payload: {
          device_id: DPOP_SESSION.device_id,
          bik_jws: bikJws,
          dpop_jws: dpopJws,
          signal_data: DPOP_SESSION.signal_data
        }
      });
      logger.info('Creating session init request with payload:', body);
      const r = await fetch(CONFIG.ENDPOINTS.SESSION_INIT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'DPoP': dpopJws, 'BIK': bikJws },
        credentials: 'include',
        body: body
      });
      logger.info(`${CONFIG.ENDPOINTS.SESSION_INIT}: Fetch request completed, status:`, r.status);
      
      if (!r.ok) {
        logger.error(`${CONFIG.ENDPOINTS.SESSION_INIT} failed:`, r.status);
      }
      
      const j = await r.json();
      logger.info(`${CONFIG.ENDPOINTS.SESSION_INIT}: response:`, j);
      CSRF = j.csrf; 
      REG_NONCE = j.reg_nonce;
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.CSRF, value: j.csrf });
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.SESSION_NONCE, value: j.reg_nonce });




      await bikRegisterStep();
      //await dpopBindStep();
  
    }
//create new server session


    logger.info('DPOP_SESSION:', DPOP_SESSION);
    
    logger.info('Getting session status');
    const sessionStatus = await getSessionStatus();
    logger.info('Session status:', sessionStatus);
    if (sessionStatus && sessionStatus.valid) {
      logger.info('Using restored session');
      return sessionStatus;
    }


    logger.info('No valid session found, initializing fresh session');
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
    const { localBIK, localBikJkt } = await checkLocalBIK();
    const { localDPoP } = await checkLocalDPoP();
    
    // Step 5: Check server BIK status
    const serverBIK = sessionStatus.bik_registered;
    const serverDPoP = sessionStatus.dpop_bound;
    
    // Step 4: Test DPoP binding functionality
    const { dpopWorking } = await testDPoPBinding();
    
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
      await storeSignalDataForRestoredBIK();
    }
    
    // Step 7: Get current username
    const { hasUsername, username } = await getCurrentUsername();
    
    // Step 7: Check for mismatches and handle them
    const mismatchResult = await checkAndHandleMismatches(localBIK, localDPoP, serverBIK, serverDPoP);
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


async function checkLocalBIK() {
  try {
    const bikRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIK);
    const bikData = bikRecord?.value || null;
    return {
      localBIK: bikData,
      localBikJkt: bikData?.bik_jkt || null
    };
  } catch (error) {
    logger.error('Error checking local BIK:', error);
    return { localBIK: null, localBikJkt: null };
  }
}
  
async function checkLocalDPoP() {
  try {
    const dpopRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP);
    const dpopData = dpopRecord?.value || null;
    const result = {
      localDPoP: dpopData,
      localDpopJkt: dpopData?.dpop_jkt || null
    };
    logger.info('Local DPoP detection result:', result);
    return result;
  } catch (error) {
    logger.error('Error checking local DPoP:', error);
    return { localDPoP: null, localDpopJkt: null };
  }
}
  
  async function testDPoPBinding() {
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
  }
  
  /**
   * Check for client/server mismatches and handle them
   */
  async function checkAndHandleMismatches(localBIK, localDPoP, serverBIK, serverDPoP) {
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
  }

  /**
   * Store signal data for restored BIK to build historical baseline
   */
  async function storeSignalDataForRestoredBIK() {
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


// Simplified: Use direct idbGet/idbPut with single session store

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

async function createBIK() {
  try {
    const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
    const bikJkt = await jwkThumbprint(publicJwk);
    const keyData = { 
      bik_jkt: bikJkt,
      privateKey, 
      publicKey, 
      publicJwk, 
      createdAt: Date.now() 
    };
    
    // Store in session object
    DPOP_SESSION.bik = keyData;
    DPOP_SESSION.bik_jkt = bikJkt;
    
    // Store in IndexedDB (single record with JKT included)
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.BIK, value: keyData });
    
    logger.debug('BIK key created: ', keyData);
    return true;
  } catch (error) {
    logger.error('Failed to create BIK:', error);
    return false;
  }
}

async function createDPoP() {
  try {
    const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
    const dpopJkt = await jwkThumbprint(publicJwk);
    const keyData = { 
      dpop_jkt: dpopJkt,
      privateKey, 
      publicKey, 
      publicJwk, 
      createdAt: Date.now() 
    };
    
    // Store in session object
    DPOP_SESSION.dpop = keyData;
    DPOP_SESSION.dpop_jkt = dpopJkt;
    
    // Store in IndexedDB (single record with JKT included)
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP, value: keyData });
    
    logger.debug('DPoP key created: ', keyData);
    return true;
  } catch (error) {
    logger.error('Failed to create DPoP:', error);
    return false;
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
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.BIK_JKT, value: j.bik_jkt });
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
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.BIND, value: j.bind });
    const serverNonce = r.headers.get('DPoP-Nonce'); 
    if (serverNonce) await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_NONCE, value: serverNonce });

    logger.info('dpop/bind ok', j, 'nonce=', serverNonce || null);
    return { ...j, dpopKeyId: CONFIG.STORAGE.SESSION.DPOP, nonce: serverNonce || null };
  } catch (error) {
    logger.error('DPoP binding failed:', error);
    if (error.name === 'AuthenticationError' || error.name === 'NetworkError') throw error;
    throw new AuthenticationError('DPoP binding failed', { originalError: error.message });
  }
}

async function ensureBinding() {
  let bind = (await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIND))?.value;
  if (!bind) {
    const ok = await resumeViaPage();
    if (!ok) throw new AuthenticationError('no binding token (resume failed)');
    bind = (await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIND))?.value;
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
        bind = (await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIND))?.value;
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
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_NONCE, value: n });
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
        await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.BIND, value: null });
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
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.BIND, value: j.bind });
    const n = r2.headers.get('DPoP-Nonce'); 
    if (n) {
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_NONCE, value: n });
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
  return await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_NONCE);
}

export async function getBindToken() {
  return await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIND);
}

export async function getBIK() {
  try {
    return await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.BIK);
  } catch {
    return null;
  }
}

/**
 * Restore CSRF token and reg_nonce from IndexedDB
 */
export async function restoreSessionTokens() {
  try {
    const csrf = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.CSRF);
    const regNonce = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.SESSION_NONCE);
    
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

function getCurrentOrigin() {
  return globalThis.location?.origin || globalThis.self?.location?.origin || 'http://localhost';
}



