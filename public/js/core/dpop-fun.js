// DPop-Fun core: keys, bind, DPoP proof, signed fetch, client flush

import { jwkThumbprint, generateES256KeyPair, createJwsWithDefaults, b64u } from '../utils/jose-lite.js';
import { idbPut, idbGet, idbWipe, idbDelete, STORES } from '../utils/idb.js';
import { logger } from '../utils/logging.js';
import { CONFIG } from '../utils/config.js';
import { FingerprintService } from '../services/FingerprintService.js';


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
  bik_jws: null,
  dpop: null,
  dpop_nonce: null,         
  auth_method: null,
  auth_status: null,
  auth_username: null,
  signal_data: null,
  geolocation: null,
  client_ip: null,
  csrf: null,
  state: SessionState.pending_dpop_bind,
  dpop_bind: null,
  dpop_bind_expires_at: null,
  last_username: null,
  created_at: null,
  updated_at: null,
  session_flag: null,
  session_flag_comment: null,
  state: null
}


//Main entry point for session setup
export async function setupSession(retryAttempted = false) {
  let newSession = false;
  try {
    logger.info('Setting up session', retryAttempted ? '(retry)' : '');

    logger.info('STEP 1. Check for device ID');
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

    logger.info('STEP 2. Check for BIK key');
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

    logger.info('STEP 3. Check for DPoP key');
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

    logger.info('STEP 4. Check for CSRF token');
    const csrfRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.CSRF);
    const csrf = csrfRecord?.value || null;
    if (csrf) {
      DPOP_SESSION.csrf = csrf;
      logger.info('CSRF token found: ', csrf);
    } else {
      logger.warn('CSRF token not found, retrying...');
    }

    logger.info('STEP 5. Check for DPoP nonce');
    const dpopNonceRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_NONCE);
    const dpopNonce = dpopNonceRecord?.value || null;
    if (dpopNonce) {
      DPOP_SESSION.dpop_nonce = dpopNonce;
      logger.info('DPoP nonce found: ', dpopNonce);
    }

    logger.info('STEP 6. Check for DPoP bind');
    const dpopBindRecord = await idbGet(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_BIND);
    const dpopBind = dpopBindRecord?.value || null;
    if (dpopBind) {
      DPOP_SESSION.dpop_bind = dpopBind;
      logger.info('DPoP bind found: ', dpopBind);
    }

    logger.info('STEP 6. Collect signal data');
    DPOP_SESSION.signal_data = await FingerprintService.collectFingerprint(); // Auto-detect device type
    logger.info('Signal data collected: ', DPOP_SESSION.signal_data);
    logger.info('Detected device type: ', DPOP_SESSION.signal_data.deviceType);


    logger.info('STEP 7. Create new server session');
    
    const bikJws = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.BIK_REG,
      payload: { 
        device_id: DPOP_SESSION.device_id,
      },
      privateKey: DPOP_SESSION.bik.privateKey,
      publicJwk: DPOP_SESSION.bik.publicJwk
    });

    DPOP_SESSION.bik_jws = bikJws;

    const dpopJws = await createDPoPProof("POST", window.location.origin + "/session/init");

    const body = JSON.stringify({
      payload: {
        device_id: DPOP_SESSION.device_id,
        signal_data: DPOP_SESSION.signal_data
      }
    });
    logger.info('Creating session init request with headers:', {
      'Content-Type': 'application/json', 
      'DPoP': dpopJws, 
      'BIK': bikJws,
      'Dpop-Bind': DPOP_SESSION.dpop_bind,
      'Dpop-Nonce': DPOP_SESSION.dpop_nonce,
      'X-CSRF-Token': DPOP_SESSION.csrf
    });
    const r = await fetch(CONFIG.ENDPOINTS.SESSION_INIT, {
      method: 'POST', 
      headers: { 
        'Content-Type': 'application/json', 
        'DPoP': dpopJws, 
        'BIK': bikJws,
        'Dpop-Bind': DPOP_SESSION.dpop_bind,
        'Dpop-Nonce': DPOP_SESSION.dpop_nonce,
        'X-CSRF-Token': DPOP_SESSION.csrf
      },
      credentials: 'include', 
      body: body
    });
    
    // Parse the JSON response
    const responseData = await r.json();
    
    // Get headers
    DPOP_SESSION.csrf = r.headers.get('X-Csrf-Token'); 
    DPOP_SESSION.dpop_nonce = r.headers.get('Dpop-Nonce');
    DPOP_SESSION.dpop_bind = r.headers.get('Dpop-Bind');
    
    // Get data from response body
    DPOP_SESSION.dpop_bind_expires_at = responseData.dpop_bind_expires_at;
    DPOP_SESSION.session_flag = responseData.session_flag;
    DPOP_SESSION.session_flag_comment = responseData.session_flag_comment;
    DPOP_SESSION.session_state = responseData.state;
    DPOP_SESSION.auth_method = responseData.auth_method;
    DPOP_SESSION.auth_status = responseData.auth_status;
    DPOP_SESSION.auth_username = responseData.auth_username;
    DPOP_SESSION.user_id = responseData.user_id;
    DPOP_SESSION.expires_at = responseData.expires_at;
    DPOP_SESSION.created_at = responseData.created_at;
    DPOP_SESSION.updated_at = responseData.updated_at;
    DPOP_SESSION.geolocation = responseData.geolocation;
    DPOP_SESSION.client_ip = responseData.client_ip;
    DPOP_SESSION.active_user_sessions = responseData.active_user_sessions;


    logger.info(`${CONFIG.ENDPOINTS.SESSION_INIT}: response:`, DPOP_SESSION);
    
    if (!r.ok) {
      logger.error(`${CONFIG.ENDPOINTS.SESSION_INIT} failed:`, r.status, responseData);
      
      // If session init failed due to invalid nonce/csrf, clear stale data and retry once
      if ((r.status === 400 || r.status === 401) && !retryAttempted) {
        logger.info('Session init failed with auth error, clearing stale session data and retrying...');
        await idbDelete(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_BIND);
        await idbDelete(STORES.SESSION, CONFIG.STORAGE.SESSION.CSRF);
        await idbDelete(STORES.SESSION, CONFIG.STORAGE.SESSION.DPOP_NONCE);
        
        // Retry the session init
        return await setupSession(true);
      }
      
      throw new Error(`Session init failed: ${r.status} - ${responseData.detail || 'Unknown error'}`);
    }
    
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.CSRF, value: DPOP_SESSION.csrf });
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_NONCE, value: DPOP_SESSION.dpop_nonce });
    await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_BIND, value: DPOP_SESSION.dpop_bind });

    return DPOP_SESSION;
  } catch (error) {
    logger.error('Session setup failed:', error);
    throw error;
  }
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
    
    logger.info('BIK key created: ', keyData);
    return true;
  } catch (error) {
    logger.error('Failed to create BIK:', error);
    return false;
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
    
    logger.info('DPoP key created: ', keyData);
    return true;
  } catch (error) {
    logger.error('Failed to create DPoP:', error);
    return false;
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

export async function createDPoPProof(method, url) {
  try {
    if (!DPOP_SESSION.dpop || !DPOP_SESSION.dpop.privateKey) {
      throw new Error('DPoP key not available. Call createDPoP() first.');
    }

    const payload = {
      htm: method.toUpperCase(),
      htu: url,
      iat: Math.floor(Date.now() / 1000),
      jti: crypto.randomUUID(),
      nonce: DPOP_SESSION.dpop_nonce,
      device_id: DPOP_SESSION.device_id
    };


    const dpopProof = await createJwsWithDefaults({
      typ: CONFIG.CRYPTO.JWT_TYPES.DPOP_PROOF,
      payload,
      privateKey: DPOP_SESSION.dpop.privateKey,
      publicJwk: DPOP_SESSION.dpop.publicJwk
    });

    logger.info('DPoP proof created for:', { method, url });
    return dpopProof;
  } catch (error) {
    logger.error('Failed to create DPoP proof:', error);
    throw error;
  }
}


export async function dpopFetch(method, url, options = {}, retryCount = 0) {
  const MAX_RETRIES = 1; // Only retry once for nonce errors
  
  try {
    if (!DPOP_SESSION.dpop) {
      throw new Error('DPoP key not available. Call setupSession() first.');
    }

    // Convert relative URL to absolute URL for DPoP proof
    const fullUrl = url.startsWith('http') ? url : `${window.location.origin}${url}`;

    // Create DPoP proof with full URL
    const dpopProof = await createDPoPProof(method, fullUrl);

    // Prepare headers
    const headers = {
      'Content-Type': 'application/json',
      'BIK': DPOP_SESSION.bik_jws,
      'DPoP': dpopProof,
      'Dpop-Nonce': DPOP_SESSION.dpop_nonce,
      'X-CSRF-Token': DPOP_SESSION.csrf,
      ...options.headers
    };

    // Make the request (can use relative or absolute URL)
    const response = await fetch(url, {
      method,
      headers,
      credentials: 'include',
      ...options
    });

    // Update nonce from response headers for next request
    const newNonce = response.headers.get('Dpop-Nonce');
    if (newNonce) {
      DPOP_SESSION.dpop_nonce = newNonce;
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_NONCE, value: newNonce });
      logger.info('Updated DPoP nonce from response:', newNonce);
    }

    // Update other session headers if present
    const newCsrf = response.headers.get('X-Csrf-Token');
    if (newCsrf) {
      DPOP_SESSION.csrf = newCsrf;
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.CSRF, value: newCsrf });
    }

    const newBind = response.headers.get('Dpop-Bind');
    if (newBind) {
      DPOP_SESSION.dpop_bind = newBind;
      await idbPut(STORES.SESSION, { id: CONFIG.STORAGE.SESSION.DPOP_BIND, value: newBind });
    }

    // Check for nonce error and retry if we have a new nonce
    if (!response.ok && response.status === 400 && newNonce && retryCount < MAX_RETRIES) {
      try {
        // Clone the response so we can read it without consuming the original
        const responseClone = response.clone();
        const errorData = await responseClone.json();
        if (errorData.detail && errorData.detail.toLowerCase().includes('nonce')) {
          logger.warn('Nonce error detected, retrying with new nonce:', newNonce);
          // Retry the request with the new nonce
          return await dpopFetch(method, url, options, retryCount + 1);
        }
      } catch (jsonError) {
        // If we can't parse the error response, don't retry
        logger.warn('Failed to parse error response, not retrying:', jsonError);
      }
    }

    logger.info('Authenticated request made:', { method, url, status: response.status });
    return response;
  } catch (error) {
    logger.error('Authenticated request failed:', error);
    throw error;
  }
}










