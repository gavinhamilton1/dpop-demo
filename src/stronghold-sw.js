// src/stronghold-sw.js v2
// Stronghold service worker: signs /api/* with DPoP + DPoP-Bind, handles nonce retry, and session resume.

import { idbGet, idbPut, STORES } from '/src/idb.js';
import { b64uJSON, sigToJoseEcdsa, createJwsES256 } from '/src/jose-lite.js';
import { createDpopProof, canonicalUrl } from '/src/dpop.js';
import { swLogger } from '/src/utils/logging.js';
import { AuthenticationError, NetworkError, StorageError } from '/src/utils/errors.js';
import { CONFIG } from '/src/utils/config.js';

// -------- base/origin helpers (make relative URLs absolute for Node/Undici) ----------
function getOrigin() {
  try {
    // In real SW, self.location exists. In tests, we may only have href or nothing.
    if (self.location?.origin) return self.location.origin;
    if (self.location?.href)   return new URL(self.location.href).origin;
  } catch {}
  // Jest/Node fallback
  return 'http://localhost';
}

function abs(url) {
  try { return new URL(url, getOrigin()).toString(); }
  catch { return url; }
}

// ---- IDB helpers -----------------------------------------------------------
async function getBind() {
  try {
    return (await idbGet(STORES.META, CONFIG.STORAGE.KEYS.BIND))?.value || null;
  } catch (error) {
    swLogger.error('Failed to get bind from storage:', error);
    return null;
  }
}

async function setBind(v) {
  try {
    return await idbPut(STORES.META, { id: CONFIG.STORAGE.KEYS.BIND, value: v });
  } catch (error) {
    swLogger.error('Failed to set bind in storage:', error);
    throw new StorageError('Failed to set bind', { originalError: error.message });
  }
}

async function getNonce() {
  try {
    return (await idbGet(STORES.META, CONFIG.STORAGE.KEYS.DPOP_NONCE))?.value || null;
  } catch (error) {
    swLogger.error('Failed to get nonce from storage:', error);
    return null;
  }
}

async function setNonce(v) {
  try {
    return await idbPut(STORES.META, { id: CONFIG.STORAGE.KEYS.DPOP_NONCE, value: v });
  } catch (error) {
    swLogger.error('Failed to set nonce in storage:', error);
    throw new StorageError('Failed to set nonce', { originalError: error.message });
  }
}

async function ensureDPoP() {
  try {
    const rec = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.DPOP_CURRENT);
    if (!rec?.privateKey || !rec?.publicJwk) {
      throw new AuthenticationError('DPoP key not found in IDB');
    }
    return { privateKey: rec.privateKey, publicJwk: rec.publicJwk };
  } catch (error) {
    swLogger.error('Failed to ensure DPoP key:', error);
    throw new AuthenticationError('Failed to ensure DPoP key', { originalError: error.message });
  }
}

async function ensureBIK() {
  try {
    const rec = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.BIK_CURRENT);
    if (!rec?.privateKey || !rec?.publicJwk) {
      throw new AuthenticationError('BIK key not found in IDB');
    }
    return { privateKey: rec.privateKey, publicJwk: rec.publicJwk };
  } catch (error) {
    swLogger.error('Failed to ensure BIK key:', error);
    throw new AuthenticationError('Failed to ensure BIK key', { originalError: error.message });
  }
}

function shouldSign(url) {
  try { 
    return new URL(url).pathname.startsWith('/api/'); 
  } catch { 
    return false; 
  }
}

// ---- resume (bind rehydration) ---------------------------------------------
async function resumeIfNeeded() {
  try {
    const existing = await getBind();
    if (existing) return existing;
    
    swLogger.debug('No existing bind found, attempting resume');
    
    // 1) ask server for resume_nonce
    const initReq = new Request(abs(CONFIG.ENDPOINTS.SESSION_RESUME_INIT), { method: 'POST' });
    const r1 = await fetch(initReq);
    if (!r1.ok) {
      swLogger.warn('Session resume init failed:', r1.status);
      return null;
    }
    const { resume_nonce } = await r1.json();

    // 2) sign JWS with BIK
    const bik = await ensureBIK();
    const jws = await createJwsES256({
      protectedHeader: { alg: CONFIG.CRYPTO.ALGORITHM, typ: CONFIG.CRYPTO.JWT_TYPES.BIK_RESUME, jwk: bik.publicJwk },
      payload: { resume_nonce, iat: Math.floor(Date.now()/1000) },
      privateKey: bik.privateKey
    });

    // 3) confirm
    const confReq = new Request(abs(CONFIG.ENDPOINTS.SESSION_RESUME_CONFIRM), {
      method: 'POST',
      body: jws
    });
    const r2 = await fetch(confReq);
    if (!r2.ok) {
      swLogger.warn('Session resume confirm failed:', r2.status);
      return null;
    }
    const j = await r2.json();

    await setBind(j.bind);
    const n = r2.headers.get('DPoP-Nonce');
    if (n) await setNonce(n);

    swLogger.debug('Session resume completed successfully');
    return j.bind;
  } catch (e) {
    swLogger.error('Session resume failed:', e.message);
    return null;
  }
}

// ---- signed fetch core ------------------------------------------------------
async function signedFetchFromEvent(req) {
  try {
    let bind = await getBind();
    if (!bind) bind = await resumeIfNeeded();
    if (!bind) {
      // No bind: forward as-is (likely 428 from server)
      swLogger.debug('No bind available, forwarding request as-is');
      return fetch(req);
    }

    const dpop = await ensureDPoP();
    const url = canonicalUrl(req.url);
    const method = req.method.toUpperCase();

    swLogger.debug('Signing request:', { url, method });

    // Buffer original body exactly once, then build fresh Requests
    const needsBody = !(method === 'GET' || method === 'HEAD');
    const bodyBuf = needsBody ? await req.clone().arrayBuffer() : undefined;

    const headers = new Headers(req.headers);
    const n0 = await getNonce();
    headers.set('DPoP', await createDpopProof({
      url, method, nonce: n0, privateKey: dpop.privateKey, publicJwk: dpop.publicJwk
    }));
    headers.set('DPoP-Bind', bind);

    let signedReq = new Request(req.url, { method, headers, body: bodyBuf });
    let res = await fetch(signedReq);

    // Nonce challenge retry
    if ((res.status === CONFIG.HTTP.STATUS_CODES.UNAUTHORIZED || res.status === CONFIG.HTTP.STATUS_CODES.PRECONDITION_REQUIRED) && res.headers.has('DPoP-Nonce')) {
      swLogger.debug('Handling nonce challenge');
      const n = res.headers.get('DPoP-Nonce');
      await setNonce(n);
      headers.set('DPoP', await createDpopProof({
        url, method, nonce: n, privateKey: dpop.privateKey, publicJwk: dpop.publicJwk
      }));
      const retryReq = new Request(req.url, { method, headers, body: bodyBuf });
      res = await fetch(retryReq);
    }

    const n2 = res.headers.get('DPoP-Nonce');
    if (n2) await setNonce(n2);
    
    swLogger.debug('Signed fetch completed successfully');
    return res;
  } catch (error) {
    swLogger.error('Signed fetch failed:', error);
    return new Response(JSON.stringify({ 
      ok: false, 
      error: error.message,
      code: error.code || 'UNKNOWN_ERROR'
    }), {
      status: CONFIG.HTTP.STATUS_CODES.INTERNAL_SERVER_ERROR, 
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

// ---- SW lifecycle & wiring --------------------------------------------------
self.__listeners = self.__listeners || { install: [], activate: [], fetch: [], message: [] };

self.addEventListener('install', (e) => {
  swLogger.debug('Service worker installing');
  e.waitUntil(self.skipWaiting());
});
self.__listeners.install?.push?.(() => {});

self.addEventListener('activate', (e) => {
  swLogger.debug('Service worker activating');
  e.waitUntil(self.clients.claim());
});
self.__listeners.activate?.push?.(() => {});

self.addEventListener('message', async (ev) => {
  try {
    const msg = ev.data || {};
    if (msg.type === 'stronghold/bind') {
      swLogger.debug('Received bind update from page');
      if (msg.bind) await setBind(msg.bind);
      if (msg.nonce) await setNonce(msg.nonce);
    }
    if (msg.type === 'stronghold/flush-client') {
      swLogger.debug('Received flush client message');
      try {
        await new Promise((resolve, reject) => {
          const req = indexedDB.deleteDatabase(CONFIG.STORAGE.DB_NAME);
          req.onsuccess = () => resolve();
          req.onerror = () => reject(req.error);
          req.onblocked = () => reject(new Error('IDB deletion blocked'));
        });
        swLogger.debug('Client flush completed successfully');
      } catch (e) {
        swLogger.error('Client flush error:', e?.message || e);
      }
    }
  } catch (error) {
    swLogger.error('Error handling service worker message:', error);
  }
});
self.__listeners.message?.push?.(() => {});

self.addEventListener('fetch', (event) => {
  const url = new URL(event.request.url);
  const req = event.request;
  
  const isSSE = event.request.headers.get('Accept') === 'text/event-stream'
    || url.pathname.startsWith('/link/events/');
  if (isSSE) {
    swLogger.debug('Skipping SSE request');
    return;
  }

  if (!shouldSign(req.url)) {
    swLogger.debug('Request does not require signing:', req.url);
    return;
  }
  
  swLogger.debug('Intercepting request for signing:', req.url);
  event.respondWith((async () => {
    try {
      return await signedFetchFromEvent(req);
    } catch (e) {
      swLogger.error('Error in signed fetch:', e.message);
      return new Response(JSON.stringify({ 
        ok: false, 
        error: e.message,
        code: e.code || 'UNKNOWN_ERROR'
      }), {
        status: CONFIG.HTTP.STATUS_CODES.INTERNAL_SERVER_ERROR, 
        headers: { 'Content-Type': 'application/json' }
      });
    }
  })());
});
self.__listeners.fetch?.push?.(() => {});
