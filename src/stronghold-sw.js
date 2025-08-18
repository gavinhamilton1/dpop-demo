// src/stronghold-sw.js
// Stronghold service worker: signs /api/* with DPoP + DPoP-Bind, handles nonce retry, and session resume.

import { idbGet, idbPut, STORES } from './idb.js';
import { b64uJSON, sigToJoseEcdsa, createJwsES256 } from './jose-lite.js';

const swlog = (...a) => console.debug('[stronghold/sw]', ...a);

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
async function getBind()        { return (await idbGet(STORES.META, 'bind'))?.value || null; }
async function setBind(v)       { return idbPut(STORES.META, { id: 'bind', value: v }); }
async function getNonce()       { return (await idbGet(STORES.META, 'dpop_nonce'))?.value || null; }
async function setNonce(v)      { return idbPut(STORES.META, { id: 'dpop_nonce', value: v }); }
async function ensureDPoP() {
  const rec = await idbGet(STORES.KEYS, 'dpop.current');
  if (!rec?.privateKey || !rec?.publicJwk) throw new Error('DPoP key not found in IDB');
  return { privateKey: rec.privateKey, publicJwk: rec.publicJwk };
}
async function ensureBIK() {
  const rec = await idbGet(STORES.KEYS, 'bik.current');
  if (!rec?.privateKey || !rec?.publicJwk) throw new Error('BIK key not found in IDB');
  return { privateKey: rec.privateKey, publicJwk: rec.publicJwk };
}

// ---- URL / proof helpers ---------------------------------------------------
function canonical(urlStr) {
  const u = new URL(urlStr);
  const scheme = u.protocol.toLowerCase();
  const host = u.hostname.toLowerCase();
  let port = u.port;
  if ((scheme === 'https:' && port === '443') || (scheme === 'http:' && port === '80')) port = '';
  const netloc = port ? `${host}:${port}` : host;
  const path = u.pathname || '/';
  const query = u.search || '';
  return `${scheme}//${netloc}${path}${query}`;
}

async function createDpopProof({ url, method, nonce, privateKey, publicJwk }) {
  const h = b64uJSON({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk });
  const p = b64uJSON({
    htu: canonical(url),
    htm: method.toUpperCase(),
    iat: Math.floor(Date.now() / 1000),
    jti: crypto.randomUUID(),
    ...(nonce ? { nonce } : {})
  });
  const input = new TextEncoder().encode(`${h}.${p}`);
  const sig   = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, input);
  const raw   = sigToJoseEcdsa(sig, 32);
  const s     = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `${h}.${p}.${s}`;
}

function shouldSign(url) {
  try { return new URL(url).pathname.startsWith('/api/'); }
  catch { return false; }
}

// ---- resume (bind rehydration) ---------------------------------------------
async function resumeIfNeeded() {
  const existing = await getBind();
  if (existing) return existing;
  try {
    // 1) ask server for resume_nonce
    const initReq = new Request(abs('/session/resume-init'), { method: 'POST' });
    const r1 = await fetch(initReq);
    if (!r1.ok) return null;
    const { resume_nonce } = await r1.json();

    // 2) sign JWS with BIK
    const bik = await ensureBIK();
    const jws = await createJwsES256({
      protectedHeader: { alg: 'ES256', typ: 'bik-resume+jws', jwk: bik.publicJwk },
      payload: { resume_nonce, iat: Math.floor(Date.now()/1000) },
      privateKey: bik.privateKey
    });

    // 3) confirm
    const confReq = new Request(abs('/session/resume-confirm'), {
      method: 'POST',
      body: jws
    });
    const r2 = await fetch(confReq);
    if (!r2.ok) return null;
    const j = await r2.json();

    await setBind(j.bind);
    const n = r2.headers.get('DPoP-Nonce');
    if (n) await setNonce(n);

    return j.bind;
  } catch (e) {
    swlog('resume failed', e.message);
    return null;
  }
}

// ---- signed fetch core ------------------------------------------------------
async function signedFetchFromEvent(req) {
  let bind = await getBind();
  if (!bind) bind = await resumeIfNeeded();
  if (!bind) {
    // No bind: forward as-is (likely 428 from server)
    return fetch(req);
  }

  const dpop   = await ensureDPoP();
  const url    = canonical(req.url);
  const method = req.method.toUpperCase();

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
  if ((res.status === 401 || res.status === 428) && res.headers.has('DPoP-Nonce')) {
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
  return res;
}

// ---- SW lifecycle & wiring --------------------------------------------------
self.__listeners = self.__listeners || { install: [], activate: [], fetch: [], message: [] };

self.addEventListener('install', (e) => {
  swlog('install'); e.waitUntil(self.skipWaiting());
});
self.__listeners.install?.push?.(() => {});

self.addEventListener('activate', (e) => {
  swlog('activate'); e.waitUntil(self.clients.claim());
});
self.__listeners.activate?.push?.(() => {});

self.addEventListener('message', async (ev) => {
  const msg = ev.data || {};
  if (msg.type === 'stronghold/bind') {
    swlog('bind update from page');
    if (msg.bind)  await setBind(msg.bind);
    if (msg.nonce) await setNonce(msg.nonce);
  }
  if (msg.type === 'stronghold/flush-client') {
    try {
      await new Promise((resolve, reject) => {
        const req = indexedDB.deleteDatabase('stronghold-demo');
        req.onsuccess = () => resolve();
        req.onerror   = () => reject(req.error);
        req.onblocked = () => reject(new Error('IDB deletion blocked'));
      });
    } catch (e) {
      swlog('client flush error:', e?.message || e);
    }
  }
});
self.__listeners.message?.push?.(() => {});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (!shouldSign(req.url)) return;
  event.respondWith((async () => {
    try {
      return await signedFetchFromEvent(req);
    } catch (e) {
      swlog('error', e.message);
      return new Response(JSON.stringify({ ok: false, error: e.message }), {
        status: 500, headers: { 'Content-Type': 'application/json' }
      });
    }
  })());
});
self.__listeners.fetch?.push?.(() => {});
