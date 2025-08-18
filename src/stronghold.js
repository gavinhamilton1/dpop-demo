// Stronghold core: keys, bind, DPoP proof, signed fetch, client flush

import { b64uJSON, sigToJoseEcdsa, createJwsES256, jwkThumbprint } from '/src/jose-lite.js';
import { idbPut, idbGet, idbWipe, STORES } from '/src/idb.js';

export { createJwsES256, idbWipe };

const LOG = (...a) => console.debug('[stronghold/core]', ...a);
const BIK_ROTATE_SEC  = 7 * 24 * 3600;  // 7d
const DPOP_ROTATE_SEC = 1 * 24 * 3600;  // 1d

let CSRF = null;
let REG_NONCE = null;

export async function get(key) { return idbGet(STORES.META, key); }
export async function set(key, value) { return idbPut(STORES.META, { id: key, value }); }

export function canonicalUrl(inputUrl) {
  const u = new URL(inputUrl, location.origin);
  const scheme = u.protocol.toLowerCase();
  const host = u.hostname.toLowerCase();
  let port = u.port;
  if ((scheme === 'https:' && port === '443') || (scheme === 'http:' && port === '80')) port = '';
  const netloc = port ? `${host}:${port}` : host;
  const path = u.pathname || '/';
  const query = u.search || '';
  return `${scheme}//${netloc}${path}${query}`;
}

async function generateES256KeyPair() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicJwk };
}
async function maybeRotate(rec, ttlSec, label) {
  if (!rec?.createdAt) return true;
  const ageSec = (Date.now() - rec.createdAt) / 1000;
  if (ageSec > ttlSec) { console.warn(`[stronghold/core] rotating ${label}, age=${ageSec.toFixed(0)}s`); return true; }
  return false;
}

export async function ensureBIK() {
  let rec = await idbGet(STORES.KEYS, 'bik.current');
  if (!rec || await maybeRotate(rec, BIK_ROTATE_SEC, 'BIK')) {
    const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
    rec = { id: 'bik.current', privateKey, publicKey, publicJwk, createdAt: Date.now() };
    await idbPut(STORES.KEYS, rec);
  }
  return { privateKey: rec.privateKey, publicKey: rec.publicKey, publicJwk: rec.publicJwk, jkt: await jwkThumbprint(rec.publicJwk) };
}

export async function ensureDPoP() {
  let rec = await idbGet(STORES.KEYS, 'dpop.current');
  if (!rec || await maybeRotate(rec, DPOP_ROTATE_SEC, 'DPoP')) {
    const { privateKey, publicKey, publicJwk } = await generateES256KeyPair();
    rec = { id: 'dpop.current', privateKey, publicKey, publicJwk, createdAt: Date.now() };
    await idbPut(STORES.KEYS, rec);
  }
  return { privateKey: rec.privateKey, publicKey: rec.publicKey, publicJwk: rec.publicJwk, jkt: await jwkThumbprint(rec.publicJwk) };
}

export async function createDpopProof({ url, method, nonce, privateKey, publicJwk }) {
  const h = b64uJSON({ alg: 'ES256', typ: 'dpop+jwt', jwk: publicJwk });
  const p = b64uJSON({ htu: canonicalUrl(url), htm: method.toUpperCase(), iat: Math.floor(Date.now()/1000), jti: crypto.randomUUID(), ...(nonce ? { nonce } : {}) });
  const input = new TextEncoder().encode(`${h}.${p}`);
  const sig   = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, privateKey, input);
  const raw   = sigToJoseEcdsa(sig, 32);
  const s     = btoa(String.fromCharCode(...raw)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  return `${h}.${p}.${s}`;
}

export async function sessionInit({ sessionInitUrl = '/session/init', browserUuid = null } = {}) {
  const existing = (await get('browser_uuid'))?.value;
  const uuid = browserUuid || existing || crypto.randomUUID();
  if (!existing) await set('browser_uuid', uuid);

  const r = await fetch(sessionInitUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'include',
    body: JSON.stringify({ browser_uuid: uuid })
  });
  if (!r.ok) throw new Error(`session/init failed: ${r.status}`);
  const j = await r.json();
  CSRF = j.csrf; REG_NONCE = j.reg_nonce;
  LOG('sessionInit ok', j);
  return j;
}

export async function bikRegisterStep({ bikRegisterUrl = '/browser/register' } = {}) {
  if (!CSRF || !REG_NONCE) throw new Error('missing csrf/reg_nonce (call sessionInit first)');
  const bik = await ensureBIK();
  const protectedHeader = { alg: 'ES256', typ: 'bik-reg+jws', jwk: bik.publicJwk };
  const payload         = { nonce: REG_NONCE, iat: Math.floor(Date.now()/1000) };
  const jws = await createJwsES256({ protectedHeader, payload, privateKey: bik.privateKey });

  const r = await fetch(bikRegisterUrl, { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': CSRF }, body: jws });
  if (!r.ok) throw new Error(`bik register failed: ${r.status}`);
  const j = await r.json();
  await set('bik_jkt', j.bik_jkt);
  LOG('bik/register ok', j);
  return j;
}

export async function dpopBindStep({ dpopBindUrl = '/dpop/bind' } = {}) {
  if (!CSRF) throw new Error('missing csrf (call sessionInit first)');
  const bik  = await ensureBIK();
  const dpop = await ensureDPoP();

  const protectedHeader = { alg: 'ES256', typ: 'dpop-bind+jws', jwk: bik.publicJwk };
  const payload = { dpop_jwk: dpop.publicJwk, nonce: crypto.randomUUID(), iat: Math.floor(Date.now() / 1000) };
  const jws = await createJwsES256({ protectedHeader, payload, privateKey: bik.privateKey });

  const r = await fetch(dpopBindUrl, { method: 'POST', credentials: 'include', headers: { 'X-CSRF-Token': CSRF }, body: jws });
  if (!r.ok) throw new Error(`dpop bind failed: ${r.status}`);
  const j = await r.json();

  await set('bind', j.bind);
  const serverNonce = r.headers.get('DPoP-Nonce'); if (serverNonce) await set('dpop_nonce', serverNonce);

  LOG('dpop/bind ok', j, 'nonce=', serverNonce || null);
  return { ...j, dpopKeyId: 'dpop.current', nonce: serverNonce || null };
}

export async function strongholdFetch(url, { method = 'GET', body = null } = {}) {
  let bind = (await get('bind'))?.value;
  const dpopNonce = (await get('dpop_nonce'))?.value || null;

  if (!bind) {
    const ok = await resumeViaPage();
    if (!ok) throw new Error('no binding token (resume failed)');
    bind = (await get('bind'))?.value;
  }

  const dpop = await ensureDPoP();
  const fullUrl = canonicalUrl(url);
  let proof = await createDpopProof({ url: fullUrl, method, nonce: dpopNonce, privateKey: dpop.privateKey, publicJwk: dpop.publicJwk });
  let headers = { 'Content-Type': 'application/json', 'DPoP': proof, 'DPoP-Bind': bind };
  const init = { method, headers, credentials: 'include', body: body ? JSON.stringify(body) : undefined };

  let res = await fetch(fullUrl, init);

  if ((res.status === 401 || res.status === 428) && res.headers.get('DPoP-Nonce')) {
    const n = res.headers.get('DPoP-Nonce');
    await set('dpop_nonce', n);
    proof = await createDpopProof({ url: fullUrl, method, nonce: n, privateKey: dpop.privateKey, publicJwk: dpop.publicJwk });
    headers = { ...headers, 'DPoP': proof };
    res = await fetch(fullUrl, { ...init, headers });
  }

  if (!res.ok) {
    const t = await res.text().catch(()=>String(res.status));
    throw new Error(`request failed: ${res.status} ${t}`);
  }
  const n2 = res.headers.get('DPoP-Nonce');
  if (n2) await set('dpop_nonce', n2);
  return res.json();
}

async function resumeViaPage() {
  const r1 = await fetch('/session/resume-init', { method: 'POST', credentials: 'include' });
  if (!r1.ok) return false;
  const { resume_nonce } = await r1.json();
  const bik = await ensureBIK();
  const jws = await createJwsES256({
    protectedHeader: { alg: 'ES256', typ: 'bik-resume+jws', jwk: bik.publicJwk },
    payload: { resume_nonce, iat: Math.floor(Date.now()/1000) },
    privateKey: bik.privateKey
  });
  const r2 = await fetch('/session/resume-confirm', { method: 'POST', credentials: 'include', body: jws });
  if (!r2.ok) return false;
  const j = await r2.json();
  await set('bind', j.bind);
  const n = r2.headers.get('DPoP-Nonce'); if (n) await set('dpop_nonce', n);
  return true;
}

export async function clientFlush({ unregisterSW = false } = {}) {
  CSRF = null; REG_NONCE = null;
  await idbWipe();
  try {
    if (navigator.serviceWorker?.controller) {
      navigator.serviceWorker.controller.postMessage({ type: 'stronghold/flush-client' });
    }
  } catch {}
  if (unregisterSW && 'serviceWorker' in navigator) {
    const regs = await navigator.serviceWorker.getRegistrations();
    for (const r of regs) { try { await r.unregister(); } catch {} }
  }
  return { ok: true };
}
