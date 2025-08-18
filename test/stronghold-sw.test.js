// test/stronghold-sw.test.js
/* eslint-env jest */
import { jest } from '@jest/globals';

// ---- Mock ../src/idb.js (ESM-safe) and expose __bags so tests can clear state ----
const META = new Map();
const KEYS = new Map();

await jest.unstable_mockModule('../src/idb.js', () => ({
  STORES: { META: 'META', KEYS: 'KEYS' },
  idbGet: async (store, id) => (store === 'META' ? META : KEYS).get(id),
  idbPut: async (store, rec) => (store === 'META' ? META : KEYS).set(rec.id, rec),
  __bags: { META, KEYS },
}));

const { STORES, idbGet, idbPut, __bags } = await import('../src/idb.js');

// ---- SW harness -------------------------------------------------------------
function setupSWEnv() {
  const listeners = { install: [], activate: [], fetch: [], message: [] };
  global.self = {
    location: { origin: 'http://localhost:8000', href: 'http://localhost:8000/' },
    __listeners: listeners,
    skipWaiting: jest.fn(() => Promise.resolve()),
    clients: { claim: jest.fn(() => Promise.resolve()) },
    addEventListener(type, handler) { listeners[type]?.push(handler); },
  };

  // Minimal indexedDB stub for the flush test (deleteDatabase)
  global.indexedDB = {
    deleteDatabase: (name) => {
      const req = {};
      queueMicrotask(() => {
        META.clear();
        KEYS.clear();
        req.onsuccess && req.onsuccess();
      });
      return req;
    },
  };
}

// tiny fallbacks if WHATWG fetch classes aren’t present (some Jest envs)
function ensureFetchPrimitives() {
  if (!globalThis.Headers) {
    class H {
      constructor(init) {
        this.m = new Map();
        if (init) for (const [k, v] of Object.entries(init)) this.m.set(String(k).toLowerCase(), String(v));
      }
      set(k, v) { this.m.set(String(k).toLowerCase(), String(v)); }
      get(k) { return this.m.get(String(k).toLowerCase()) ?? null; }
      has(k) { return this.m.has(String(k).toLowerCase()); }
    }
    global.Headers = H;
  }
  if (!globalThis.Request) {
    class Rq {
      constructor(url, opts = {}) {
        this.url = url;
        this.method = (opts.method || 'GET').toUpperCase();
        this.headers = opts.headers instanceof Headers ? opts.headers : new Headers(opts.headers || {});
        this._body = opts.body ?? null;
      }
      clone() { return new Request(this.url, { method: this.method, headers: this.headers, body: this._body }); }
      async arrayBuffer() {
        if (this._body == null) return new ArrayBuffer(0);
        if (this._body instanceof ArrayBuffer) return this._body;
        const s = typeof this._body === 'string' ? this._body : JSON.stringify(this._body);
        return new TextEncoder().encode(s).buffer;
      }
    }
    global.Request = Rq;
  }
  if (!globalThis.Response) {
    class Rs {
      constructor(body, init = {}) {
        this.status = init.status ?? 200;
        this.headers = init.headers instanceof Headers ? init.headers : new Headers(init.headers || {});
        this._body = body ?? null;
      }
      async json() {
        if (this._body == null) return {};
        if (typeof this._body === 'string') return JSON.parse(this._body);
        if (this._body instanceof ArrayBuffer) return JSON.parse(new TextDecoder().decode(this._body));
        return this._body;
      }
      async text() {
        if (this._body == null) return '';
        if (typeof this._body === 'string') return this._body;
        if (this._body instanceof ArrayBuffer) return new TextDecoder().decode(this._body);
        return JSON.stringify(this._body);
      }
    }
    global.Response = Rs;
  }
}

async function importSWFresh() {
  await jest.isolateModulesAsync(async () => {
    await import('../src/stronghold-sw.js'); // registers listeners on self
  });
}

function triggerInstall() {
  const h = self.__listeners.install[0];
  if (h) h({ waitUntil: (p) => p });
}
function triggerActivate() {
  const h = self.__listeners.activate[0];
  if (h) h({ waitUntil: (p) => p });
}
async function triggerFetchAndWait(req) {
  const h = self.__listeners.fetch[0];
  if (!h) throw new Error('no fetch listeners registered');
  return await new Promise((resolve) => h({
    request: req,
    respondWith: (p) => resolve(p),
  }));
}
function postMessageToSW(data) {
  const h = self.__listeners.message[0];
  if (h) h({ data });
}

async function seedDpopKey() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  await idbPut(STORES.KEYS, { id: 'dpop.current', privateKey: kp.privateKey, publicJwk: jwk, createdAt: Date.now() });
}

async function seedBikKey() {
  const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
  const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  await idbPut(STORES.KEYS, { id: 'bik.current', privateKey: kp.privateKey, publicJwk: jwk, createdAt: Date.now() });
}

// ---- Global resets before each test ----------------------------------------
beforeEach(async () => {
  __bags.META.clear();
  __bags.KEYS.clear();

  jest.resetModules();
  setupSWEnv();
  ensureFetchPrimitives();

  // each test supplies its own fetch mock
  global.fetch = undefined;

  await importSWFresh();
  triggerInstall();
  triggerActivate();
});

// ---- Tests ------------------------------------------------------------------

test('signs /api/* request with DPoP + DPoP-Bind when bind present', async () => {
  await seedDpopKey();
  await idbPut(STORES.META, { id: 'bind', value: 'BIND_1' });

  global.fetch = jest.fn(async (req) => {
    expect(req.headers.get('DPoP-Bind')).toBe('BIND_1');
    expect(req.headers.get('DPoP')).toBeTruthy();
    return new Response(JSON.stringify({ ok: true }), {
      status: 200, headers: { 'Content-Type': 'application/json' }
    });
  });

  const req = new Request('http://localhost:8000/api/echo', { method: 'POST', body: '{}' });
  const res = await triggerFetchAndWait(req);
  const j = await res.json();
  expect(j.ok).toBe(true);
  expect(global.fetch).toHaveBeenCalledTimes(1);
});

test('nonce retry: first 428 with Nonce, then 200; stores final nonce', async () => {
  await seedDpopKey();
  await idbPut(STORES.META, { id: 'bind', value: 'BIND_1' });

  const NONCE1 = 'N1', NONCE2 = 'N2';
  global.fetch = jest.fn()
    // 1st attempt -> 428 with nonce
    .mockImplementationOnce(async (req) => {
      expect(req.headers.get('DPoP-Bind')).toBe('BIND_1');
      expect(req.headers.get('DPoP')).toBeTruthy();
      return new Response(JSON.stringify({ detail: 'dpop required' }), {
        status: 428,
        headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': NONCE1 }
      });
    })
    // 2nd attempt -> success, returns a fresh nonce
    .mockImplementationOnce(async (req) => {
      expect(req.headers.get('DPoP-Bind')).toBe('BIND_1');
      expect(req.headers.get('DPoP')).toBeTruthy();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': NONCE2 }
      });
    });

  const req = new Request('http://localhost:8000/api/echo', { method: 'GET' });
  const res = await triggerFetchAndWait(req);
  const j = await res.json();
  expect(j.ok).toBe(true);
  expect(global.fetch).toHaveBeenCalledTimes(2);

  const nonceRec = await idbGet(STORES.META, 'dpop_nonce');
  expect(nonceRec?.value).toBe(NONCE2);
});

test('resume flow: no bind → resume-init/confirm → signs API call and persists bind/nonce', async () => {
  await seedDpopKey();
  await seedBikKey(); // IMPORTANT: SW signs /session/resume-confirm with BIK

  global.fetch = jest.fn()
    // /session/resume-init
    .mockImplementationOnce(async (input) => {
      const url = typeof input === 'string' ? input : input.url;
      expect(url).toMatch(/\/session\/resume-init$/);
      return new Response(JSON.stringify({ resume_nonce: 'RESUME1' }), {
        status: 200, headers: { 'Content-Type': 'application/json' }
      });
    })
    // /session/resume-confirm
    .mockImplementationOnce(async (input) => {
      const url = typeof input === 'string' ? input : input.url;
      expect(url).toMatch(/\/session\/resume-confirm$/);
      return new Response(JSON.stringify({ bind: 'BIND_2' }), {
        status: 200, headers: { 'Content-Type': 'application/json', 'DPoP-Nonce': 'N2' }
      });
    })
    // final signed API call with the new bind
    .mockImplementationOnce(async (req) => {
      expect(req.headers.get('DPoP-Bind')).toBe('BIND_2');
      expect(req.headers.get('DPoP')).toBeTruthy();
      return new Response(JSON.stringify({ ok: true }), {
        status: 200, headers: { 'Content-Type': 'application/json' }
      });
    });

  const res = await triggerFetchAndWait(new Request('http://localhost:8000/api/echo', { method: 'GET' }));
  const j = await res.json();
  expect(j.ok).toBe(true);

  const bindRec  = await idbGet(STORES.META, 'bind');
  const nonceRec = await idbGet(STORES.META, 'dpop_nonce');
  expect(bindRec?.value).toBe('BIND_2');
  expect(nonceRec?.value).toBe('N2');
  expect(global.fetch).toHaveBeenCalledTimes(3);
});

test('message: stronghold/flush-client deletes IDB quietly', async () => {
  await idbPut(STORES.META, { id: 'pre', value: 'ok' });
  await idbPut(STORES.KEYS, { id: 'k', value: 'v' });

  postMessageToSW({ type: 'stronghold/flush-client' });
  await new Promise((r) => setTimeout(r, 0)); // allow deleteDatabase microtask

  const m = await idbGet(STORES.META, 'pre');
  const k = await idbGet(STORES.KEYS, 'k');
  expect(m).toBeUndefined();
  expect(k).toBeUndefined();
});

test('install/activate lifecycle calls skipWaiting and clients.claim', async () => {
  triggerInstall();
  triggerActivate();
  expect(self.skipWaiting).toHaveBeenCalled();
  expect(self.clients.claim).toHaveBeenCalled();
});

test('fetch error path returns 500 JSON', async () => {
  await seedDpopKey();
  await idbPut(STORES.META, { id: 'bind', value: 'BIND_ERR' });

  global.fetch = jest.fn().mockImplementationOnce(async () => {
    throw new Error('network down');
  });

  const res = await triggerFetchAndWait(new Request('http://localhost:8000/api/echo', { method: 'GET' }));
  expect(res.status).toBe(500);
  const j = await res.json();
  expect(j.ok).toBe(false);
  expect(String(j.error || '')).toMatch(/network down/i);
});
