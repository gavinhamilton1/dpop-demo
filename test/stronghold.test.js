// test/stronghold.test.js
import { jest } from '@jest/globals';
import {
  ensureBIK, ensureDPoP,
  strongholdFetch, sessionInit, bikRegisterStep, dpopBindStep,
  get as CoreGet, set as CoreSet, clientFlush
} from '/src/stronghold.js';
import { canonicalUrl, createDpopProof } from '/src/dpop.js';
import { idbGet, idbPut, STORES } from '/src/idb.js';

const jsonRes = (status, body, headers = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => body,
  text: async () => JSON.stringify(body),
  headers: { get: (k) => headers[k] || null }
});

describe('stronghold.js', () => {
  beforeEach(async () => {
    await clientFlush({ unregisterSW: false });
    global.fetch = undefined;
  });

  test('canonicalUrl normalizes default ports', () => {
    expect(canonicalUrl('http://example.com:80/x?y')).toBe('http://example.com/x?y');
    expect(canonicalUrl('https://example.com:443/')).toBe('https://example.com/');
    expect(canonicalUrl('/rel')).toMatch(/^http:\/\/localhost:8000\/rel$/);
  });

  test('ensureBIK creates persistent non-exportable key and reuses it', async () => {
    const a = await ensureBIK();
    const b = await ensureBIK();
    expect(a.jkt).toBeDefined();
    expect(b.jkt).toBe(a.jkt);
    expect(a.privateKey).toBeTruthy();
  });

  test('ensureDPoP persists and rotates with TTL (simulated age)', async () => {
    const first = await ensureDPoP();

    // IMPORTANT: edit the KEYS store (not META) so rotation actually triggers
    const rec = await idbGet(STORES.KEYS, 'dpop.current');
    const aged = { ...rec, createdAt: Date.now() - (2 * 24 * 3600 * 1000) }; // 2 days ago
    await idbPut(STORES.KEYS, aged);

    const rotated = await ensureDPoP();
    expect(rotated.jkt).not.toBe(first.jkt);
  });

  test('createDpopProof has valid header/payload structure', async () => {
    const d = await ensureDPoP();
    const jwt = await createDpopProof({
      url: 'https://api.example.com:443/thing?q=1',
      method: 'post',
      nonce: 'ABC',
      privateKey: d.privateKey,
      publicJwk: d.publicJwk
    });
    const [h, p, s] = jwt.split('.');
    expect(h && p && s).toBeTruthy();
    const header = JSON.parse(Buffer.from(h.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'));
    const pl     = JSON.parse(Buffer.from(p.replace(/-/g,'+').replace(/_/g,'/'), 'base64').toString('utf8'));
    expect(header.typ).toBe('dpop+jwt');
    expect(pl.htm).toBe('POST');
    expect(pl.nonce).toBe('ABC');
  });

  test('strongholdFetch handles 428 challenge and updates nonce', async () => {
    await CoreSet('bind', 'BIND_TOKEN_X'); // fake existing bind

    const r1 = jsonRes(428, { detail: 'dpop required' }, { 'DPoP-Nonce': 'N1' });
    const r2 = jsonRes(200, { ok: true }, { 'DPoP-Nonce': 'N2' });

    global.fetch = jest.fn()
      .mockResolvedValueOnce(r1)
      .mockResolvedValueOnce(r2);

    const out = await strongholdFetch('/api/echo', { method: 'POST', body: { hello: 'world' } });
    expect(out.ok).toBe(true);

    expect((await CoreGet('dpop_nonce'))?.value).toBe('N2');
    expect(global.fetch).toHaveBeenCalledTimes(2);
  });

  test('strongholdFetch error path throws message with status + body', async () => {
    await CoreSet('bind', 'BIND_TOKEN');
    global.fetch = jest.fn().mockResolvedValueOnce({
      ok: false,
      status: 500,
      headers: { get: () => null },
      text: async () => 'boom'
    });
    await expect(strongholdFetch('/api/echo', { method: 'POST', body: {} }))
      .rejects
      .toThrow(/500 boom/);
  });

  test('sessionInit → bikRegisterStep → dpopBindStep (mocked server)', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce(jsonRes(200, { csrf: 'CSRF1', reg_nonce: 'REG1', state: 'pending-bind' }))
      .mockResolvedValueOnce(jsonRes(200, { bik_jkt: 'JKT_BIK', state: 'bound-bik' }))
      .mockResolvedValueOnce(jsonRes(200, { bind: 'BIND_1', cnf: { dpop_jkt: 'JKT_DPOP' }, expires_at: 123 }, { 'DPoP-Nonce': 'N_BIND' }));

    const s = await sessionInit({ sessionInitUrl: '/session/init' });
    expect(s.csrf).toBe('CSRF1');

    const b = await bikRegisterStep({ bikRegisterUrl: '/browser/register' });
    expect(b.bik_jkt).toBe('JKT_BIK');

    const d = await dpopBindStep({ dpopBindUrl: '/dpop/bind' });
    expect(d.bind).toBe('BIND_1');
    expect((await CoreGet('bind'))?.value).toBe('BIND_1');
    expect((await CoreGet('dpop_nonce'))?.value).toBe('N_BIND');
  });

  test('strongholdFetch triggers resumeViaPage when no bind (resume success)', async () => {
    global.fetch = jest.fn()
      .mockResolvedValueOnce(jsonRes(200, { resume_nonce: 'R1' }, { 'DPoP-Nonce': 'N0' }))
      .mockResolvedValueOnce(jsonRes(200, { bind: 'BIND_RESUMED' }, { 'DPoP-Nonce': 'N1' }))
      .mockResolvedValueOnce(jsonRes(200, { ok: true }, { 'DPoP-Nonce': 'N2' }));

    const j = await strongholdFetch('/api/echo', { method: 'POST', body: { x: 1 } });
    expect(j.ok).toBe(true);
    expect((await CoreGet('bind'))?.value).toBe('BIND_RESUMED');
    expect((await CoreGet('dpop_nonce'))?.value).toBe('N2');
  });

  test('clientFlush wipes IDB and pings SW when present', async () => {
    await CoreSet('bind', 'B');
    const postMessage = jest.fn();
    global.navigator.serviceWorker = { controller: { postMessage } };

    const r = await clientFlush({ unregisterSW: false });
    expect(r.ok).toBe(true);
    expect(postMessage).toHaveBeenCalledWith({ type: 'stronghold/flush-client' });

    const after = await CoreGet('bind');
    expect(after == null).toBe(true); // allow null or undefined
  });
});
