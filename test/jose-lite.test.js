import { b64u, b64uJSON, sigToJoseEcdsa, createJwsES256, jwkThumbprint } from '../src/jose-lite.js';

function b64uDecodeToBytes(s) {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : '';
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad;
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

describe('jose-lite.js', () => {
  test('b64u is URL-safe (no + /) and may include = padding', () => {
    const out1 = b64u(new Uint8Array([0, 0, 0]));
    const out2 = b64u(new Uint8Array([255, 255, 255]));
    expect(out1).toMatch(/^[A-Za-z0-9_-]+=?=?$/);
    expect(out2).toMatch(/^[A-Za-z0-9_-]+=?=?$/);
    expect(out1).not.toMatch(/[+/]/);
    expect(out2).not.toMatch(/[+/]/);
  });

  test('b64uJSON encodes compact JSON to base64url', () => {
    const enc = b64uJSON({ a: 1, z: 'ok' });
    expect(enc).toMatch(/^[A-Za-z0-9_-]+=?=?$/);
    const bytes = b64uDecodeToBytes(enc);
    const obj = JSON.parse(new TextDecoder().decode(bytes));
    expect(obj).toEqual({ a: 1, z: 'ok' });
  });

  test('sigToJoseEcdsa: DER → 64-byte JOSE', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const msg = new TextEncoder().encode('hello');
    const der = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, kp.privateKey, msg);
    const jose = sigToJoseEcdsa(der, 32);
    expect(jose).toBeInstanceOf(Uint8Array);
    expect(jose.length).toBe(64);
  });

  test('sigToJoseEcdsa: malformed DER throws with implementation-specific messages', () => {
    expect(() => sigToJoseEcdsa(new Uint8Array([0x31, 0x00]))).toThrow(/Unsupported ECDSA signature format/i);
    expect(() => sigToJoseEcdsa(new Uint8Array([0x30, 0x00]))).toThrow(/DER r/i);
    expect(() => sigToJoseEcdsa(new Uint8Array([0x30, 0x06, 0x02, 0x01, 0x01, 0x03, 0x01, 0x02]))).toThrow(/DER s/i);
  });

  test('createJwsES256 builds valid compact JWS', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign','verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const hdr = { alg: 'ES256', typ: 'unit+jws', jwk };
    const payload = { iat: Math.floor(Date.now()/1000), msg: 'hi' };
    const compact = await (await import('../src/jose-lite.js')).createJwsES256({ protectedHeader: hdr, payload, privateKey: kp.privateKey });

    const parts = compact.split('.');
    expect(parts).toHaveLength(3);
    const H = JSON.parse(new TextDecoder().decode(b64uDecodeToBytes(parts[0])));
    const P = JSON.parse(new TextDecoder().decode(b64uDecodeToBytes(parts[1])));
    const S = b64uDecodeToBytes(parts[2]);

    expect(H.alg).toBe('ES256');
    expect(H.typ).toBe('unit+jws');
    expect(H.jwk?.kty).toBe('EC');
    expect(P.msg).toBe('hi');
    expect(S.length).toBe(64);
  });

  test('jwkThumbprint returns base64url (EC and non-EC tolerated)', async () => {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify']);
    const jwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    const tpEC = await jwkThumbprint(jwk);
    expect(tpEC).toMatch(/^[A-Za-z0-9_-]{10,}$/);

    const tpOther = await jwkThumbprint({ kty: 'RSA' });
    expect(tpOther).toMatch(/^[A-Za-z0-9_-]{10,}$/);
  });
});
