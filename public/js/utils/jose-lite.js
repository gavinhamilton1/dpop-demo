// src/jose-lite.js
import { logger } from './logging.js';
import { validateJwk } from './validation.js';
import { CONFIG } from './config.js';

export const b64u = (bytes) => {
  try {
    const bin = String.fromCharCode(...(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)));
    return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
  } catch (error) {
    throw new Error('Failed to encode bytes to base64url', { originalError: error.message });
  }
};

export const b64uJSON = (obj) => {
  try {
    return b64u(new TextEncoder().encode(JSON.stringify(obj)));
  } catch (error) {
    throw new Error('Failed to encode JSON to base64url', { originalError: error.message });
  }
};

// Base64url decoding utilities (moved from passkeys.js to eliminate duplication)
export const b64uToBuf = (s) => {
  try {
    const pad = '='.repeat((4 - (s.length % 4)) % 4);
    const b = atob((s + pad).replace(/-/g, '+').replace(/_/g, '/'));
    const buf = new Uint8Array(b.length);
    for (let i = 0; i < b.length; i++) buf[i] = b.charCodeAt(i);
    return buf.buffer;
  } catch (error) {
    throw new Error('Failed to decode base64url to buffer', { originalError: error.message });
  }
};

export const bufToB64u = (buf) => {
  try {
    const b = new Uint8Array(buf);
    let s = ''; 
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/,'');
  } catch (error) {
    throw new Error('Failed to encode buffer to base64url', { originalError: error.message });
  }
};

export function sigToJoseEcdsa(sig, size=32) {
  try {
    const u = new Uint8Array(sig);
    if (u.length === size*2) return u;
    if (u[0] !== 0x30) throw new Error('Unsupported ECDSA signature format');
    let i=2;
    if (u[i++]!==0x02) throw new Error('DER r');
    let rLen=u[i++]; let r=u.slice(i, i+rLen); i+=rLen;
    if (u[i++]!==0x02) throw new Error('DER s');
    let sLen=u[i++]; let s=u.slice(i, i+sLen);
    if (r[0]===0x00) r=r.slice(1);
    if (s[0]===0x00) s=s.slice(1);
    const R=new Uint8Array(size); R.set(r, size-r.length);
    const S=new Uint8Array(size); S.set(s, size-s.length);
    const out=new Uint8Array(size*2); out.set(R,0); out.set(S,size);
    return out;
  } catch (error) {
    // Preserve original error message for test compatibility
    if (error.message.includes('Unsupported ECDSA signature format') || 
        error.message.includes('DER r') || 
        error.message.includes('DER s')) {
      throw error; // Re-throw original error for tests
    }
    throw new Error('Failed to convert signature to JOSE format', { originalError: error.message });
  }
}

export async function createJwsES256({ protectedHeader, payload, privateKey }) {
  try {
    logger.debug('Creating JWS with header:', protectedHeader);
    const h = b64uJSON(protectedHeader);
    const p = b64uJSON(payload);
    const input = new TextEncoder().encode(`${h}.${p}`);
    const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, input);
    const sigJose = sigToJoseEcdsa(sig, 32);
    const s = b64u(sigJose);
    const jws = `${h}.${p}.${s}`;
    logger.debug('JWS created successfully');
    return jws;
  } catch (error) {
    logger.error('Failed to create JWS:', error);
    throw new Error('Failed to create JWS', { originalError: error.message });
  }
}

export async function jwkThumbprint(jwk) {
  try {
    validateJwk(jwk);
    const ordered = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
    const data = new TextEncoder().encode(JSON.stringify(ordered));
    const hash = await crypto.subtle.digest('SHA-256', data);
    return b64u(hash);
  } catch (error) {
    if (error.name === 'DPopFunError') throw error;
    throw new Error('Failed to create JWK thumbprint', { originalError: error.message });
  }
}

export async function generateES256KeyPair() {
  try {
    logger.info('Generating new ES256 key pair');
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: CONFIG.CRYPTO.CURVE }, false, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
    logger.info('ES256 key pair generated successfully');
    return { privateKey: kp.privateKey, publicKey: kp.publicKey, publicJwk };
  } catch (error) {
    logger.error('Failed to generate ES256 key pair:', error);
    throw new Error('Failed to generate key pair', { originalError: error.message });
  }
}

export async function createJwsWithDefaults({ typ, payload, privateKey, publicJwk }) {
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
    throw Error('Failed to create JWS', { originalError: error.message });
  }
}