// /src/dpop.js
import { b64uJSON, sigToJoseEcdsa } from '/src/jose-lite.js';
import { cryptoLogger } from './utils/logging.js';
import { CryptoError } from './utils/errors.js';
import { validateUrl, validateMethod, validateKeyPair, validateNonce } from './utils/validation.js';
import { CONFIG } from './utils/config.js';

export function canonicalUrl(inputUrl, base) {
  try {
    validateUrl(inputUrl);
    const u = new URL(inputUrl, base ?? (globalThis.location?.origin ?? globalThis.self?.location?.origin ?? 'http://localhost'));
    const scheme = u.protocol.toLowerCase();
    const host = u.hostname.toLowerCase();
    let port = u.port;
    if ((scheme === 'https:' && port === '443') || (scheme === 'http:' && port === '80')) port = '';
    const netloc = port ? `${host}:${port}` : host;
    const canonical = `${scheme}//${netloc}${u.pathname || '/'}${u.search || ''}`;
    cryptoLogger.debug('Canonicalized URL:', { input: inputUrl, output: canonical });
    return canonical;
  } catch (error) {
    if (error.name === 'StrongholdError') throw error;
    throw new CryptoError('Failed to canonicalize URL', { originalError: error.message, url: inputUrl });
  }
}

export async function createDpopProof({ url, method, nonce, privateKey, publicJwk }) {
  try {
    validateUrl(url);
    const validatedMethod = validateMethod(method);
    validateNonce(nonce);
    validateKeyPair({ privateKey, publicKey: null, publicJwk });

    cryptoLogger.debug('Creating DPoP proof:', { url, method: validatedMethod, hasNonce: !!nonce });

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
    
    cryptoLogger.debug('DPoP proof created successfully');
    return proof;
  } catch (error) {
    cryptoLogger.error('Failed to create DPoP proof:', error);
    if (error.name === 'StrongholdError') throw error;
    throw new CryptoError('Failed to create DPoP proof', { 
      originalError: error.message, 
      url, 
      method, 
      hasNonce: !!nonce 
    });
  }
}
