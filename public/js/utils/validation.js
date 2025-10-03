// src/utils/validation.js
import { CONFIG } from './config.js';
import { DPopFunError } from './errors.js';

export const validateUrl = (url) => {
  if (typeof url !== 'string') {
    throw new DPopFunError('URL must be a string', 'VALIDATION_ERROR', { url });
  }
  try {
    // Handle relative URLs by making them absolute
    const absoluteUrl = url.startsWith('http') ? url : new URL(url, 'http://localhost').href;
    new URL(absoluteUrl);
    return true;
  } catch {
    throw new DPopFunError('Invalid URL format', 'VALIDATION_ERROR', { url });
  }
};

export const validateMethod = (method) => {
  const upperMethod = method?.toUpperCase();
  if (!CONFIG.HTTP.METHODS.includes(upperMethod)) {
    throw new DPopFunError(
      'Invalid HTTP method', 
      'VALIDATION_ERROR', 
      { method, allowedMethods: CONFIG.HTTP.METHODS }
    );
  }
  return upperMethod;
};

export const validateKeyPair = (keyPair) => {
  if (!keyPair || typeof keyPair !== 'object') {
    throw new DPopFunError('Key pair must be an object', 'VALIDATION_ERROR', { keyPair });
  }
  if (!keyPair.privateKey || !keyPair.publicJwk) {
    throw new DPopFunError(
      'Key pair must have privateKey and publicJwk properties', 
      'VALIDATION_ERROR', 
      { keyPair }
    );
  }
  return true;
};

export const validateJwk = (jwk) => {
  if (!jwk || typeof jwk !== 'object') {
    throw new DPopFunError('JWK must be an object', 'VALIDATION_ERROR', { jwk });
  }
  
  // Basic validation - require kty
  if (jwk.kty === undefined || jwk.kty === null) {
    throw new DPopFunError('JWK missing required field: kty', 'VALIDATION_ERROR', { jwk, missingField: 'kty' });
  }
  
  // For EC keys, validate required fields
  if (jwk.kty === 'EC') {
    const requiredFields = ['crv', 'x', 'y'];
    for (const field of requiredFields) {
      if (jwk[field] === undefined || jwk[field] === null) {
        throw new DPopFunError(
          `JWK missing required field: ${field}`, 
          'VALIDATION_ERROR', 
          { jwk, missingField: field }
        );
      }
    }
  }
  
  return true;
};

export const validateNonce = (nonce) => {
  if (nonce !== null && nonce !== undefined && typeof nonce !== 'string') {
    throw new DPopFunError('Nonce must be a string, null, or undefined', 'VALIDATION_ERROR', { nonce });
  }
  return true;
};
