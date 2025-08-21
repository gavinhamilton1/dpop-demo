// src/utils/validation.js
import { CONFIG } from './config.js';
import { StrongholdError } from './errors.js';

export const validateUrl = (url) => {
  if (typeof url !== 'string') {
    throw new StrongholdError('URL must be a string', 'VALIDATION_ERROR', { url });
  }
  try {
    // Handle relative URLs by making them absolute
    const absoluteUrl = url.startsWith('http') ? url : new URL(url, 'http://localhost').href;
    new URL(absoluteUrl);
    return true;
  } catch {
    throw new StrongholdError('Invalid URL format', 'VALIDATION_ERROR', { url });
  }
};

export const validateMethod = (method) => {
  const upperMethod = method?.toUpperCase();
  if (!CONFIG.HTTP.METHODS.includes(upperMethod)) {
    throw new StrongholdError(
      'Invalid HTTP method', 
      'VALIDATION_ERROR', 
      { method, allowedMethods: CONFIG.HTTP.METHODS }
    );
  }
  return upperMethod;
};

export const validateKeyPair = (keyPair) => {
  if (!keyPair || typeof keyPair !== 'object') {
    throw new StrongholdError('Key pair must be an object', 'VALIDATION_ERROR', { keyPair });
  }
  if (!keyPair.privateKey || !keyPair.publicJwk) {
    throw new StrongholdError(
      'Key pair must have privateKey and publicJwk properties', 
      'VALIDATION_ERROR', 
      { keyPair }
    );
  }
  return true;
};

export const validateJwk = (jwk) => {
  if (!jwk || typeof jwk !== 'object') {
    throw new StrongholdError('JWK must be an object', 'VALIDATION_ERROR', { jwk });
  }
  
  // Basic validation - require kty
  if (jwk.kty === undefined || jwk.kty === null) {
    throw new StrongholdError('JWK missing required field: kty', 'VALIDATION_ERROR', { jwk, missingField: 'kty' });
  }
  
  // For EC keys, validate required fields
  if (jwk.kty === 'EC') {
    const requiredFields = ['crv', 'x', 'y'];
    for (const field of requiredFields) {
      if (jwk[field] === undefined || jwk[field] === null) {
        throw new StrongholdError(
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
    throw new StrongholdError('Nonce must be a string, null, or undefined', 'VALIDATION_ERROR', { nonce });
  }
  return true;
};
