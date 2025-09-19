// /public/js/passkeys.js
import * as DpopFun from './dpop-fun.js';
import { b64uToBuf, bufToB64u } from '../utils/jose-lite.js';
import { logger } from '../utils/logging.js';
import { AuthenticationError, NetworkError } from '../utils/errors.js';

export async function checkSupport() {
  try {
    logger.debug('Checking WebAuthn support');
    const hasAPI = !!(window.PublicKeyCredential && navigator.credentials);
    const uvp = hasAPI && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().catch(() => false);
    const result = { hasAPI, uvp: !!uvp };
    logger.debug('WebAuthn support check result:', result);
    return result;
  } catch (error) {
    logger.error('Failed to check WebAuthn support:', error);
    throw new AuthenticationError('Failed to check WebAuthn support', { originalError: error.message });
  }
}

// ----- Registration -----
export async function registerPasskey() {
  try {
    logger.debug('Starting passkey registration');
    
    // 1) get options
    const opts = await DpopFun.dpopFunFetch('/webauthn/registration/options', { method: 'POST' });
    logger.debug('Registration options received');

    const pub = {
      rp: opts.rp,
      user: {
        ...opts.user,
        id: b64uToBuf(opts.user.id),
      },
      pubKeyCredParams: opts.pubKeyCredParams,
      challenge: b64uToBuf(opts.challenge),
      attestation: opts.attestation || 'none',
      authenticatorSelection: opts.authenticatorSelection || {},
    };

    // 2) create
    logger.debug('Creating credential with navigator.credentials.create');
    const cred = await navigator.credentials.create({ publicKey: pub });
    if (!cred) {
      logger.warn('User cancelled passkey registration');
      throw new AuthenticationError('registration cancelled');
    }
    logger.debug('Credential created successfully');

    // 3) send to server
    const att = {
      id: cred.id,
      rawId: bufToB64u(cred.rawId),
      type: cred.type,
      response: {
        clientDataJSON: bufToB64u(cred.response.clientDataJSON),
        attestationObject: bufToB64u(cred.response.attestationObject),
      },
      transports: cred.response.getTransports?.() || ['internal'],
    };

    logger.debug('Sending attestation to server for verification');
    const result = await DpopFun.dpopFunFetch('/webauthn/registration/verify', {
      method: 'POST',
      body: att,
    });
    
    logger.debug('Passkey registration completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      logger.info('User cancelled passkey registration');
      throw new AuthenticationError('Registration cancelled by user', { 
        originalError: error.message,
        cancelled: true 
      });
    }
    
    // Handle specific error types
    if (error.name === 'AuthenticationError') throw error;
    if (error.name === 'NetworkError') throw error;
    
    // Handle other WebAuthn errors
    if (error.name === 'InvalidStateError' || error.name === 'SecurityError') {
      logger.warn('Passkey registration failed - retryable error:', error);
      throw new AuthenticationError('Registration failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    logger.error('Passkey registration failed:', error);
    throw new AuthenticationError('Passkey registration failed', { originalError: error.message });
  }
}

// ----- Authentication (preflight-able) -----

export async function getAuthOptions() {
  try {
    logger.debug('Getting authentication options');
    const options = await DpopFun.dpopFunFetch('/webauthn/authentication/options', { method: 'POST' });
    logger.debug('Authentication options received');
    return options;
  } catch (error) {
    logger.error('Failed to get authentication options:', error);
    if (error.name === 'NetworkError') throw error;
    throw new AuthenticationError('Failed to get authentication options', { originalError: error.message });
  }
}

export async function authenticatePasskey(passedOpts) {
  try {
    logger.debug('Starting passkey authentication');
    
    // allow caller to pass pre-fetched options
    const opts = passedOpts || await getAuthOptions();

    const allow = Array.isArray(opts.allowCredentials) ? opts.allowCredentials : [];
    // If you want to avoid "external device" chooser when none are local,
    // handle that in the page logic before calling this function.

    const pub = {
      rpId: opts.rpId,
      challenge: b64uToBuf(opts.challenge),
      userVerification: opts.userVerification || 'preferred',
    };

    if (allow.length) {
      pub.allowCredentials = allow.map(c => ({
        type: 'public-key',
        id: b64uToBuf(c.id),
        transports: c.transports || ['internal'],
      }));
    }

    logger.debug('Getting assertion with navigator.credentials.get');
    const assertion = await navigator.credentials.get({ publicKey: pub });
    if (!assertion) {
      logger.warn('User cancelled passkey authentication');
      throw new AuthenticationError('authentication cancelled');
    }
    logger.debug('Assertion received successfully');

    const payload = {
      id: assertion.id,
      rawId: bufToB64u(assertion.rawId),
      type: assertion.type,
      response: {
        clientDataJSON: bufToB64u(assertion.response.clientDataJSON),
        authenticatorData: bufToB64u(assertion.response.authenticatorData),
        signature: bufToB64u(assertion.response.signature),
        userHandle: assertion.response.userHandle ? bufToB64u(assertion.response.userHandle) : undefined,
      },
    };

    logger.debug('Sending assertion to server for verification');
    const result = await DpopFun.dpopFunFetch('/webauthn/authentication/verify', {
      method: 'POST',
      body: payload,
    });
    
    logger.debug('Passkey authentication completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      logger.info('User cancelled passkey authentication');
      throw new AuthenticationError('Authentication cancelled by user', { 
        originalError: error.message,
        cancelled: true 
      });
    }
    
    // Handle specific error types
    if (error.name === 'AuthenticationError') throw error;
    if (error.name === 'NetworkError') throw error;
    
    // Handle other WebAuthn errors
    if (error.name === 'InvalidStateError' || error.name === 'SecurityError') {
      logger.warn('Passkey authentication failed - retryable error:', error);
      throw new AuthenticationError('Authentication failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    logger.error('Passkey authentication failed:', error);
    throw new AuthenticationError('Passkey authentication failed', { originalError: error.message });
  }
}
