// /public/js/passkeys.js
import * as DpopFun from './dpop-fun.js';
import { b64uToBuf, bufToB64u } from '../utils/jose-lite.js';
import { logger } from '../utils/logging.js';

/**
 * Check if WebAuthn is supported in this browser
 * @returns {boolean} Whether WebAuthn is supported
 */
export function isSupported() {
  return !!(window.PublicKeyCredential && 
           typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function');
}

/**
 * Check if user-verifying platform authenticator is available
 * @returns {Promise<boolean>} Whether UVPA is available
 */
export async function isUserVerifyingPlatformAuthenticatorAvailable() {
  if (!isSupported()) {
    return false;
  }
  
  try {
    return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
  } catch (error) {
    logger.warn('UVPA check failed:', error);
    return false;
  }
}

/**
 * Get basic passkey support status (browser capabilities only)
 * @returns {Promise<Object>} Support status with isSupported and hasUVPA
 */
export async function getBasicSupportStatus() {
  return {
    isSupported: isSupported(),
    hasUVPA: await isUserVerifyingPlatformAuthenticatorAvailable(),
    hasCredentials: false // Will be checked later when authenticated
  };
}

/**
 * Legacy checkSupport function for backward compatibility
 * @returns {Promise<Object>} Support status
 */
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
    throw new Error('Failed to check WebAuthn support: ' + error.message);
  }
}

// ----- Registration -----
export async function registerPasskey(username) {
  try {
    logger.debug('Starting passkey registration for username:', username);
    
    // 1) get options with username
    const optionsResponse = await DpopFun.dpopFetch('POST', '/webauthn/registration/options', {
      body: JSON.stringify({ username })
    });
    const opts = await optionsResponse.json();
    logger.debug('Registration options received:', { 
      username: opts.user?.name, 
      userId: opts.user?.id,
      displayName: opts.user?.displayName 
    });

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
      throw new Error('registration cancelled');
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
      username: username  // Include username for server-side storage
    };

    logger.debug('Sending attestation to server for verification');
    const verifyResponse = await DpopFun.dpopFetch('POST', '/webauthn/registration/verify', {
      body: JSON.stringify(att),
    });
    const result = await verifyResponse.json();
    
    logger.debug('Passkey registration completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      logger.info('User cancelled passkey registration');
      throw new Error('Registration cancelled by user', { 
        originalError: error.message,
        cancelled: true 
      });
    }
    
    
    // Handle other WebAuthn errors
    if (error.name === 'InvalidStateError' || error.name === 'SecurityError') {
      logger.warn('Passkey registration failed - retryable error:', error);
      throw new Error('Registration failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    logger.error('Passkey registration failed:', error);
    throw new Error('Passkey registration failed', { originalError: error.message });
  }
}

// ----- Authentication (preflight-able) -----

export async function getAuthOptions(username = null) {
  try {
    logger.debug('Getting authentication options', username ? `for username: ${username}` : '');
    const body = username ? JSON.stringify({ username }) : undefined;
    const optionsResponse = await DpopFun.dpopFetch('POST', '/webauthn/authentication/options', 
      body ? { body } : {}
    );
    const options = await optionsResponse.json();
    logger.debug('Authentication options received');
    return options;
  } catch (error) {
    logger.error('Failed to get authentication options:', error);
    if (error.name === 'NetworkError') throw error;
    throw new Error('Failed to get authentication options', { originalError: error.message });
  }
}

/**
 * Check if passkeys exist for the current user
 * Note: This requires an authenticated session
 * @returns {Promise<boolean>} Whether passkeys exist
 */
export async function hasExistingPasskeys() {
  try {
    const options = await getAuthOptions();
    return options.allowCredentials && options.allowCredentials.length > 0;
  } catch (error) {
    logger.warn('Failed to check existing passkeys:', error);
    return false;
  }
}

export async function authenticatePasskey(username = null, passedOpts = null) {
  try {
    logger.debug('Starting passkey authentication', username ? `for username: ${username}` : '');
    logger.debug('Passed options:', passedOpts);
    
    // allow caller to pass pre-fetched options, otherwise fetch with username
    const opts = passedOpts || await getAuthOptions(username);
    logger.debug('Using authentication options:', opts);

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
    logger.debug('Authentication options:', { 
      allowCredentials: pub.allowCredentials?.length || 0,
      challenge: pub.challenge ? 'present' : 'missing',
      rpId: pub.rpId
    });
    
    const assertion = await navigator.credentials.get({ publicKey: pub });
    logger.debug('Raw assertion result:', assertion);
    
    if (!assertion) {
      logger.warn('User cancelled passkey authentication');
      throw new Error('authentication cancelled');
    }
    logger.debug('Assertion received successfully');
    logger.debug('Assertion object:', { 
      hasId: 'id' in assertion, 
      hasRawId: 'rawId' in assertion,
      hasType: 'type' in assertion,
      hasResponse: 'response' in assertion,
      keys: Object.keys(assertion)
    });

    // Validate assertion object has required properties
    if (!assertion.id || !assertion.rawId || !assertion.type || !assertion.response) {
      logger.error('Invalid assertion object:', assertion);
      throw new Error('Invalid passkey assertion received');
    }

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
      username: username  // Include username for server-side verification
    };

    logger.debug('Sending assertion to server for verification');
    const verifyResponse = await DpopFun.dpopFetch('POST', '/webauthn/authentication/verify', {
      body: JSON.stringify(payload),
    });
    const result = await verifyResponse.json();
    
    logger.debug('Passkey authentication completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      logger.info('User cancelled passkey authentication');
      throw new Error('Authentication cancelled by user', { 
        originalError: error.message,
        cancelled: true 
      });
    }
    
    
    // Handle other WebAuthn errors
    if (error.name === 'InvalidStateError' || error.name === 'SecurityError') {
      logger.warn('Passkey authentication failed - retryable error:', error);
      throw new Error('Authentication failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    logger.error('Passkey authentication failed:', error);
    throw new Error('Passkey authentication failed', { originalError: error.message });
  }
}