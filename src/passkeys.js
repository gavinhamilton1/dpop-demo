// /src/passkeys.js
import * as Stronghold from '/src/stronghold.js';
import { b64uToBuf, bufToB64u } from '/src/jose-lite.js';
import { cryptoLogger } from './utils/logging.js';
import { AuthenticationError, NetworkError } from './utils/errors.js';

export async function checkSupport() {
  try {
    cryptoLogger.debug('Checking WebAuthn support');
    const hasAPI = !!(window.PublicKeyCredential && navigator.credentials);
    const uvp = hasAPI && await PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable?.().catch(() => false);
    const result = { hasAPI, uvp: !!uvp };
    cryptoLogger.debug('WebAuthn support check result:', result);
    return result;
  } catch (error) {
    cryptoLogger.error('Failed to check WebAuthn support:', error);
    throw new AuthenticationError('Failed to check WebAuthn support', { originalError: error.message });
  }
}

// ----- Registration -----
export async function registerPasskey() {
  try {
    cryptoLogger.debug('Starting passkey registration');
    
    // 1) get options
    const opts = await Stronghold.strongholdFetch('/webauthn/registration/options', { method: 'POST' });
    cryptoLogger.debug('Registration options received');

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
    cryptoLogger.debug('Creating credential with navigator.credentials.create');
    const cred = await navigator.credentials.create({ publicKey: pub });
    if (!cred) {
      cryptoLogger.warn('User cancelled passkey registration');
      throw new AuthenticationError('registration cancelled');
    }
    cryptoLogger.debug('Credential created successfully');

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

    cryptoLogger.debug('Sending attestation to server for verification');
    const result = await Stronghold.strongholdFetch('/webauthn/registration/verify', {
      method: 'POST',
      body: att,
    });
    
    cryptoLogger.debug('Passkey registration completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      cryptoLogger.info('User cancelled passkey registration');
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
      cryptoLogger.warn('Passkey registration failed - retryable error:', error);
      throw new AuthenticationError('Registration failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    cryptoLogger.error('Passkey registration failed:', error);
    throw new AuthenticationError('Passkey registration failed', { originalError: error.message });
  }
}

// ----- Authentication (preflight-able) -----

export async function getAuthOptions() {
  try {
    cryptoLogger.debug('Getting authentication options');
    const options = await Stronghold.strongholdFetch('/webauthn/authentication/options', { method: 'POST' });
    cryptoLogger.debug('Authentication options received');
    return options;
  } catch (error) {
    cryptoLogger.error('Failed to get authentication options:', error);
    if (error.name === 'NetworkError') throw error;
    throw new AuthenticationError('Failed to get authentication options', { originalError: error.message });
  }
}

export async function authenticatePasskey(passedOpts) {
  try {
    cryptoLogger.debug('Starting passkey authentication');
    
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

    cryptoLogger.debug('Getting assertion with navigator.credentials.get');
    const assertion = await navigator.credentials.get({ publicKey: pub });
    if (!assertion) {
      cryptoLogger.warn('User cancelled passkey authentication');
      throw new AuthenticationError('authentication cancelled');
    }
    cryptoLogger.debug('Assertion received successfully');

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

    cryptoLogger.debug('Sending assertion to server for verification');
    const result = await Stronghold.strongholdFetch('/webauthn/authentication/verify', {
      method: 'POST',
      body: payload,
    });
    
    cryptoLogger.debug('Passkey authentication completed successfully');
    return result;
  } catch (error) {
    // Handle user cancellation gracefully first
    if (error.name === 'NotAllowedError') {
      cryptoLogger.info('User cancelled passkey authentication');
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
      cryptoLogger.warn('Passkey authentication failed - retryable error:', error);
      throw new AuthenticationError('Authentication failed - please try again', { 
        originalError: error.message,
        retryable: true 
      });
    }
    
    // Log other errors as errors
    cryptoLogger.error('Passkey authentication failed:', error);
    throw new AuthenticationError('Passkey authentication failed', { originalError: error.message });
  }
}
