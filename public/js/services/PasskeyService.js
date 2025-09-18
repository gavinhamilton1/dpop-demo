// src/services/PasskeyService.js
// WebAuthn/Passkey service

import { ApiService } from './ApiService.js';
import * as Passkeys from '../passkeys.js';

export class PasskeyService extends ApiService {
  constructor() {
    super();
    this.isSupported = this.checkSupport();
  }

  /**
   * Check if WebAuthn is supported
   * @returns {boolean} Whether WebAuthn is supported
   */
  checkSupport() {
    return window.PublicKeyCredential && 
           typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
  }

  /**
   * Check if user-verifying platform authenticator is available
   * @returns {Promise<boolean>} Whether UVPA is available
   */
  async isUserVerifyingPlatformAuthenticatorAvailable() {
    if (!this.isSupported) {
      return false;
    }
    
    try {
      return await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable();
    } catch (error) {
      console.warn('UVPA check failed:', error);
      return false;
    }
  }



  /**
   * Register a new passkey
   * @returns {Promise<Object>} Registration result
   */
  async registerPasskey() {
    if (!this.isSupported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    try {
      return await Passkeys.registerPasskey();
    } catch (error) {
      // Check if this is a cancellation error
      if (error.message && error.message.includes('cancelled')) {
        throw new Error('Registration cancelled by user');
      }
      throw new Error(`Passkey registration failed: ${error.message}`);
    }
  }

  /**
   * Authenticate with existing passkey
   * @param {Object} authOptions - Authentication options (optional)
   * @returns {Promise<Object>} Authentication result
   */
  async authenticatePasskey(authOptions = null) {
    if (!this.isSupported) {
      throw new Error('WebAuthn is not supported in this browser');
    }

    try {
      return await Passkeys.authenticatePasskey(authOptions);
    } catch (error) {
      // Check if this is a cancellation error
      if (error.message && error.message.includes('cancelled')) {
        throw new Error('Authentication cancelled by user');
      }
      throw new Error(`Passkey authentication failed: ${error.message}`);
    }
  }

  /**
   * Check if passkeys exist for the current domain
   * @returns {Promise<boolean>} Whether passkeys exist
   */
  async hasExistingPasskeys() {
    try {
      // Only check if we have DPoP binding (authentication)
      if (!this.isAuthenticated()) {
        return false;
      }
      const options = await Passkeys.getAuthOptions();
      return options.allowCredentials && options.allowCredentials.length > 0;
    } catch (error) {
      console.warn('Failed to check existing passkeys:', error);
      return false;
    }
  }

  /**
   * Check if the service is authenticated (has DPoP binding)
   * @returns {boolean} Whether authenticated
   */
  isAuthenticated() {
    // This should be set by the AppController when DPoP is bound
    return this.authenticated || false;
  }

  /**
   * Set authentication status
   * @param {boolean} status - Authentication status
   */
  setAuthenticated(status) {
    this.authenticated = status;
  }



  /**
   * Get passkey support status
   * @returns {Promise<Object>} Support status
   */
  async getSupportStatus() {
    return {
      isSupported: this.isSupported,
      hasUVPA: await this.isUserVerifyingPlatformAuthenticatorAvailable(),
      hasCredentials: await this.hasExistingPasskeys()
    };
  }

  /**
   * Get basic passkey support status (browser only, no server check)
   * @returns {Promise<Object>} Support status
   */
  async getBasicSupportStatus() {
    return {
      isSupported: this.isSupported,
      hasUVPA: await this.isUserVerifyingPlatformAuthenticatorAvailable(),
      hasCredentials: false // Will be checked later when authenticated
    };
  }
}
