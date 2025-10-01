/**
 * Unified Mobile Service
 * Consolidates all mobile authentication and linking functionality
 */
import * as DpopFun from '../core/dpop-fun.js';
import * as Passkeys from '../core/passkeys.js';
import { FingerprintService } from './FingerprintService.js';
import { logger } from '../utils/logging.js';
import { CONFIG } from '../utils/config.js';

export class UnifiedMobileService {
  constructor() {
    this.currentLinkId = null;
    this.isLoginFlow = false;
    this.username = null;
    this.desktopUsername = null;
    this.onComplete = null;
    this.onError = null;
    this.onAuthenticated = null;
  }

  /**
   * Initialize for registration flow (desktop-initiated)
   * @param {string} linkId - Link ID from QR scan
   * @param {Function} onComplete - Callback when complete
   * @param {Function} onError - Callback when error
   * @param {Function} onAuthenticated - Callback when authenticated
   */
  async initRegistrationFlow(linkId, onComplete, onError, onAuthenticated = null) {
    this.isLoginFlow = false;
    this.currentLinkId = linkId;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onAuthenticated = onAuthenticated;
    
    logger.info('Initializing mobile registration flow');
    
    // Start the mobile linking process to get desktop username
    await this.startMobileLinking();
    
    return this.startMobileSession();
  }

  /**
   * Initialize for login flow (desktop-initiated)
   * @param {string} username - Username to authenticate
   * @param {string} linkId - Link ID from QR scan
   * @param {Function} onComplete - Callback when complete
   * @param {Function} onError - Callback when error
   * @param {Function} onAuthenticated - Callback when authenticated
   */
  async initLoginFlow(username, linkId, onComplete, onError, onAuthenticated = null) {
    this.isLoginFlow = true;
    this.username = username;
    this.currentLinkId = linkId;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onAuthenticated = onAuthenticated;
    
    logger.info(`Initializing mobile login flow for username: ${username}`);
    return this.startMobileSession();
  }

  /**
   * Start mobile session and begin authentication process
   */
  async startMobileSession() {
    try {
      logger.info('Setting up mobile session...');
      
      // Step 1: Setup fresh mobile session
      const sessionData = await DpopFun.initializeFreshSession();
      logger.info('Mobile session setup completed');
      
      // Step 2: Collect mobile device fingerprint
      await this.collectMobileFingerprint();
      
      // Step 3: Set username for both flows
      if (this.isLoginFlow) {
        await this.setUsernameForLogin();
      } else {
        await this.setUsernameForRegistration();
      }
      
      // Step 4: Handle passkey authentication
      await this.handlePasskeyAuthentication();
      
      // Step 5: Complete mobile linking for both flows
      await this.completeMobileLinking();
      
    } catch (error) {
      logger.error('Mobile session setup failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Collect mobile device fingerprint
   */
  async collectMobileFingerprint() {
    try {
      logger.info('Starting mobile fingerprint collection...');
      
      // Small delay to ensure session is established
      await new Promise(resolve => setTimeout(resolve, 100));
      
      await FingerprintService.collectFingerprint('mobile');
      logger.info('Mobile fingerprint collection completed successfully');
      
    } catch (error) {
      logger.warn(`Mobile fingerprint collection failed: ${error.message}`);
      // Continue with authentication flow even if fingerprinting fails
    }
  }

  /**
   * Start mobile linking process to get desktop username
   */
  async startMobileLinking() {
    try {
      logger.info('Starting mobile linking process...');
      
      // Call the mobile link start endpoint to get desktop username
      const data = await DpopFun.dpopFunFetch('/link/mobile/start', {
        method: 'POST',
        body: { lid: this.currentLinkId }
      });
      
      logger.info('Link start response data:', data);
      this.desktopUsername = data.desktop_username;
      
      logger.info(`Desktop username received from linking: ${this.desktopUsername}`);
      
    } catch (error) {
      logger.error('Failed to start mobile linking:', error);
      throw error;
    }
  }

  /**
   * Set username for login flow using provided username
   */
  async setUsernameForLogin() {
    try {
      logger.info(`Setting username for mobile login flow: ${this.username}`);
      
      if (!this.username) {
        throw new Error('No username provided for login flow');
      }
      
      // For login flow, we need to set the username in the session for passkey authentication
      // We'll use the existing username for authentication without creating a new user record
      logger.info('Using existing username for mobile login flow authentication');
      
      // Store the username in the mobile session for passkey authentication
      // This doesn't create a new user record, just sets the username in the session
      await DpopFun.dpopFunFetch('/onboarding/signin', {
        method: 'POST',
        body: { username: this.username }
      });
      
      logger.info('Username set in mobile session for authentication');
      
    } catch (error) {
      logger.error('Failed to set username for mobile login:', error);
      throw error;
    }
  }

  /**
   * Set username for registration flow using desktop session username
   */
  async setUsernameForRegistration() {
    try {
      logger.info('Setting desktop username for mobile registration flow...');
      
      if (!this.desktopUsername) {
        logger.warn('No desktop username available from linking process, generating fallback username');
        // Generate a fallback username for mobile registration
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 8);
        this.desktopUsername = `mobile_${timestamp}_${random}`;
        logger.info(`Generated fallback username: ${this.desktopUsername}`);
      }
      
      logger.info(`Using username for mobile registration: ${this.desktopUsername}`);
      
      // For registration flow, try to create a new username first
      // If it already exists, use the existing one
      try {
        await DpopFun.dpopFunFetch('/onboarding/username', {
          method: 'POST',
          body: { username: this.desktopUsername }
        });
        logger.info('New username created successfully for mobile registration');
      } catch (error) {
        if (error.message && error.message.includes('Username already taken')) {
          logger.info('Username already exists, using existing username for mobile registration');
          // Use the existing username by signing in
          await DpopFun.dpopFunFetch('/onboarding/signin', {
            method: 'POST',
            body: { username: this.desktopUsername }
          });
          logger.info('Existing username linked to mobile session');
        } else {
          throw error;
        }
      }
      
    } catch (error) {
      logger.error('Failed to bind username for mobile registration:', error);
      throw error;
    }
  }

  /**
   * Handle passkey authentication based on flow type
   */
  async handlePasskeyAuthentication() {
    try {
      if (this.isLoginFlow) {
        // For login flow, create a new passkey on the mobile device
        // This allows cross-device authentication by creating a new passkey
        // linked to the existing user account
        logger.info('Login flow - creating new passkey for cross-device authentication...');
        await this.createNewPasskeyForLogin();
      } else {
        // For registration flow, create new passkey with platform authenticator
        logger.info('Registration flow - creating new passkey with platform authenticator...');
        await this.createNewPasskeyForRegistration();
      }
    } catch (error) {
      logger.error('Passkey authentication failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Create new passkey for login flow (cross-device authentication)
   */
  async createNewPasskeyForLogin() {
    try {
      logger.info('Creating new passkey for login flow (cross-device authentication)...');
      
      // Register new passkey using platform authenticator
      // The registerPasskey function will get options from server and handle registration
      logger.info('Calling Passkeys.registerPasskey() for login flow...');
      const result = await Passkeys.registerPasskey();
      logger.info('Passkeys.registerPasskey() completed successfully for login flow:', result);
      
      logger.info('New passkey created successfully for login flow');
      
      // Mark user as authenticated in session
      await this.markUserAsAuthenticated();
      
      // Notify about authentication
      if (this.onAuthenticated) {
        this.onAuthenticated('mobile passkey');
      }
      
    } catch (error) {
      logger.error('Failed to create new passkey for login:', error);
      logger.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
      throw error;
    }
  }

  /**
   * Create new passkey for registration flow using platform authenticator
   */
  async createNewPasskeyForRegistration() {
    try {
      logger.info('Creating new passkey for registration flow...');
      
      // Register new passkey using platform authenticator
      // The registerPasskey function will get options from server and handle registration
      logger.info('Calling Passkeys.registerPasskey()...');
      const result = await Passkeys.registerPasskey();
      logger.info('Passkeys.registerPasskey() completed successfully:', result);
      
      logger.info('New passkey created successfully for registration flow');
      
      // Set mobile authentication for registration flow (without trying to authenticate again)
      await this.setMobileAuthForRegistration();
      
      // Notify about authentication
      if (this.onAuthenticated) {
        this.onAuthenticated('mobile passkey');
      }
      
    } catch (error) {
      logger.error('Failed to create new passkey for registration:', error);
      logger.error('Error details:', {
        name: error.name,
        message: error.message,
        stack: error.stack
      });
      // If passkey creation fails, fall back to setting session values
      await this.setMobileAuthForRegistration();
    }
  }

  /**
   * Set mobile authentication for registration flow (without passkey)
   */
  async setMobileAuthForRegistration() {
    try {
      logger.info('Setting mobile authentication for registration flow...');
      
      // Get the current session status to get the username
      const sessionData = await DpopFun.dpopFunFetch('/session/status');
      const username = sessionData.username;
      
      if (!username) {
        throw new Error('No username found in session for mobile registration');
      }
      
      // Store the authentication data in the session for later use
      // This will be used by the mobile linking completion
      this.registrationAuthData = {
        passkey_auth: true,
        passkey_principal: username, // Use username as principal
        mobile_auth: true
      };
      
      // Update the session with the authentication data
      await DpopFun.dpopFunFetch('/session/update-auth', {
        method: 'POST',
        body: {
          passkey_auth: true,
          passkey_principal: username, // Use username as principal
          mobile_auth: true
        }
      });
      
      logger.info('Mobile authentication data prepared and set in session for registration flow');
      
    } catch (error) {
      logger.error('Failed to set mobile authentication for registration:', error);
      throw error;
    }
  }

  /**
   * Authenticate with existing passkey for login flow
   */
  async authenticateWithExistingPasskey() {
    try {
      logger.info('Authenticating with existing passkey...');
      
      // Get authentication options for the username
      const authOptions = await this.getAuthOptionsForUser(this.username);
      
      if (!authOptions || !authOptions.allowCredentials || authOptions.allowCredentials.length === 0) {
        logger.info('No existing passkey found for login flow');
        throw new Error('No passkey registered for this user. Please complete registration first.');
      }
      
      // Authenticate with passkey
      await Passkeys.authenticatePasskey(authOptions);
      logger.info('Passkey authentication successful');
      
      // Mark user as authenticated in session
      await this.markUserAsAuthenticated();
      
      // Notify about authentication
      if (this.onAuthenticated) {
        this.onAuthenticated('mobile passkey');
      }
      
    } catch (error) {
      logger.error('Passkey authentication failed:', error);
      throw error;
    }
  }


  /**
   * Register new passkey for registration flow
   */
  async registerNewPasskey() {
    try {
      logger.info('Registering new passkey...');
      
      // Check if passkey already exists
      let authOptions = null;
      try {
        authOptions = await Passkeys.getAuthOptions();
        const hasCreds = !!(authOptions.allowCredentials && authOptions.allowCredentials.length);
        
        if (hasCreds) {
          logger.info('Passkey already exists, authenticating instead');
          await Passkeys.authenticatePasskey(authOptions);
        } else {
          logger.info('No existing passkey, registering new one');
          await Passkeys.registerPasskey();
        }
      } catch (error) {
        logger.info('No existing passkey, registering new one');
        await Passkeys.registerPasskey();
      }
      
      logger.info('Passkey registration/authentication successful');
      
    } catch (error) {
      logger.error('Passkey registration failed:', error);
      throw error;
    }
  }

  /**
   * Get authentication options for a specific user
   * @param {string} username - Username to get auth options for
   */
  async getAuthOptionsForUser(username) {
    try {
      logger.info(`Getting authentication options for user: ${username}`);
      
      const response = await DpopFun.dpopFunFetch('/webauthn/authentication/options', {
        method: 'POST',
        body: { username }
      });
      
      return response;
    } catch (error) {
      logger.error('Failed to get authentication options:', error);
      
      // If user has no BIK, return null to indicate no existing passkey
      if (error.message && error.message.includes('User has no registered BIK')) {
        logger.info('User has no BIK registered, will create new passkey');
        return null;
      }
      
      throw error;
    }
  }

  /**
   * Mark user as authenticated in the session
   */
  async markUserAsAuthenticated() {
    try {
      logger.info('Marking user as authenticated in session...');
      
      const response = await DpopFun.dpopFunFetch('/session/mark-authenticated', {
        method: 'POST',
        body: { 
          username: this.username,
          passkey_auth: true,
          passkey_principal: this.username
        }
      });
      
      logger.info('User marked as authenticated successfully');
      return response;
      
    } catch (error) {
      logger.error('Failed to mark user as authenticated:', error);
      throw error;
    }
  }

  /**
   * Complete mobile linking process
   */
  async completeMobileLinking() {
    try {
      logger.info(`Completing mobile linking for link ID: ${this.currentLinkId}`);
      
      // Check session status before completing
      try {
        const sessionStatus = await DpopFun.getSessionStatus();
        logger.info('Session status before mobile linking completion:', {
          hasSession: sessionStatus.valid,
          passkey_auth: sessionStatus.passkey_auth,
          passkey_principal: sessionStatus.passkey_principal,
          username: sessionStatus.username
        });
      } catch (error) {
        logger.warn('Could not check session status before mobile linking completion:', error);
      }
      
      // Complete the mobile linking process
      const completeData = await DpopFun.dpopFunFetch('/link/mobile/complete', {
        method: 'POST',
        body: { link_id: this.currentLinkId }
      });
      
      logger.info('Mobile link completed successfully');
      
      if (this.onComplete) {
        this.onComplete(completeData);
      }
      
      return completeData;
      
    } catch (error) {
      logger.error('Mobile linking completion failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Issue bootstrap code for desktop verification (registration flow only)
   */
  async issueBootstrapCode() {
    if (this.isLoginFlow) {
      logger.info('Skipping bootstrap code for login flow');
      return;
    }

    try {
      logger.info(`Issuing bootstrap code for link ID: ${this.currentLinkId}`);
      
      const response = await DpopFun.dpopFunFetch('/link/mobile/issue-bc', {
        method: 'POST',
        body: { link_id: this.currentLinkId }
      });
      
      logger.info('Bootstrap code issued successfully');
      return response;
      
    } catch (error) {
      logger.error('Failed to issue bootstrap code:', error);
      throw error;
    }
  }
}
