// src/services/DpopFunService.js
// DPoP-Fun-specific API service

import { ApiService } from './ApiService.js';
import * as DpopFun from '../dpop-fun.js';
import { CONFIG } from '../utils/config.js';

export class DpopFunService extends ApiService {
  constructor() {
    super();
    this.session = null;
    this.bik = null;
    this.dpop = null;
  }

  /**
   * Initialize a new session
   * @returns {Promise<Object>} Session data
   */
  async initSession() {
    try {
      const response = await DpopFun.sessionInit({ sessionInitUrl: '/session/init' });
      this.session = response;
      return response;
    } catch (error) {
      throw new Error(`Session initialization failed: ${error.message}`);
    }
  }

  /**
   * Register BIK (Binding Identity Key)
   * @returns {Promise<Object>} BIK registration data
   */
  async registerBIK() {
    if (!this.session) {
      throw new Error('Session not initialized');
    }

    try {
      const response = await DpopFun.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
      this.bik = response;
      return response;
    } catch (error) {
      throw new Error(`BIK registration failed: ${error.message}`);
    }
  }

  /**
   * Bind DPoP (Demonstration of Proof-of-Possession)
   * @returns {Promise<Object>} DPoP binding data
   */
  async bindDPoP() {
    if (!this.session || !this.bik) {
      throw new Error('Session and BIK must be initialized');
    }

    try {
      const response = await DpopFun.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
      this.dpop = response;
      return response;
    } catch (error) {
      throw new Error(`DPoP binding failed: ${error.message}`);
    }
  }

  /**
   * Make a secure API request with DPoP
   * @param {string} url - Request URL
   * @param {Object} options - Request options
   * @returns {Promise<Object>} Response data
   */
  async secureRequest(url, options = {}) {
    if (!this.dpop) {
      throw new Error('DPoP not bound');
    }

    return DpopFun.dpopFunFetch(url, options);
  }

  /**
   * Test API endpoint
   * @param {Object} requestData - Request data
   * @returns {Promise<Object>} Test response
   */
  async testAPI(requestData) {
    return this.secureRequest('/api/echo', {
      method: 'POST',
      body: JSON.stringify(requestData)
    });
  }

  /**
   * Start cross-device linking
   * @returns {Promise<Object>} Linking data
   */
  async startLinking() {
    return this.secureRequest('/link/start', {
      method: 'POST'
    });
  }

  /**
   * Complete mobile linking
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Completion data
   */
  async completeMobileLink(linkId) {
    return this.secureRequest('/link/mobile/complete', {
      method: 'POST',
      body: JSON.stringify({ link_id: linkId })
    });
  }

  /**
   * Get linking status
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Status data
   */
  async getLinkStatus(linkId) {
    return this.secureRequest(`/link/status/${linkId}`);
  }

  /**
   * Get session status
   * @returns {Promise<Object>} Session status
   */
  async getSessionStatus() {
    return this.get('/session/status');
  }

  /**
   * Restore service state from existing session
   * This is called when we detect an existing valid session
   */
  async restoreSessionState() {
    try {
      // Get the current session status
      const status = await this.getSessionStatus();
      
      if (status.valid) {
        // For existing sessions, we need to use the session resume process
        // to get fresh binding tokens without overwriting the session
        
        // Mark that we have a session
        this.session = { state: status.state };
        
        if (status.bik_registered) {
          // Mark that we have BIK
          this.bik = { registered: true };
        }
        
        if (status.dpop_bound) {
          // Mark that we have DPoP and trigger resume to get fresh binding token
          this.dpop = { bound: true };
          
          // Use the session resume process to get fresh binding token
          await this.resumeSession();
        }
        
        return true;
      }
      
      return false;
    } catch (error) {
      throw new Error(`Failed to restore session state: ${error.message}`);
    }
  }

  /**
   * Restore session state from IndexedDB and get fresh nonces from server
   */
  async resumeSession() {
    try {
      // First restore CSRF token and reg_nonce from IndexedDB
      await DpopFun.restoreSessionTokens();
      
      // Verify we have the necessary tokens
      const csrf = await DpopFun.get(CONFIG.STORAGE.KEYS.CSRF);
      const bind = await DpopFun.get(CONFIG.STORAGE.KEYS.BIND);
      
      if (!csrf?.value) {
        throw new Error('CSRF token not found in storage');
      }
      
      if (!bind?.value) {
        throw new Error('Binding token not found in storage');
      }
      
      // Now call the server-side resume process to get fresh DPoP nonce
      const resumeSuccess = await DpopFun.resumeViaPage();
      if (!resumeSuccess) {
        throw new Error('Server-side session resume failed');
      }
      
      // Session state restored successfully with fresh nonce
      
      return true;
    } catch (error) {
      throw new Error(`Session restoration failed: ${error.message}`);
    }
  }

  /**
   * Perform a full session resume when binding token is expired
   */
  async performFullResume() {
    try {
      // Call the resume endpoints directly to get a fresh binding token
      const r1 = await this.post('/session/resume-init');
      const { resume_nonce } = r1;
      
      // Get the BIK from storage
      const bik = await DpopFun.getBIK();
      if (!bik) {
        throw new Error('BIK not found in storage');
      }
      
      // Create the resume JWS manually
      const jws = await this.createResumeJws(resume_nonce, bik);
      
      // Confirm the resume
      const r2 = await this.post('/session/resume-confirm', jws);
      const { bind } = r2;
      
      // Store the binding token
      await DpopFun.set(CONFIG.STORAGE.KEYS.BIND, bind);
      
      return true;
    } catch (error) {
      throw new Error(`Full session resume failed: ${error.message}`);
    }
  }

  /**
   * Create a resume JWS manually
   */
  async createResumeJws(resume_nonce, bik) {
    // Import the necessary crypto functions from the Stronghold module
    const { jose } = await import('../jose-lite.js');
    
    // Create the JWS payload
    const payload = {
      resume_nonce,
      iat: Math.floor(Date.now() / 1000)
    };
    
    // Create the JWS header
    const header = {
      alg: 'ES256',
      typ: 'bik-resume+jws',
      jwk: bik.publicJwk
    };
    
    // Sign the JWS
    const jws = await jose.sign(header, payload, bik.privateKey);
    
    return jws;
  }



  /**
   * Clear session data
   */
  clearSession() {
    this.session = null;
    this.bik = null;
    this.dpop = null;
  }

  /**
   * Get current session state
   * @returns {Object} Session state
   */
  getSessionState() {
    return {
      hasSession: !!this.session,
      hasBIK: !!this.bik,
      hasDPoP: !!this.dpop,
      session: this.session,
      bik: this.bik,
      dpop: this.dpop
    };
  }

  /**
   * Check if session is ready for API calls
   * @returns {boolean} Whether session is ready
   */
  isReady() {
    return !!(this.session && this.bik && this.dpop);
  }
}
