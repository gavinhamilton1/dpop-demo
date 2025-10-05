// src/services/DpopFunService.js
// DPoP-Fun-specific API service

import { ApiService } from './ApiService.js';
import * as DpopFun from '../core/dpop-fun.js';
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
    try {
      return await DpopFun.getSessionStatus();
    } catch (error) {
      throw new Error(`Failed to get session status: ${error.message}`);
    }
  }

  /**
   * Restore service state from existing session
   * This is called when we detect an existing valid session
   */
  async restoreSessionState() {
    try {
      // Use the core session restoration logic
      const sessionData = await DpopFun.restoreSession();
      
      if (sessionData.hasSession) {
        // Update service state based on restored session
        this.session = { state: sessionData.sessionStatus?.state };
        this.bik = sessionData.hasBIK ? { registered: true } : null;
        this.dpop = sessionData.hasDPoP ? { bound: true } : null;
        
        return true;
      }
      
      return false;
    } catch (error) {
      throw new Error(`Failed to restore session state: ${error.message}`);
    }
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
