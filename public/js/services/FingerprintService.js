/**
 * FingerprintService - Centralized fingerprint collection service
 * Collects device fingerprinting data including User Agent Client Hints and automation detection
 */

export class FingerprintService {
  /**
   * Helper function for safe property access
   * @param {Function} fn - Function to execute safely
   * @param {*} fallback - Fallback value if function throws
   * @returns {*} Result of function or fallback value
   */
  static safe(fn, fallback = null) {
    try { 
      return fn(); 
    } catch { 
      return fallback; 
    }
  }

  /**
   * Get WebGL vendor information
   * @returns {string} WebGL vendor or 'unknown'
   */
  static getWebGLVendor() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'unknown';
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'unknown';
      
      return gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL);
    } catch (e) {
      return 'unknown';
    }
  }

  /**
   * Get WebGL renderer information
   * @returns {string} WebGL renderer or 'unknown'
   */
  static getWebGLRenderer() {
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (!gl) return 'unknown';
      
      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
      if (!debugInfo) return 'unknown';
      
      return gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
    } catch (e) {
      return 'unknown';
    }
  }

  /**
   * Collect User Agent Client Hints data
   * @returns {Promise<Object|null>} UA-CH data or null if not supported
   */
  static async collectUserAgentClientHints() {
    try {
      const uaCh = await navigator.userAgentData?.getHighEntropyValues([
        'platform', 'platformVersion', 'architecture', 'model', 
        'uaFullVersion', 'bitness', 'fullVersionList'
      ]).catch(() => null);

      if (!uaCh) return null;

      return {
        mobile: navigator.userAgentData?.mobile ?? null,
        platform: uaCh.platform,
        platformVersion: uaCh.platformVersion,
        architecture: uaCh.architecture,
        model: uaCh.model,
        uaFullVersion: uaCh.uaFullVersion,
        bitness: uaCh.bitness,
        fullVersionList: uaCh.fullVersionList
      };
    } catch (error) {
      console.warn('Failed to collect User Agent Client Hints:', error);
      return null;
    }
  }

  /**
   * Collect automation detection data
   * @returns {Promise<Object>} Automation detection data
   */
  static async collectAutomationData() {
    try {
      const automation = {
        webdriver: !!navigator.webdriver,
        headlessUA: /\bHeadlessChrome\b/i.test(navigator.userAgent || ''),
        // Selenium/Puppeteer often patch these; treat as soft
        pluginsLength: this.safe(() => navigator.plugins?.length ?? null, null),
        mimeTypesLength: this.safe(() => navigator.mimeTypes?.length ?? null, null),
        permissionsAnomalies: await (async () => {
          if (!navigator.permissions?.query) return null;
          try {
            const names = ['notifications','camera','microphone'];
            const results = {};
            for (const n of names) {
              const s = await navigator.permissions.query({ name: n });
              results[n] = s.state; // 'granted'|'denied'|'prompt'
            }
            return results;
          } catch { return null; }
        })(),
        // Focus/visibility at capture time (bots often offscreen)
        visibilityState: document.visibilityState,
        hasFocus: document.hasFocus?.() ?? null
      };

      return automation;
    } catch (error) {
      console.warn('Failed to collect automation data:', error);
      return {
        webdriver: false,
        headlessUA: false,
        pluginsLength: null,
        mimeTypesLength: null,
        permissionsAnomalies: null,
        visibilityState: 'unknown',
        hasFocus: null
      };
    }
  }

  /**
   * Collect comprehensive device fingerprint
   * @param {string} deviceType - 'desktop' or 'mobile'
   * @returns {Promise<Object>} Complete fingerprint data
   */
  static async collectFingerprint(deviceType = 'unknown') {
    try {
      console.log(`🔍 FINGERPRINT COLLECTION STARTED for ${deviceType}`);
      
      // Collect User Agent Client Hints data
      const uaCh = await this.collectUserAgentClientHints();
      
      // Collect automation detection data
      const automation = await this.collectAutomationData();
      
      // Collect basic device information
      const fingerprint = {
        userAgent: navigator.userAgent,
        screenResolution: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        language: navigator.language,
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency || 'unknown',
        deviceMemory: navigator.deviceMemory || 'unknown',
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack || 'unknown',
        webglVendor: this.getWebGLVendor(),
        webglRenderer: this.getWebGLRenderer(),
        ua_ch: uaCh,
        automation: automation,
        timestamp: new Date().toISOString(),
        deviceType: deviceType
      };

      console.log(`FINGERPRINT COLLECTION COMPLETED for ${deviceType}:`, Object.keys(fingerprint).length, 'signals');
      return fingerprint;
      
    } catch (error) {
      console.error(`FINGERPRINT COLLECTION FAILED for ${deviceType}:`, error);
      throw error;
    }
  }

  /**
   * Send fingerprint data to server
   * @param {Object} fingerprint - Fingerprint data to send
   * @returns {Promise<Object>} Server response
   */
  static async sendFingerprintToServer(fingerprint) {
    try {
      console.log('📤 Sending fingerprint to server...');
      
      const response = await fetch('/session/fingerprint', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify(fingerprint)
      });

      if (!response.ok) {
        const errorText = await response.text();
        throw new Error(`Failed to store fingerprint: ${response.status} ${errorText}`);
      }

      const result = await response.json();
      console.log('Fingerprint sent to server successfully');
      return result;
      
    } catch (error) {
      console.error('Failed to send fingerprint to server:', error);
      throw error;
    }
  }

  /**
   * Collect and send fingerprint data in one operation
   * @param {string} deviceType - 'desktop' or 'mobile'
   * @returns {Promise<Object>} Server response
   */
  static async collectAndSendFingerprint(deviceType = 'unknown') {
    try {
      const fingerprint = await this.collectFingerprint(deviceType);
      const result = await this.sendFingerprintToServer(fingerprint);
      return result;
    } catch (error) {
      console.error(`Failed to collect and send fingerprint for ${deviceType}:`, error);
      throw error;
    }
  }
}
