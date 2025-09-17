// src/components/ButtonManager.js
// Button state management component

export class ButtonManager {
  constructor() {
    this.buttons = new Map();
    this.originalTexts = new Map();
  }

  /**
   * Enable a button and restore its original text
   * @param {string} id - Button ID
   * @param {string} text - Optional text to set (if not provided, uses original)
   */
  enable(id, text = null) {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.disabled = false;
    btn.classList.remove('loading', 'disabled');
    
    // Handle special cases for passkey buttons
    if (id === 'regBtn') {
      btn.innerHTML = '📝 Register Passkey';
      btn.title = '';
    } else if (id === 'authBtn') {
      btn.innerHTML = '🔐 Authenticate Passkey';
      btn.title = '';
    } else if (id === 'linkBtn') {
      btn.innerHTML = '📱 Start Device Linking (VDI/Step-up)';
      btn.title = '';
    } else {
      // Use provided text or restore original
      const originalText = this.originalTexts.get(id) || btn.getAttribute('data-original-text');
      btn.innerHTML = text || originalText || btn.innerHTML;
    }
  }

  /**
   * Disable a button
   * @param {string} id - Button ID
   * @param {string} reason - Optional reason text to display
   */
  disable(id, reason = null) {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = true;
      
      // Handle special cases for passkey buttons
      if ((id === 'regBtn' || id === 'authBtn') && reason) {
        btn.innerHTML = reason;
        btn.title = reason;
      }
    }
  }

  /**
   * Enable a button only if it's not in success state
   * @param {string} id - Button ID
   */
  enableIfNotSuccess(id) {
    const btn = document.getElementById(id);
    if (!btn) return;

    // Don't change button if it has success state
    if (btn.classList.contains('success') || btn.querySelector('.btn-status-icon.success')) {
      btn.disabled = false;
      return;
    }

    // Otherwise, just enable without changing text or classes
    btn.disabled = false;
  }

  /**
   * Set button to loading state
   * @param {string} id - Button ID
   * @param {string} loadingText - Text to show while loading
   */
  setLoading(id, loadingText = 'Loading...') {
    const btn = document.getElementById(id);
    if (!btn) return;

    // Store original text if not already stored
    if (!this.originalTexts.has(id)) {
      this.originalTexts.set(id, btn.innerHTML);
    }

    btn.disabled = true;
    
    // Check if this is an accent button
    const isAccentButton = btn.classList.contains('btn-accent');
    
    if (!isAccentButton) {
      btn.classList.add('loading');
    }
    
    btn.innerHTML = `⏳ ${loadingText}`;
  }

  /**
   * Set button to success state
   * @param {string} id - Button ID
   * @param {string} successText - Text to show on success
   * @param {number} resetDelay - Delay before resetting (default: 2000ms)
   */
  setSuccess(id, successText = 'Complete!', resetDelay = 2000) {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.disabled = false;
    btn.classList.remove('loading');
    
    // Check if this is an accent button
    const isAccentButton = btn.classList.contains('btn-accent');
    
    if (!isAccentButton) {
      btn.classList.add('success');
    }
    
    btn.innerHTML = `✓ ${successText}`;

    // Reset after delay (skip if resetDelay is 0)
    if (resetDelay > 0) {
      setTimeout(() => {
        if (!isAccentButton) {
          btn.classList.remove('success');
        }
        
        let originalText;
        
        if (id === 'linkBtn') {
          // For link button, always use the correct original text
          originalText = '📱 Start Device Linking (VDI/Step-up)';
        } else if (id === 'registerBrowserBtn') {
          // For register browser button, always use the correct original text
          originalText = '🔐 Register Browser & Bind DPoP';
        } else {
          originalText = this.originalTexts.get(id) || btn.getAttribute('data-original-text') || btn.innerHTML.replace(/^✓ [^!]*! /, '');
        }
        
        btn.innerHTML = `${originalText} <span class="btn-status-icon success">✓</span>`;
      }, resetDelay);
    } else {
      // For permanent success state (resetDelay = 0), set the final state immediately
      // Remove success class to get normal button color
      if (!isAccentButton) {
        btn.classList.remove('success');
      }
      
      let originalText;
      
      if (id === 'linkBtn') {
        originalText = '📱 Start Device Linking (VDI/Step-up)';
      } else if (id === 'registerBrowserBtn') {
        originalText = '🔐 Register Browser & Bind DPoP';
      } else {
        originalText = this.originalTexts.get(id) || btn.getAttribute('data-original-text') || btn.innerHTML.replace(/^✓ [^!]*! /, '');
      }
      
      btn.innerHTML = `${originalText} <span class="btn-status-icon success">✓</span>`;
    }
  }

  /**
   * Set button to error state
   * @param {string} id - Button ID
   * @param {string} errorText - Text to show on error
   * @param {number} resetDelay - Delay before resetting (default: 3000ms)
   */
  setError(id, errorText = 'Failed', resetDelay = 3000) {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.disabled = false;
    btn.classList.remove('loading');
    
    // Check if this is an accent button
    const isAccentButton = btn.classList.contains('btn-accent');
    
    if (!isAccentButton) {
      btn.classList.add('error');
    }
    
    btn.innerHTML = `✗ ${errorText}`;

    // Reset after delay
    setTimeout(() => {
      if (!isAccentButton) {
        btn.classList.remove('error');
      }
      
      const originalText = this.originalTexts.get(id) || btn.getAttribute('data-original-text') || btn.innerHTML.replace(/^✗ [^!]*! /, '');
      btn.innerHTML = `${originalText} <span class="btn-status-icon error">✗</span>`;
    }, resetDelay);
  }

  /**
   * Reset a button to its original state
   * @param {string} id - Button ID
   */
  reset(id) {
    const btn = document.getElementById(id);
    if (!btn) return;

    btn.disabled = false;
    
    // Check if this is an accent button
    const isAccentButton = btn.classList.contains('btn-accent');
    
    if (!isAccentButton) {
      btn.classList.remove('loading', 'success', 'error', 'disabled');
    }
    
    const originalText = this.originalTexts.get(id) || btn.getAttribute('data-original-text');
    if (originalText) {
      btn.innerHTML = originalText;
    }
  }

  /**
   * Reset all buttons to their original states
   */
  resetAll() {
    this.buttons.forEach((_, id) => {
      this.reset(id);
    });
  }

  /**
   * Disable multiple buttons
   * @param {string[]} ids - Array of button IDs
   */
  disableMultiple(ids) {
    ids.forEach(id => this.disable(id));
  }

  /**
   * Enable multiple buttons
   * @param {string[]} ids - Array of button IDs
   */
  enableMultiple(ids) {
    ids.forEach(id => this.enable(id));
  }

  /**
   * Get button state
   * @param {string} id - Button ID
   * @returns {Object} Button state object
   */
  getState(id) {
    const btn = document.getElementById(id);
    if (!btn) return null;

    return {
      id,
      disabled: btn.disabled,
      loading: btn.classList.contains('loading'),
      success: btn.classList.contains('success'),
      error: btn.classList.contains('error'),
      text: btn.innerHTML,
      originalText: this.originalTexts.get(id)
    };
  }

  /**
   * Check if button exists
   * @param {string} id - Button ID
   * @returns {boolean} Whether button exists
   */
  exists(id) {
    return document.getElementById(id) !== null;
  }

  /**
   * Initialize button manager with default buttons
   * @param {string[]} buttonIds - Array of button IDs to manage
   */
  initialize(buttonIds = []) {
    buttonIds.forEach(id => {
      if (this.exists(id)) {
        this.buttons.set(id, document.getElementById(id));
        // Store original text
        const btn = document.getElementById(id);
        this.originalTexts.set(id, btn.innerHTML);
      }
    });
  }
}
