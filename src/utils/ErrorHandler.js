// src/utils/ErrorHandler.js
// Centralized error handling utility

export class ErrorHandler {
  constructor(logger = null) {
    this.logger = logger;
    this.errorTypes = {
      NETWORK: 'NETWORK_ERROR',
      AUTH: 'AUTH_ERROR',
      VALIDATION: 'VALIDATION_ERROR',
      WEBAUTHN: 'WEBAUTHN_ERROR',
      LINKING: 'LINKING_ERROR',
      UNKNOWN: 'UNKNOWN_ERROR'
    };
  }

  /**
   * Handle and categorize errors
   * @param {Error} error - Error object
   * @param {string} context - Error context
   * @returns {Object} Categorized error object
   */
  handle(error, context = '') {
    const errorInfo = this.categorizeError(error);
    
    // Log error
    if (this.logger) {
      this.logger.error(`${context}: ${error.message}`, errorInfo);
    } else {
      console.error(`${context}:`, error, errorInfo);
    }

    return {
      type: errorInfo.type,
      message: this.getUserFriendlyMessage(errorInfo),
      originalError: error,
      context,
      timestamp: new Date().toISOString(),
      ...errorInfo
    };
  }

  /**
   * Categorize error based on type and message
   * @param {Error} error - Error object
   * @returns {Object} Categorized error info
   */
  categorizeError(error) {
    const message = error.message.toLowerCase();
    const stack = error.stack || '';

    // Network errors
    if (message.includes('fetch') || message.includes('network') || 
        message.includes('http') || message.includes('timeout')) {
      return {
        type: this.errorTypes.NETWORK,
        category: 'network',
        severity: 'high',
        retryable: true
      };
    }

    // Authentication errors
    if (message.includes('auth') || message.includes('unauthorized') || 
        message.includes('forbidden') || message.includes('token')) {
      return {
        type: this.errorTypes.AUTH,
        category: 'authentication',
        severity: 'high',
        retryable: false
      };
    }

    // WebAuthn errors
    if (message.includes('webauthn') || message.includes('passkey') || 
        message.includes('credential') || message.includes('authenticator')) {
      // Check for cancellation specifically
      if (message.includes('cancelled')) {
        return {
          type: this.errorTypes.WEBAUTHN,
          category: 'webauthn',
          severity: 'low',
          retryable: false,
          cancelled: true
        };
      }
      return {
        type: this.errorTypes.WEBAUTHN,
        category: 'webauthn',
        severity: 'medium',
        retryable: true
      };
    }

    // Linking errors
    if (message.includes('link') || message.includes('qr') || 
        message.includes('device') || message.includes('cross-device')) {
      return {
        type: this.errorTypes.LINKING,
        category: 'linking',
        severity: 'medium',
        retryable: true
      };
    }

    // Validation errors
    if (message.includes('validation') || message.includes('invalid') || 
        message.includes('required') || message.includes('format')) {
      return {
        type: this.errorTypes.VALIDATION,
        category: 'validation',
        severity: 'low',
        retryable: false
      };
    }

    // Unknown errors
    return {
      type: this.errorTypes.UNKNOWN,
      category: 'unknown',
      severity: 'medium',
      retryable: false
    };
  }

  /**
   * Get user-friendly error message
   * @param {Object} errorInfo - Categorized error info
   * @returns {string} User-friendly message
   */
  getUserFriendlyMessage(errorInfo) {
    // Handle cancellation specifically
    if (errorInfo.cancelled) {
      return 'Operation cancelled by user.';
    }

    const messages = {
      [this.errorTypes.NETWORK]: 'Network connection failed. Please check your internet connection and try again.',
      [this.errorTypes.AUTH]: 'Authentication failed. Please refresh the page and try again.',
      [this.errorTypes.WEBAUTHN]: 'Passkey operation failed. Please try again or use a different authentication method.',
      [this.errorTypes.LINKING]: 'Device linking failed. Please try scanning the QR code again.',
      [this.errorTypes.VALIDATION]: 'Invalid input. Please check your data and try again.',
      [this.errorTypes.UNKNOWN]: 'An unexpected error occurred. Please try again or contact support.'
    };

    return messages[errorInfo.type] || messages[this.errorTypes.UNKNOWN];
  }

  /**
   * Check if error is retryable
   * @param {Error} error - Error object
   * @returns {boolean} Whether error is retryable
   */
  isRetryable(error) {
    const errorInfo = this.categorizeError(error);
    return errorInfo.retryable;
  }

  /**
   * Get error severity
   * @param {Error} error - Error object
   * @returns {string} Error severity ('low', 'medium', 'high')
   */
  getSeverity(error) {
    const errorInfo = this.categorizeError(error);
    return errorInfo.severity;
  }

  /**
   * Create a retry wrapper for async functions
   * @param {Function} fn - Function to retry
   * @param {number} maxRetries - Maximum retry attempts
   * @param {number} delay - Delay between retries in ms
   * @returns {Function} Retry wrapper function
   */
  createRetryWrapper(fn, maxRetries = 3, delay = 1000) {
    return async (...args) => {
      let lastError;
      
      for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
          return await fn(...args);
        } catch (error) {
          lastError = error;
          
          if (!this.isRetryable(error) || attempt === maxRetries) {
            throw error;
          }
          
          // Wait before retrying
          await new Promise(resolve => setTimeout(resolve, delay * attempt));
        }
      }
      
      throw lastError;
    };
  }

  /**
   * Handle async function with error handling
   * @param {Function} fn - Async function to execute
   * @param {string} context - Error context
   * @param {Function} onError - Error callback
   * @returns {Promise} Function result
   */
  async handleAsync(fn, context = '', onError = null) {
    try {
      return await fn();
    } catch (error) {
      const handledError = this.handle(error, context);
      
      if (onError) {
        onError(handledError);
      }
      
      throw handledError;
    }
  }

  /**
   * Show error notification to user
   * @param {Object} error - Handled error object
   * @param {string} containerId - Container ID for notification
   */
  showNotification(error, containerId = 'notifications') {
    const container = document.getElementById(containerId);
    if (!container) return;

    const notification = document.createElement('div');
    notification.className = `notification notification-${error.type.toLowerCase()}`;
    
    // Create notification content without inline handlers
    const content = document.createElement('div');
    content.className = 'notification-content';
    content.innerHTML = `
      <div class="notification-title">${this.getSeverityTitle(error.severity)}</div>
      <div class="notification-message">${error.message}</div>
    `;
    
    // Create close button with proper event listener
    const closeBtn = document.createElement('button');
    closeBtn.className = 'notification-close';
    closeBtn.textContent = '×';
    closeBtn.addEventListener('click', () => {
      notification.remove();
    });
    
    notification.appendChild(content);
    notification.appendChild(closeBtn);
    container.appendChild(notification);

    // Auto-remove after 5 seconds
    setTimeout(() => {
      if (notification.parentElement) {
        notification.remove();
      }
    }, 5000);
  }

  /**
   * Get severity title
   * @param {string} severity - Error severity
   * @returns {string} Severity title
   */
  getSeverityTitle(severity) {
    const titles = {
      low: 'Information',
      medium: 'Warning',
      high: 'Error'
    };
    return titles[severity] || 'Error';
  }

  /**
   * Set logger instance
   * @param {Logger} logger - Logger instance
   */
  setLogger(logger) {
    this.logger = logger;
  }
}
