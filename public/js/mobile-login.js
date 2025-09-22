/**
 * Mobile Login Controller
 * Handles mobile passkey authentication for login flow
 */
import { UnifiedMobileService } from './services/UnifiedMobileService.js';
import { logger } from './utils/logging.js';

class MobileLoginController {
  constructor() {
    this.mobileService = new UnifiedMobileService();
    this.username = null;
    this.linkId = null;
    this.init();
  }

  async init() {
    try {
      logger.info('Initializing Mobile Login Controller...');
      
      // Get username from URL parameters
      this.username = this.getUsernameFromUrl();
      if (!this.username) {
        this.showError('Username is required for mobile login');
        return;
      }
      
      // Get link ID from URL parameters
      this.linkId = this.getLinkIdFromUrl();
      if (!this.linkId) {
        this.showError('Link ID is required for mobile login');
        return;
      }
      
      logger.info(`Mobile login initialized for username: ${this.username}, link ID: ${this.linkId}`);
      
      // Start the authentication flow
      await this.startAuthenticationFlow();
      
    } catch (error) {
      logger.error('Failed to initialize mobile login:', error);
      this.showError('Failed to initialize mobile login');
    }
  }

  /**
   * Get username from URL parameters
   */
  getUsernameFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('username');
  }

  /**
   * Get link ID from URL parameters
   */
  getLinkIdFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('linkId');
  }

  /**
   * Start the mobile authentication flow
   */
  async startAuthenticationFlow() {
    try {
      logger.info('Starting mobile authentication flow...');
      
      // Initialize mobile authentication service for login flow
      await this.mobileService.initLoginFlow(
        this.username,
        this.linkId,
        this.onAuthenticationComplete.bind(this),
        this.onAuthenticationError.bind(this),
        this.onAuthenticationSuccess.bind(this)
      );
      
    } catch (error) {
      logger.error('Failed to start authentication flow:', error);
      this.showError('Failed to start authentication flow');
    }
  }

  /**
   * Handle authentication success (when passkey authentication completes)
   */
  onAuthenticationSuccess(method) {
    logger.info(`Mobile authentication successful with method: ${method}`);
    // Authentication status is handled by the desktop side through SSE
  }

  /**
   * Handle authentication completion
   */
  async onAuthenticationComplete(data) {
    try {
      logger.info('Authentication completed successfully');
      
      // Update step 2 status
      this.updateStepStatus('step-passkey', 'completed', 'Passkey authentication successful');
      
      // Update step 3 status - mobile linking is already completed by UnifiedMobileService
      this.updateStepStatus('step-complete', 'completed', 'Mobile linking completed');
      
      // Show success message
      this.showSuccess();
      
    } catch (error) {
      logger.error('Failed to complete authentication:', error);
      this.showError('Failed to complete authentication');
    }
  }

  /**
   * Handle authentication error
   */
  onAuthenticationError(error) {
    logger.error('Authentication failed:', error);
    this.showError(`Authentication failed: ${error.message}`);
  }


  /**
   * Update step status
   */
  updateStepStatus(stepId, status, message) {
    const stepEl = document.getElementById(stepId);
    if (!stepEl) return;
    
    const statusEl = stepEl.querySelector('.status-message');
    if (!statusEl) return;
    
    // Update step number color
    const stepNumber = stepEl.querySelector('.step-number');
    if (stepNumber) {
      stepNumber.className = `step-number ${status}`;
    }
    
    // Update status message
    if (status === 'active') {
      statusEl.innerHTML = `
        <div class="spinner"></div>
        <span>${message}</span>
      `;
    } else if (status === 'completed') {
      statusEl.innerHTML = `
        <div class="success-icon">✓</div>
        <span>${message}</span>
      `;
    } else if (status === 'error') {
      statusEl.innerHTML = `
        <div class="error-icon">✗</div>
        <span>${message}</span>
      `;
    }
  }

  /**
   * Show success message
   */
  showSuccess() {
    const successEl = document.getElementById('successMessage');
    if (successEl) {
      successEl.style.display = 'block';
    }
    
    // Hide all step cards
    document.querySelectorAll('.step-card').forEach(card => {
      card.style.display = 'none';
    });
  }

  /**
   * Show error message
   */
  showError(message) {
    const errorEl = document.getElementById('errorMessage');
    const errorDetails = document.getElementById('errorDetails');
    
    if (errorEl && errorDetails) {
      errorDetails.textContent = message;
      errorEl.style.display = 'block';
    }
    
    // Hide all step cards
    document.querySelectorAll('.step-card').forEach(card => {
      card.style.display = 'none';
    });
  }

  /**
   * Setup event listeners
   */
  setupEventListeners() {
    // Close button
    const closeBtn = document.getElementById('closeBtn');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        window.close();
      });
    }
    
    // Retry button
    const retryBtn = document.getElementById('retryBtn');
    if (retryBtn) {
      retryBtn.addEventListener('click', () => {
        location.reload();
      });
    }
    
    // Cancel button
    const cancelBtn = document.getElementById('cancelBtn');
    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        window.close();
      });
    }
  }
}

// Initialize the controller when the page loads
document.addEventListener('DOMContentLoaded', () => {
  const controller = new MobileLoginController();
  controller.setupEventListeners();
});
