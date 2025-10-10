/**
 * Mobile Controller
 * Handles mobile device linking flows (both registration and login)
 */

import { MobileLinkService } from './mobilelink.js';
import { logger } from './utils/logging.js';

class MobileController {
  constructor() {
    this.mobileLinkService = new MobileLinkService();
    this.linkId = null;
    this.username = null;
    this.bcTimerInterval = null;
    this.verificationPollInterval = null;
    this.eventSource = null;
    this.sseRetried = false;
    this.init();
  }

  async init() {
    try {
      logger.info('Initializing Mobile Controller...');
      
      // Get link ID from URL parameters
      this.linkId = this.getLinkIdFromUrl();
      if (!this.linkId) {
        this.showError('Invalid link - Link ID is required');
        return;
      }
      
      logger.info('Link ID from URL:', this.linkId);
      
      // Determine flow type from URL (optional parameter)
      const urlParams = new URLSearchParams(window.location.search);
      const flowType = urlParams.get('flow') || 'registration';
      
      // Start the appropriate flow
      if (flowType === 'login') {
        await this.startLoginFlow();
      } else {
        await this.startRegistrationFlow();
      }
      
    } catch (error) {
      logger.error('Failed to initialize mobile controller:', error);
      this.showError(`Initialization failed: ${error.message}`);
    }
  }

  /**
   * Start registration flow (link mobile device and create passkey)
   */
  async startRegistrationFlow() {
    try {
      logger.info('Starting mobile registration flow...');
      this.updateStep(1, 'active', 'Setting up mobile session...');
      
      await this.mobileLinkService.initMobileRegistrationFlow(
        this.linkId,
        (data) => this.onComplete(data),
        (error) => this.onError(error),
        (authMethod) => this.onAuthenticated(authMethod),
        () => this.onSessionSetup()  // Callback when session setup completes
      );
      
    } catch (error) {
      logger.error('Registration flow failed:', error);
      this.showError(`Registration failed: ${error.message}`);
    }
  }

  /**
   * Handle session setup completion (step 1)
   */
  onSessionSetup() {
    logger.info('Mobile session setup completed');
    this.updateStep(1, 'completed', 'Mobile session ready');
    this.updateStep(2, 'active', 'Verifying identity...');
  }

  /**
   * Start login flow (authenticate with existing passkey)
   */
  async startLoginFlow() {
    try {
      logger.info('Starting mobile login flow...');
      
      // Get username from desktop session via linking
      this.updateStep(1, 'active', 'Connecting to desktop session...');
      
      // First, link mobile to desktop to get username
      const response = await fetch('/link/mobile/start', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ lid: this.linkId })
      });
      
      if (!response.ok) {
        throw new Error('Failed to connect to desktop session');
      }
      
      const data = await response.json();
      this.username = data.desktop_username;
      
      if (!this.username) {
        throw new Error('Username not found in desktop session');
      }
      
      logger.info('Desktop username received:', this.username);
      this.updateStep(1, 'completed', 'Connected to desktop session');
      
      // Now start the mobile login flow
      this.updateStep(2, 'active', 'Authenticating with passkey...');
      
      await this.mobileLinkService.initMobileLoginFlow(
        this.username,
        this.linkId,
        (data) => this.onComplete(data),
        (error) => this.onError(error),
        (authMethod) => this.onAuthenticated(authMethod)
      );
      
    } catch (error) {
      logger.error('Login flow failed:', error);
      this.showError(`Login failed: ${error.message}`);
    }
  }

  /**
   * Handle authentication success (step 2 complete)
   */
  onAuthenticated(authMethod) {
    logger.info('Authentication successful:', authMethod);
    this.updateStep(2, 'completed', 'Identity verified');
    this.updateStep(3, 'active', 'Finalizing...');
  }

  /**
   * Handle completion
   */
  async onComplete(data) {
    logger.info('Mobile linking completed:', data);
    this.updateStep(3, 'completed', 'Linking complete!');
    
    // Show bootstrap code if in registration flow
    if (this.mobileLinkService.flowType === 'registration') {
      await this.showBootstrapCode();
    } else {
      this.showSuccess('Mobile device linked successfully!');
    }
  }

  /**
   * Handle error
   */
  onError(error) {
    logger.error('Mobile linking error:', error);
    this.showError(`Error: ${error.message}`);
    this.updateStep(1, 'error', 'Failed');
  }

  /**
   * Show bootstrap code for desktop verification
   */
  async showBootstrapCode() {
    try {
      logger.info('Requesting bootstrap code...');
      
      const bcData = await this.mobileLinkService.issueBootstrapCode();
      
      if (!bcData || !bcData.bc) {
        throw new Error('Failed to get bootstrap code');
      }
      
      logger.info('Bootstrap code received:', bcData.bc);
      
      // Show BC card
      const bcCard = document.getElementById('bcCard');
      const bcCodeEl = document.getElementById('bcCode');
      const bcQREl = document.getElementById('bcQR');
      const bcTimerEl = document.getElementById('bcTimer');
      
      if (bcCard && bcCodeEl) {
        // Format BC code as XXXX-XXXX
        const formattedBC = bcData.bc.length === 8 
          ? `${bcData.bc.substring(0, 4)}-${bcData.bc.substring(4)}`
          : bcData.bc;
        bcCodeEl.textContent = formattedBC;
        bcCard.classList.add('active');
        
        // Generate QR code for BC
        if (bcQREl && window.QRCode) {
          bcQREl.innerHTML = '';
          const bcUrl = `/verify/device?bc=${bcData.bc}`;
          new QRCode(bcQREl, {
            text: bcUrl,
            width: 200,
            height: 200,
            colorDark: '#000000',
            colorLight: '#FFFFFF',
            correctLevel: QRCode.CorrectLevel.M
          });
        }
        
        // Start countdown timer
        const expiresAt = bcData.expires_at || 60;
        this.startBCTimer(expiresAt, bcTimerEl);
        
        // Add cancel button handler
        const bcCancelBtn = document.getElementById('bcCancel');
        if (bcCancelBtn) {
          bcCancelBtn.addEventListener('click', () => {
            bcCard.classList.remove('active');
            this.stopPollingForVerification();
            this.showMessage('Bootstrap code cancelled', 'info');
          });
        }
        
        // Start polling for verification status
        this.startPollingForVerification();
      }
      
    } catch (error) {
      logger.error('Failed to show bootstrap code:', error);
      this.showError('Failed to generate verification code');
    }
  }

  /**
   * Start listening for verification status (SSE with polling fallback)
   */
  startPollingForVerification() {
    logger.info('Starting to listen for verification status...');
    
    // Try SSE first
    this.trySSE();
  }

  /**
   * Try to establish SSE connection
   */
  trySSE() {
    try {
      logger.info('Attempting SSE connection...');
      
      this.eventSource = new EventSource(`/link/status/${this.linkId}/stream`);
      
      this.eventSource.onopen = () => {
        logger.info('SSE connection established');
      };
      
      this.eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          logger.info('SSE message received:', data);
          
          if (data.error) {
            logger.error('SSE error:', data.error);
            this.fallbackToPolling();
            return;
          }
          
          if (data.status) {
            this.handleStatusUpdate(data.status);
          }
        } catch (error) {
          logger.error('Error parsing SSE message:', error);
        }
      };
      
      this.eventSource.onerror = (error) => {
        logger.error('SSE connection error:', error);
        this.stopSSE();
        this.fallbackToPolling();
      };
      
    } catch (error) {
      logger.error('Failed to create SSE connection:', error);
      this.fallbackToPolling();
    }
  }

  /**
   * Fallback to polling if SSE fails
   */
  fallbackToPolling() {
    if (this.sseRetried) {
      logger.info('SSE already failed once, skipping retry');
      return;
    }
    
    this.sseRetried = true;
    logger.info('Falling back to polling...');
    
    // Poll every 2 seconds
    this.verificationPollInterval = setInterval(async () => {
      try {
        const response = await fetch(`/link/status/${this.linkId}`);
        if (!response.ok) return;
        
        const data = await response.json();
        logger.info('Poll - Link status:', data.status);
        
        if (data.status) {
          this.handleStatusUpdate(data.status);
        }
      } catch (error) {
        logger.error('Error polling for verification:', error);
      }
    }, 2000);
  }

  /**
   * Handle status update from SSE or polling
   */
  handleStatusUpdate(status) {
    // Check if desktop has completed verification
    if (status === 'completed' || status === 'verified' || status === 'confirmed') {
      this.stopPollingForVerification();
      this.onLinkingVerified();
    } else if (status === 'expired' || status === 'timeout') {
      this.stopPollingForVerification();
      this.showError('Verification link expired. Please try again.');
    }
  }

  /**
   * Stop SSE connection
   */
  stopSSE() {
    if (this.eventSource) {
      this.eventSource.close();
      this.eventSource = null;
      logger.info('SSE connection closed');
    }
  }

  /**
   * Stop polling for verification
   */
  stopPollingForVerification() {
    this.stopSSE();
    
    if (this.verificationPollInterval) {
      clearInterval(this.verificationPollInterval);
      this.verificationPollInterval = null;
      logger.info('Stopped polling for verification');
    }
  }

  /**
   * Handle successful linking verification
   */
  onLinkingVerified() {
    logger.info('Desktop has verified the bootstrap code!');
    
    // Hide BC card
    const bcCard = document.getElementById('bcCard');
    if (bcCard) {
      bcCard.classList.remove('active');
    }
    
    // Stop BC timer
    if (this.bcTimerInterval) {
      clearInterval(this.bcTimerInterval);
    }
    
    // Show success message
    this.updateStep(3, 'completed', 'Verified on desktop!');
    this.showSuccess('✓ Device successfully linked! You can now close this page.');
  }

  /**
   * Start BC timer countdown
   */
  startBCTimer(expiresAt, timerEl) {
    if (this.bcTimerInterval) {
      clearInterval(this.bcTimerInterval);
    }
    
    const updateTimer = () => {
      const now = Math.floor(Date.now() / 1000);
      const remaining = Math.max(0, expiresAt - now);
      
      if (timerEl) {
        timerEl.textContent = remaining;
      }
      
      if (remaining === 0) {
        clearInterval(this.bcTimerInterval);
        this.showError('Bootstrap code expired');
      }
    };
    
    updateTimer();
    this.bcTimerInterval = setInterval(updateTimer, 1000);
  }

  /**
   * Update progress step
   */
  updateStep(stepNumber, status, message = '') {
    const step = document.getElementById(`step-${stepNumber}`);
    if (!step) return;
    
    const statusDiv = step.querySelector('.step-status');
    const stepNumberDiv = step.querySelector('.step-number');
    
    step.classList.remove('pending', 'active', 'completed', 'error');
    step.classList.add(status);
    
    if (statusDiv) {
      statusDiv.textContent = message || this.getDefaultMessage(status);
    }
    
    if (stepNumberDiv) {
      if (status === 'completed') {
        stepNumberDiv.textContent = '✓';
      } else if (status === 'error') {
        stepNumberDiv.textContent = '✗';
      }
    }
  }

  /**
   * Get default message for status
   */
  getDefaultMessage(status) {
    switch (status) {
      case 'pending': return 'Waiting...';
      case 'active': return 'In progress...';
      case 'completed': return 'Completed';
      case 'error': return 'Failed';
      default: return '';
    }
  }

  /**
   * Show success message
   */
  showSuccess(message) {
    this.showMessage(message, 'success');
  }

  /**
   * Show error message
   */
  showError(message) {
    this.showMessage(message, 'error');
  }

  /**
   * Show message in container
   */
  showMessage(message, type = 'info') {
    const container = document.getElementById('messageContainer');
    if (!container) return;
    
    const messageEl = document.createElement('div');
    messageEl.className = `${type}-message`;
    messageEl.textContent = message;
    
    container.innerHTML = '';
    container.appendChild(messageEl);
  }

  /**
   * Get link ID from URL parameters
   */
  getLinkIdFromUrl() {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get('lid') || urlParams.get('linkId');
  }

  /**
   * Cleanup on page unload
   */
  cleanup() {
    if (this.bcTimerInterval) {
      clearInterval(this.bcTimerInterval);
    }
    this.stopPollingForVerification();
    if (this.mobileLinkService) {
      this.mobileLinkService.cleanup();
    }
  }
}

// Initialize controller when page loads
window.addEventListener('DOMContentLoaded', () => {
  const controller = new MobileController();
  
  // Cleanup on page unload
  window.addEventListener('beforeunload', () => {
    controller.cleanup();
  });
});
