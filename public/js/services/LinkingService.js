// src/services/LinkingService.js
// Comprehensive cross-device linking service with UI rendering

import { ApiService } from './ApiService.js';
import * as DpopFun from '../core/dpop-fun.js';
import { generateQRCode } from '../utils/qr-generator.js';
import { logger } from '../utils/logging.js';
import { SignatureShare } from '../signature-share.js';

export class LinkingService extends ApiService {
  constructor(dpopFunService = null) {
    super();
    this.dpopFunService = dpopFunService;
    this.currentLinkId = null;
    this.statusCallbacks = new Map();
    this.websocket = null;
    this.statusInterval = null;
    this.containerElement = null;
    this.onStepComplete = null;
    this.onStepSkip = null;
    this.isOptional = false;
    this.stepCompleted = false;
    this.verificationPhaseShown = false;
    this.eventListenersAttached = false;
    this.hadBIKBeforeLinking = false;
    this.bikWasAuthenticated = false;
  }

  /**
   * Render the mobile linking step UI
   * @param {string} containerId - ID of the container element to render UI in
   * @param {boolean} isOptional - Whether this step can be skipped
   * @param {Function} onStepComplete - Callback when step completes
   * @param {Function} onStepSkip - Callback when step is skipped
   */
  renderMobileLinkingStep(containerId, isOptional = false, onStepComplete = null, onStepSkip = null) {
    this.containerElement = document.getElementById(containerId);
    if (!this.containerElement) {
      throw new Error(`Container element with ID '${containerId}' not found`);
    }

    this.isOptional = isOptional;
    this.onStepComplete = onStepComplete;
    this.onStepSkip = onStepSkip;

    this.containerElement.innerHTML = `
      <div class="mobile-link-container">
        <div id="qrPhase">
          <h3>Link Mobile Device</h3>
          <p>Click the button below to generate a QR code for mobile device linking.</p>
          <div class="step-actions" style="margin-top: 1rem;">
            <button class="btn primary" id="startLinkBtn">Start Mobile Linking</button>
            ${isOptional ? '<button class="btn secondary" id="skipMobileBtn">Skip</button>' : ''}
          </div>
          <div id="qrContainer" class="qr-container" style="display: none;">
            <h3>Scan QR Code with Mobile Device</h3>
            <div class="qr-code-container">
              <div class="qr-code" id="qrcode"></div>
            </div>
            <p id="linkIdDisplay">Link ID: <span id="linkId"></span></p>
            <p id="qrUrlDisplay"><strong>URL:</strong> <code id="qrUrl"></code></p>
            <div class="qr-status" id="qrStatus">Waiting for scan...</div>
          </div>
        </div>
        
        <div id="verifyPhase" style="display: none;">
          <div class="verify-grid">
            <!-- Code entry -->
            <div class="verify-card" id="codeCard">
              <h2 class="verify-card-title">Enter code from mobile</h2>
              <form id="codeForm" autocomplete="one-time-code">
                <div class="codeboxes" id="codeBoxes"></div>
                <div class="verify-actions">
                  <button class="btn btn-secondary" type="submit" disabled>Verify & continue</button>
                  <button class="btn btn-primary" type="button" id="useCamBtn">Scan QR Code shown on your Mobile from here</button>
                </div>
                <div class="verify-status" id="codeStatus">Code expires ~60s after it appears on your phone.</div>
              </form>
            </div>

            <!-- Camera scan (jsQR) -->
            <div class="verify-card hidden" id="camCard">
              <h2 class="verify-card-title">Scan QR from your phone</h2>
              <div class="camera-container">
                <video id="qrVideo" class="verify-video" playsinline muted></video>
                <div class="privacy-overlay">
                  <div class="blur-overlay"></div>
                  <div class="scanning-blur"></div>
                  <div class="scanning-window">
                    <div class="scanning-text">Aim QR code here</div>
                  </div>
                  <div class="scanning-corners">
                    <div class="corner top-left"></div>
                    <div class="corner top-right"></div>
                    <div class="corner bottom-left"></div>
                    <div class="corner bottom-right"></div>
                  </div>
                </div>
              </div>
              <canvas id="qrCanvas"></canvas>
              <div class="verify-actions" style="margin-top:1rem">
                <button class="btn btn-secondary" id="stopCamBtn" type="button">Use code instead</button>
                <span class="verify-subtitle" id="camHint">Position the QR code within the scanning area.</span>
              </div>
              <div class="verify-status status" id="camStatus">Scanning…</div>
            </div>
          </div>
        </div>
      </div>
    `;

    this.attachEventListeners();
  }

  /**
   * Attach event listeners for the mobile linking step
   */
  attachEventListeners() {
    // Handle start link button
    document.getElementById('startLinkBtn').addEventListener('click', async () => {
      await this.startLinking('qrContainer');
    });
    
    // Handle skip button (only if it exists)
    const skipBtn = document.getElementById('skipMobileBtn');
    if (skipBtn) {
      skipBtn.addEventListener('click', () => {
        if (this.onStepSkip) {
          this.onStepSkip();
        }
      });
    }

    // Handle camera button
    const useCamBtn = document.getElementById('useCamBtn');
    if (useCamBtn) {
      useCamBtn.addEventListener('click', async () => {
        await this.startCamera();
      });
    }

    // Handle stop camera button
    const stopCamBtn = document.getElementById('stopCamBtn');
    if (stopCamBtn) {
      stopCamBtn.addEventListener('click', () => {
        this.stopCamera();
      });
    }
  }

  /**
   * Start cross-device linking process
   * @returns {Promise<Object>} Linking data with QR code
   */
  async startLinking(qrContainerEl) {
    try {
      logger.info('Starting mobile linking process...');
      
      // Check if we already have a BIK before starting linking
      try {
        const sessionStatus = await DpopFun.getSessionStatus();
        this.hadBIKBeforeLinking = sessionStatus.bik_registered || false;
        
        // Also check if the BIK was tied to an authenticated user session
        this.bikWasAuthenticated = sessionStatus.username && sessionStatus.bik_registered && sessionStatus.user_authenticated;
        
        logger.info('BIK status before linking:', {
          bikExists: this.hadBIKBeforeLinking,
          bikWasAuthenticated: this.bikWasAuthenticated,
          username: sessionStatus.username
        });
      } catch (error) {
        logger.warn('Could not check BIK status before linking:', error.message);
        this.hadBIKBeforeLinking = false;
        this.bikWasAuthenticated = false;
      }
      
      // Reset verification phase flag
      this.verificationPhaseShown = false;
      
      // Disable start button
      const startBtn = document.getElementById('startLinkBtn');
      if (startBtn) {
        startBtn.disabled = true;
        startBtn.textContent = 'Creating QR...';
      }
      
      // Show QR code container
      const qrContainer = document.getElementById(qrContainerEl);
      if (qrContainer) {
        qrContainer.style.display = 'block';
      }
      
      // Start linking using DPoP-authenticated request
      const linkData = await DpopFun.dpopFunFetch('/link/start', {
        method: 'POST'
      });
      
      this.currentLinkId = linkData.linkId;
      
      // Render the linking UI
      this.renderLinkingUI(linkData);
      
      // Start SSE monitoring for real-time status updates (use SSE to avoid WebSocket conflict with SignatureShare)
      this.monitorStatus(linkData.linkId, (data) => {
        logger.info('Desktop received status data:', data);
        this.updateQRStatus(data.status);
      }, (error) => {
        logger.error('Status monitoring error:', error);
      }, 'sse');
      
      // Update button to show success
      if (startBtn) {
        startBtn.textContent = 'QR created!';
        startBtn.classList.add('success');
      }
      
      logger.info('Mobile linking started successfully', linkData);
      return linkData;
      
    } catch (error) {
      logger.error('Failed to start mobile linking:', error);
      
      // Re-enable start button on error
      const startBtn = document.getElementById('startLinkBtn');
      if (startBtn) {
        startBtn.disabled = false;
        startBtn.textContent = 'Start Mobile Linking';
        startBtn.classList.remove('success');
      }
      
      throw error;
    }
  }

  /**
   * Render the linking UI in the container
   * @param {Object} linkData - Link data from server
   */
  renderLinkingUI(linkData) {
    // Update the existing QR container with link data
    const linkIdEl = document.getElementById('linkId');
    const qrUrlEl = document.getElementById('qrUrl');
    
    if (linkIdEl) linkIdEl.textContent = linkData.linkId;
    if (qrUrlEl) qrUrlEl.textContent = linkData.qr_url;

    // Generate QR code with AprilTag overlay
    generateQRCode('qrcode', linkData.qr_url, linkData.linkId, (status) => {
      const statusEl = document.getElementById('qrStatus');
      if (statusEl) {
        statusEl.textContent = status;
      }
    });
  }

  /**
   * Complete mobile linking
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Completion result
   */
  async completeMobileLink(linkId) {
    try {
      if (!this.dpopFunService) {
        throw new Error('DpopFunService not provided');
      }
      const response = await this.dpopFunService.secureRequest('/link/mobile/complete', {
        method: 'POST',
        body: JSON.stringify({
          link_id: linkId
        })
      });
      return response;
    } catch (error) {
      throw new Error(`Failed to complete mobile link: ${error.message}`);
    }
  }

  /**
   * Get linking status
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Status data
   */
  async getLinkStatus(linkId) {
    try {
      if (!this.dpopFunService) {
        throw new Error('DpopFunService not provided');
      }
      const response = await this.dpopFunService.secureRequest(`/link/status/${linkId}`, {
        method: 'GET'
      });
      return response;
    } catch (error) {
      throw new Error(`Failed to get link status: ${error.message}`);
    }
  }

  /**
   * Start WebSocket connection for real-time status updates
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   */
  startWebSocket(linkId, onStatusUpdate, onError) {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/link/ws/${linkId}`;
      
      this.websocket = new WebSocket(wsUrl);
      
      this.websocket.onopen = () => {
        logger.info('WebSocket connected for linking status');
      };
      
      this.websocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onStatusUpdate(data);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      
      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        onError(error);
      };
      
      this.websocket.onclose = () => {
        logger.info('WebSocket disconnected');
      };
      
    } catch (error) {
      console.error('Failed to start WebSocket:', error);
      onError(error);
    }
  }

  /**
   * Start Server-Sent Events for status updates
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   */
  startSSE(linkId, onStatusUpdate, onError) {
    try {
      // Use fetch with streaming instead of EventSource to support credentials
      const controller = new AbortController();
      this.currentSSEController = controller;
      
      const startSSEStream = async () => {
        try {
          logger.info('Starting SSE stream with fetch...');
          const response = await fetch(`/link/events/${linkId}`, {
            method: 'GET',
            credentials: 'include', // This is the key difference from EventSource
            headers: {
              'Accept': 'text/event-stream',
              'Cache-Control': 'no-cache'
            },
            signal: controller.signal
          });
          
          if (!response.ok) {
            throw new Error(`SSE request failed: ${response.status}`);
          }
          
          logger.info('SSE connection opened successfully');
          
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // Keep incomplete line in buffer
            
            for (const line of lines) {
              if (line.trim() === '') continue;
              
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.slice(6));
                  onStatusUpdate(data);
                } catch (error) {
                  console.error('Failed to parse SSE data:', error);
                }
              } else if (line.startsWith('event: ')) {
                // Handle event type if needed
                const eventType = line.slice(7);
                logger.info('SSE event type:', eventType);
              }
            }
          }
        } catch (error) {
          if (error.name === 'AbortError') {
            logger.info('SSE stream aborted');
            return;
          }
          console.error('SSE stream error:', error);
          onError(error);
          
          // SSE failed - don't fall back to polling
          console.error('SSE connection failed, not falling back to polling');
        }
      };
      
      startSSEStream();
      
      return { close: () => controller.abort() };
      
    } catch (error) {
      console.error('Failed to start SSE:', error);
      onError(error);
      return null;
    }
  }


  /**
   * Update QR status display
   * @param {string} status - Status to display
   */
  updateQRStatus(status) {
    const statusEl = document.getElementById('qrStatus');
    if (!statusEl) return;
    
    logger.info('Desktop received status update:', status);

    switch (status) {
      case 'scanned':
        statusEl.textContent = 'QR code scanned! Waiting for passkey verification...';
        statusEl.className = 'qr-status scanned';
        // Don't show BC code entry yet - wait for mobile to complete passkey verification
        break;
      case 'linked':
        logger.info('Status is linked, checking if verification phase needed');
        statusEl.textContent = 'Mobile device linked!';
        statusEl.className = 'qr-status success';
        
        // Check if we need verification phase based on BIK status
        if (!this.hadBIKBeforeLinking) {
          // New BIK was created - show verification phase
          logger.info('New BIK was created, showing verification phase');
          statusEl.textContent = 'Mobile device linked! Enter verification code below.';
          if (!this.verificationPhaseShown) {
            logger.info('Showing verification phase for linked status');
            this.verificationPhaseShown = true;
            this.showVerificationPhase();
          } else {
            logger.info('Verification phase already shown, skipping');
          }
        } else if (this.bikWasAuthenticated) {
          // Existing authenticated BIK was used - show success message
          logger.info('Existing authenticated BIK was used, showing success message');
          statusEl.textContent = 'Mobile device linked successfully! Using existing authenticated identity.';
          statusEl.className = 'qr-status success';
          
          // Hide QR phase and show success message
          const qrPhase = document.getElementById('qrPhase');
          if (qrPhase) {
            qrPhase.innerHTML = `
              <div class="step-status success">
                <h3>✓ Mobile Device Linked Successfully</h3>
                <p>Your mobile device has been linked using your existing authenticated identity.</p>
                <p>No additional verification is required.</p>
              </div>
            `;
          }
          
          // Complete the step after a short delay
          setTimeout(() => {
            this.completeStep();
          }, 2000);
        } else {
          // Existing BIK but not authenticated - show verification phase
          logger.info('Existing BIK but not authenticated, showing verification phase');
          statusEl.textContent = 'Mobile device linked! Enter verification code below.';
          if (!this.verificationPhaseShown) {
            logger.info('Showing verification phase for unauthenticated BIK');
            this.verificationPhaseShown = true;
            this.showVerificationPhase();
          } else {
            logger.info('Verification phase already shown, skipping');
          }
        }
        break;
      case 'confirmed':
        logger.info('Status is confirmed, completing step');
        statusEl.textContent = 'Mobile device linked successfully!';
        statusEl.className = 'qr-status success';
        this.completeStep();
        break;
      case 'completed':
        statusEl.textContent = 'Mobile device linked successfully!';
        statusEl.className = 'qr-status success';
        this.completeStep();
        break;
      case 'failed':
        statusEl.textContent = 'Linking failed. Please try again.';
        statusEl.className = 'qr-status error';
        break;
      default:
        statusEl.textContent = 'Waiting for scan...';
        statusEl.className = 'qr-status';
    }
  }

  /**
   * Force show verification phase (for journeys context)
   */
  forceShowVerificationPhase() {
    logger.info('Force showing verification phase for journeys');
    this.hadBIKBeforeLinking = false; // Override BIK check
    this.showVerificationPhase();
  }

  /**
   * Show verification phase UI
   */
  showVerificationPhase() {
    logger.info('showVerificationPhase called');
    const qrPhase = document.getElementById('qrPhase');
    const verifyPhase = document.getElementById('verifyPhase');
    
    logger.info('qrPhase element:', qrPhase);
    logger.info('verifyPhase element:', verifyPhase);
    
    if (qrPhase) qrPhase.style.display = 'none';
    if (verifyPhase) verifyPhase.style.display = 'block';
    
    // Initialize code input fields
    this.initializeCodeInputs();

    
    // Set up camera toggle buttons
    const useCamBtn = document.getElementById('useCamBtn');
    const stopCamBtn = document.getElementById('stopCamBtn');
    
    if (useCamBtn) {
      useCamBtn.addEventListener('click', () => {
        this.switchToCamera();
      });
    }
    
    if (stopCamBtn) {
      stopCamBtn.addEventListener('click', () => {
        this.switchToCodeInput();
      });
    }
    
    logger.info('Verification phase shown');
  }

  /**
   * Initialize code input fields
   */
  initializeCodeInputs() {
    const codeBoxes = document.getElementById('codeBoxes');
    if (!codeBoxes) return;

    // Create 8 input fields for the bootstrap code
    codeBoxes.innerHTML = '';
    for (let i = 0; i < 8; i++) {
      const input = document.createElement('input');
      input.type = 'text';
      input.maxLength = 1;
      input.className = 'code-input';
      input.dataset.index = i;
      input.autocomplete = 'off';
      codeBoxes.appendChild(input);
    }
    
    // Focus the first input
    const firstInput = codeBoxes.querySelector('.code-input');
    if (firstInput) {
      firstInput.focus();
    }

    // Add event listeners for code input
    this.attachCodeInputListeners();
  }

  /**
   * Attach event listeners for code input fields
   */
  attachCodeInputListeners() {
    // Prevent duplicate event listener attachments
    if (this.eventListenersAttached) return;
    
    const codeBoxes = document.getElementById('codeBoxes');
    if (!codeBoxes) return;

    // Add input event listener
    codeBoxes.addEventListener('input', (e) => {
      if (e.target.classList.contains('code-input')) {
        const index = parseInt(e.target.dataset.index);
        const value = e.target.value.toUpperCase();
        // Update the input value to uppercase
        e.target.value = value;
        
        // Move to next input if character entered
        if (value && index < 7) {
          const nextInput = codeBoxes.children[index + 1];
          if (nextInput) {
            nextInput.focus();
          }
        } else if (value && index === 7) {
          this.checkCodeCompletion();
        }
      }
    });

    // Handle form submission
    const codeForm = document.getElementById('codeForm');
    if (codeForm) {
      codeForm.addEventListener('submit', (e) => {
        e.preventDefault();
        this.handleCodeSubmission();
      });
    }
    
    this.eventListenersAttached = true;
  }


  /**
   * Check if code input is complete
   */
  checkCodeCompletion() {
    const codeBoxes = document.getElementById('codeBoxes');
    if (!codeBoxes) return;

    const inputs = codeBoxes.querySelectorAll('.code-input');
    const code = Array.from(inputs).map(input => input.value).join('');
    
    // Don't auto-submit, just check if all fields are filled
    if (code.length === 8) {
      // Enable submit button or show visual feedback that code is complete
      const submitBtn = document.querySelector('#codeForm button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.classList.add('btn-primary');
        submitBtn.classList.remove('btn-secondary');
      }
    } else {
      // Disable submit button if not complete
      const submitBtn = document.querySelector('#codeForm button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.classList.add('btn-secondary');
        submitBtn.classList.remove('btn-primary');
      }
    }
  }

  /**
   * Handle code submission
   */
  async handleCodeSubmission() {
    logger.info('handleCodeSubmission called');
    const codeBoxes = document.getElementById('codeBoxes');
    
    let code = '';
    if (codeBoxes) {
      const inputs = codeBoxes.querySelectorAll('.code-input');
      code = Array.from(inputs).map(input => input.value).join('');
    }
    logger.info('Code:', code);

    if (code.length !== 8) {
      this.updateCodeStatus('Please enter an 8-character code', 'error');
      return;
    }

    try {
      this.updateCodeStatus('Verifying code...', 'info');
      
      // Submit the bootstrap code
      const response = await DpopFun.dpopFunFetch('/device/redeem', {
        method: 'POST',
        body: { bc: code }
      });

      if (response && response.dpop_nonce) {
        logger.info('BC code validation successful, response:', response);
        this.updateCodeStatus('Code verified successfully!', 'success');
        
        // Verification phase should already be shown when status became 'linked'
        
        // The scribble receiver will be shown by updateMobileLinkingStepStatus when the step completes
        
        // Don't complete step immediately - wait for SSE confirmation
        // The step will be completed when SSE status is 'linked' or 'completed'
      } else {
        this.updateCodeStatus('Invalid code. Please try again.', 'error');
        }
      } catch (error) {
      this.updateCodeStatus('Verification failed. Please try again.', 'error');
    }
  }

  // toggleInputMode method removed - no longer needed

  /**
   * Update code status message
   */
  updateCodeStatus(message, type = 'info') {
    const statusEl = document.getElementById('codeStatus');
    if (statusEl) {
      statusEl.textContent = message;
      statusEl.className = `verify-status ${type}`;
    }
  }

  /**
   * Replace BC code entry with scribble receiver
   */
  replaceWithScribbleReceiver() {
    try {
      logger.info('replaceWithScribbleReceiver called');
      logger.info('Replacing BC code entry with scribble receiver...');
      
      // Find the code card and replace its content
      const codeCard = document.getElementById('codeCard');
      logger.info('codeCard element:', codeCard);
      
      if (!codeCard) {
        console.error('codeCard element not found!');
        return;
      }

      // Replace the code card content with scribble receiver
      codeCard.innerHTML = `
        <p class="scribble-description">Draw on your mobile device to see it appear here in real-time!</p>
        <div class="scribble-canvas-container" id="scribbleCanvasContainer">
          <!-- Canvas will be created by SignatureShare.initDesktop() -->
        </div>
      `;

      // Initialize signature sharing for desktop (viewing)
      this.signatureShare = new SignatureShare();
      logger.info('Initializing SignatureShare with linkId:', this.currentLinkId);
      this.signatureShare.initDesktop(this.currentLinkId);
      logger.info('Scribble receiver initialized successfully', 'success');
      
      logger.info('Scribble receiver initialized successfully');
      
    } catch (error) {
      logger.error('Failed to initialize scribble receiver:', error);
    }
  }

  /**
   * Complete the mobile linking step
   */
  completeStep() {
    if (this.onStepComplete && !this.stepCompleted) {
      this.stepCompleted = true; // Prevent multiple calls
      
      // Update the mobile linking step UI to show completion
      this.updateMobileLinkingStepStatus('completed');
      
      // Call the journey's completeStep method
      this.onStepComplete();
    }
  }

  /**
   * Update the mobile linking step status in the UI
   * @param {string} status - Status to display ('active', 'completed', 'failed')
   */
  updateMobileLinkingStepStatus(status) {
    const container = this.containerElement;
    if (!container) return;

    if (status === 'completed') {
      // Check if we should show scribble receiver instead of completion message
      const codeCard = container.querySelector('#codeCard');
      if (codeCard) {
        // Replace BC code entry with scribble receiver
        this.replaceWithScribbleReceiver();
      } else {
        // Hide the QR and verification phases
        const qrPhase = container.querySelector('#qrPhase');
        const verifyPhase = container.querySelector('#verifyPhase');
        
        if (qrPhase) qrPhase.style.display = 'none';
        if (verifyPhase) verifyPhase.style.display = 'none';
        
        // Show completion message
        container.innerHTML = `
          <div class="step-status success">
            <h3>✓ Link Mobile Device</h3>
            <p>Mobile device linked successfully!</p>
          </div>
        `;
      }
    }
  }


  /**
   * Stop all status monitoring
   */
  stopStatusMonitoring() {
    if (this.websocket) {
      this.websocket.close();
      this.websocket = null;
    }
    
    if (this.currentEventSource) {
      this.currentEventSource.close();
      this.currentEventSource = null;
    }
    
    if (this.currentSSEController) {
      this.currentSSEController.abort();
      this.currentSSEController = null;
    }
    
    if (this.statusInterval) {
      clearTimeout(this.statusInterval);
      this.statusInterval = null;
    }
  }

  /**
   * Monitor linking status with fallback methods
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   * @param {string} preferredMethod - Preferred method ('websocket', 'sse', 'polling')
   */
  monitorStatus(linkId, onStatusUpdate, onError, preferredMethod = 'websocket') {
    this.stopStatusMonitoring();
    
    const methods = {
      websocket: () => this.startWebSocket(linkId, onStatusUpdate, onError),
      sse: () => this.startSSE(linkId, onStatusUpdate, onError)
    };
    
    // Try preferred method first
    if (methods[preferredMethod]) {
      try {
        const result = methods[preferredMethod]();
        if (result) {
          logger.info(`Using ${preferredMethod} for status monitoring`);
          return;
        }
      } catch (error) {
        console.warn(`${preferredMethod} failed:`, error);
      }
    }
    
    // Try fallback methods in order
    const fallbackOrder = ['websocket', 'sse'].filter(method => method !== preferredMethod);
    
    for (const method of fallbackOrder) {
      try {
        const result = methods[method]();
        if (result) {
          logger.info(`Using ${method} as fallback for status monitoring`);
          return;
        }
      } catch (error) {
        console.warn(`${method} fallback failed:`, error);
      }
    }
    
    // No fallback to polling - just fail
    console.error('All real-time methods failed, no polling fallback');
    onError(new Error('All real-time connection methods failed'));
  }

  /**
   * Get current link ID
   * @returns {string|null} Current link ID
   */
  getCurrentLinkId() {
    return this.currentLinkId;
  }

  /**
   * Clear current link
   */
  clearLink() {
    this.currentLinkId = null;
    this.stopStatusMonitoring();
  }

  /**
   * Start camera for QR code scanning
   */
  async startCamera() {
    try {
      const codeCard = document.getElementById('codeCard');
      const camCard = document.getElementById('camCard');
      const video = document.getElementById('qrVideo');
      const camStatus = document.getElementById('camStatus');
      
      logger.info('Starting camera - elements found:', {
        codeCard: !!codeCard,
        camCard: !!camCard,
        video: !!video,
        camStatus: !!camStatus
      });
      
      // Debug video element properties
      if (video) {
        logger.info('Video element properties:', {
          tagName: video.tagName,
          id: video.id,
          className: video.className,
          style: video.style.cssText,
          offsetWidth: video.offsetWidth,
          offsetHeight: video.offsetHeight,
          clientWidth: video.clientWidth,
          clientHeight: video.clientHeight,
          getComputedStyle: window.getComputedStyle(video).display
        });
      }
      
      if (!codeCard || !camCard || !video || !camStatus) {
        throw new Error('Camera elements not found');
      }

      // Switch to camera view
      codeCard.classList.add('hidden');
      camCard.classList.remove('hidden');
      logger.info('Switched to camera view');

      // Request camera access
      logger.info('Requesting camera access...');
      this.cameraStream = await navigator.mediaDevices.getUserMedia({ 
        video: { 
          facingMode: 'environment', 
          width: { ideal: 1280 }, 
          height: { ideal: 720 } 
        } 
      });

      logger.info('Camera stream obtained:', this.cameraStream);
      video.srcObject = this.cameraStream;
      
      // Add event listeners to debug video loading
      video.addEventListener('loadedmetadata', () => {
        logger.info('Video metadata loaded:', {
          videoWidth: video.videoWidth,
          videoHeight: video.videoHeight,
          duration: video.duration
        });
      });
      
      video.addEventListener('canplay', () => {
        logger.info('Video can play');
      });
      
      video.addEventListener('error', (e) => {
        logger.error('Video error:', e);
      });
      
      await video.play();
      logger.info('Video started playing');
      
      // Check video properties after play
      setTimeout(() => {
        logger.info('Video properties after play:', {
          videoWidth: video.videoWidth,
          videoHeight: video.videoHeight,
          currentTime: video.currentTime,
          paused: video.paused,
          readyState: video.readyState,
          srcObject: !!video.srcObject,
          offsetWidth: video.offsetWidth,
          offsetHeight: video.offsetHeight,
          clientWidth: video.clientWidth,
          clientHeight: video.clientHeight,
          style: video.style.cssText,
          computedStyle: {
            display: window.getComputedStyle(video).display,
            width: window.getComputedStyle(video).width,
            height: window.getComputedStyle(video).height,
            visibility: window.getComputedStyle(video).visibility
          }
        });
      }, 1000);
      
      camStatus.textContent = 'Scanning…';
      camStatus.className = 'verify-status status';

      // Start QR code detection loop
      this.startQRDetection();

    } catch (error) {
      const camStatus = document.getElementById('camStatus');
      if (camStatus) {
        camStatus.textContent = 'Camera permission denied or unavailable.';
        camStatus.className = 'verify-status status err';
      }
      logger.error('Camera start failed:', error);
    }
  }

  /**
   * Stop camera
   */
  stopCamera() {
    this.stopQRDetection = true;
    
    if (this.cameraStream) {
      this.cameraStream.getTracks().forEach(track => track.stop());
      this.cameraStream = null;
    }

    const codeCard = document.getElementById('codeCard');
    const camCard = document.getElementById('camCard');
    
    if (camCard) camCard.classList.add('hidden');
    if (codeCard) codeCard.classList.remove('hidden');
  }

  /**
   * Start QR code detection loop
   */
  startQRDetection() {
    const video = document.getElementById('qrVideo');
    const canvas = document.getElementById('qrCanvas');
    const ctx = canvas.getContext('2d');
    
    if (!video || !canvas) return;

    const loop = async () => {
      if (this.stopQRDetection) return;

      // Downscale for speed; keep aspect
      const vw = video.videoWidth || 640;
      const vh = video.videoHeight || 480;
      const scale = Math.min(640 / vw, 480 / vh, 1);
      const w = Math.max(320, Math.floor(vw * scale));
      const h = Math.max(240, Math.floor(vh * scale));
      
      canvas.width = w;
      canvas.height = h;
      
      // Flip the image horizontally for easier phone positioning
      ctx.save();
      ctx.scale(-1, 1);
      ctx.drawImage(video, -w, 0, w, h);
      ctx.restore();
      
      const img = ctx.getImageData(0, 0, w, h);

      // Use jsQR for detection
      if (typeof jsQR !== 'undefined') {
        const result = jsQR(img.data, w, h, { 
          inversionAttempts: "attemptBoth"
        });
        
        if (result && result.data) {
          const text = (result.data + '').trim();
          logger.info('QR detected:', text);
          
          // Check for the expected prefix
          if (text.includes('/verify/device?bc=') || text.startsWith('/verify/device?bc=')) {
            let bcRaw;
            if (text.includes('/verify/device?bc=')) {
              bcRaw = text.split('/verify/device?bc=')[1];
            } else {
              bcRaw = text.slice('/verify/device?bc='.length);
            }
            
            logger.info('BC code extracted:', bcRaw);
            this.autofillAndSubmit(bcRaw);
            this.stopCamera();
            return;
          } else {
            logger.info('QR code not matching expected format:', text);
            // ignore foreign QR codes; keep scanning
          }
        }
      }
      
      // Continue loop
      if ('requestVideoFrameCallback' in HTMLVideoElement.prototype) {
        video.requestVideoFrameCallback(loop);
      } else {
        requestAnimationFrame(loop);
      }
    };
    
    this.stopQRDetection = false;
    if ('requestVideoFrameCallback' in HTMLVideoElement.prototype) {
      video.requestVideoFrameCallback(loop);
    } else {
      requestAnimationFrame(loop);
    }
  }

  /**
   * Autofill code and submit
   */
  autofillAndSubmit(code) {
    const normalizedCode = this.normalizeCode(code);
    const codeBoxes = document.getElementById('codeBoxes');
    
    if (!codeBoxes) return;

    const inputs = codeBoxes.querySelectorAll('.code-input');
    for (let i = 0; i < Math.min(normalizedCode.length, inputs.length); i++) {
      inputs[i].value = normalizedCode[i];
    }

    // Only auto-submit if the code is complete (8 characters)
    if (normalizedCode.length === 8) {
      // Trigger form submission
      const codeForm = document.getElementById('codeForm');
      if (codeForm) {
        codeForm.requestSubmit();
      }
    }
  }

  /**
   * Normalize code (remove non-alphanumeric characters and convert to uppercase)
   */
  normalizeCode(code) {
    return (code + '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  }

  /**
   * Clean up the linking service
   */
  cleanup() {
    this.stopStatusMonitoring();
    this.currentLinkId = null;
    this.containerElement = null;
    this.onStepComplete = null;
    this.onStepSkip = null;
  }

  /**
   * Check if currently linking
   * @returns {boolean} Whether currently linking
   */
  isLinking() {
    return !!this.currentLinkId;
  }
}
