/**
 * Mobile Linking Service
 * Unified service for cross-device linking (desktop and mobile)
 * 
 * Desktop Side: QR code generation, status monitoring, BC verification
 * Mobile Side: Session setup, passkey auth, linking completion
 */

import * as DpopFun from './core/dpop-fun.js';
import * as Passkeys from './core/passkeys.js';
import { FingerprintService } from './services/FingerprintService.js';
import { generateQRCode } from './utils/qr-generator.js';
import { logger } from './utils/logging.js';
import { SignatureShare } from './signature-share.js';
import { idbGet, idbDelete } from './utils/idb.js';

/**
 * Mobile Linking Service
 * Handles both desktop (QR generation, monitoring) and mobile (session setup, auth) sides
 */
export class MobileLinkService {
  constructor() {
    // Common properties
    this.currentLinkId = null;
    this.flowType = 'registration'; // 'registration' or 'login'
    
    // Desktop properties
    this.statusCallbacks = new Map();
    this.websocket = null;
    this.currentEventSource = null;
    this.currentSSEController = null;
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
    this.cameraStream = null;
    this.stopQRDetection = false;
    this.signatureShare = null;
    
    // Mobile properties
    this.username = null;
    this.desktopUsername = null;
    this.onComplete = null;
    this.onError = null;
    this.onAuthenticated = null;
    this.onSessionSetup = null;
    this.registrationAuthData = null;
  }

  // ============================================================================
  // DESKTOP SIDE - QR Code Generation and Monitoring
  // ============================================================================

  /**
   * Render the mobile linking step UI (Desktop side)
   * @param {string} containerId - ID of the container element to render UI in
   * @param {boolean} isOptional - Whether this step can be skipped
   * @param {Function} onStepComplete - Callback when step completes
   * @param {Function} onStepSkip - Callback when step is skipped
   * @param {string} flowType - Type of flow ('registration' or 'login')
   */
  renderMobileLinkingStep(containerId, isOptional = false, onStepComplete = null, onStepSkip = null, flowType = 'registration') {
    this.containerElement = document.getElementById(containerId);
    if (!this.containerElement) {
      throw new Error(`Container element with ID '${containerId}' not found`);
    }

    this.isOptional = isOptional;
    this.onStepComplete = onStepComplete;
    this.onStepSkip = onStepSkip;
    this.flowType = flowType;

    // Check if the HTML already exists to avoid recreating elements
    const existingQrPhase = document.getElementById('qrPhase');
    const existingVerifyPhase = document.getElementById('verifyPhase');
    
    if (existingQrPhase && existingVerifyPhase) {
      logger.info('Mobile linking HTML already exists, reusing existing elements');
      this.attachEventListeners();
      return;
    }

    // Determine text based on flow type
    const isAuthentication = flowType === 'login';
    const title = isAuthentication ? 'Mobile Authentication' : 'Link Mobile Device';

    this.containerElement.innerHTML = `
      <div class="mobile-link-container">
        <div id="qrPhase">
          <h3>${title}</h3>
          <p id="loadingMessage">Generating QR code...</p>
          <div id="qrContainer" class="qr-container">
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
                <video id="qrVideo" class="verify-video" playsinline muted style="transform: scaleX(-1);"></video>
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
              <canvas id="qrCanvas" style="display: none;"></canvas>
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
    
    // Automatically start linking and generate QR code
    setTimeout(async () => {
      await this.startLinking('qrContainer');
      // Hide loading message after QR is generated
      const loadingMsg = document.getElementById('loadingMessage');
      if (loadingMsg) {
        loadingMsg.style.display = 'none';
      }
    }, 100);
  }

  /**
   * Attach event listeners for the mobile linking step (Desktop side)
   */
  attachEventListeners() {
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
   * Start cross-device linking process (Desktop side)
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
      
      // Show QR code container
      const qrContainer = document.getElementById(qrContainerEl);
      if (qrContainer) {
        qrContainer.style.display = 'block';
      }
      
      // Start linking using DPoP-authenticated request
      const linkData = await DpopFun.dpopFetch('POST', '/link/start', {
        body: JSON.stringify({
          flow_type: this.flowType || 'registration',
          username: this.desktopUsername || null  // Include username from desktop
        })
      });
      
      if (!linkData.ok) {
        const errorData = await linkData.json();
        logger.error('Failed to start linking:', errorData);
        throw new Error(errorData.detail || 'Failed to start mobile linking');
      }
      
      const response = await linkData.json();
      
      if (!response.linkId || !response.qr_url) {
        logger.error('Invalid response from link/start:', response);
        throw new Error('Invalid link response - missing linkId or qr_url');
      }
      
      this.currentLinkId = response.linkId;
      
      // Store the flow type from server response
      this.flowType = response.flow_type || 'registration';
      logger.info('Flow type received from server:', this.flowType);
      
      // Render the linking UI
      this.renderLinkingUI(response);
      
      // Start SSE monitoring for real-time status updates (use SSE to avoid WebSocket conflict with SignatureShare)
      this.monitorStatus(response.linkId, (data) => {
        logger.info('Desktop received status data:', data);
        this.updateQRStatus(data.status);
      }, (error) => {
        logger.error('Status monitoring error:', error);
      }, 'sse');
      
      logger.info('Mobile linking started successfully', response);
      return response;
      
    } catch (error) {
      logger.error('Failed to start mobile linking:', error);
      
      // Show error message to user
      const loadingMsg = document.getElementById('loadingMessage');
      if (loadingMsg) {
        loadingMsg.textContent = 'Failed to generate QR code. Please try again.';
        loadingMsg.style.color = 'red';
      }
      
      throw error;
    }
  }

  /**
   * Render the linking UI in the container (Desktop side)
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
   * Update QR status display (Desktop side)
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
        break;
      case 'linked':
        // Registration flow only - login flows get "completed" status instead
        logger.info('Status is linked - showing verification phase for registration');
        statusEl.textContent = 'Mobile device linked! Enter verification code below.';
        statusEl.className = 'qr-status success';
        
        if (!this.verificationPhaseShown) {
          logger.info('Showing verification phase for registration flow');
          this.verificationPhaseShown = true;
          this.showVerificationPhase();
        } else {
          logger.info('Verification phase already shown, skipping');
        }
        break;
      case 'confirmed':
        logger.info('Status is confirmed, completing step');
        statusEl.textContent = 'Mobile device linked successfully!';
        statusEl.className = 'qr-status success';
        this.completeStep();
        break;
      case 'completed':
        logger.info('Status is completed - completing desktop step');
        logger.info('Flow type:', this.flowType);
        logger.info('onStepComplete exists:', !!this.onStepComplete);
        logger.info('stepCompleted flag:', this.stepCompleted);
        statusEl.textContent = 'Authentication successful! Updating desktop...';
        statusEl.className = 'qr-status success';
        
        // Hide QR phase and show success message
        const qrPhase = document.getElementById('qrPhase');
        if (qrPhase) {
          qrPhase.innerHTML = `
            <div class="step-status success">
              <h3>✓ Authentication Successful</h3>
              <p>Your mobile device has been authenticated successfully.</p>
              <p>Updating desktop session...</p>
            </div>
          `;
        }
        
        // Add small delay to ensure server has finished updating desktop session
        setTimeout(() => {
          logger.info('Timeout complete, calling completeStep()');
          this.completeStep();
        }, 500);
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
   * Show verification phase UI (Desktop side)
   */
  showVerificationPhase() {
    logger.info('showVerificationPhase called');
    const qrPhase = document.getElementById('qrPhase');
    const verifyPhase = document.getElementById('verifyPhase');
    
    if (qrPhase) qrPhase.style.display = 'none';
    if (verifyPhase) verifyPhase.style.display = 'block';
    
    // Initialize code input fields
    this.initializeCodeInputs();
  }

  /**
   * Initialize code input fields (Desktop side)
   */
  initializeCodeInputs() {
    const codeBoxes = document.getElementById('codeBoxes');
    if (!codeBoxes) return;

    // Create 8 input fields for the bootstrap code in two groups of 4
    codeBoxes.innerHTML = '';
    
    // First group of 4
    for (let i = 0; i < 4; i++) {
      const input = document.createElement('input');
      input.type = 'text';
      input.maxLength = 1;
      input.className = 'code-input';
      input.dataset.index = i;
      input.autocomplete = 'off';
      input.pattern = '[A-Za-z0-9]';
      codeBoxes.appendChild(input);
    }
    
    // Add dash separator
    const separator = document.createElement('span');
    separator.className = 'code-separator';
    separator.textContent = '-';
    codeBoxes.appendChild(separator);
    
    // Second group of 4
    for (let i = 4; i < 8; i++) {
      const input = document.createElement('input');
      input.type = 'text';
      input.maxLength = 1;
      input.className = 'code-input';
      input.dataset.index = i;
      input.autocomplete = 'off';
      input.pattern = '[A-Za-z0-9]';
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
   * Attach event listeners for code input fields (Desktop side)
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
        let value = e.target.value.toUpperCase();
        
        // Only allow alphanumeric characters
        value = value.replace(/[^A-Z0-9]/g, '');
        
        // Update the input value
        e.target.value = value;
        
        // Move to next input if character entered
        if (value && index < 7) {
          // Get all inputs (skip the separator)
          const inputs = Array.from(codeBoxes.querySelectorAll('.code-input'));
          const nextInput = inputs[index + 1];
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
   * Check if code input is complete (Desktop side)
   */
  checkCodeCompletion() {
    const codeBoxes = document.getElementById('codeBoxes');
    if (!codeBoxes) return;

    const inputs = codeBoxes.querySelectorAll('.code-input');
    const code = Array.from(inputs).map(input => input.value).join('');
    
    // Don't auto-submit, just check if all fields are filled
    if (code.length === 8) {
      // Enable submit button
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
   * Handle code submission (Desktop side)
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
      const response = await DpopFun.dpopFetch('POST', '/device/redeem', {
        body: JSON.stringify({ bc: code })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        logger.error('BC code validation failed:', errorData);
        this.updateCodeStatus(errorData.detail || 'Invalid or expired code', 'error');
        return;
      }
      
      const result = await response.json();

      if (result && result.ok) {
        logger.info('BC code validation successful, response:', result);
        this.updateCodeStatus('Code verified successfully!', 'success');
        
        // Complete the step after successful verification
        setTimeout(() => {
          this.completeStep();
        }, 1000);
      } else {
        this.updateCodeStatus('Invalid code. Please try again.', 'error');
      }
    } catch (error) {
      logger.error('BC code verification error:', error);
      this.updateCodeStatus('Verification failed. Please try again.', 'error');
    }
  }

  /**
   * Update code status message (Desktop side)
   */
  updateCodeStatus(message, type = 'info') {
    const statusEl = document.getElementById('codeStatus');
    if (statusEl) {
      statusEl.textContent = message;
      statusEl.className = `verify-status ${type}`;
    }
  }

  /**
   * Start camera for QR code scanning (Desktop side)
   */
  async startCamera() {
    try {
      const codeCard = document.getElementById('codeCard');
      const camCard = document.getElementById('camCard');
      const video = document.getElementById('qrVideo');
      const camStatus = document.getElementById('camStatus');
      
      if (!codeCard || !camCard || !video || !camStatus) {
        throw new Error('Camera elements not found');
      }

      // Switch to camera view
      codeCard.classList.add('hidden');
      camCard.classList.remove('hidden');
      
      // Request camera access with smaller resolution
      this.cameraStream = await navigator.mediaDevices.getUserMedia({ 
        video: { 
          facingMode: 'environment', 
          width: { ideal: 480 }, 
          height: { ideal: 480 } 
        } 
      });

      video.srcObject = this.cameraStream;
      video.setAttribute('playsinline', '');
      video.setAttribute('muted', '');
      await video.play();
      
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
   * Stop camera (Desktop side)
   */
  stopCamera() {
    this.stopQRDetection = true;
    
    if (this.cameraStream) {
      this.cameraStream.getTracks().forEach(track => track.stop());
      this.cameraStream = null;
    }

    const video = document.getElementById('qrVideo');
    if (video) {
      video.srcObject = null;
      video.load();
    }

    const codeCard = document.getElementById('codeCard');
    const camCard = document.getElementById('camCard');
    
    if (camCard) camCard.classList.add('hidden');
    if (codeCard) codeCard.classList.remove('hidden');
  }

  /**
   * Start QR code detection loop (Desktop side)
   */
  startQRDetection() {
    const video = document.getElementById('qrVideo');
    const canvas = document.getElementById('qrCanvas');
    const ctx = canvas.getContext('2d');
    
    if (!video || !canvas) return;

    const loop = async () => {
      if (this.stopQRDetection) return;

      const vw = video.videoWidth || 480;
      const vh = video.videoHeight || 480;
      const scale = Math.min(480 / vw, 480 / vh, 1);
      const w = Math.max(300, Math.floor(vw * scale));
      const h = Math.max(300, Math.floor(vh * scale));
      
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
          
          // Check for the expected prefix
          if (text.includes('/verify/device?bc=') || text.startsWith('/verify/device?bc=')) {
            let bcRaw;
            if (text.includes('/verify/device?bc=')) {
              bcRaw = text.split('/verify/device?bc=')[1];
            } else {
              bcRaw = text.slice('/verify/device?bc='.length);
            }
            
            logger.info('BC code extracted from QR:', bcRaw);
            this.autofillAndSubmit(bcRaw);
            this.stopCamera();
            return;
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
   * Autofill code and submit (Desktop side)
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
      const codeForm = document.getElementById('codeForm');
      if (codeForm) {
        codeForm.requestSubmit();
      }
    }
  }

  /**
   * Normalize code (Desktop side)
   */
  normalizeCode(code) {
    return (code + '').replace(/[^A-Z0-9]/gi, '').toUpperCase();
  }

  /**
   * Complete the mobile linking step (Desktop side)
   */
  completeStep() {
    logger.info('completeStep called, stepCompleted:', this.stepCompleted);
    if (!this.stepCompleted) {
      this.stepCompleted = true;
      
      logger.info('Completing step, onStepComplete exists:', !!this.onStepComplete);
      
      // Call the callback if defined
      if (this.onStepComplete && typeof this.onStepComplete === 'function') {
        logger.info('Calling onStepComplete callback...');
        this.onStepComplete();
        logger.info('onStepComplete callback completed');
      } else {
        logger.info('Link completion successful, no callback defined');
      }
    } else {
      logger.info('Step already completed, skipping');
    }
  }

  /**
   * Monitor linking status with fallback methods (Desktop side)
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
    
    // All methods failed
    console.error('All real-time methods failed');
    onError(new Error('All real-time connection methods failed'));
  }

  /**
   * Start WebSocket connection for real-time status updates (Desktop side)
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
   * Start Server-Sent Events for status updates (Desktop side)
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   */
  startSSE(linkId, onStatusUpdate, onError) {
    try {
      const controller = new AbortController();
      this.currentSSEController = controller;
      
      const startSSEStream = async () => {
        try {
          const response = await fetch(`/link/status/${linkId}/stream`, {
            method: 'GET',
            credentials: 'include',
            headers: {
              'Accept': 'text/event-stream',
              'Cache-Control': 'no-cache'
            },
            signal: controller.signal
          });
          
          if (!response.ok) {
            throw new Error(`SSE request failed: ${response.status}`);
          }
          
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || '';
            
            for (const line of lines) {
              if (line.trim() === '') continue;
              
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.slice(6));
                  logger.info('SSE data received:', data);
                  onStatusUpdate(data);
                } catch (error) {
                  console.error('Failed to parse SSE data:', error);
                }
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
   * Stop all status monitoring (Desktop side)
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

  // ============================================================================
  // MOBILE SIDE - Session Setup and Authentication
  // ============================================================================

  /**
   * Initialize for registration flow (Mobile side)
   * @param {string} linkId - Link ID from QR scan
   * @param {Function} onComplete - Callback when complete
   * @param {Function} onError - Callback when error
   * @param {Function} onAuthenticated - Callback when authenticated
   * @param {Function} onSessionSetup - Callback when mobile session setup completes
   */
  async initMobileRegistrationFlow(linkId, onComplete, onError, onAuthenticated = null, onSessionSetup = null) {
    this.flowType = 'registration';
    this.currentLinkId = linkId;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onAuthenticated = onAuthenticated;
    this.onSessionSetup = onSessionSetup;
    
    logger.info('Initializing mobile registration flow');
    
    try {
      // Step 1: Establish mobile session (BIK + DPoP)
      await this.startMobileSession();
      
      // Notify that session setup is complete
      if (this.onSessionSetup) {
        this.onSessionSetup();
      }
      
      // Step 2: Link mobile session to desktop session and get desktop username
      await this.linkMobileToDesktop();
      
      // Step 3: Continue registration using desktop username
      await this.continueRegistrationWithDesktopUsername();
    } catch (error) {
      logger.error('Mobile registration flow failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Initialize for login flow (Mobile side)
   * @param {string} username - Username to authenticate
   * @param {string} linkId - Link ID from QR scan
   * @param {Function} onComplete - Callback when complete
   * @param {Function} onError - Callback when error
   * @param {Function} onAuthenticated - Callback when authenticated
   */
  async initMobileLoginFlow(username, linkId, onComplete, onError, onAuthenticated = null) {
    this.flowType = 'login';
    this.username = username;
    this.currentLinkId = linkId;
    this.onComplete = onComplete;
    this.onError = onError;
    this.onAuthenticated = onAuthenticated;
    
    logger.info(`Initializing mobile login flow for username: ${username}`);
    
    try {
      await this.startMobileSession();
    } catch (error) {
      logger.error('Mobile login flow failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Start mobile session and begin authentication process (Mobile side)
   */
  async startMobileSession() {
    try {
      logger.info('Setting up mobile session...');
      
      // Check if dpop_bind exists and if it's expired
      const dpopBind = await idbGet('session', 'dpop_bind');
      let shouldClearSession = false;
      
      if (dpopBind) {
        try {
          // Parse the JWT to check expiration
          const parts = dpopBind.split('.');
          if (parts.length === 3) {
            const payload = JSON.parse(atob(parts[1]));
            const now = Math.floor(Date.now() / 1000);
            
            if (payload.exp && now > payload.exp) {
              logger.info('DPoP bind token expired, will clear session data');
              shouldClearSession = true;
            }
          }
        } catch (parseError) {
          logger.warn('Failed to parse dpop_bind token:', parseError);
          shouldClearSession = true;
        }
      } else {
        // If no dpop_bind but we have csrf/nonce, they're orphaned from old session
        const csrf = await idbGet('session', 'csrf');
        const nonce = await idbGet('session', 'dpop_nonce');
        
        if (csrf || nonce) {
          logger.info('Found orphaned session tokens without dpop_bind, will clear');
          shouldClearSession = true;
        }
      }
      
      // Clear stale session data if needed
      if (shouldClearSession) {
        logger.info('Clearing stale session data...');
        await idbDelete('session', 'dpop_bind');
        await idbDelete('session', 'csrf');
        await idbDelete('session', 'dpop_nonce');
      }
      
      // Step 1: Setup mobile session (same as desktop, but fingerprint will detect mobile)
      let sessionData;
      try {
        sessionData = await DpopFun.setupSession();
        logger.info('Mobile session setup completed');
      } catch (setupError) {
        // If setup failed, it might be due to stale tokens - retry once
        logger.warn('First session setup attempt failed, retrying with fresh state...', setupError);
        await idbDelete('session', 'dpop_bind');
        await idbDelete('session', 'csrf');
        await idbDelete('session', 'dpop_nonce');
        sessionData = await DpopFun.setupSession();
        logger.info('Mobile session setup completed after retry');
      }
      
      // Note: setupSession() already collects signal_data/fingerprint which includes device type
      // The FingerprintService will automatically detect if this is a mobile device
      
      // Step 2: Handle authentication based on flow type
      if (this.flowType === 'login') {
        await this.setUsernameForLogin();
        await this.handlePasskeyAuthentication();
        await this.completeMobileLinking();
      }
      // For registration flows, username and authentication are handled separately
      
    } catch (error) {
      logger.error('Mobile session setup failed:', error);
      if (this.onError) {
        this.onError(error);
      }
      throw error;
    }
  }

  /**
   * Set username for login flow (Mobile side)
   */
  async setUsernameForLogin() {
    try {
      logger.info(`Setting username for mobile login flow: ${this.username}`);
      
      if (!this.username) {
        throw new Error('No username provided for login flow');
      }
      
      // Username is already available for passkey authentication
      logger.info('Username available for passkey authentication:', this.username);
      
    } catch (error) {
      logger.error('Failed to set username for mobile login:', error);
      throw error;
    }
  }

  /**
   * Handle passkey authentication based on flow type (Mobile side)
   */
  async handlePasskeyAuthentication() {
    try {
      if (this.flowType === 'registration') {
        // Registration flow - create new passkey for usernameless discovery
        logger.info('Registration flow - creating new passkey for usernameless discovery...');
        await this.createNewPasskeyForRegistration();
      } else if (this.flowType === 'login') {
        // Login flow - authenticate with existing passkey
        logger.info('Login flow - authenticating with existing passkey...');
        await this.authenticateWithExistingPasskey();
      } else {
        throw new Error(`Unknown flow type: ${this.flowType}`);
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
   * Authenticate with existing passkey for login flow (Mobile side)
   */
  async authenticateWithExistingPasskey() {
    try {
      logger.info('Authenticating with existing passkey for username:', this.username);
      
      // For mobile login, get auth options with the username
      // This allows the server to return the specific credentials for this user
      // But we still use empty allowCredentials for usernameless discovery on the client
      const authOptions = await Passkeys.getAuthOptions(this.username);
      logger.info('Auth options received, has credentials:', authOptions._meta?.hasCredentials);
      
      // Override allowCredentials to empty array for usernameless discovery
      // This allows the platform authenticator to present available passkeys
      authOptions.allowCredentials = [];
      
      // Authenticate with passkey (browser will show available passkeys)
      const result = await Passkeys.authenticatePasskey(this.username, authOptions);
      logger.info('Passkey authentication successful:', result);
      
      // Notify about authentication
      if (this.onAuthenticated) {
        this.onAuthenticated('mobile passkey');
      }
      
    } catch (error) {
      logger.error('Failed to authenticate with existing passkey:', error);
      throw error;
    }
  }

  /**
   * Create new passkey for registration flow (Mobile side)
   */
  async createNewPasskeyForRegistration() {
    try {
      logger.info('Creating new passkey for registration flow...');
      
      // Register new passkey
      const result = await Passkeys.registerPasskey(this.username);
      logger.info('New passkey created successfully:', result);
      
      // Notify about authentication
      if (this.onAuthenticated) {
        this.onAuthenticated('mobile passkey');
      }
      
    } catch (error) {
      logger.error('Failed to create new passkey for registration:', error);
      throw error;
    }
  }

  /**
   * Link mobile session to desktop session (Mobile side)
   */
  async linkMobileToDesktop() {
    try {
      logger.info('Linking mobile session to desktop session...');
      
      const response = await DpopFun.dpopFetch('POST', '/link/mobile/start', {
        body: JSON.stringify({ lid: this.currentLinkId })
      });
      const data = await response.json();
      
      // Extract desktop username from the response
      this.desktopUsername = data.desktop_username;
      logger.info(`Desktop username received: ${this.desktopUsername}`);
      
      return data;
      
    } catch (error) {
      logger.error('Failed to link mobile session to desktop:', error);
      throw error;
    }
  }

  /**
   * Continue registration using desktop username (Mobile side)
   */
  async continueRegistrationWithDesktopUsername() {
    try {
      logger.info('Continuing registration with desktop username...');
      
      // Use the desktop username for registration (if available)
      this.username = this.desktopUsername;
      
      // If no desktop username, generate one for mobile
      if (!this.username) {
        logger.info('No desktop username found, generating mobile username...');
        const timestamp = Date.now().toString(36);
        const random = Math.random().toString(36).substring(2, 8);
        this.username = `mobile_${timestamp}_${random}`;
        logger.info('Generated mobile username:', this.username);
      }
      
      logger.info(`Username for mobile registration: ${this.username}`);
      
      // Continue with passkey authentication
      await this.handlePasskeyAuthentication();
      
      // Complete mobile linking
      await this.completeMobileLinking();
      
    } catch (error) {
      logger.error('Failed to continue registration with desktop username:', error);
      throw error;
    }
  }

  /**
   * Complete mobile linking process (Mobile side)
   */
  async completeMobileLinking() {
    try {
      logger.info(`Completing mobile linking for link ID: ${this.currentLinkId}, flow type: ${this.flowType}`);
      
      // Complete the mobile linking process
      const response = await DpopFun.dpopFetch('POST', '/link/mobile/complete', {
        body: JSON.stringify({ link_id: this.currentLinkId })
      });
      
      if (!response.ok) {
        const errorData = await response.json();
        logger.error('Mobile link complete failed:', errorData);
        throw new Error(errorData.detail || 'Failed to complete mobile linking');
      }
      
      const completeData = await response.json();
      
      logger.info('Mobile link completed successfully, response:', completeData);
      logger.info('Flow type:', this.flowType);
      
      if (this.onComplete) {
        logger.info('Calling onComplete callback...');
        this.onComplete(completeData);
      }
      if (this.onStepComplete) {
        logger.info('Calling onStepComplete callback...');
        this.onStepComplete(completeData);
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
   * Issue bootstrap code for desktop verification (Mobile side - registration flow only)
   */
  async issueBootstrapCode() {
    if (this.flowType === 'login') {
      logger.info('Skipping bootstrap code for login flow');
      return;
    }

    try {
      logger.info(`Issuing bootstrap code for link ID: ${this.currentLinkId}`);
      
      const response = await DpopFun.dpopFetch('POST', '/link/mobile/issue-bc', {
        body: JSON.stringify({ lid: this.currentLinkId })
      });
      const data = await response.json();
      
      logger.info('Bootstrap code issued successfully');
      return data;
      
    } catch (error) {
      logger.error('Failed to issue bootstrap code:', error);
      throw error;
    }
  }

  // ============================================================================
  // SHARED/UTILITY METHODS
  // ============================================================================

  /**
   * Clean up all resources
   */
  cleanup() {
    this.stopStatusMonitoring();
    this.stopCamera();
    this.currentLinkId = null;
    
    if (this.containerElement) {
      this.containerElement.innerHTML = '';
    }
    
    this.containerElement = null;
    this.onStepComplete = null;
    this.onStepSkip = null;
  }

  /**
   * Destroy instance and clean up all resources
   */
  destroy() {
    logger.info('Destroying MobileLinkService - cleaning up all resources');
    this.cleanup();
  }

  /**
   * Get current link ID
   * @returns {string|null} Current link ID
   */
  getCurrentLinkId() {
    return this.currentLinkId;
  }

  /**
   * Check if currently linking
   * @returns {boolean} Whether currently linking
   */
  isLinking() {
    return !!this.currentLinkId;
  }

  /**
   * Clear current link
   */
  clearLink() {
    this.currentLinkId = null;
    this.stopStatusMonitoring();
  }
}