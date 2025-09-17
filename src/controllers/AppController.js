// src/controllers/AppController.js
// Main application controller

import { ButtonManager } from '../components/ButtonManager.js';
import { Logger } from '../components/Logger.js';
import { StrongholdService } from '../services/StrongholdService.js';
import { PasskeyService } from '../services/PasskeyService.js';
import { LinkingService } from '../services/LinkingService.js';
import { FingerprintService } from '../services/FingerprintService.js';
import { ErrorHandler } from '../utils/ErrorHandler.js';

export class AppController {
  constructor() {
    // Initialize components
    this.logger = new Logger('logContainer');
    this.buttonManager = new ButtonManager();
    this.errorHandler = new ErrorHandler(this.logger);
    
    // Initialize services
    this.stronghold = new StrongholdService();
    this.passkeys = new PasskeyService();
    this.linking = new LinkingService(this.stronghold);
    
    // Application state
    this.state = {
      isInitialized: false,
      username: null,
      hasSession: false,
      hasBIK: false,
      hasDPoP: false,
      passkeySupported: false,
      passkeyEnabled: false,
      hasExistingPasskeys: false,
      isLinking: false
    };
    
    // Bind methods
    this.handleError = this.handleError.bind(this);
    this.updateState = this.updateState.bind(this);
  }

  /**
   * Initialize the application
   */
  async initialize() {
    try {
      this.logger.info('Initializing application...');
      
            // Initialize button manager
      this.buttonManager.initialize([
        'registerModeBtn', 'signinModeBtn', 'submitUsernameBtn', 'submitSigninBtn', 'registerBrowserBtn', 'initBtn', 'bikBtn', 'dpopBtn', 'apiBtn',
        'regBtn', 'authBtn', 'linkBtn', 'flushBtn', 'clientFlushBtn',
        'swRegBtn', 'swUnregBtn', 'echoSWBtn', 'testSWBtn'
      ]);
      
      // Check passkey support
      await this.checkPasskeySupport();
      
      // Check for existing session and restore state
      await this.checkExistingSession();
      
      // Update initial state
      this.updateState();
      
      // Set up event listeners
      this.setupEventListeners();
      
      // Set up modal functionality
      this.setupModalHandlers();
      
      this.state.isInitialized = true;
      this.logger.success('Application initialized successfully');
      
    } catch (error) {
      this.handleError(error, 'Application initialization');
    }
  }

  /**
   * Check passkey support and update UI
   */
  async checkPasskeySupport() {
    try {
      // Only check browser support during initialization
      const supportStatus = await this.passkeys.getBasicSupportStatus();
      
      this.state.passkeySupported = supportStatus.isSupported;
      this.state.passkeyEnabled = supportStatus.hasUVPA;
      
      // Update passkey buttons
      if (this.state.passkeySupported && this.state.passkeyEnabled) {
        this.buttonManager.enable('regBtn');
        this.buttonManager.enable('authBtn');
      } else {
        const reason = !this.state.passkeySupported ? 
          '❌ Passkeys not supported by this browser' : 
          '❌ Passkeys not supported by this browser';
        
        this.buttonManager.disable('regBtn', reason);
        this.buttonManager.disable('authBtn', reason);
        
        this.logger.warn(`Passkey buttons disabled: ${reason}`);
      }
      
    } catch (error) {
      // Don't fail initialization if passkey check fails
      this.logger.warn('Passkey support check failed, continuing without passkeys', error);
      this.state.passkeySupported = false;
      this.state.passkeyEnabled = false;
      
      const reason = '❌ Passkeys not supported by this browser';
      this.buttonManager.disable('regBtn', reason);
      this.buttonManager.disable('authBtn', reason);
    }
  }

  /**
   * Check for existing session and restore state
   */
  async checkExistingSession() {
    try {
      this.logger.info('Checking for existing session...');
      
      // Check if we have a valid session
      const sessionStatus = await this.stronghold.getSessionStatus();
      this.logger.debug('Session status received:', sessionStatus);
      
      if (sessionStatus && sessionStatus.valid) {
        this.logger.info('Valid session found, checking DPoP binding...');
        this.logger.debug('Session details:', {
          state: sessionStatus.state,
          bik_registered: sessionStatus.bik_registered,
          dpop_bound: sessionStatus.dpop_bound
        });
        
        this.state.hasSession = true;
        
        // Restore the service's internal state
        await this.stronghold.restoreSessionState();
        
        // Check if DPoP is bound
        if (sessionStatus.dpop_bound) {
          this.logger.info('DPoP binding found - resuming session to get fresh binding token');
          this.state.hasSession = true;
          this.state.hasBIK = true;
          this.state.hasDPoP = true;
          
          // Check for existing passkeys
          await this.checkExistingPasskeys();
          
          // Update passkey authentication state
          this.passkeys.setAuthenticated(true);
          
          // Set success states for completed steps (no auto-reset for restored sessions)
          this.buttonManager.setSuccess('registerBrowserBtn', 'Browser registered & DPoP bound!', 0);
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
          this.buttonManager.setSuccess('bikBtn', 'BIK restored!', 0);
          this.buttonManager.setSuccess('dpopBtn', 'DPoP restored!', 0);
          
          this.logger.success('Session resume completed - ready for secure operations');
          
        } else if (sessionStatus.bik_registered) {
          this.logger.info('BIK registered but DPoP not bound');
          this.state.hasBIK = true;
          
          // Set success state for session and BIK (no auto-reset for restored sessions)
          this.buttonManager.setSuccess('registerBrowserBtn', 'Browser registered (DPoP pending)', 0);
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
          this.buttonManager.setSuccess('bikBtn', 'BIK restored!', 0);
        } else {
          this.logger.info('Session exists but BIK not registered');
          
          // Set success state for session only (no auto-reset for restored sessions)
          this.buttonManager.setSuccess('registerBrowserBtn', 'Session restored (registration pending)', 0);
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
        }
        
      } else {
        this.logger.info('No valid session found - starting fresh');
      }
      
    } catch (error) {
      this.logger.warn('Failed to check existing session, starting fresh', error);
      // Continue with fresh state
    }
  }

  /**
   * Check for existing passkeys after authentication
   */
  async checkExistingPasskeys() {
    try {
      const hasPasskeys = await this.passkeys.hasExistingPasskeys();
      this.state.hasExistingPasskeys = hasPasskeys;
      
      if (hasPasskeys) {
        this.logger.info('Existing passkeys found for this domain');
      } else {
        this.logger.info('No existing passkeys found for this domain');
      }
      
    } catch (error) {
      this.logger.warn('Failed to check existing passkeys', error);
      this.state.hasExistingPasskeys = false;
    }
  }

  /**
   * Submit username during onboarding
   */
  async submitUsername() {
    await this.errorHandler.handleAsync(async () => {
      const usernameInput = document.getElementById('usernameInput');
      const submitBtn = document.getElementById('submitUsernameBtn');
      const errorDiv = document.getElementById('usernameError');
      
      if (!usernameInput || !submitBtn || !errorDiv) {
        throw new Error('Username form elements not found');
      }
      
      const username = usernameInput.value.trim();
      
      // Clear previous errors
      errorDiv.style.display = 'none';
      errorDiv.textContent = '';
      
      // Basic validation
      if (!username) {
        this.showUsernameError('Username is required');
        return;
      }
      
      if (username.length < 3) {
        this.showUsernameError('Username must be at least 3 characters');
        return;
      }
      
      if (username.length > 50) {
        this.showUsernameError('Username must be less than 50 characters');
        return;
      }
      
      // Check for valid characters
      if (!/^[a-zA-Z0-9_-]+$/.test(username)) {
        this.showUsernameError('Username can only contain letters, numbers, underscores, and hyphens');
        return;
      }
      
      // Disable form during submission
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ Submitting...';
      usernameInput.disabled = true;
      
      try {
        const response = await fetch('/onboarding/username', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ username })
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          const errorMessage = errorData.detail || `HTTP ${response.status}`;
          this.showUsernameError(errorMessage);
          return; // Don't throw error for validation failures
        }
        
        const data = await response.json();
        
        // Success - show success message
        this.showUsernameSuccess(username);
        this.logger.success(`Username '${username}' submitted successfully!`);
        
        // Store username in state
        this.state.username = username;
        
      } catch (error) {
        // Only show error for unexpected network/server errors
        this.showUsernameError('Network error. Please try again.');
        this.logger.error('Unexpected error during username submission:', error);
      } finally {
        // Re-enable form
        submitBtn.disabled = false;
        submitBtn.textContent = '📝 Register Username';
        usernameInput.disabled = false;
      }
      
    }, 'Username submission', this.handleError);
  }

  /**
   * Show username error message
   */
  showUsernameError(message) {
    const errorDiv = document.getElementById('usernameError');
    if (errorDiv) {
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
    }
  }

  /**
   * Show success message after username submission
   */
  showUsernameSuccess(username, type = 'register') {
    // Find the User Binding section (the demo-section that contains the onboarding forms)
    const onboardingSections = document.querySelectorAll('.demo-section');
    let onboardingSection = null;
    
    for (const section of onboardingSections) {
      if (section.querySelector('#usernameInput') || section.querySelector('#signinUsernameInput') || section.querySelector('.onboarding-toggle')) {
        onboardingSection = section;
        break;
      }
    }
    
    if (onboardingSection) {
      // Hide the toggle buttons
      const toggleDiv = onboardingSection.querySelector('.onboarding-toggle');
      if (toggleDiv) {
        toggleDiv.style.display = 'none';
      }
      
      // Hide both forms
      const registerForm = onboardingSection.querySelector('#registerForm');
      const signinForm = onboardingSection.querySelector('#signinForm');
      if (registerForm) registerForm.style.display = 'none';
      if (signinForm) signinForm.style.display = 'none';
      
      // Show success message
      const successDiv = document.createElement('div');
      successDiv.className = 'onboarding-success';
      
      const message = type === 'signin' 
        ? `Welcome back, ${username}! Your session has been restored successfully. You can now proceed with the demo below.`
        : `Welcome, ${username}! Your user binding has been completed successfully. You can now proceed with the demo below.`;
      
      successDiv.innerHTML = `
        <div class="success-icon">✅</div>
        <h3>Welcome, ${username}!</h3>
        <p>${message}</p>
      `;
      
      onboardingSection.appendChild(successDiv);
    }
  }

  /**
   * Hide the entire onboarding section after user continues
   */
  hideOnboardingSection() {
    const onboardingSection = document.querySelector('.demo-section');
    if (onboardingSection && onboardingSection.querySelector('#usernameInput')) {
      onboardingSection.style.display = 'none';
    }
  }

  /**
   * Switch to register mode
   */
  switchToRegisterMode() {
    const registerBtn = document.getElementById('registerModeBtn');
    const signinBtn = document.getElementById('signinModeBtn');
    const registerForm = document.getElementById('registerForm');
    const signinForm = document.getElementById('signinForm');

    if (registerBtn) registerBtn.classList.add('active');
    if (signinBtn) signinBtn.classList.remove('active');
    if (registerForm) registerForm.style.display = 'block';
    if (signinForm) signinForm.style.display = 'none';

    // Clear any errors
    this.clearAllErrors();
  }

  /**
   * Switch to sign-in mode
   */
  switchToSigninMode() {
    const registerBtn = document.getElementById('registerModeBtn');
    const signinBtn = document.getElementById('signinModeBtn');
    const registerForm = document.getElementById('registerForm');
    const signinForm = document.getElementById('signinForm');

    if (registerBtn) registerBtn.classList.remove('active');
    if (signinBtn) signinBtn.classList.add('active');
    if (registerForm) registerForm.style.display = 'none';
    if (signinForm) signinForm.style.display = 'block';

    // Clear any errors
    this.clearAllErrors();
  }

  /**
   * Submit sign-in
   */
  async submitSignin() {
    await this.errorHandler.handleAsync(async () => {
      const usernameInput = document.getElementById('signinUsernameInput');
      const submitBtn = document.getElementById('submitSigninBtn');
      const errorDiv = document.getElementById('signinError');
      
      if (!usernameInput || !submitBtn || !errorDiv) {
        throw new Error('Sign-in form elements not found');
      }
      
      const username = usernameInput.value.trim();
      
      // Clear previous errors
      errorDiv.style.display = 'none';
      errorDiv.textContent = '';
      
      // Basic validation
      if (!username) {
        this.showSigninError('Username is required');
        return;
      }
      
      // Disable form during submission
      submitBtn.disabled = true;
      submitBtn.textContent = '⏳ Signing in...';
      usernameInput.disabled = true;
      
      try {
        const response = await fetch('/onboarding/signin', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          credentials: 'include',
          body: JSON.stringify({ username })
        });
        
        if (!response.ok) {
          const errorData = await response.json();
          const errorMessage = errorData.detail || `HTTP ${response.status}`;
          this.showSigninError(errorMessage);
          return; // Don't throw error for validation failures
        }
        
        const data = await response.json();
        
        // Success - show success message
        this.showUsernameSuccess(username, 'signin');
        this.logger.success(`Welcome back, ${username}!`);
        
        // Store username in state
        this.state.username = username;
        
      } catch (error) {
        // Only show error for unexpected network/server errors
        this.showSigninError('Network error. Please try again.');
        this.logger.error('Unexpected error during sign-in:', error);
      } finally {
        // Re-enable form
        submitBtn.disabled = false;
        submitBtn.textContent = '🔐 Sign In';
        usernameInput.disabled = false;
      }
      
    }, 'Sign-in', this.handleError);
  }

  /**
   * Show sign-in error message
   */
  showSigninError(message) {
    const errorDiv = document.getElementById('signinError');
    if (errorDiv) {
      errorDiv.textContent = message;
      errorDiv.style.display = 'block';
    }
  }

  /**
   * Clear all error messages
   */
  clearAllErrors() {
    const usernameError = document.getElementById('usernameError');
    const signinError = document.getElementById('signinError');
    
    if (usernameError) {
      usernameError.style.display = 'none';
      usernameError.textContent = '';
    }
    
    if (signinError) {
      signinError.style.display = 'none';
      signinError.textContent = '';
    }
  }

  /**
   * Set up event listeners
   */
  setupEventListeners() {
    // Mode toggle buttons
    document.getElementById('registerModeBtn')?.addEventListener('click', () => {
      this.switchToRegisterMode();
    });

    document.getElementById('signinModeBtn')?.addEventListener('click', () => {
      this.switchToSigninMode();
    });

    // Username submission (register)
    document.getElementById('submitUsernameBtn')?.addEventListener('click', () => {
      this.submitUsername();
    });

    // Username input - handle Enter key (register)
    document.getElementById('usernameInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.submitUsername();
      }
    });

    // Sign in submission
    document.getElementById('submitSigninBtn')?.addEventListener('click', () => {
      this.submitSignin();
    });

    // Sign in input - handle Enter key
    document.getElementById('signinUsernameInput')?.addEventListener('keypress', (e) => {
      if (e.key === 'Enter') {
        this.submitSignin();
      }
    });

    // Register browser and bind DPoP (merged function)
    document.getElementById('registerBrowserBtn')?.addEventListener('click', () => {
      this.registerBrowserAndBindDPoP();
    });

    // API testing
    document.getElementById('apiBtn')?.addEventListener('click', () => {
      this.testAPI();
    });

    // Passkey registration
    document.getElementById('regBtn')?.addEventListener('click', () => {
      this.registerPasskey();
    });

    // Passkey authentication
    document.getElementById('authBtn')?.addEventListener('click', () => {
      this.authenticatePasskey();
    });

    // Cross-device linking
    document.getElementById('linkBtn')?.addEventListener('click', () => {
      this.startLinking();
    });

    // Flush buttons
    document.getElementById('flushBtn')?.addEventListener('click', () => {
      this.serverFlush();
    });

    document.getElementById('clientFlushBtn')?.addEventListener('click', () => {
      this.clientFlush();
    });


  }

  /**
   * Initialize session
   */
  async initializeSession() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('initBtn', 'Initializing...');
      console.log('Starting session initialization...');
      
      const session = await this.stronghold.initSession();
      
      this.state.hasSession = true;
      this.updateState();
      
      this.buttonManager.setSuccess('initBtn', 'Session initialized!');
      this.logger.success('Session initialized successfully', session);
      
      // Collect device fingerprinting data after session is confirmed working
      console.log('About to collect fingerprint...');
      await this.collectFingerprint();
      console.log('Fingerprint collection completed');
      
    }, 'Session initialization', this.handleError);
  }

  /**
   * Collect device fingerprinting data
   */
  async collectFingerprint() {
    try {
      this.logger.info('Starting fingerprint collection...');
      
      // Use the centralized FingerprintService
      const result = await FingerprintService.collectAndSendFingerprint('desktop');
      
      this.logger.info('Fingerprint collection completed successfully');
      return result;
    } catch (error) {
      console.log('❌ FINGERPRINT COLLECTION FAILED:', error);
      this.logger.error('Failed to collect fingerprint:', error);
      // Don't throw - fingerprinting failure shouldn't break session initialization
    }
  }


  /**
   * Get canvas fingerprint
   */
  getCanvasFingerprint() {
    try {
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      
      // Draw some text and shapes
      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('Canvas fingerprint', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('Canvas fingerprint', 4, 17);
      
      return canvas.toDataURL();
    } catch (e) {
      return 'unknown';
    }
  }

  /**
   * Get audio fingerprint
   */
  async getAudioFingerprint() {
    try {
      const audioContext = new (window.AudioContext || window.webkitAudioContext)();
      const oscillator = audioContext.createOscillator();
      const analyser = audioContext.createAnalyser();
      const gainNode = audioContext.createGain();
      const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);
      
      oscillator.type = 'triangle';
      oscillator.frequency.value = 10000;
      
      gainNode.gain.value = 0;
      
      oscillator.connect(analyser);
      analyser.connect(scriptProcessor);
      scriptProcessor.connect(gainNode);
      gainNode.connect(audioContext.destination);
      
      oscillator.start(0);
      
      return new Promise((resolve) => {
        scriptProcessor.onaudioprocess = (event) => {
          const buffer = event.inputBuffer.getChannelData(0);
          const fingerprint = Array.from(buffer.slice(0, 30)).map(x => x.toFixed(3)).join(',');
          audioContext.close();
          resolve(fingerprint);
        };
      });
    } catch (e) {
      return 'unknown';
    }
  }

  /**
   * Register BIK
   */
  async registerBIK() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('bikBtn', 'Registering BIK...');
      
      const bik = await this.stronghold.registerBIK();
      
      this.state.hasBIK = true;
      this.updateState();
      
      this.buttonManager.setSuccess('bikBtn', 'BIK registered!');
      this.logger.success('BIK registered successfully', bik);
      
    }, 'BIK registration', this.handleError);
  }

  /**
   * Bind DPoP
   */
  async bindDPoP() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('dpopBtn', 'Binding DPoP...');
      
      this.logger.debug('Starting DPoP binding process...');
      this.logger.debug('Current state before binding:', {
        hasSession: this.state.hasSession,
        hasBIK: this.state.hasBIK,
        hasDPoP: this.state.hasDPoP
      });
      
      const dpop = await this.stronghold.bindDPoP();
      
      this.logger.debug('DPoP binding completed:', dpop);
      
      this.state.hasDPoP = true;
      
      // Enable passkey service authentication after DPoP binding
      this.passkeys.setAuthenticated(true);
      
      // Check for existing passkeys now that we're authenticated
      await this.checkExistingPasskeys();
      
      this.updateState();
      
      this.buttonManager.setSuccess('dpopBtn', 'DPoP bound!');
      this.logger.success('DPoP bound successfully', dpop);
      
    }, 'DPoP binding', this.handleError);
  }

  /**
   * Register browser and bind DPoP (merged function)
   */
  async registerBrowserAndBindDPoP() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('registerBrowserBtn', 'Setting up browser...');
      
      // Step 1: Initialize session
      this.logger.info('Step 1: Initializing session...');
      const session = await this.stronghold.initSession();
      this.state.hasSession = true;
      this.logger.success('Session initialized successfully', session);
      
      // Collect device fingerprinting data after session is confirmed working
      console.log('About to collect fingerprint...');
      await this.collectFingerprint();
      console.log('Fingerprint collection completed');
      
      // Step 2: Register BIK
      this.logger.info('Step 2: Registering browser identity...');
      const bik = await this.stronghold.registerBIK();
      this.state.hasBIK = true;
      this.logger.success('Browser identity registered successfully', bik);
      
      // Step 3: Bind DPoP
      this.logger.info('Step 3: Binding DPoP token...');
      this.logger.debug('Current state before binding:', {
        hasSession: this.state.hasSession,
        hasBIK: this.state.hasBIK,
        hasDPoP: this.state.hasDPoP
      });
      
      const dpop = await this.stronghold.bindDPoP();
      this.state.hasDPoP = true;
      
      // Enable passkey service authentication after DPoP binding
      this.passkeys.setAuthenticated(true);
      
      // Check for existing passkeys now that we're authenticated
      await this.checkExistingPasskeys();
      
      this.updateState();
      
      this.buttonManager.setSuccess('registerBrowserBtn', 'Browser registered & DPoP bound!');
      this.logger.success('Browser registration and DPoP binding completed successfully', { session, bik, dpop });
      
    }, 'Browser registration and DPoP binding', this.handleError);
  }

  /**
   * Test API
   */
  async testAPI() {
    // Show the modal first
    this.showApiModal();
  }

  /**
   * Register passkey
   */
  async registerPasskey() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('regBtn', 'Creating passkey...');
      
      try {
        const result = await this.passkeys.registerPasskey();
        
        this.state.passkeyEnabled = true;
        this.updateState();
        
        this.buttonManager.setSuccess('regBtn', 'Passkey created!');
        this.logger.success('Passkey registered successfully', result);
        
      } catch (error) {
        // Handle user cancellation gracefully
        if (error.message && error.message.includes('cancelled')) {
          this.buttonManager.reset('regBtn');
          this.logger.info('Passkey registration cancelled by user');
          return; // Don't treat cancellation as an error
        }
        
        // Re-throw other errors for normal error handling
        throw error;
      }
      
    }, 'Passkey registration', this.handleError);
  }

  /**
   * Authenticate passkey
   */
  async authenticatePasskey() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('authBtn', 'Authenticating...');
      
      try {
        const result = await this.passkeys.authenticatePasskey();
        
        this.buttonManager.setSuccess('authBtn', 'Authenticated!');
        this.logger.success('Passkey authentication successful', result);
        
      } catch (error) {
        // Handle user cancellation gracefully
        if (error.message && error.message.includes('cancelled')) {
          this.buttonManager.reset('authBtn');
          this.logger.info('Passkey authentication cancelled by user');
          return; // Don't treat cancellation as an error
        }
        
        // Re-throw other errors for normal error handling
        throw error;
      }
      
    }, 'Passkey authentication', this.handleError);
  }

  /**
   * Start cross-device linking
   */
  async startLinking() {
    await this.errorHandler.handleAsync(async () => {
      // Clean up existing elements
      this.cleanupLinkingElements();
      
      this.buttonManager.setLoading('linkBtn', 'Creating QR...');
      
      const linkData = await this.linking.startLinking();
      
      this.state.isLinking = true;
      this.updateState();
      
      // Create QR code
      this.createQRCode(linkData.qr_url, linkData.linkId);
      
      // Start status monitoring
      this.monitorLinkingStatus(linkData.linkId);
      
      this.buttonManager.setSuccess('linkBtn', 'QR created!');
      this.logger.success('Cross-device linking started', linkData);
      
    }, 'Cross-device linking', this.handleError);
  }

  /**
   * Monitor linking status
   * @param {string} linkId - Link ID
   */
  monitorLinkingStatus(linkId) {
    const onStatusUpdate = (status) => {
      // Handle different message types
      if (status.type === 'status') {
        this.logger.info(`Linking status: ${status.status}`, status);
        
        if (status.status === 'scanned') {
          this.updateQRStatus('scanned');
        } else if (status.status === 'linked' || status.status === 'completed') {
          this.handleLinkingComplete(linkId);
        } else if (status.status === 'failed') {
          this.handleLinkingFailed(status.error);
        }
      } else if (status.type === 'signature') {
        this.logger.info('Signature data received', status.data);
        // Handle signature data if needed
      } else {
        this.logger.info('Unknown message type received', status);
      }
    };

    const onError = (error) => {
      this.logger.error('Linking status monitoring failed', error);
    };

    // Try SSE first, fallback to polling
    this.linking.monitorStatus(linkId, onStatusUpdate, onError, 'sse');
  }

  /**
   * Handle linking completion
   * @param {string} linkId - Link ID
   */
  async handleLinkingComplete(linkId) {
    try {
      this.updateQRStatus('completed');
      
      // Remove QR code container
      const qrContainer = document.querySelector('.qr-container');
      if (qrContainer) {
        qrContainer.remove();
      }
      
      this.state.isLinking = false;
      this.updateState();
      
      this.logger.success('Cross-device linking completed successfully');
      this.logger.info('Redirecting to verify page to enter BC code...');
      
      // Redirect to verify page to enter BC code
      setTimeout(() => {
        window.location.href = '/verify';
      }, 1000);
      
    } catch (error) {
      this.handleError(error, 'Linking completion');
    }
  }

  /**
   * Handle linking failure
   * @param {string} error - Error message
   */
  handleLinkingFailed(error) {
    this.updateQRStatus('failed');
    this.state.isLinking = false;
    this.updateState();
    
    this.logger.error('Cross-device linking failed', error);
  }


  /**
   * Create QR code element
   * @param {string} qrData - QR code data
   * @param {string} linkId - Link ID
   */
  createQRCode(qrData, linkId) {
    const container = document.createElement('div');
    container.className = 'qr-container';
    container.innerHTML = `
      <h3>Scan QR Code with Mobile Device</h3>
      <div class="qr-code" id="qrcode"></div>
      <p>Link ID: ${linkId}</p>
      <p><strong>URL:</strong> <code>${qrData}</code></p>
      <div class="qr-status" id="qrStatus">Waiting for scan...</div>
    `;

    // Insert after the sequence step containing the link button
    const linkBtn = document.getElementById('linkBtn');
    if (linkBtn && linkBtn.parentNode) {
      const sequenceStep = linkBtn.closest('.sequence-step');
      if (sequenceStep && sequenceStep.parentNode) {
        // Insert after the entire sequence step
        sequenceStep.parentNode.insertBefore(container, sequenceStep.nextSibling);
      } else {
        // Fallback: insert after the button
        linkBtn.parentNode.insertBefore(container, linkBtn.nextSibling);
      }
    }

    // Generate QR code
    if (window.QRCode) {
      new QRCode(document.getElementById('qrcode'), qrData);
      
      // Add AprilTag overlay after QR code is generated
      setTimeout(async () => {
        if (window.QRGenerator) {
          const qrGenerator = new QRGenerator();
          await qrGenerator.generateQRWithAprilTag('qrcode', qrData);
        }
      }, 100); // Small delay to ensure QR code is rendered
    }
  }

  /**
   * Update QR code status
   * @param {string} status - Status ('scanned', 'completed', 'failed')
   */
  updateQRStatus(status) {
    const statusElement = document.getElementById('qrStatus');
    if (!statusElement) return;

    const statusTexts = {
      scanned: '📱 Device scanned - completing link...',
      completed: '✅ Link completed successfully!',
      failed: '❌ Link failed - please try again'
    };

    statusElement.textContent = statusTexts[status] || 'Unknown status';
    statusElement.className = `qr-status qr-status-${status}`;
  }

  /**
   * Clean up linking elements
   */
  cleanupLinkingElements() {
    const existingQR = document.querySelector('.qr-container');
    if (existingQR) existingQR.remove();
    
    const existingSignature = document.querySelector('.signature-container');
    if (existingSignature) existingSignature.remove();
    
    // Clean up AprilTag overlay if it exists
    const apriltagOverlay = document.getElementById('apriltag-overlay');
    if (apriltagOverlay) apriltagOverlay.remove();
  }

  /**
   * Set up modal handlers
   */
  setupModalHandlers() {
    const modal = document.getElementById('apiModal');
    const closeBtn = document.getElementById('closeApiModal');
    const cancelBtn = document.getElementById('cancelApiRequest');
    const sendBtn = document.getElementById('sendApiRequest');

    // Close modal handlers
    if (closeBtn) {
      closeBtn.addEventListener('click', () => {
        this.hideApiModal();
      });
    }

    if (cancelBtn) {
      cancelBtn.addEventListener('click', () => {
        this.hideApiModal();
      });
    }

    // Close modal when clicking outside
    if (modal) {
      modal.addEventListener('click', (e) => {
        if (e.target === modal) {
          this.hideApiModal();
        }
      });
    }

    // Close modal with Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && modal && modal.classList.contains('show')) {
        this.hideApiModal();
      }
    });

    // Send API request
    if (sendBtn) {
      sendBtn.addEventListener('click', () => {
        this.sendApiRequest();
      });
    }
  }

  /**
   * Show API test modal
   */
  showApiModal() {
    const modal = document.getElementById('apiModal');
    if (modal) {
      modal.classList.add('show');
      
      // Reset response boxes
      const apiResponse = modal.querySelector('#apiResponse');
      const clientRequest = modal.querySelector('#clientRequest');
      
      if (apiResponse) {
        apiResponse.innerHTML = '<em>Click "Send Request" to test the API...</em>';
        apiResponse.className = 'response-box';
      }
      
      if (clientRequest) {
        clientRequest.innerHTML = '<em>Request details will appear here...</em>';
        clientRequest.className = 'response-box';
      }
    }
  }

  /**
   * Hide API test modal
   */
  hideApiModal() {
    const modal = document.getElementById('apiModal');
    if (modal) {
      modal.classList.remove('show');
    }
  }

  /**
   * Send API request from modal
   */
  async sendApiRequest() {
    const sendBtn = document.getElementById('sendApiRequest');
    const apiResponse = document.getElementById('apiResponse');
    const clientRequest = document.getElementById('clientRequest');
    const apiMessage = document.getElementById('apiMessage');

    if (!sendBtn || !apiResponse || !clientRequest || !apiMessage) return;

    try {
      sendBtn.disabled = true;
      sendBtn.textContent = 'Sending...';
      apiResponse.innerHTML = 'Sending request...';
      apiResponse.className = 'response-box';
      clientRequest.innerHTML = 'Preparing request...';
      clientRequest.className = 'response-box';

      this.logger.info('Testing API access with DPoP token...');

      const message = apiMessage.value.trim() || 'Hello from Browser Identity & DPoP Security Demo!';
      
      const testData = {
        message: message,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent
      };

      // Capture request details before making the request
      const requestDetails = await this.captureRequestDetails(testData);
      
      const response = await this.stronghold.testAPI(testData);

      // Display request details
      clientRequest.innerHTML = JSON.stringify(requestDetails, null, 2);
      clientRequest.className = 'response-box info';

      // Display response
      apiResponse.innerHTML = JSON.stringify(response, null, 2);
      apiResponse.className = 'response-box success';

      this.buttonManager.setSuccess('apiBtn', 'API test successful!');
      this.logger.success('API access successful - DPoP token working!');
      this.logger.info(`Response: ${JSON.stringify(response, null, 2)}`);
      this.logger.success('DPoP cryptographic binding verified');

    } catch (error) {
      // Display error
      apiResponse.innerHTML = `Error: ${error.message}`;
      apiResponse.className = 'response-box error';
      clientRequest.innerHTML = 'Request details unavailable due to error';
      clientRequest.className = 'response-box error';

      this.buttonManager.setError('apiBtn', 'API test failed');
      this.logger.error(`API access failed: ${error.message}`);
    } finally {
      sendBtn.disabled = false;
      sendBtn.textContent = 'Send Request';
    }
  }

  /**
   * Capture request details including DPoP
   * @param {Object} testData - Test data
   * @returns {Promise<Object>} Request details
   */
  async captureRequestDetails(testData) {
    try {
      // Import the stronghold module to access its functions
      const Stronghold = await import('../stronghold.js');
      
      // Get current DPoP state
      const dpopNonce = await Stronghold.getDpopNonce();
      const bindToken = await Stronghold.getBindToken();
      
      // Get browser identity key info (without exposing private key)
      const bik = await Stronghold.getBIK();
      
      // Ensure nonce is a string or undefined
      const nonceValue = typeof dpopNonce === 'string' ? dpopNonce : undefined;
      
      // Create the actual DPoP proof that will be used
      const dpopProof = await Stronghold.createDpopProof({
        url: window.location.origin + '/api/echo',
        method: 'POST',
        nonce: nonceValue,
        privateKey: bik.privateKey,
        publicJwk: bik.publicJwk
      });

      return {
        timestamp: new Date().toISOString(),
        url: '/api/echo',
        method: 'POST',
        requestBody: testData,
        headers: {
          'Content-Type': 'application/json',
          'DPoP': dpopProof,
          'DPoP-Bind': bindToken || 'Not bound'
        },
        dpopDetails: {
          nonce: dpopNonce || 'Not set',
          proofStructure: {
            header: dpopProof.split('.')[0],
            payload: dpopProof.split('.')[1],
            signature: dpopProof.split('.')[2] ? `${dpopProof.split('.')[2].substring(0, 20)}...` : 'None'
          },
          browserIdentityKey: {
            kid: bik?.publicJwk?.kid || 'Not available',
            kty: bik?.publicJwk?.kty || 'Not available',
            crv: bik?.publicJwk?.crv || 'Not available',
            publicKeyThumbprint: bik?.publicJwk ? await Stronghold.jwkThumbprint(bik.publicJwk) : 'Not available'
          }
        }
      };
    } catch (error) {
      return {
        error: 'Failed to capture request details',
        details: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  /**
   * Update application state
   */
  updateState() {
    this.logger.debug('Updating application state:', this.state);
    
    // Register Browser & Bind DPoP button - enabled by default (first step)
    if (!this.state.hasDPoP) {
      this.buttonManager.enableIfNotSuccess('registerBrowserBtn');
    } else {
      // Keep enabled even after completion to allow re-running
      this.buttonManager.enableIfNotSuccess('registerBrowserBtn');
    }
    
    // Update button states based on dependencies, preserving success states
    if (this.state.hasSession) {
      this.buttonManager.enableIfNotSuccess('bikBtn');
    } else {
      this.buttonManager.disable('bikBtn');
    }

    if (this.state.hasSession && this.state.hasBIK && !this.state.hasDPoP) {
      this.logger.debug('Enabling DPoP button - hasSession:', this.state.hasSession, 'hasBIK:', this.state.hasBIK, 'hasDPoP:', this.state.hasDPoP);
      this.buttonManager.enableIfNotSuccess('dpopBtn');
    } else if (this.state.hasDPoP) {
      this.logger.debug('DPoP already bound - keeping button enabled');
      this.buttonManager.enableIfNotSuccess('dpopBtn');
    } else {
      this.logger.debug('Disabling DPoP button - hasSession:', this.state.hasSession, 'hasBIK:', this.state.hasBIK, 'hasDPoP:', this.state.hasDPoP);
      this.buttonManager.disable('dpopBtn');
    }

    if (this.state.hasDPoP) {
      this.buttonManager.enableIfNotSuccess('apiBtn');
      this.buttonManager.enableIfNotSuccess('linkBtn');
    } else {
      this.buttonManager.disable('apiBtn');
      this.buttonManager.disable('linkBtn');
    }

    // Log state changes
    this.logger.debug('Application state updated', this.state);
  }

  /**
   * Handle errors
   * @param {Error} error - Error object
   * @param {string} context - Error context
   */
  handleError(error, context) {
    const handledError = this.errorHandler.handle(error, context);
    
    // Show notification to user
    this.errorHandler.showNotification(handledError);
    
    // Reset button states
    this.buttonManager.resetAll();
  }

  /**
   * Server flush - clear all server-side data
   */
  async serverFlush() {
    try {
      this.buttonManager.setLoading('flushBtn', 'Flushing...');
      
      const response = await fetch('/_admin/flush', {
        method: 'POST',
        credentials: 'include'
      });
      
      if (!response.ok) {
        throw new Error(`Server flush failed: ${response.status}`);
      }
      
      const result = await response.json();
      this.logger.success('Server data flushed successfully');
      
      // Reset all states since server data is cleared
      this.resetAllStates();
      
      this.buttonManager.setSuccess('flushBtn', 'Server flushed!');
      
    } catch (error) {
      this.handleError(error, 'Server flush');
      this.buttonManager.reset('flushBtn');
    }
  }

  /**
   * Client flush - clear all client-side data
   */
  async clientFlush() {
    try {
      this.buttonManager.setLoading('clientFlushBtn', 'Flushing...');
      
      // Clear IndexedDB storage
      await this.clearClientStorage();
      
      this.logger.success('Client data flushed successfully');
      
      // Reset all states since client data is cleared
      this.resetAllStates();
      
      this.buttonManager.setSuccess('clientFlushBtn', 'Client flushed!');
      
    } catch (error) {
      this.handleError(error, 'Client flush');
      this.buttonManager.reset('clientFlushBtn');
    }
  }

    /**
   * Clear client-side storage (IndexedDB)
   */
  async clearClientStorage() {
    try {
      // Clear IndexedDB manually since storage utilities don't exist
      return new Promise((resolve, reject) => {
        const request = indexedDB.open('stronghold', 1);
        
        request.onerror = () => {
          reject(new Error('Failed to open IndexedDB'));
        };
        
        request.onsuccess = () => {
          const db = request.result;
          try {
            // Check what stores actually exist
            const storeNames = Array.from(db.objectStoreNames);
            this.logger.debug('Available IndexedDB stores:', storeNames);
            
            if (storeNames.length === 0) {
              // No stores exist, nothing to clear
              db.close();
              resolve();
              return;
            }
            
            // Only clear stores that actually exist
            const storesToClear = storeNames.filter(name => ['keys', 'meta'].includes(name));
            
            if (storesToClear.length === 0) {
              // No matching stores found
              db.close();
              resolve();
              return;
            }
            
            const transaction = db.transaction(storesToClear, 'readwrite');
            const clearPromises = storesToClear.map(storeName => {
              return new Promise((storeResolve, storeReject) => {
                const store = transaction.objectStore(storeName);
                const clearRequest = store.clear();
                
                clearRequest.onsuccess = () => storeResolve();
                clearRequest.onerror = () => storeReject(new Error(`Failed to clear ${storeName} store`));
              });
            });
            
            // Wait for all stores to be cleared
            Promise.all(clearPromises)
              .then(() => {
                db.close();
                resolve();
              })
              .catch((error) => {
                db.close();
                reject(error);
              });
            
          } catch (error) {
            db.close();
            reject(new Error(`IndexedDB transaction failed: ${error.message}`));
          }
        };
      });
    } catch (error) {
      throw new Error(`Failed to clear client storage: ${error.message}`);
    }
  }

  /**
   * Reset all application states
   */
  resetAllStates() {
    // Reset state
    this.state = {
      isInitialized: false,
      hasSession: false,
      hasBIK: false,
      hasDPoP: false,
      passkeySupported: false,
      passkeyEnabled: false,
      hasExistingPasskeys: false
    };
    
    // Reset service states
    this.stronghold.clearSession();
    this.passkeys.setAuthenticated(false);
    
    // Reset all buttons
    this.buttonManager.reset('initBtn');
    this.buttonManager.reset('bikBtn');
    this.buttonManager.reset('dpopBtn');
    this.buttonManager.reset('apiBtn');
    this.buttonManager.reset('regBtn');
    this.buttonManager.reset('authBtn');
    this.buttonManager.reset('linkBtn');
    
    // Disable buttons that require authentication
    this.buttonManager.disable('bikBtn');
    this.buttonManager.disable('dpopBtn');
    this.buttonManager.disable('apiBtn');
    this.buttonManager.disable('regBtn');
    this.buttonManager.disable('authBtn');
    this.buttonManager.disable('linkBtn');
    
    // Re-enable passkey buttons if supported
    if (this.state.passkeySupported && this.state.passkeyEnabled) {
      this.buttonManager.enable('regBtn');
      this.buttonManager.enable('authBtn');
    }
    
    this.logger.info('All application states reset');
  }

  /**
   * Get application state
   * @returns {Object} Current state
   */
  getState() {
    return { ...this.state };
  }


  getState() {
    return { ...this.state };
  }

  /**
   * Cleanup resources
   */
  cleanup() {
    this.linking.stopStatusMonitoring();
    this.buttonManager.resetAll();
  }
}
