// src/controllers/AppController.js
// Main application controller

import { ButtonManager } from './ButtonManager.js';
import { logger } from '../utils/logging.js';
import { DpopFunService } from '../services/DpopFunService.js';
import { PasskeyService } from '../services/PasskeyService.js';
import { LinkingService } from '../services/LinkingService.js';
import { FingerprintService } from '../services/FingerprintService.js';
import { ErrorHandler } from '../utils/ErrorHandler.js';
import { createQRContainer } from '../utils/qr-generator.js';

export class AppController {
  constructor() {
    // Initialize components
    this.buttonManager = new ButtonManager();
    this.errorHandler = new ErrorHandler(logger);
    
    // Initialize services
    this.dpopFun = new DpopFunService();
    this.passkeys = new PasskeyService();
    this.linking = new LinkingService(this.dpopFun);
    
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
      logger.info('Initializing application...');
      
            // Initialize button manager
      this.buttonManager.initialize([
        'registerModeBtn', 'signinModeBtn', 'submitUsernameBtn', 'submitSigninBtn', 'initBtn', 'bikBtn', 'dpopBtn', 'apiBtn',
        'regBtn', 'authBtn', 'linkBtn', 'flushBtn', 'clientFlushBtn',
        'swRegBtn', 'swUnregBtn', 'echoSWBtn', 'testSWBtn',
        'registerFaceBtn', 'verifyFaceBtn'
      ]);
      
      // Check passkey support
      await this.checkPasskeySupport();
      
      // Check for existing session and restore state
      await this.checkExistingSession();
      
      // Automatically register browser and bind DPoP if needed
      await this.autoRegisterBrowserAndBindDPoP();
      
      // Update initial state
      this.updateState();
      
      // Set up event listeners
      this.setupEventListeners();
      
      // Set up modal functionality
      this.setupModalHandlers();
      
      this.state.isInitialized = true;
      logger.success('Application initialized successfully');
      
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
        
        logger.warn(`Passkey buttons disabled: ${reason}`);
      }
      
    } catch (error) {
      // Don't fail initialization if passkey check fails
      logger.warn('Passkey support check failed, continuing without passkeys', error);
      this.state.passkeySupported = false;
      this.state.passkeyEnabled = false;
      
      const reason = '❌ Passkeys not supported by this browser';
      this.buttonManager.disable('regBtn', reason);
      this.buttonManager.disable('authBtn', reason);
    }
  }

  /**
   * Check for existing username in session
   */
  async checkExistingUsername() {
    try {
      // Use dpopFunFetch to include DPoP proof headers
      const data = await this.dpopFun.secureRequest('/onboarding/current-user');
      
      this.state.username = data.username;
      logger.info('Existing username found:', data.username);
      
      // Show success message for existing username
      this.showUsernameSuccess(data.username, 'signin');
      return true;
    } catch (error) {
      logger.debug('Could not check for existing username:', error);
      return false;
    }
  }


  /**
   * Update session status indicator
   */
  updateSessionStatusIndicator(status, icon, text, detail, ttlSeconds = null) {
    const indicator = document.getElementById('sessionStatusIndicator');
    if (!indicator) return;
    
    indicator.className = `status-indicator ${status}`;
    
    // Update status title (the actual text element)
    const statusTitle = indicator.querySelector('.status-title');
    if (statusTitle) {
      statusTitle.textContent = text;
    }
    
    // Update status detail
    const statusDetail = indicator.querySelector('.status-detail');
    if (statusDetail) {
      statusDetail.textContent = detail;
    }
    
    // Update TTL display
    const ttlElement = document.getElementById('sessionTTL');
    if (ttlElement) {
      if (ttlSeconds !== null && ttlSeconds > 0) {
        ttlElement.style.display = 'block';
        this.updateTTLDisplay(ttlSeconds);
      } else {
        ttlElement.style.display = 'none';
      }
    }
    
    // Show signal summary for successful states
    if (status === 'new-session' || status === 'reconnect') {
      this.loadSignalSummary();
    } else {
      this.hideSignalSummary();
    }
  }

  /**
   * Update TTL display with countdown
   */
  updateTTLDisplay(ttlSeconds) {
    const ttlValue = document.querySelector('.ttl-value');
    const ttlElement = document.getElementById('sessionTTL');
    if (!ttlValue || !ttlElement) {
      // TTL elements were removed from HTML, so skip TTL display
      return;
    }
    
    const hours = Math.floor(ttlSeconds / 3600);
    const minutes = Math.floor((ttlSeconds % 3600) / 60);
    const seconds = ttlSeconds % 60;
    
    let timeString;
    if (hours > 0) {
      timeString = `${hours}:${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    } else {
      timeString = `${minutes}:${seconds.toString().padStart(2, '0')}`;
    }
    
    ttlValue.textContent = timeString;
    
    // Update styling based on remaining time
    ttlElement.className = 'status-ttl';
    if (ttlSeconds < 300) { // Less than 5 minutes
      ttlElement.classList.add('danger');
    } else if (ttlSeconds < 900) { // Less than 15 minutes
      ttlElement.classList.add('warning');
    }
  }

  /**
   * Start TTL countdown timer
   */
  startTTLTimer(initialTTL) {
    // Clear existing timer
    if (this.ttlTimer) {
      clearInterval(this.ttlTimer);
    }
    
    let remainingSeconds = initialTTL;
    this.updateTTLDisplay(remainingSeconds);
    
    this.ttlTimer = setInterval(() => {
      remainingSeconds--;
      if (remainingSeconds <= 0) {
        clearInterval(this.ttlTimer);
        this.updateSessionStatusIndicator('loading', '⏰', 'Session Expired', 'DPoP binding has expired, refreshing...');
        // Optionally trigger session refresh
        setTimeout(() => {
          this.autoRegisterBrowserAndBindDPoP();
        }, 2000);
      } else {
        this.updateTTLDisplay(remainingSeconds);
      }
    }, 1000);
  }

  /**
   * Load and display signal summary
   */
  async loadSignalSummary() {
    try {
      const response = await fetch('/session/fingerprint', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.displaySignalSummary(data.fingerprint, data.device_type);
      } else {
        logger.debug('Could not load fingerprint data for signal summary');
        this.hideSignalSummary();
      }
    } catch (error) {
      logger.debug('Failed to load signal summary:', error);
      this.hideSignalSummary();
    }
  }

  /**
   * Display signal summary data
   */
  displaySignalSummary(fingerprint, deviceType) {
    const signalSummary = document.getElementById('signalSummary');
    if (!signalSummary || !fingerprint) {
      this.hideSignalSummary();
      return;
    }

    // Extract key signals
    const location = this.extractLocation(fingerprint);
    const device = this.extractDevice(fingerprint, deviceType);
    const browser = this.extractBrowser(fingerprint);

    // Update display elements
    const signalLocation = document.getElementById('signalLocation');
    const signalDevice = document.getElementById('signalDevice');
    const signalBrowser = document.getElementById('signalBrowser');
    
    if (signalLocation) signalLocation.textContent = location;
    if (signalDevice) signalDevice.textContent = device;
    if (signalBrowser) signalBrowser.textContent = browser;

    // Show the summary
    signalSummary.style.display = 'block';
  }

  /**
   * Hide signal summary
   */
  hideSignalSummary() {
    const signalSummary = document.getElementById('signalSummary');
    if (signalSummary) {
      signalSummary.style.display = 'none';
    }
  }

  /**
   * Extract location information from fingerprint
   */
  extractLocation(fingerprint) {
    const timezone = fingerprint.timezone || 'Unknown';
    const language = fingerprint.language || 'Unknown';
    
    // Try to get geolocation if available
    if (fingerprint.geolocation) {
      const geo = fingerprint.geolocation;
      if (geo.city && geo.country) {
        return `${geo.city}, ${geo.country}`;
      } else if (geo.country) {
        return geo.country;
      }
    }
    
    // Fallback to timezone
    return timezone.replace('_', ' ');
  }

  /**
   * Extract device information from fingerprint
   */
  extractDevice(fingerprint, deviceType) {
    const platform = fingerprint.platform || 'Unknown';
    const hardwareConcurrency = fingerprint.hardwareConcurrency || 'Unknown';
    const deviceMemory = fingerprint.deviceMemory || 'Unknown';
    
    let deviceInfo = `${deviceType || 'Unknown'}`;
    if (platform !== 'Unknown') {
      deviceInfo += ` (${platform})`;
    }
    
    return deviceInfo;
  }

  /**
   * Extract browser information from fingerprint
   */
  extractBrowser(fingerprint) {
    const userAgent = fingerprint.userAgent || '';
    const webglVendor = fingerprint.webglVendor || 'Unknown';
    
    // Try to extract browser name from user agent
    let browserName = 'Unknown';
    if (userAgent.includes('Chrome')) browserName = 'Chrome';
    else if (userAgent.includes('Firefox')) browserName = 'Firefox';
    else if (userAgent.includes('Safari')) browserName = 'Safari';
    else if (userAgent.includes('Edge')) browserName = 'Edge';
    
    return browserName;
  }

  /**
   * Show signal details modal
   */
  async showSignalDetailsModal() {
    const modal = document.getElementById('signalDetailsModal');
    const content = document.getElementById('signalDetailsContent');
    
    if (!modal || !content) return;
    
    // Show modal
    modal.style.display = 'flex';
    
    // Show loading state
    content.innerHTML = '<div class="loading-text">Loading signal data...</div>';
    
    try {
      // Fetch fingerprint data
      const response = await fetch('/session/fingerprint', {
        credentials: 'include'
      });
      
      if (response.ok) {
        const data = await response.json();
        this.renderSignalDetails(data.fingerprint, data.device_type);
      } else {
        content.innerHTML = '<div class="loading-text">Failed to load signal data</div>';
      }
    } catch (error) {
      content.innerHTML = '<div class="loading-text">Error loading signal data</div>';
    }
  }

  /**
   * Hide signal details modal
   */
  hideSignalDetailsModal() {
    const modal = document.getElementById('signalDetailsModal');
    if (modal) {
      modal.style.display = 'none';
    }
  }

  /**
   * Render detailed signal data in modal
   */
  renderSignalDetails(fingerprint, deviceType) {
    const content = document.getElementById('signalDetailsContent');
    if (!content || !fingerprint) return;
    
    const sections = [
      {
        title: '🌍 Location & Environment',
        data: {
          'Timezone': fingerprint.timezone || 'Unknown',
          'Language': fingerprint.language || 'Unknown',
          'Country': fingerprint.geolocation?.country || 'Unknown',
          'City': fingerprint.geolocation?.city || 'Unknown',
          'Region': fingerprint.geolocation?.region || 'Unknown'
        }
      },
      {
        title: '💻 Device Information',
        data: {
          'Device Type': deviceType || 'Unknown',
          'Platform': fingerprint.platform || 'Unknown',
          'Hardware Concurrency': fingerprint.hardwareConcurrency || 'Unknown',
          'Device Memory': fingerprint.deviceMemory || 'Unknown',
          'Cookie Enabled': fingerprint.cookieEnabled ? 'Yes' : 'No',
          'Do Not Track': fingerprint.doNotTrack || 'Unknown'
        }
      },
      {
        title: '🌐 Browser Details',
        data: {
          'User Agent': fingerprint.userAgent || 'Unknown',
          'WebGL Vendor': fingerprint.webglVendor || 'Unknown',
          'WebGL Renderer': fingerprint.webglRenderer || 'Unknown',
          'Color Depth': fingerprint.colorDepth || 'Unknown',
          'Screen Resolution': fingerprint.screenResolution || 'Unknown'
        }
      },
      {
        title: '🔒 Security & Automation',
        data: {
          'WebDriver': fingerprint.automation?.webdriver ? 'Detected' : 'Not Detected',
          'Headless UA': fingerprint.automation?.headlessUA ? 'Detected' : 'Not Detected',
          'Plugins Count': fingerprint.automation?.pluginsLength || 'Unknown',
          'MIME Types Count': fingerprint.automation?.mimeTypesLength || 'Unknown',
          'Visibility State': fingerprint.automation?.visibilityState || 'Unknown',
          'Has Focus': fingerprint.automation?.hasFocus ? 'Yes' : 'No'
        }
      }
    ];
    
    let html = '';
    sections.forEach(section => {
      html += `
        <div class="signal-detail-section">
          <div class="signal-detail-title">${section.title}</div>
          <div class="signal-detail-grid">
      `;
      
      Object.entries(section.data).forEach(([key, value]) => {
        html += `
          <div class="signal-detail-item">
            <div class="signal-detail-label">${key}:</div>
            <div class="signal-detail-value">${value}</div>
          </div>
        `;
      });
      
      html += `
          </div>
        </div>
      `;
    });
    
    content.innerHTML = html;
  }

  /**
   * Automatically register browser and bind DPoP if needed
   */
  async autoRegisterBrowserAndBindDPoP() {
    try {
      // Import the core DPoP functions
      const DpopFun = await import('../core/dpop-fun.js');
      
      // Use the core session setup logic
      const sessionData = await DpopFun.setupSession();
      
      // Update local state
      this.state.hasSession = sessionData.hasSession;
      this.state.hasBIK = sessionData.hasBIK;
      this.state.hasDPoP = sessionData.hasDPoP;

      // Enable passkey service authentication after DPoP binding
      if (sessionData.hasDPoP) {
        this.passkeys.setAuthenticated(true);
        await this.checkExistingPasskeys();
      }
      
      // Update UI based on session state
      if (sessionData.hasSession && sessionData.hasDPoP) {
        const ttlSeconds = sessionData.sessionStatus?.ttl_seconds || 0;
        
        if (sessionData.details?.serverSession && sessionData.details?.localBIK) {
          // Existing session restored
          this.updateSessionStatusIndicator('reconnect', '✅', 'Session Restored', 'Browser identity and DPoP binding restored from existing session', ttlSeconds);
        } else {
          // New session created
          this.updateSessionStatusIndicator('new-session', '✅', 'New Session Created', 'Browser identity registered and DPoP token bound successfully', ttlSeconds);
        }
        
        if (ttlSeconds > 0) {
          this.startTTLTimer(ttlSeconds);
        }
        
        logger.success('Session setup completed successfully', sessionData);
      } else {
        throw new Error('Session setup failed - missing required components');
      }
      
    } catch (error) {
      this.updateSessionStatusIndicator('loading', '❌', 'Registration Failed', `Error: ${error.message}`);
      logger.error('Automatic registration failed:', error);
      throw error;
    }
  }

  /**
   * Check for existing session and restore state
   */
  async checkExistingSession() {
    try {
      logger.info('Checking for existing session...');
      
      // Check if we have a valid session
      const sessionStatus = await this.dpopFun.getSessionStatus();
      logger.debug('Session status received:', sessionStatus);
      
      if (sessionStatus && sessionStatus.valid) {
        logger.info('Valid session found, checking DPoP binding...');
        logger.debug('Session details:', {
          valid: sessionStatus.valid,
          state: sessionStatus.state,
          bik_registered: sessionStatus.bik_registered,
          dpop_bound: sessionStatus.dpop_bound
        });
        
        this.state.hasSession = true;
        
        // Restore the service's internal state
        await this.dpopFun.restoreSessionState();
        
        // Check if DPoP is bound
        if (sessionStatus.dpop_bound) {
          logger.info('DPoP binding found - resuming session to get fresh binding token');
          this.state.hasSession = true;
          this.state.hasBIK = true;
          this.state.hasDPoP = true;
          
          // Check for existing passkeys
          await this.checkExistingPasskeys();
          
          // Update passkey authentication state
          this.passkeys.setAuthenticated(true);
          
          // Check for existing username
          await this.checkExistingUsername();
          
          // Set success states for completed steps (no auto-reset for restored sessions)
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
          this.buttonManager.setSuccess('bikBtn', 'BIK restored!', 0);
          this.buttonManager.setSuccess('dpopBtn', 'DPoP restored!', 0);
          
          logger.success('Session resume completed - ready for secure operations');
          
        } else if (sessionStatus.bik_registered) {
          logger.info('BIK registered but DPoP not bound');
          this.state.hasBIK = true;
          
          // Set success state for session and BIK (no auto-reset for restored sessions)
          // registerBrowserBtn removed - status shown in session indicator
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
          this.buttonManager.setSuccess('bikBtn', 'BIK restored!', 0);
        } else {
          logger.info('Session exists but BIK not registered');
          
          // Set success state for session only (no auto-reset for restored sessions)
          // registerBrowserBtn removed - status shown in session indicator
          this.buttonManager.setSuccess('initBtn', 'Session restored!', 0);
        }
        
      } else {
        logger.info('No valid session found - starting fresh');
      }
      
    } catch (error) {
      logger.warn('Failed to check existing session, starting fresh', error);
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
        logger.info('Existing passkeys found for this domain');
      } else {
        logger.info('No existing passkeys found for this domain');
      }
      
    } catch (error) {
      logger.warn('Failed to check existing passkeys', error);
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
        logger.success(`Username '${username}' submitted successfully!`);
        
        // Store username in state
        this.state.username = username;
        
        // Update button states
        this.updateState();
        
      } catch (error) {
        // Only show error for unexpected network/server errors
        this.showUsernameError('Network error. Please try again.');
        logger.error('Unexpected error during username submission:', error);
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
        logger.success(`Welcome back, ${username}!`);
        
        // Store username in state
        this.state.username = username;
        
        // Update button states
        this.updateState();
        
      } catch (error) {
        // Only show error for unexpected network/server errors
        this.showSigninError('Network error. Please try again.');
        logger.error('Unexpected error during sign-in:', error);
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
   * Register face biometrics
   */
  async registerFace() {
    await this.errorHandler.handleAsync(async () => {
      // Check if user has valid session
      if (!this.state.username) {
        this.showFaceStatus('error', 'Please complete user binding first');
        return;
      }

      // Show inline face capture UI for registration
      this.showFaceCaptureUI('register');
    }, 'Face Registration', this.handleError);
  }

  /**
   * Verify face biometrics
   */
  async verifyFace() {
    await this.errorHandler.handleAsync(async () => {
      // Check if user has valid session
      if (!this.state.username) {
        this.showFaceStatus('error', 'Please complete user binding first');
        return;
      }

      // Show inline face capture UI for verification
      this.showFaceCaptureUI('verify');
    }, 'Face Verification', this.handleError);
  }

  /**
   * Show face status message
   */
  showFaceStatus(type, message) {
    const statusDiv = document.getElementById('faceStatus');
    if (!statusDiv) return;

    const messageDiv = statusDiv.querySelector('.status-message');
    if (!messageDiv) return;

    // Clear previous classes
    statusDiv.className = 'face-status';
    statusDiv.classList.add(type);

    // Set message
    messageDiv.textContent = message;
    statusDiv.style.display = 'block';

    // Auto-hide after 5 seconds for info messages
    if (type === 'info') {
      setTimeout(() => {
        statusDiv.style.display = 'none';
      }, 5000);
    }
  }

  /**
   * Show inline face capture UI
   */
  showFaceCaptureUI(mode) {
    const container = document.getElementById('faceCaptureContainer');
    if (!container) {
      this.showFaceStatus('error', 'Face capture UI not found');
      return;
    }

    // Show the face capture container
    container.style.display = 'block';

    // Scroll to the face biometrics section
    const section = container.closest('.demo-section');
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }

    // Reset face capture if it exists, then initialize
    if (window.faceCapture && window.faceCapture.resetFaceCapture) {
      window.faceCapture.resetFaceCapture();
      window.faceCapture.setMode(mode);
      // Restart the capture process
      setTimeout(() => {
        window.faceCapture.startCapture();
      }, 100);
    } else {
      this.initializeFaceCapture(mode);
    }
  }

  /**
   * Initialize face capture module
   */
  async initializeFaceCapture(mode) {
    try {
      // Dynamically import the face capture module
      const faceCaptureModule = await import('/public/js/face-capture.js');
      window.faceCapture = new faceCaptureModule.FaceCaptureInline(mode);
      await window.faceCapture.init();

      // Auto-start the face capture process
      await window.faceCapture.startCapture();
    } catch (error) {
      logger.error('Failed to initialize face capture:', error);
      this.showFaceStatus('error', 'Failed to initialize face capture. Please refresh and try again.');
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

    // Face biometrics
    document.getElementById('registerFaceBtn')?.addEventListener('click', () => {
      this.registerFace();
    });

    document.getElementById('verifyFaceBtn')?.addEventListener('click', () => {
      this.verifyFace();
    });

    // Signal details modal
    document.getElementById('signalDetailsBtn')?.addEventListener('click', () => {
      this.showSignalDetailsModal();
    });

    document.getElementById('signalModalClose')?.addEventListener('click', () => {
      this.hideSignalDetailsModal();
    });

    // Close modal when clicking outside
    document.getElementById('signalDetailsModal')?.addEventListener('click', (e) => {
      if (e.target.id === 'signalDetailsModal') {
        this.hideSignalDetailsModal();
      }
    });

    // Register browser and bind DPoP (merged function)
    // registerBrowserBtn removed - now handled automatically

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
      
      const session = await this.dpopFun.initSession();
      
      this.state.hasSession = true;
      this.updateState();
      
      this.buttonManager.setSuccess('initBtn', 'Session initialized!');
      logger.success('Session initialized successfully', session);
      
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
      logger.info('Starting fingerprint collection...');
      
      // Use the centralized FingerprintService
      const result = await FingerprintService.collectAndSendFingerprint('desktop');
      
      logger.info('Fingerprint collection completed successfully');
      return result;
    } catch (error) {
      console.log('FINGERPRINT COLLECTION FAILED:', error);
      logger.error('Failed to collect fingerprint:', error);
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
      
      const bik = await this.dpopFun.registerBIK();
      
      this.state.hasBIK = true;
      this.updateState();
      
      this.buttonManager.setSuccess('bikBtn', 'BIK registered!');
      logger.success('BIK registered successfully', bik);
      
    }, 'BIK registration', this.handleError);
  }

  /**
   * Bind DPoP
   */
  async bindDPoP() {
    await this.errorHandler.handleAsync(async () => {
      this.buttonManager.setLoading('dpopBtn', 'Binding DPoP...');
      
      logger.debug('Starting DPoP binding process...');
      logger.debug('Current state before binding:', {
        hasSession: this.state.hasSession,
        hasBIK: this.state.hasBIK,
        hasDPoP: this.state.hasDPoP
      });
      
      const dpop = await this.dpopFun.bindDPoP();
      
      logger.debug('DPoP binding completed:', dpop);
      
      this.state.hasDPoP = true;
      
      // Enable passkey service authentication after DPoP binding
      this.passkeys.setAuthenticated(true);
      
      // Check for existing passkeys now that we're authenticated
      await this.checkExistingPasskeys();
      
      this.updateState();
      
      this.buttonManager.setSuccess('dpopBtn', 'DPoP bound!');
      logger.success('DPoP bound successfully', dpop);
      
    }, 'DPoP binding', this.handleError);
  }

  // registerBrowserAndBindDPoP method removed - now handled automatically in autoRegisterBrowserAndBindDPoP

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
        logger.success('Passkey registered successfully', result);
        
      } catch (error) {
        // Handle user cancellation gracefully
        if (error.message && error.message.includes('cancelled')) {
          this.buttonManager.reset('regBtn');
          logger.info('Passkey registration cancelled by user');
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
        logger.success('Passkey authentication successful', result);
        
      } catch (error) {
        // Handle user cancellation gracefully
        if (error.message && error.message.includes('cancelled')) {
          this.buttonManager.reset('authBtn');
          logger.info('Passkey authentication cancelled by user');
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
      logger.success('Cross-device linking started', linkData);
      
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
        logger.info(`Linking status: ${status.status}`, status);
        
        if (status.status === 'scanned') {
          this.updateQRStatus('scanned');
        } else if (status.status === 'linked' || status.status === 'completed') {
          this.handleLinkingComplete(linkId);
        } else if (status.status === 'failed') {
          this.handleLinkingFailed(status.error);
        }
      } else if (status.type === 'signature') {
        logger.info('Signature data received', status.data);
        // Handle signature data if needed
      } else {
        logger.info('Unknown message type received', status);
      }
    };

    const onError = (error) => {
      logger.error('Linking status monitoring failed', error);
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
      
      logger.success('Cross-device linking completed successfully');
      logger.info('Redirecting to verify page to enter BC code...');
      
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
    
    logger.error('Cross-device linking failed', error);
  }


  /**
   * Create QR code element
   * @param {string} qrData - QR code data
   * @param {string} linkId - Link ID
   */
  createQRCode(qrData, linkId) {
    // Use shared QR container utility
    const container = createQRContainer(qrData, linkId);

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

      logger.info('Testing API access with DPoP token...');

      const message = apiMessage.value.trim() || 'Hello from Browser Identity & DPoP Security Demo!';
      
      const testData = {
        message: message,
        timestamp: new Date().toISOString(),
        userAgent: navigator.userAgent
      };

      // Capture request details before making the request
      const requestDetails = await this.captureRequestDetails(testData);
      
      const response = await this.dpopFun.testAPI(testData);

      // Display request details
      clientRequest.innerHTML = JSON.stringify(requestDetails, null, 2);
      clientRequest.className = 'response-box info';

      // Display response
      apiResponse.innerHTML = JSON.stringify(response, null, 2);
      apiResponse.className = 'response-box success';

      this.buttonManager.setSuccess('apiBtn', 'API test successful!');
      logger.success('API access successful - DPoP token working!');
      logger.info(`Response: ${JSON.stringify(response, null, 2)}`);
      logger.success('DPoP cryptographic binding verified');

    } catch (error) {
      // Display error
      apiResponse.innerHTML = `Error: ${error.message}`;
      apiResponse.className = 'response-box error';
      clientRequest.innerHTML = 'Request details unavailable due to error';
      clientRequest.className = 'response-box error';

      this.buttonManager.setError('apiBtn', 'API test failed');
      logger.error(`API access failed: ${error.message}`);
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
      // Import the dpop-fun module to access its functions
      const DpopFun = await import('../core/dpop-fun.js');
      
      // Get current DPoP state
      const dpopNonce = await DpopFun.getDpopNonce();
      const bindToken = await DpopFun.getBindToken();
      
      // Get browser identity key info (without exposing private key)
      const bik = await DpopFun.getBIK();
      
      // Ensure nonce is a string or undefined
      const nonceValue = typeof dpopNonce === 'string' ? dpopNonce : undefined;
      
      // Create the actual DPoP proof that will be used
      const dpopProof = await DpopFun.createDpopProof({
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
            publicKeyThumbprint: bik?.publicJwk ? await DpopFun.jwkThumbprint(bik.publicJwk) : 'Not available'
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
    logger.debug('Updating application state:', this.state);
    
    // Register Browser & Bind DPoP button - enabled by default (first step)
    if (!this.state.hasDPoP) {
      // registerBrowserBtn removed - now handled automatically
    } else {
      // Keep enabled even after completion to allow re-running
      // registerBrowserBtn removed - now handled automatically
    }
    
    // Update button states based on dependencies, preserving success states
    if (this.state.hasSession) {
      this.buttonManager.enableIfNotSuccess('bikBtn');
    } else {
      this.buttonManager.disable('bikBtn');
    }

    if (this.state.hasSession && this.state.hasBIK && !this.state.hasDPoP) {
      logger.debug('Enabling DPoP button - hasSession:', this.state.hasSession, 'hasBIK:', this.state.hasBIK, 'hasDPoP:', this.state.hasDPoP);
      this.buttonManager.enableIfNotSuccess('dpopBtn');
    } else if (this.state.hasDPoP) {
      logger.debug('DPoP already bound - keeping button enabled');
      this.buttonManager.enableIfNotSuccess('dpopBtn');
    } else {
      logger.debug('Disabling DPoP button - hasSession:', this.state.hasSession, 'hasBIK:', this.state.hasBIK, 'hasDPoP:', this.state.hasDPoP);
      this.buttonManager.disable('dpopBtn');
    }

    if (this.state.hasDPoP) {
      this.buttonManager.enableIfNotSuccess('apiBtn');
      this.buttonManager.enableIfNotSuccess('linkBtn');
    } else {
      this.buttonManager.disable('apiBtn');
      this.buttonManager.disable('linkBtn');
    }

    // Face biometrics buttons - enabled when user has valid session (username + DPoP)
    if (this.state.hasDPoP && this.state.username) {
      this.buttonManager.enableIfNotSuccess('registerFaceBtn');
      this.buttonManager.enableIfNotSuccess('verifyFaceBtn');
    } else {
      this.buttonManager.disable('registerFaceBtn');
      this.buttonManager.disable('verifyFaceBtn');
    }

    // Log state changes
    logger.debug('Application state updated', this.state);
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
      logger.success('Server data flushed successfully');
      
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
      
      logger.success('Client data flushed successfully');
      
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
      // Import the idbWipe function to properly delete the entire database
      const { idbWipe } = await import('../idb.js');
      
      logger.debug('Deleting entire IndexedDB database...');
      await idbWipe();
      logger.debug('IndexedDB database deleted successfully');
      
    } catch (error) {
      logger.error('Failed to clear client storage:', error);
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
    this.dpopFun.clearSession();
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
    
    logger.info('All application states reset');
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
    
    // Clear TTL timer
    if (this.ttlTimer) {
      clearInterval(this.ttlTimer);
      this.ttlTimer = null;
    }
  }
}
