import { logger } from '../js/utils/logging.js';
import * as DpopFun from '../js/core/dpop-fun.js';
import * as Passkeys from '../js/core/passkeys.js';
import { MobileLinkService } from '../js/mobilelink.js';


class AppController {
    constructor() {
        this.modal = document.getElementById('sessionStatusModal');
        this.modalContent = this.modal.querySelector('.modal-content');
        this.sessionHeader = document.getElementById('sessionHeader');
        this.sessionBody = document.getElementById('sessionBody');
        this.closeBtn = document.querySelector('[data-close-modal]');
        this.sessionTimerDisplay = document.getElementById('sessionTimer');
        this.idleTimerDisplay = document.getElementById('idleTimer');
        
        // Track collapsed state
        this.isCollapsed = false;
        
        // Track authentication state
        this.isAuthenticated = false;
        
        // New elements for overview section
        this.bindingState = document.getElementById('bindingState');
        this.sessionFlag = document.getElementById('sessionFlag');
        this.sessionCount = document.getElementById('sessionCount');
        this.authMethod = document.getElementById('authMethod');
        this.reportActivityBtn = document.getElementById('reportActivityBtn');
        this.sessionHistorySection = document.getElementById('sessionHistorySection');
        this.sessionHistoryList = document.getElementById('sessionHistoryList');
        this.devicesSection = document.getElementById('devicesSection');
        this.devicesList = document.getElementById('devicesList');
        this.credentialsSection = document.getElementById('credentialsSection');
        this.credentialsList = document.getElementById('credentialsList');
        this.passkeyAuthBtn = document.getElementById('passkeyAuthBtn');
        this.mobileLinkBtn = document.getElementById('mobileLinkBtn');
        this.usernameInput = document.getElementById('usernameInput');
        this.checkUsernameBtn = document.getElementById('checkUsernameBtn');
        
        // Mobile linking service
        this.mobileLinkService = null;
        
        // Session details modal
        this.sessionDetailsModal = document.getElementById('sessionDetailsModal');
        this.sessionsList = document.getElementById('sessionsList');
        this.closeSessionDetailsBtn = document.querySelector('[data-close-session-details]');
        
        // Current username for authentication
        this.username = null;

        this.TOTAL_SESSION_MINUTES = 60;
        this.IDLE_TIMEOUT_MINUTES = 15;
        
        this.sessionSeconds = this.TOTAL_SESSION_MINUTES * 60;
        this.idleSeconds = this.IDLE_TIMEOUT_MINUTES * 60;
        this.idleResetTimeout;
        
        // Mock data for multiple sessions (in real app, this would come from API)
        this.allSessions = [];

        this.initialize();
    }

    async initialize() {
        this.initializeEventListeners();
        this.initializeDisplayValues();
        this.setupActivityListeners();
        
        // Initialize passkey button
        await this.initializePasskeyButton();

        try {
            const SESSION_DATA = await DpopFun.setupSession();
            if (SESSION_DATA) {
                // Calculate session seconds from expires_at timestamp
                if (SESSION_DATA.expires_at) {
                    const now = Math.floor(Date.now() / 1000);
                    this.sessionSeconds = Math.max(0, SESSION_DATA.expires_at - now);
                    logger.info('Session expires at:', SESSION_DATA.expires_at, 'Current time:', now, 'Seconds remaining:', this.sessionSeconds);
                } else {
                    this.sessionSeconds = this.TOTAL_SESSION_MINUTES * 60;
                    logger.warn('No expires_at from server, using default:', this.sessionSeconds);
                }
                
                // Idle timeout can still use default or server value if provided
                this.idleSeconds = SESSION_DATA.idle_seconds || this.IDLE_TIMEOUT_MINUTES * 60;
                
                // Update display with actual values
                this.sessionTimerDisplay.textContent = this.formatTime(this.sessionSeconds);
                this.idleTimerDisplay.textContent = this.formatTime(this.idleSeconds);
                
                // Populate UI with real session data
                await this.populateSessionUI(SESSION_DATA);
                
                // Restore authentication state if user is logged in
                this.restoreAuthenticationState(SESSION_DATA);
                
                // Start timers only after session is properly set up
                this.startTimers();
            } else {
                logger.error('Failed to setup session');
                // Use default values if session setup fails
                this.startTimers();
            }
        } catch (error) {
            logger.error('Error setting up session:', error);
            // Use default values if session setup fails
            this.startTimers();
        }
    }

    initializeEventListeners() {
        // Close/collapse button handler
        this.closeBtn.addEventListener('click', (e) => {
            e.stopPropagation();
            this.toggleCollapse();
        });

        // Header click to expand when collapsed
        this.sessionHeader.addEventListener('click', () => {
            if (this.isCollapsed) {
                this.toggleCollapse();
            }
        });

        this.closeSessionDetailsBtn.addEventListener('click', () => {
            this.sessionDetailsModal.style.display = 'none';
        });

        // Username input - enable/disable auth buttons based on username presence
        this.usernameInput.addEventListener('input', () => {
            this.handleUsernameChange();
        });

        // Username input - check on Enter key
        this.usernameInput.addEventListener('keypress', async (e) => {
            if (e.key === 'Enter' && this.username) {
                await this.checkUsernameForPasskeys();
            }
        });

        // Check username button
        this.checkUsernameBtn.addEventListener('click', async () => {
            await this.checkUsernameForPasskeys();
        });

        // Passkey Auth button
        this.passkeyAuthBtn.addEventListener('click', async () => {
            await this.handlePasskeyAuth();
        });

        // Mobile Link button
        this.mobileLinkBtn.addEventListener('click', async () => {
            await this.handleMobileLink();
        });

        // Inspector button for risk signals
        const inspectorBtn = document.getElementById('inspectRiskSignals');
        if (inspectorBtn) {
            inspectorBtn.addEventListener('click', async () => {
                // Get current session data
                const sessionData = await DpopFun.setupSession();
                if (sessionData) {
                    this.showSignalDataModal(sessionData);
                }
            });
        }

        // Close modals when clicking outside
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) {
                this.modal.classList.remove('active');
            }
        });

        this.sessionDetailsModal.addEventListener('click', (e) => {
            if (e.target === this.sessionDetailsModal) {
                this.sessionDetailsModal.style.display = 'none';
            }
        });
    }

    initializeDisplayValues() {
        // Display initial values without starting timers
        this.sessionTimerDisplay.textContent = this.formatTime(this.sessionSeconds);
        this.idleTimerDisplay.textContent = this.formatTime(this.idleSeconds);
    }

    formatTime(secs) {
        const minutes = Math.floor(secs / 60);
        const seconds = secs % 60;
        return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;
    }

    
    resetIdleTimer() {
        this.idleSeconds = this.IDLE_TIMEOUT_MINUTES * 60;
        this.idleTimerDisplay.classList.remove('idle-alert');
    }

    runSessionTimer() {
        if (this.sessionSeconds > 0) {
            this.sessionSeconds--;
            this.sessionTimerDisplay.textContent = this.formatTime(this.sessionSeconds);
            if (this.sessionSeconds <= 120) {
                this.sessionTimerDisplay.classList.add('time-alert');
            }
        } else {
            clearInterval(this.sessionInterval);
            logger.warn("Session expired. Forcing logout.");
            this.handleSessionExpired();
        }
    }
    
    runIdleTimer() {
        if (this.idleSeconds > 0) {
            this.idleSeconds--;
            this.idleTimerDisplay.textContent = this.formatTime(this.idleSeconds);
            if (this.idleSeconds <= 60) {
                this.idleTimerDisplay.classList.add('idle-alert');
            }
        } else {
            clearInterval(this.idleInterval);
            logger.warn("Idle timeout reached. Forcing logout.");
            this.handleIdleExpired();
        }
    }
    
    async handleSessionExpired() {
        logger.info('Session timer expired - logging out user');
        
        try {
            // Call logout endpoint
            const response = await DpopFun.dpopFetch('POST', '/session/logout');
            
            if (response.ok) {
                logger.info('Session logged out due to expiration');
            }
        } catch (error) {
            logger.error('Failed to logout expired session:', error);
        }
        
        // Reset authentication flag
        this.isAuthenticated = false;
        
        // Reset UI state
        this.username = null;
        this.usernameInput.value = '';
        this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Create Passkey';
        this.passkeyAuthBtn.classList.remove('logout-mode');
        this.passkeyAuthBtn.disabled = true;
        this.checkUsernameBtn.disabled = true;
        this.mobileLinkBtn.disabled = true;
        this.mobileLinkBtn.querySelector('.btn-text').textContent = 'Link Mobile Device';
        this.mobileLinkBtn.dataset.mode = 'register';
        
        // Refresh session data
        try {
            const freshSessionData = await DpopFun.setupSession();
            if (freshSessionData) {
                await this.populateSessionUI(freshSessionData);
            }
        } catch (error) {
            logger.error('Failed to refresh session after expiration:', error);
        }
        
        alert('Your session has expired. Please authenticate again.');
    }
    
    async handleIdleExpired() {
        logger.info('Idle timer expired - logging out user');
        
        try {
            // Call logout endpoint
            const response = await DpopFun.dpopFetch('POST', '/session/logout');
            
            if (response.ok) {
                logger.info('Session logged out due to idle timeout');
            }
        } catch (error) {
            logger.error('Failed to logout idle session:', error);
        }
        
        // Reset authentication flag
        this.isAuthenticated = false;
        
        // Reset UI state
        this.username = null;
        this.usernameInput.value = '';
        this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Create Passkey';
        this.passkeyAuthBtn.classList.remove('logout-mode');
        this.passkeyAuthBtn.disabled = true;
        this.checkUsernameBtn.disabled = true;
        this.mobileLinkBtn.disabled = true;
        this.mobileLinkBtn.querySelector('.btn-text').textContent = 'Link Mobile Device';
        this.mobileLinkBtn.dataset.mode = 'register';
        
        // Refresh session data
        try {
            const freshSessionData = await DpopFun.setupSession();
            if (freshSessionData) {
                await this.populateSessionUI(freshSessionData);
            }
        } catch (error) {
            logger.error('Failed to refresh session after idle timeout:', error);
        }
        
        alert('Your session has been terminated due to inactivity. Please authenticate again.');
    }

    startTimers() {
        this.sessionInterval = setInterval(() => this.runSessionTimer(), 1000);
        this.idleInterval = setInterval(() => this.runIdleTimer(), 1000);
    }

    handleUserActivity() {
        this.resetIdleTimer();
    }

    toggleCollapse() {
        this.isCollapsed = !this.isCollapsed;
        
        if (this.isCollapsed) {
            // Collapse: hide body, change button, add collapsed class
            this.sessionBody.style.display = 'none';
            this.closeBtn.textContent = '+';
            this.modalContent.classList.add('collapsed');
            this.sessionHeader.style.cursor = 'pointer';
            logger.info('Session panel collapsed');
        } else {
            // Expand: show body, change button, remove collapsed class
            this.sessionBody.style.display = 'block';
            this.closeBtn.textContent = '−';
            this.modalContent.classList.remove('collapsed');
            this.sessionHeader.style.cursor = 'default';
            logger.info('Session panel expanded');
        }
    }

    setupActivityListeners() {
        document.addEventListener('mousemove', () => this.handleUserActivity());
        document.addEventListener('keydown', () => this.handleUserActivity());  // Changed from keypress to keydown
        document.addEventListener('click', () => this.handleUserActivity());
        document.addEventListener('scroll', () => this.handleUserActivity());  // Added scroll for completeness
        document.addEventListener('touchstart', () => this.handleUserActivity());  // Added touch for mobile
    }


    async populateSessionUI(sessionData) {
        // Store session data for use in other methods
        this.sessionData = sessionData;
        
        // Update overview section
        this.updateOverviewSection(sessionData);
        
        // Update session history in third column
        await this.updateSessionHistoryList(sessionData);
        
        // Update devices list
        await this.updateDevicesList(sessionData);
        
        // Update credentials list
        await this.updateCredentialsList(sessionData);
        
        // Update session history (old section - can be removed later)
        this.updateSessionHistory(sessionData);
        
        // Mock multiple sessions for demonstration
        this.mockMultipleSessions(sessionData);
        
        logger.info('Session UI populated with data:', sessionData);
    }

    updateOverviewSection(sessionData) {
        // Debug logging to see what we're receiving
        logger.info('updateOverviewSection - sessionData:', sessionData);
        logger.info('Session state:', sessionData.session_state);
        logger.info('Session flag:', sessionData.session_flag);
        logger.info('Auth method:', sessionData.auth_method);
        logger.info('Active sessions:', sessionData.active_user_sessions);
        
        // Update binding state
        if (this.bindingState) {
            // Map server state values to display values
            // Note: dpop-fun.js stores responseData.state as DPOP_SESSION.session_state
            const state = sessionData.session_state || sessionData.state;
            let bindingStateText = 'Pending';
            let bindingStateClass = 'status-pending';
            
            if (state === 'BOUND_DPOP' || state === 'AUTHENTICATED') {
                bindingStateText = 'Bound';
                bindingStateClass = 'status-bound';
            } else if (state === 'PENDING_BIND') {
                bindingStateText = 'Pending';
                bindingStateClass = 'status-pending';
            }
            
            logger.info('Binding state text:', bindingStateText, 'class:', bindingStateClass);
            this.bindingState.textContent = bindingStateText;
            this.bindingState.className = `value ${bindingStateClass}`;
        }

        // Update session flag
        if (this.sessionFlag) {
            const sessionFlag = sessionData.session_flag || 'GREEN';
            this.sessionFlag.textContent = sessionFlag;
            this.sessionFlag.className = `value status-flag ${sessionFlag.toLowerCase()}`;
        }

        // Update session count and warning
        this.updateSessionCount();

        // Update auth method
        if (this.authMethod) {
            const authMethod = sessionData.auth_method || 'Unauthenticated';
            this.authMethod.textContent = authMethod;
        }
    }

    updateSessionCount() {
        // Use the server-provided active session count (default to 1 if not provided)
        const sessionCount = this.sessionData?.active_user_sessions ?? 1;
        logger.info('updateSessionCount - active_user_sessions:', this.sessionData?.active_user_sessions, 'count:', sessionCount);
        
        if (this.sessionCount) {
            this.sessionCount.textContent = sessionCount;
        }

    }

    async updateSessionHistoryList(sessionData) {
        if (!this.sessionHistoryList) return;

        // Check if user is authenticated
        if (!sessionData.auth_username || sessionData.auth_status !== 'authenticated') {
            // Hide section when not authenticated
            if (this.sessionHistorySection) {
                this.sessionHistorySection.style.display = 'none';
            }
            return;
        }
        
        // Show section when authenticated
        if (this.sessionHistorySection) {
            this.sessionHistorySection.style.display = 'block';
            logger.info('Session History section shown');
        }

        try {
            // Fetch session history from server (last 10 days)
            const response = await DpopFun.dpopFetch('GET', '/session/history');
            
            if (!response.ok) {
                logger.warn('Failed to fetch session history:', response.status);
                this.sessionHistoryList.innerHTML = '<p class="no-history">Unable to load session history</p>';
                return;
            }
            
            const data = await response.json();
            const history = data.history || [];
            
            if (history.length === 0) {
            this.sessionHistoryList.innerHTML = '<p class="no-history">No previous sessions</p>';
            return;
        }

            // Populate with actual history using template
        this.sessionHistoryList.innerHTML = '';
            const template = document.getElementById('historyItemTemplate');
            const currentTime = Math.floor(Date.now() / 1000);
            const currentSessionId = sessionData.session_id;
            
            logger.info('Current session ID:', currentSessionId);
            logger.info('First history session:', history[0]);
            
            history.forEach(session => {
                // Clone the template
                const clone = template.content.cloneNode(true);
                
                const sessionId = session.session_id;
                
                // Determine if session is active
                const isActive = session.session_status === 'ACTIVE' && session.expires_at > currentTime;
                const isCurrentSession = sessionId === currentSessionId;
                
                logger.info(`Session ${sessionId}: isActive=${isActive}, isCurrentSession=${isCurrentSession}, status=${session.session_status}, expires_at=${session.expires_at}, currentTime=${currentTime}`);
                
                // Extract data
            const timeAgo = this.formatTimeAgo(session.created_at);
                let location = 'Unknown';
                
                if (session.geolocation) {
                    try {
                        const geo = typeof session.geolocation === 'string' ? 
                            JSON.parse(session.geolocation) : session.geolocation;
                        location = `${geo.city || 'Unknown'}, ${geo.country_code || geo.country || ''}`;
                    } catch (e) {
                        location = 'Unknown location';
                    }
                }
                
                const authMethod = session.auth_method || 'None';
                const deviceType = session.device_type || 'unknown';
                
                // Parse signal data for primary indicators (without screen resolution)
                let signalInfo = '';
                if (session.signal_data) {
                    try {
                        const signal = typeof session.signal_data === 'string' ? 
                            JSON.parse(session.signal_data) : session.signal_data;
                        
                        const browser = this.extractBrowserName(signal.userAgent);
                        const platform = signal.platform || 'Unknown';
                        
                        signalInfo = `${browser} • ${platform}`;
                    } catch (e) {
                        signalInfo = 'Signal data unavailable';
                    }
                }

                // Populate template with data
                // Set device icon
                const deviceIconEl = clone.querySelector('[data-device-icon]');
                if (deviceIconEl) {
                    deviceIconEl.textContent = deviceType === 'mobile' ? '📱' : '💻';
                }
                
                clone.querySelector('[data-time]').textContent = timeAgo;
                clone.querySelector('[data-method]').textContent = authMethod;
                clone.querySelector('[data-location]').textContent = `${location} • ${deviceType}`;
                
                // Set status badge
                const statusEl = clone.querySelector('[data-status]');
                if (isCurrentSession) {
                    statusEl.textContent = 'Current';
                    statusEl.className = 'history-status current';
                } else if (isActive) {
                    statusEl.textContent = 'Active';
                    statusEl.className = 'history-status active';
                } else {
                    statusEl.textContent = 'Expired';
                    statusEl.className = 'history-status expired';
                }
                
                // Set linked session info
                const linkedEl = clone.querySelector('[data-linked]');
                const linkedTextEl = clone.querySelector('[data-linked-text]');
                if (session.linked_session_id) {
                    const linkedDeviceType = session.linked_device_type || 'unknown';
                    const linkedTimeAgo = session.linked_created_at ? 
                        this.formatTimeAgo(session.linked_created_at) : 'unknown time';
                    linkedTextEl.textContent = `Linked to ${linkedDeviceType} session (${linkedTimeAgo})`;
                    linkedEl.style.display = 'flex';
                } else {
                    linkedEl.style.display = 'none';
                }
                
                // Set signal info
                const signalEl = clone.querySelector('[data-signal]');
                if (signalInfo) {
                    // Create text node and insert before the button
                    const textNode = document.createTextNode(signalInfo + ' • ');
                    const signalBtn = signalEl.querySelector('[data-signal-link]');
                    if (signalBtn) {
                        signalEl.insertBefore(textNode, signalBtn);
                    }
                    signalEl.style.display = 'block';
                } else {
                    signalEl.style.display = 'none';
                }
                
                // Handle action buttons
                const killBtn = clone.querySelector('[data-kill-btn]');
                const reportBtn = clone.querySelector('[data-report-btn]');
                
                // Show kill button only for active sessions (not current session)
                if (isActive && !isCurrentSession) {
                    killBtn.style.display = 'block';
                    killBtn.addEventListener('click', () => {
                        this.killSession(sessionId, session);
                    });
                } else {
                    killBtn.style.display = 'none';
                }
                
                // Report button always visible
                reportBtn.addEventListener('click', () => {
                    this.reportSuspiciousSession(sessionId, session);
                });
                
                // Add signal data button handler - AFTER appending to DOM
                this.sessionHistoryList.appendChild(clone);
                
                const historyItem = this.sessionHistoryList.lastElementChild;
                const signalBtn = historyItem.querySelector('[data-signal-link]');
                if (signalBtn) {
                    signalBtn.addEventListener('click', () => {
                        this.showSignalDataModal(session);
                    });
                }
            });
            
            logger.info(`Loaded ${history.length} session history items`);
            
        } catch (error) {
            logger.error('Failed to load session history:', error);
            this.sessionHistoryList.innerHTML = '<p class="no-history">Unable to load session history</p>';
        }
    }

    extractBrowserName(userAgent) {
        if (!userAgent) return 'Unknown Browser';
        
        const ua = userAgent.toLowerCase();
        
        if (ua.includes('firefox')) return 'Firefox';
        if (ua.includes('edg')) return 'Edge';
        if (ua.includes('chrome')) return 'Chrome';
        if (ua.includes('safari')) return 'Safari';
        if (ua.includes('opera') || ua.includes('opr')) return 'Opera';
        
        return 'Unknown Browser';
    }

    formatTimeAgo(timestamp) {
        if (!timestamp) return 'Unknown time';
        
        const now = Math.floor(Date.now() / 1000);
        const diff = now - timestamp;
        
        if (diff < 60) return 'Just now';
        if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
        if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
        if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
        
        const date = new Date(timestamp * 1000);
        return date.toLocaleDateString();
    }

    handleUsernameChange() {
        const username = this.usernameInput.value.trim();
        this.username = username || null;
        
        // Enable/disable buttons based on username presence
        const hasUsername = username.length > 0;
        
        // Enable check username button if username is present
        this.checkUsernameBtn.disabled = !hasUsername;
        
        // Disable both auth buttons until "Go" is clicked
        this.passkeyAuthBtn.disabled = true;
        this.mobileLinkBtn.disabled = true;
        
        logger.info('Username changed:', { username: this.username, hasUsername });
    }

    restoreAuthenticationState(sessionData) {
        // Check if user is authenticated
        if (sessionData.auth_status === 'authenticated' && sessionData.auth_username) {
            logger.info('Restoring authenticated state for user:', sessionData.auth_username);
            
            // Set username field
            this.usernameInput.value = sessionData.auth_username;
            this.username = sessionData.auth_username;
            
            // Update button to logout mode
            const btnText = this.passkeyAuthBtn.querySelector('.btn-text');
            const btnIcon = this.passkeyAuthBtn.querySelector('.btn-icon');
            
            btnText.textContent = 'Logout';
            btnIcon.textContent = '🚪';
            this.passkeyAuthBtn.classList.add('logout-mode');
            this.passkeyAuthBtn.disabled = false;
            
            // Mark that user is authenticated (used to prevent button text changes)
            this.isAuthenticated = true;
            
            // Enable the check username button
            this.checkUsernameBtn.disabled = false;
            
            // Check for mobile passkey to set mobile link button state (but don't change passkey button)
            this.checkForMobilePasskey();
            
            logger.info('Authentication state restored');
        } else {
            logger.info('No authenticated session found');
            this.isAuthenticated = false;
        }
    }

    async checkUsernameForPasskeys() {
        if (!this.username) {
            logger.warn('No username provided');
            return;
        }

        const btnText = this.checkUsernameBtn.querySelector('.btn-text');
        const originalText = btnText.textContent;
        
        try {
            btnText.textContent = '...';
            this.checkUsernameBtn.disabled = true;
            
            logger.info('Checking for passkeys for username:', this.username);
            
            // Call authentication options endpoint to check if passkeys exist for this username
            const options = await Passkeys.getAuthOptions(this.username);
            
            const hasPasskeys = options._meta?.hasCredentials || false;
            const passkeyCount = options._meta?.registeredCount || 0;
            
            logger.info('Passkey check result:', { username: this.username, hasPasskeys, count: passkeyCount });
            
            // Only update passkey button text if user is not already authenticated
            if (!this.isAuthenticated) {
                const passkeyBtnText = this.passkeyAuthBtn.querySelector('.btn-text');
                if (hasPasskeys) {
                    passkeyBtnText.textContent = 'Login with Passkey';
                    this.passkeyAuthBtn.disabled = false;
                } else {
                    passkeyBtnText.textContent = 'Create Passkey';
                    this.passkeyAuthBtn.disabled = false;
                }
            }
            
            // Check for mobile passkey and update mobile link button
            await this.checkForMobilePasskey(options);
            
            // Restore Go button
            btnText.textContent = originalText;
            this.checkUsernameBtn.disabled = false;
            
        } catch (error) {
            logger.error('Failed to check for passkeys:', error);
            btnText.textContent = originalText;
            this.checkUsernameBtn.disabled = false;
            
            // Only update on error if not authenticated
            if (!this.isAuthenticated) {
                this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Create Passkey';
                this.passkeyAuthBtn.disabled = false;
            }
            
            // Enable mobile link button with default text
            this.mobileLinkBtn.disabled = false;
            this.mobileLinkBtn.querySelector('.btn-text').textContent = 'Link Mobile Device';
        }
    }
    
    async checkForMobilePasskey(authOptions = null) {
        try {
            // If no authOptions provided, fetch them
            if (!authOptions && this.username) {
                try {
                    authOptions = await Passkeys.getAuthOptions(this.username);
                } catch (error) {
                    logger.warn('Failed to get auth options for mobile passkey check:', error);
                    return;
                }
            }
            
            // Check if user has a mobile device passkey using server metadata
            let hasMobilePasskey = false;
            
            if (authOptions && authOptions._meta) {
                // Use the mobileCredentials count from server metadata
                hasMobilePasskey = (authOptions._meta.mobileCredentials || 0) > 0;
                
                logger.info('Mobile passkey check:', {
                    mobileCredentials: authOptions._meta.mobileCredentials,
                    desktopCredentials: authOptions._meta.desktopCredentials,
                    totalCredentials: authOptions._meta.totalCredentials,
                    hasMobilePasskey
                });
            }
            
            // Update mobile link button
            const mobileBtnText = this.mobileLinkBtn.querySelector('.btn-text');
            if (hasMobilePasskey) {
                mobileBtnText.textContent = 'Login with Mobile';
                this.mobileLinkBtn.dataset.mode = 'login';
            } else {
                mobileBtnText.textContent = 'Link Mobile Device';
                this.mobileLinkBtn.dataset.mode = 'registration';
            }
            
            this.mobileLinkBtn.disabled = false;
            
        } catch (error) {
            logger.warn('Failed to check for mobile passkey:', error);
            // Default to link mode
            this.mobileLinkBtn.disabled = false;
            this.mobileLinkBtn.querySelector('.btn-text').textContent = 'Link Mobile Device';
            this.mobileLinkBtn.dataset.mode = 'registration';
        }
    }

    async initializePasskeyButton() {
        try {
            // Check if passkeys are supported
            const supportStatus = await Passkeys.getBasicSupportStatus();
            
            logger.info('Passkey support status:', supportStatus);
            
            if (!supportStatus.isSupported || !supportStatus.hasUVPA) {
                // Platform doesn't support passkeys
                this.passkeyAuthBtn.disabled = true;
                this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Passkeys Not Supported';
                logger.warn('Passkeys not supported on this platform');
                return;
            }
            
            // Check if user has existing passkeys (requires authenticated session)
            let hasCredentials = false;
            if (this.sessionData && this.sessionData.auth_method === 'Passkey') {
                hasCredentials = await Passkeys.hasExistingPasskeys();
            }
            
            // Set button label based on credential existence
            if (hasCredentials) {
                this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Login with Passkey';
            } else {
                this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Create Passkey';
            }
            
            // Button remains disabled until username is entered
            this.passkeyAuthBtn.disabled = true;
            
            logger.info('Passkey button initialized:', hasCredentials ? 'Login mode' : 'Create mode');
        } catch (error) {
            logger.error('Failed to initialize passkey button:', error);
            this.passkeyAuthBtn.disabled = true;
            this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Passkey Error';
        }
    }

    async handlePasskeyAuth() {
        if (!this.username) {
            alert('Please enter a username first');
            return;
        }
        
        const btnText = this.passkeyAuthBtn.querySelector('.btn-text');
        const originalText = btnText.textContent;
        
        try {
            btnText.textContent = 'Processing...';
            this.passkeyAuthBtn.disabled = true;
            
            if (originalText === 'Create Passkey') {
                // Register new passkey with username
                logger.info('Starting passkey registration for user:', this.username);
                const result = await Passkeys.registerPasskey(this.username);
                logger.info('Passkey registration successful:', result);
                
                // After successful registration, user is authenticated
                // Update button to logout mode
                btnText.textContent = 'Logout';
                this.passkeyAuthBtn.querySelector('.btn-icon').textContent = '🚪';
                this.passkeyAuthBtn.classList.add('logout-mode');
                this.passkeyAuthBtn.disabled = false;
                
                // Set authenticated flag
                this.isAuthenticated = true;
                
                logger.info(`Passkey created and authenticated as ${this.username}`);
                
                // Fetch fresh session data to show authenticated state
                try {
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } catch (error) {
                    logger.error('Failed to refresh session data after registration:', error);
                }
            } else if (originalText === 'Login with Passkey') {
                // Authenticate with existing passkey
                logger.info('Starting passkey authentication for user:', this.username);
                const result = await Passkeys.authenticatePasskey(this.username);
                logger.info('Passkey authentication successful:', result);
                
                // Update button to logout mode
                btnText.textContent = 'Logout';
                this.passkeyAuthBtn.querySelector('.btn-icon').textContent = '🚪';
                this.passkeyAuthBtn.classList.add('logout-mode');
                this.passkeyAuthBtn.disabled = false;
                
                // Set authenticated flag
                this.isAuthenticated = true;
                
                logger.info(`Authenticated as ${this.username}`);
                
                // Fetch fresh session data to show authenticated state
                try {
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } catch (error) {
                    logger.error('Failed to refresh session data after login:', error);
                }
            } else if (originalText === 'Logout') {
                // Handle logout
                logger.info('Logging out user:', this.username);
                btnText.textContent = 'Logging out...';
                
                // Call logout endpoint
                try {
                    const response = await DpopFun.dpopFetch('POST', '/session/logout', {
                        body: JSON.stringify({})
                    });
                    const result = await response.json();
                    logger.info('Logout successful:', result);
                } catch (error) {
                    logger.error('Logout request failed:', error);
                    // Continue with UI cleanup even if server call fails
                }
                
                // Reset authentication flag
                this.isAuthenticated = false;
                
                // Reset button states
                btnText.textContent = 'Create Passkey';
                this.passkeyAuthBtn.querySelector('.btn-icon').textContent = '🔑';
                this.passkeyAuthBtn.classList.remove('logout-mode');
                this.passkeyAuthBtn.disabled = true;
                
                // Reset mobile link button
                this.mobileLinkBtn.disabled = true;
                this.mobileLinkBtn.querySelector('.btn-text').textContent = 'Link Mobile Device';
                this.mobileLinkBtn.dataset.mode = 'registration';
                
                // Clear username
                this.usernameInput.value = '';
                this.username = null;
                this.checkUsernameBtn.disabled = true;
                
                // Refresh session data to show logged out state
                try {
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } catch (error) {
                    logger.error('Failed to refresh session data after logout:', error);
                }
            }
        } catch (error) {
            logger.error('Passkey operation failed:', error);
            alert(`Passkey operation failed: ${error.message}`);
            
            // Restore button state
            btnText.textContent = originalText;
            this.passkeyAuthBtn.disabled = !this.username;
        }
    }

    async handleMobileLink() {
        if (!this.username) {
            alert('Please enter a username and click Go first');
            return;
        }
        
        logger.info('Mobile link button clicked for username:', this.username);
        logger.info('Button data-mode:', this.mobileLinkBtn.dataset.mode);
        logger.info('Button text:', this.mobileLinkBtn.querySelector('.btn-text').textContent);
        
        try {
            // Re-check for mobile passkey to ensure button state is current
            await this.checkForMobilePasskey();
            
            // Show mobile linking modal
            this.showMobileLinkingModal();
            
            // Initialize mobile link service
            if (!this.mobileLinkService) {
                this.mobileLinkService = new MobileLinkService();
            }
            
            // Set username on the service so it can be sent with the link request
            this.mobileLinkService.desktopUsername = this.username;
            
            // Determine flow type based on button mode (set by checkForMobilePasskey)
            const flowType = this.mobileLinkBtn.dataset.mode || 'registration';
            logger.info('Mobile linking flow type after re-check:', flowType);
            
            // Render the mobile linking UI
            this.mobileLinkService.renderMobileLinkingStep(
                'mobileLinkingModalContent',
                false, // not optional
                () => this.onMobileLinkComplete(),
                null,
                flowType
            );
            
        } catch (error) {
            logger.error('Failed to start mobile linking:', error);
            alert(`Failed to start mobile linking: ${error.message}`);
        }
    }
    
    showMobileLinkingModal() {
        // Create modal if it doesn't exist
        let modal = document.getElementById('mobileLinkingModal');
        if (!modal) {
            // Clone modal from template
            const template = document.getElementById('mobileLinkingModalTemplate');
            const clone = template.content.cloneNode(true);
            document.body.appendChild(clone);
            
            modal = document.getElementById('mobileLinkingModal');
            
            // Add close button handler
            document.getElementById('closeMobileLinkBtn').addEventListener('click', () => {
                this.closeMobileLinkingModal();
            });
        }
        
        // Show the modal
        modal.classList.add('active');
        modal.style.display = 'flex';
    }
    
    closeMobileLinkingModal() {
        const modal = document.getElementById('mobileLinkingModal');
        if (modal) {
            modal.classList.remove('active');
            modal.style.display = 'none';
        }
        
        // Clean up mobile link service
        if (this.mobileLinkService) {
            this.mobileLinkService.cleanup();
        }
    }
    
    async onMobileLinkComplete() {
        logger.info('Mobile linking completed successfully - updating desktop UI');
        
        // Close the modal
        this.closeMobileLinkingModal();
        
        // Refresh session data
        try {
            logger.info('Fetching fresh session data after mobile linking...');
            const freshSessionData = await DpopFun.setupSession();
            logger.info('Fresh session data received:', freshSessionData);
            logger.info('Auth status:', freshSessionData.auth_status);
            logger.info('Auth username:', freshSessionData.auth_username);
            logger.info('Auth method:', freshSessionData.auth_method);
            
            if (freshSessionData) {
                logger.info('Populating UI with fresh session data...');
                await this.populateSessionUI(freshSessionData);
                
                // Restore authentication state (in case of mobile login flow)
                logger.info('Restoring authentication state...');
                logger.info('Calling restoreAuthenticationState with:', {
                    auth_status: freshSessionData.auth_status,
                    auth_username: freshSessionData.auth_username,
                    auth_method: freshSessionData.auth_method
                });
                this.restoreAuthenticationState(freshSessionData);
                
                logger.info('Desktop UI update complete');
                logger.info('isAuthenticated flag:', this.isAuthenticated);
            }
        } catch (error) {
            logger.error('Failed to refresh session data after mobile linking:', error);
        }
    }

    updateAuthMethod(sessionData) {
        const authMethod = document.getElementById('authMethod');
        if (authMethod) {
            authMethod.textContent = sessionData.auth_method || 'Unauthenticated';
        }
    }

    updatePrimarySignal(sessionData) {
        const primarySignal = document.getElementById('primarySignal');
        if (primarySignal && sessionData.client_ip) {
            const browserInfo = sessionData.geolocation ? 
                `${sessionData.geolocation.city || 'Unknown'}, ${sessionData.geolocation.country || 'Unknown'}` : 
                'Unknown Location';
            primarySignal.textContent = `IP: ${sessionData.client_ip}, ${browserInfo}`;
        }
    }

    updateSessionHistory(sessionData) {
        // Update the first history item with current session data
        if (sessionData.created_at) {
            const sessionDate = new Date(sessionData.created_at * 1000);
            const timeAgo = this.getTimeAgo(sessionDate);
            
            const historyTime1 = document.getElementById('historyTime1');
            const historyLocation1 = document.getElementById('historyLocation1');
            const historyAuth1 = document.getElementById('historyAuth1');
            
            if (historyTime1) historyTime1.textContent = timeAgo;
            if (historyLocation1) historyLocation1.textContent = sessionData.geolocation?.city || 'Unknown';
            if (historyAuth1) historyAuth1.textContent = sessionData.auth_method || 'Unknown';
        }
    }

    getTimeAgo(date) {
        const now = new Date();
        const diffInSeconds = Math.floor((now - date) / 1000);
        
        if (diffInSeconds < 60) return 'Just now';
        if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`;
        if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`;
        return `${Math.floor(diffInSeconds / 86400)} days ago`;
    }

    mockMultipleSessions(currentSessionData) {
        // Mock data for demonstration - in real app, this would come from API
        this.allSessions = [
            {
                id: 'current-session',
                device_id: currentSessionData.device_id,
                location: currentSessionData.geolocation?.city || 'Unknown',
                browser: 'Chrome on Mac',
                last_activity: new Date(),
                ip: currentSessionData.client_ip,
                is_current: true
            },
            {
                id: 'session-2',
                device_id: 'device-123',
                location: 'London',
                browser: 'Firefox on Windows',
                last_activity: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
                ip: '203.0.113.45',
                is_current: false
            },
            {
                id: 'session-3',
                device_id: 'device-456',
                location: 'New York',
                browser: 'Safari on iPhone',
                last_activity: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
                ip: '198.51.100.23',
                is_current: false
            }
        ];
        
        this.updateSessionCount();
    }

    showSessionDetails() {
        this.populateSessionsList();
        this.sessionDetailsModal.style.display = 'flex';
    }

    populateSessionsList() {
        this.sessionsList.innerHTML = '';
        const template = document.getElementById('sessionItemTemplate');
        
        this.allSessions.forEach(session => {
            // Clone the template
            const clone = template.content.cloneNode(true);
            const sessionElement = clone.querySelector('.session-item');
            
            // Add current session class if applicable
            if (session.is_current) {
                sessionElement.classList.add('current-session');
            }
            
            // Populate data
            clone.querySelector('[data-location]').textContent = session.location;
            clone.querySelector('[data-browser]').textContent = session.browser;
            clone.querySelector('[data-ip]').textContent = `IP: ${session.ip}`;
            clone.querySelector('[data-activity]').textContent = `Last activity: ${this.getTimeAgo(session.last_activity)}`;
            
            // Show/hide current badge
            const currentBadge = clone.querySelector('[data-current-badge]');
            if (session.is_current) {
                currentBadge.style.display = 'inline';
            } else {
                currentBadge.style.display = 'none';
            }
            
            // Show/hide actions for non-current sessions
            const actionsDiv = clone.querySelector('[data-actions]');
            if (session.is_current) {
                actionsDiv.style.display = 'none';
            } else {
                actionsDiv.style.display = 'flex';

        // Add event listeners for action buttons
                const terminateBtn = clone.querySelector('[data-terminate-btn]');
                const reportBtn = clone.querySelector('[data-report-btn]');
                
                terminateBtn.addEventListener('click', () => {
                    this.terminateSession(session.id);
                });
                
                reportBtn.addEventListener('click', () => {
                    this.reportSession(session.id);
                });
            }
            
            this.sessionsList.appendChild(clone);
        });
    }

    terminateSession(sessionId) {
        if (confirm('Are you sure you want to terminate this session?')) {
            // In real app, this would make an API call
            this.allSessions = this.allSessions.filter(session => session.id !== sessionId);
            this.updateSessionCount();
            this.populateSessionsList();
            logger.info(`Terminated session: ${sessionId}`);
        }
    }

    reportSession(sessionId) {
        if (confirm('Report this session as suspicious?')) {
            // In real app, this would make an API call
            logger.info(`Reported suspicious session: ${sessionId}`);
            alert('Session reported. Security team will investigate.');
        }
    }

    reportSuspiciousActivity() {
        if (confirm('Report suspicious activity on your account?')) {
            // In real app, this would make an API call
            logger.info('Reported suspicious activity');
            alert('Suspicious activity reported. Security team will investigate.');
        }
    }

    async killSession(sessionId, sessionInfo) {
        const location = sessionInfo.geolocation ? 
            (() => {
                try {
                    const geo = typeof sessionInfo.geolocation === 'string' ? 
                        JSON.parse(sessionInfo.geolocation) : sessionInfo.geolocation;
                    return `${geo.city || 'Unknown'}, ${geo.country_code || geo.country || ''}`;
                } catch (e) {
                    return 'Unknown location';
                }
            })() : 'Unknown location';
        
        if (confirm(`Kill session from ${location}?\n\nThis will immediately terminate the session.`)) {
            try {
                logger.info(`Killing session: ${sessionId}`);
                
                // Call server endpoint to terminate the session
                const response = await DpopFun.dpopFetch('POST', '/session/kill', {
                    body: JSON.stringify({
                        payload: { session_id: sessionId }
                    })
                });
                
                if (response.ok) {
                    logger.info(`Session ${sessionId} terminated successfully`);
                    alert('Session terminated successfully.');
                    
                    // Refresh session history
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } else {
                    const error = await response.text();
                    logger.error(`Failed to terminate session: ${error}`);
                    alert(`Failed to terminate session: ${error}`);
                }
            } catch (error) {
                logger.error('Error terminating session:', error);
                alert(`Error terminating session: ${error.message}`);
            }
        }
    }

    reportSuspiciousSession(sessionId, sessionInfo) {
        const location = sessionInfo.geolocation ? 
            (() => {
                try {
                    const geo = typeof sessionInfo.geolocation === 'string' ? 
                        JSON.parse(sessionInfo.geolocation) : sessionInfo.geolocation;
                    return `${geo.city || 'Unknown'}, ${geo.country_code || geo.country || ''}`;
                } catch (e) {
                    return 'Unknown location';
                }
            })() : 'Unknown location';
        
        const timeAgo = this.formatTimeAgo(sessionInfo.created_at);
        
        if (confirm(`Report session from ${location} (${timeAgo}) as suspicious?\n\nThis will notify the security team for review.`)) {
            logger.info(`Reporting suspicious session: ${sessionId}`, sessionInfo);
            // In real app, this would make an API call to security endpoint
            alert('Suspicious session reported. Security team will investigate.');
        }
    }

    async updateDevicesList(sessionData) {
        if (!this.devicesList) return;

        // Check if user is authenticated
        if (!sessionData.auth_username || sessionData.auth_status !== 'authenticated') {
            // Hide section when not authenticated
            if (this.devicesSection) {
                this.devicesSection.style.display = 'none';
            }
            return;
        }
        
        // Show section when authenticated
        if (this.devicesSection) {
            this.devicesSection.style.display = 'block';
            logger.info('Devices section shown');
        }

        try {
            // Fetch devices from server
            const response = await DpopFun.dpopFetch('GET', '/devices');
            
            logger.info('Devices fetch response status:', response.status);
            
            if (!response.ok) {
                logger.warn('Failed to fetch devices:', response.status);
                this.devicesList.innerHTML = '<p class="no-devices">Unable to load devices</p>';
                return;
            }
            
            const data = await response.json();
            logger.info('Devices data received:', data);
            const devices = data.devices || [];
            logger.info('Number of devices:', devices.length);
            
            if (devices.length === 0) {
                this.devicesList.innerHTML = '<p class="no-devices">No registered devices</p>';
                return;
            }
            
            // Populate devices list using template
            this.devicesList.innerHTML = '';
            const template = document.getElementById('deviceItemTemplate');
            const currentDeviceId = sessionData.device_id;
            
            devices.forEach(device => {
                const clone = template.content.cloneNode(true);
                
                const isCurrentDevice = device.device_id === currentDeviceId;
                const deviceType = device.device_type || 'unknown';
                const deviceIdShort = device.device_id ? device.device_id.substring(0, 8) : 'unknown';
                
                logger.info(`Device: ${device.device_id} (${deviceIdShort}), Current: ${currentDeviceId}, isCurrentDevice: ${isCurrentDevice}`);
                
                // Set device type icon
                const typeIcon = clone.querySelector('[data-type-icon]');
                typeIcon.textContent = deviceType === 'mobile' ? '📱' : '💻';
                
                // Set device info
                clone.querySelector('[data-type]').textContent = deviceType.charAt(0).toUpperCase() + deviceType.slice(1);
                clone.querySelector('[data-id-short]').textContent = `ID: ${deviceIdShort}...`;
                
                // Show current badge if applicable
                const currentBadge = clone.querySelector('[data-current-device]');
                if (isCurrentDevice) {
                    currentBadge.style.display = 'inline';
                    logger.info(`Device ${deviceIdShort} is current device - hiding remove button`);
                } else {
                    logger.info(`Device ${deviceIdShort} is NOT current device - showing remove button`);
                }
                
                // Set device details
                const lastUsed = device.last_used ? this.formatTimeAgo(device.last_used) : 'Never';
                clone.querySelector('[data-last-used]').textContent = `Last used: ${lastUsed}`;
                clone.querySelector('[data-sessions]').textContent = `${device.session_count || 0} sessions`;
                
                // Show bound username if available
                const boundUserEl = clone.querySelector('[data-bound-user]');
                if (device.bound_username) {
                    boundUserEl.textContent = `Bound to: ${device.bound_username}`;
                    boundUserEl.style.display = 'inline';
                    boundUserEl.style.color = 'var(--color-success)';
                    boundUserEl.style.fontWeight = '600';
                }
                
                // Parse signal data
                let signalText = '';
                if (device.signal_data) {
                    try {
                        const signal = typeof device.signal_data === 'string' ? 
                            JSON.parse(device.signal_data) : device.signal_data;
                        const browser = this.extractBrowserName(signal.userAgent);
                        const platform = signal.platform || 'Unknown';
                        signalText = `${browser} • ${platform}`;
                    } catch (e) {
                        signalText = 'Signal data unavailable';
                    }
                }
                clone.querySelector('[data-device-signal]').textContent = signalText;
                
                this.devicesList.appendChild(clone);
                
                // Handle remove button - AFTER appending to DOM
                const deviceItem = this.devicesList.lastElementChild;
                const removeBtn = deviceItem.querySelector('[data-remove-btn]');
                
                logger.info(`Remove button element:`, removeBtn, 'isCurrentDevice:', isCurrentDevice);
                
                if (removeBtn) {
                    // Button is visible by default via CSS, just attach event listener
                    // Note: We don't hide the button for current device since the server
                    // prevents removing it and the entire section is hidden when not authenticated
                    logger.info(`Attaching event listener to remove button for device ${deviceIdShort}`);
                    removeBtn.addEventListener('click', () => {
                        this.removeDevice(device.device_id, device);
                    });
                } else {
                    logger.error(`Remove button not found in device item for ${deviceIdShort}`);
                }
            });
            
            logger.info(`Loaded ${devices.length} devices`);
            
            // Force show at least one device's button for testing
            const allRemoveBtns = this.devicesList.querySelectorAll('[data-remove-btn]');
            logger.info(`Total remove buttons in DOM:`, allRemoveBtns.length);
            allRemoveBtns.forEach((btn, idx) => {
                logger.info(`Button ${idx}: display=${btn.style.display}, classList=${btn.classList}`);
            });
            
        } catch (error) {
            logger.error('Failed to load devices:', error);
            this.devicesList.innerHTML = '<p class="no-devices">Unable to load devices</p>';
        }
    }

    async removeDevice(deviceId, deviceInfo) {
        const deviceType = deviceInfo.device_type || 'unknown';
        const deviceIdShort = deviceId.substring(0, 8);
        
        if (confirm(`Remove ${deviceType} device (${deviceIdShort}...)?\n\nThis will unregister the device and you'll need to re-authenticate it.`)) {
            try {
                logger.info(`Removing device: ${deviceId}`);
                
                // Call server endpoint to remove the device
                const response = await DpopFun.dpopFetch('POST', '/devices/remove', {
                    body: JSON.stringify({
                        payload: { device_id: deviceId }
                    })
                });
                
                if (response.ok) {
                    logger.info(`Device ${deviceId} removed successfully`);
                    alert('Device removed successfully.');
                    
                    // Refresh devices list
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } else {
                    const error = await response.text();
                    logger.error(`Failed to remove device: ${error}`);
                    alert(`Failed to remove device: ${error}`);
                }
            } catch (error) {
                logger.error('Error removing device:', error);
                alert(`Error removing device: ${error.message}`);
            }
        }
    }

    async updateCredentialsList(sessionData) {
        if (!this.credentialsList) return;

        // Check if user is authenticated
        if (!sessionData.auth_username || sessionData.auth_status !== 'authenticated') {
            // Hide section when not authenticated
            if (this.credentialsSection) {
                this.credentialsSection.style.display = 'none';
            }
            return;
        }
        
        // Show section when authenticated
        if (this.credentialsSection) {
            this.credentialsSection.style.display = 'block';
            logger.info('Credentials section shown');
        }

        try {
            // Fetch credentials from server
            const response = await DpopFun.dpopFetch('GET', '/credentials');
            
            logger.info('Credentials fetch response status:', response.status);
            
            if (!response.ok) {
                logger.warn('Failed to fetch credentials:', response.status);
                this.credentialsList.innerHTML = '<p class="no-credentials">Unable to load credentials</p>';
                return;
            }
            
            const data = await response.json();
            logger.info('Credentials data received:', data);
            const credentials = data.credentials || [];
            logger.info('Number of credentials:', credentials.length);
            
            if (credentials.length === 0) {
                this.credentialsList.innerHTML = '<p class="no-credentials">No passkey credentials registered</p>';
                return;
            }
            
            // Populate credentials list using template
            this.credentialsList.innerHTML = '';
            const template = document.getElementById('credentialItemTemplate');
            
            credentials.forEach(cred => {
                const clone = template.content.cloneNode(true);
                
                const deviceType = cred.device_type || 'unknown';
                const credIdShort = cred.cred_id ? cred.cred_id.substring(0, 12) : 'unknown';
                
                // Set credential icon
                const iconEl = clone.querySelector('[data-cred-icon]');
                iconEl.textContent = deviceType === 'mobile' ? '📱' : '💻';
                
                // Set credential info
                clone.querySelector('[data-cred-device-type]').textContent = deviceType.charAt(0).toUpperCase() + deviceType.slice(1) + ' Passkey';
                clone.querySelector('[data-cred-id-short]').textContent = `ID: ${credIdShort}...`;
                
                // Set credential details
                const createdAgo = cred.created_at ? this.formatTimeAgo(cred.created_at) : 'Unknown';
                clone.querySelector('[data-cred-created]').textContent = `Created: ${createdAgo}`;
                clone.querySelector('[data-sign-count]').textContent = `Used ${cred.usage_count || 0} times`;
                
                this.credentialsList.appendChild(clone);
                
                // Handle remove button - AFTER appending to DOM
                const credItem = this.credentialsList.lastElementChild;
                const removeBtn = credItem.querySelector('[data-remove-cred-btn]');
                
                if (removeBtn) {
                    logger.info(`Attaching event listener to remove button for credential ${credIdShort}`);
                    removeBtn.addEventListener('click', () => {
                        this.removeCredential(cred.cred_id, cred);
                    });
                }
            });
            
            logger.info(`Loaded ${credentials.length} credentials`);
            
        } catch (error) {
            logger.error('Failed to load credentials:', error);
            this.credentialsList.innerHTML = '<p class="no-credentials">Unable to load credentials</p>';
        }
    }

    async removeCredential(credId, credInfo) {
        const deviceType = credInfo.device_type || 'unknown';
        const credIdShort = credId.substring(0, 12);
        
        if (confirm(`Remove ${deviceType} passkey (${credIdShort}...)?\n\nThis will permanently delete this passkey credential. You won't be able to use it to log in anymore.`)) {
            try {
                logger.info(`Removing credential: ${credId}`);
                
                // Call server endpoint to remove the credential
                const response = await DpopFun.dpopFetch('POST', '/credentials/remove', {
                    body: JSON.stringify({
                        payload: { cred_id: credId }
                    })
                });
                
                if (response.ok) {
                    logger.info(`Credential ${credId} removed successfully`);
                    alert('Passkey removed successfully.');
                    
                    // Refresh credentials list
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        await this.populateSessionUI(freshSessionData);
                    }
                } else {
                    const error = await response.text();
                    logger.error(`Failed to remove credential: ${error}`);
                    alert(`Failed to remove passkey: ${error}`);
                }
            } catch (error) {
                logger.error('Error removing credential:', error);
                alert(`Error removing passkey: ${error.message}`);
            }
        }
    }

    showSignalDataModal(session) {
        logger.info('Showing signal data modal for session:', session.session_id);
        
        // Get or create modal
        let modal = document.getElementById('signalDataModal');
        if (!modal) {
            const template = document.getElementById('signalDataModalTemplate');
            const clone = template.content.cloneNode(true);
            document.body.appendChild(clone);
            modal = document.getElementById('signalDataModal');
        }
        
        // Populate modal with signal data
        const modalContent = document.getElementById('signalDataModalContent');
        if (!modalContent) return;
        
        // Parse signal data
        let signalData = {};
        if (session.signal_data) {
            try {
                signalData = typeof session.signal_data === 'string' ? 
                    JSON.parse(session.signal_data) : session.signal_data;
            } catch (e) {
                logger.error('Failed to parse signal data:', e);
                signalData = { error: 'Failed to parse signal data' };
            }
        }
        
        // Build signal data grid
        const grid = document.createElement('div');
        grid.className = 'signal-data-grid';
        
        // Helper function to add signal item
        const addSignalItem = (label, value) => {
            if (value === undefined || value === null) return;
            
            const item = document.createElement('div');
            item.className = 'signal-data-item';
            
            const labelEl = document.createElement('div');
            labelEl.className = 'signal-data-label';
            labelEl.textContent = label;
            
            const valueEl = document.createElement('div');
            valueEl.className = 'signal-data-value';
            
            // Format value based on type
            if (typeof value === 'object') {
                valueEl.innerHTML = `<code>${JSON.stringify(value, null, 2)}</code>`;
            } else if (typeof value === 'boolean') {
                valueEl.textContent = value ? 'Yes' : 'No';
            } else {
                valueEl.textContent = value;
            }
            
            item.appendChild(labelEl);
            item.appendChild(valueEl);
            grid.appendChild(item);
        };
        
        // Add IP and geolocation data first
        if (session.client_ip) {
            addSignalItem('IP Address', session.client_ip);
        }
        
        // Parse and add geolocation data
        if (session.geolocation) {
            try {
                const geo = typeof session.geolocation === 'string' ? 
                    JSON.parse(session.geolocation) : session.geolocation;
                
                if (geo.city) addSignalItem('City', geo.city);
                if (geo.region) addSignalItem('Region', geo.region);
                if (geo.country) addSignalItem('Country', geo.country);
                if (geo.postal) addSignalItem('Postal Code', geo.postal);
                if (geo.latitude && geo.longitude) {
                    addSignalItem('Coordinates', `${geo.latitude}, ${geo.longitude}`);
                }
                if (geo.timezone) addSignalItem('Geo Timezone', geo.timezone);
                if (geo.org) addSignalItem('Organization', geo.org);
                if (geo.asn) addSignalItem('ASN', geo.asn);
            } catch (e) {
                logger.error('Failed to parse geolocation:', e);
            }
        }
        
        // Add all signal data fields
        addSignalItem('User Agent', signalData.userAgent);
        addSignalItem('Platform', signalData.platform);
        addSignalItem('Screen Resolution', signalData.screenResolution);
        addSignalItem('Color Depth', signalData.colorDepth);
        addSignalItem('Timezone', signalData.timezone);
        addSignalItem('Language', signalData.language);
        addSignalItem('Hardware Concurrency', signalData.hardwareConcurrency);
        addSignalItem('Device Memory', signalData.deviceMemory);
        addSignalItem('Cookies Enabled', signalData.cookieEnabled);
        addSignalItem('Do Not Track', signalData.doNotTrack);
        addSignalItem('WebGL Vendor', signalData.webglVendor);
        addSignalItem('WebGL Renderer', signalData.webglRenderer);
        addSignalItem('Device Type', signalData.deviceType);
        addSignalItem('Timestamp', signalData.timestamp);
        
        // Add automation detection data if available
        if (signalData.automation) {
            addSignalItem('Webdriver', signalData.automation.webdriver);
            addSignalItem('Headless UA', signalData.automation.headlessUA);
            addSignalItem('Plugins Length', signalData.automation.pluginsLength);
            addSignalItem('MIME Types Length', signalData.automation.mimeTypesLength);
            addSignalItem('Visibility State', signalData.automation.visibilityState);
            addSignalItem('Has Focus', signalData.automation.hasFocus);
            
            if (signalData.automation.permissionsAnomalies) {
                addSignalItem('Permissions', signalData.automation.permissionsAnomalies);
            }
        }
        
        // Add user agent client hints if available
        if (signalData.ua_ch) {
            addSignalItem('UA Client Hints', signalData.ua_ch);
        }
        
        modalContent.innerHTML = '';
        modalContent.appendChild(grid);
        
        // Show modal
        modal.style.display = 'flex';
        
        // Add close button handler
        const closeBtn = document.getElementById('closeSignalDataBtn');
        if (closeBtn) {
            closeBtn.onclick = () => {
                modal.style.display = 'none';
            };
        }
        
        // Close on overlay click
        modal.onclick = (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        };
    }
}

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new AppController();
});

