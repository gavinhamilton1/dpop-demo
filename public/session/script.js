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
        
        // New elements for overview section
        this.bindingState = document.getElementById('bindingState');
        this.sessionFlag = document.getElementById('sessionFlag');
        this.sessionCount = document.getElementById('sessionCount');
        this.sessionWarning = document.getElementById('sessionWarning');
        this.moreDetailsLink = document.getElementById('moreDetailsLink');
        this.authMethod = document.getElementById('authMethod');
        this.reportActivityBtn = document.getElementById('reportActivityBtn');
        this.sessionHistoryList = document.getElementById('sessionHistoryList');
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
                this.populateSessionUI(SESSION_DATA);
                
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

        // More details link
        this.moreDetailsLink.addEventListener('click', (e) => {
            e.preventDefault();
            this.showSessionDetails();
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

        // Control buttons removed - using Logout button in passkey flow instead

        this.reportActivityBtn.addEventListener('click', () => {
            this.reportSuspiciousActivity();
        });

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
            console.warn("Session expired. Forcing logout.");
            // In production: window.location.href = '/logout';
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
            console.warn("Idle timeout reached (15 minutes). Forcing session end.");
            // In production: trigger session end function and notify user.
        }
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


    populateSessionUI(sessionData) {
        // Store session data for use in other methods
        this.sessionData = sessionData;
        
        // Update overview section
        this.updateOverviewSection(sessionData);
        
        // Update session history in third column
        this.updateSessionHistoryList(sessionData);
        
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

        // Show warning and more details link if more than 1 session
        if (sessionCount > 1) {
            this.sessionWarning.style.display = 'inline';
            this.moreDetailsLink.style.display = 'inline';
        } else {
            this.sessionWarning.style.display = 'none';
            this.moreDetailsLink.style.display = 'none';
        }
    }

    updateSessionHistoryList(sessionData) {
        if (!this.sessionHistoryList) return;

        // TODO: Replace with actual session history from server
        // For now, check if there's any history data in sessionData
        const hasHistory = sessionData.session_history && sessionData.session_history.length > 0;

        if (!hasHistory) {
            // Show "no previous sessions" message
            this.sessionHistoryList.innerHTML = '<p class="no-history">No previous sessions</p>';
            return;
        }

        // Populate with actual history
        this.sessionHistoryList.innerHTML = '';
        sessionData.session_history.forEach(session => {
            const historyItem = document.createElement('div');
            historyItem.className = 'history-session-item';
            
            const timeAgo = this.formatTimeAgo(session.created_at);
            const location = session.geolocation ? 
                `${session.geolocation.city}, ${session.geolocation.country}` : 
                'Unknown location';
            const authMethod = session.auth_method || 'Unknown';

            historyItem.innerHTML = `
                <span class="history-time">${timeAgo}</span>
                <span class="history-location">${location}</span>
                <span class="history-method">${authMethod}</span>
            `;

            this.sessionHistoryList.appendChild(historyItem);
        });
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
        
        // Disable passkey button until "Go" is clicked
        this.passkeyAuthBtn.disabled = true;
        
        // Enable/disable mobile link button based on username
        this.mobileLinkBtn.disabled = !hasUsername;
        
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
            
            // Enable the check username button
            this.checkUsernameBtn.disabled = false;
            
            logger.info('Authentication state restored');
        } else {
            logger.info('No authenticated session found');
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
            
            // Update passkey button based on result
            const passkeyBtnText = this.passkeyAuthBtn.querySelector('.btn-text');
            if (hasPasskeys) {
                passkeyBtnText.textContent = 'Login with Passkey';
                this.passkeyAuthBtn.disabled = false;
            } else {
                passkeyBtnText.textContent = 'Create Passkey';
                this.passkeyAuthBtn.disabled = false;
            }
            
            // Restore Go button
            btnText.textContent = originalText;
            this.checkUsernameBtn.disabled = false;
            
        } catch (error) {
            logger.error('Failed to check for passkeys:', error);
            btnText.textContent = originalText;
            this.checkUsernameBtn.disabled = false;
            
            // On error, default to create mode
            this.passkeyAuthBtn.querySelector('.btn-text').textContent = 'Create Passkey';
            this.passkeyAuthBtn.disabled = false;
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
                
                // Update button to login mode
                btnText.textContent = 'Login with Passkey';
                
                // Re-enable if username still present
                this.passkeyAuthBtn.disabled = !this.username;
                
                logger.info(`Passkey created successfully for ${this.username}`);
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
                
                logger.info(`Authenticated as ${this.username}`);
                
                // Fetch fresh session data to show authenticated state
                try {
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        this.populateSessionUI(freshSessionData);
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
                
                // Reset button state
                btnText.textContent = 'Create Passkey';
                this.passkeyAuthBtn.querySelector('.btn-icon').textContent = '🔑';
                this.passkeyAuthBtn.classList.remove('logout-mode');
                this.passkeyAuthBtn.disabled = true;
                
                // Clear username
                this.usernameInput.value = '';
                this.username = null;
                
                // Refresh session data to show logged out state
                try {
                    const freshSessionData = await DpopFun.setupSession();
                    if (freshSessionData) {
                        this.populateSessionUI(freshSessionData);
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
        
        try {
            // Show mobile linking modal
            this.showMobileLinkingModal();
            
            // Initialize mobile link service
            if (!this.mobileLinkService) {
                this.mobileLinkService = new MobileLinkService();
            }
            
            // Set username on the service so it can be sent with the link request
            this.mobileLinkService.desktopUsername = this.username;
            
            // Determine flow type based on authentication status
            const flowType = this.sessionData?.auth_status === 'authenticated' ? 'login' : 'registration';
            
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
            modal = document.createElement('div');
            modal.id = 'mobileLinkingModal';
            modal.className = 'modal-overlay';
            modal.innerHTML = `
                <div class="modal-content mobile-linking-content">
                    <div class="modal-header">
                        <h2>Link Mobile Device</h2>
                        <button class="close-btn" id="closeMobileLinkBtn">&times;</button>
                    </div>
                    <div class="modal-body" id="mobileLinkingModalContent">
                        <!-- Mobile linking UI will be rendered here -->
                    </div>
                </div>
            `;
            document.body.appendChild(modal);
            
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
        logger.info('Mobile linking completed successfully');
        
        // Close the modal
        this.closeMobileLinkingModal();
        
        // Refresh session data
        try {
            const freshSessionData = await DpopFun.setupSession();
            if (freshSessionData) {
                this.populateSessionUI(freshSessionData);
            }
        } catch (error) {
            logger.error('Failed to refresh session data after mobile linking:', error);
        }
        
        alert('Mobile device linked successfully!');
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
        
        this.allSessions.forEach(session => {
            const sessionElement = document.createElement('div');
            sessionElement.className = `session-item ${session.is_current ? 'current-session' : ''}`;
            
            sessionElement.innerHTML = `
                <div class="session-info">
                    <div class="session-header">
                        <span class="session-location">${session.location}</span>
                        <span class="session-browser">${session.browser}</span>
                        ${session.is_current ? '<span class="current-badge">Current</span>' : ''}
                    </div>
                    <div class="session-details">
                        <span class="session-ip">IP: ${session.ip}</span>
                        <span class="session-activity">Last activity: ${this.getTimeAgo(session.last_activity)}</span>
                    </div>
                </div>
                <div class="session-actions">
                    ${!session.is_current ? `
                        <button class="action-btn terminate-btn" data-session-id="${session.id}">
                            Terminate
                        </button>
                        <button class="action-btn report-btn" data-session-id="${session.id}">
                            Report
                        </button>
                    ` : ''}
                </div>
            `;
            
            this.sessionsList.appendChild(sessionElement);
        });

        // Add event listeners for action buttons
        this.sessionsList.querySelectorAll('.terminate-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const sessionId = e.target.getAttribute('data-session-id');
                this.terminateSession(sessionId);
            });
        });

        this.sessionsList.querySelectorAll('.report-btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const sessionId = e.target.getAttribute('data-session-id');
                this.reportSession(sessionId);
            });
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
}

// Initialize the app when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
    new AppController();
});

