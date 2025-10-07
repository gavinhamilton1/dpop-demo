import { logger } from '../js/utils/logging.js';
import { CONFIG } from '../js/utils/config.js';
import * as DpopFun from '../js/core/dpop-fun.js';


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
        this.endSessionBtn = document.getElementById('endSessionBtn');
        this.reportActivityBtn = document.getElementById('reportActivityBtn');
        
        // Session details modal
        this.sessionDetailsModal = document.getElementById('sessionDetailsModal');
        this.sessionsList = document.getElementById('sessionsList');
        this.closeSessionDetailsBtn = document.querySelector('[data-close-session-details]');

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

        // Control buttons
        this.endSessionBtn.addEventListener('click', () => {
            this.endCurrentSession();
        });

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
        
        // Update session history
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

    endCurrentSession() {
        if (confirm('Are you sure you want to end your current session?')) {
            // In real app, this would make an API call to end the session
            logger.info('Ending current session');
            alert('Session ended. You will be redirected to login.');
            // window.location.href = '/logout';
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

