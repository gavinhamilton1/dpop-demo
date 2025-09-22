/**
 * Journeys Page Controller
 * Provides user-friendly interfaces for different authentication flows
 */

import { logger } from '../js/utils/logging.js';
import { CONFIG } from '../js/utils/config.js';
import { idbGet, STORES } from '../js/utils/idb.js';
import * as DpopFun from './core/dpop-fun.js';
import * as Passkeys from './core/passkeys.js';
import { FingerprintService } from './services/FingerprintService.js';
import { generateQRCode } from '../js/utils/qr-generator.js';

class JourneysController {
    constructor() {
        this.currentJourney = null;
        this.currentStep = 0;
        this.sessionState = {
            hasSession: false,
            hasBIK: false,
            hasDPoP: false,
            hasUsername: false,
            hasPasskey: false,
            hasFace: false,
            isAuthenticated: false,
            authenticationMethod: null
        };
        
        
        this.journeyDefinitions = {
            newUser: {
                title: 'New User Registration',
                description: 'Create a new account with username, passkey, face, and mobile device',
                steps: [
                    {
                        id: 'username',
                        title: 'Create Username',
                        description: 'Choose a unique username for your account',
                        action: () => this.createUsername()
                    },
                    {
                        id: 'passkey',
                        title: 'Register Passkey',
                        description: 'Set up a passkey for secure authentication (if supported)',
                        action: () => this.registerPasskey(),
                        optional: true,
                        condition: () => this.checkPasskeySupport()
                    },
                    {
                        id: 'face',
                        title: 'Register Face',
                        description: 'Set up facial recognition for authentication',
                        action: () => this.registerFace(),
                        optional: true
                    },
                    {
                        id: 'mobile',
                        title: 'Link Mobile Device',
                        description: 'Connect your mobile device for cross-device authentication',
                        action: () => this.linkMobileDevice(),
                        optional: true
                    }
                ]
            },
            desktopPasskey: {
                title: 'Desktop Passkey Login',
                description: 'Sign in using your desktop passkey',
                steps: [
                    {
                        id: 'login',
                        title: 'Login with Passkey',
                        description: 'Enter your username and authenticate with your passkey',
                        action: () => this.loginWithPasskey()
                    }
                ]
            },
            faceLogin: {
                title: 'Face Recognition Login',
                description: 'Sign in using facial recognition',
                steps: [
                    {
                        id: 'username',
                        title: 'Enter Username',
                        description: 'Enter your username to continue',
                        action: () => this.enterUsername()
                    },
                    {
                        id: 'face',
                        title: 'Face Authentication',
                        description: 'Use facial recognition to sign in',
                        action: () => this.authenticateWithFace()
                    }
                ]
            },
            mobilePasskey: {
                title: 'Mobile Passkey Login',
                description: 'Sign in using your mobile device passkey',
                steps: [
                    {
                        id: 'username',
                        title: 'Enter Username',
                        description: 'Enter your username to continue',
                        action: () => this.enterUsername()
                    },
                    {
                        id: 'mobile',
                        title: 'Mobile Authentication',
                        description: 'Use your mobile device passkey to sign in',
                        action: () => this.authenticateWithMobilePasskey()
                    }
                ]
            }
        };
        
        this.init();
    }
    
    
    async init() {
        try {
            logger.info('Initializing Journeys Controller...');
            this.setupEventListeners();
            await this.checkSessionStatus();
            this.updateJourneyAvailability();
            logger.info('Journeys Controller initialized successfully');
        } catch (error) {
            logger.error('Failed to initialize Journeys Controller:', error);
        }
    }
    
    setupEventListeners() {
        // Admin control buttons
        document.getElementById('serverFlushBtn').addEventListener('click', () => this.handleServerFlush());
        document.getElementById('clientFlushBtn').addEventListener('click', () => this.handleClientFlush());
        
        // Test API button
        document.getElementById('testApiBtn').addEventListener('click', () => this.handleTestAPI());
        
        // Signal details button
        document.getElementById('signalDetailsBtn').addEventListener('click', () => this.handleSignalDetails());
        
        // Modal event listeners
        this.setupModalHandlers();
        
        // Journey selection buttons
        document.getElementById('startNewUserBtn').addEventListener('click', () => this.startJourney('newUser'));
        document.getElementById('startDesktopPasskeyBtn').addEventListener('click', () => this.startJourney('desktopPasskey'));
        document.getElementById('startFaceLoginBtn').addEventListener('click', () => this.startJourney('faceLogin'));
        document.getElementById('startMobilePasskeyBtn').addEventListener('click', () => this.startJourney('mobilePasskey'));
        
        // Username entry
        document.getElementById('continueWithUsernameBtn').addEventListener('click', () => this.continueWithUsername());
        document.getElementById('cancelUsernameBtn').addEventListener('click', () => this.cancelUsernameEntry());
        document.getElementById('usernameInput').addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.continueWithUsername();
        });
        
        // Logout
        document.getElementById('logoutBtn').addEventListener('click', () => this.logout());
    }
    
    async checkSessionStatus() {
        try {
            logger.info('Setting up session...');
            this.updateSessionStatus('loading', 'Setting up Session...', 'Checking for existing session or creating new one');
            
            // Use the consolidated session setup logic
            const sessionData = await DpopFun.setupSession();
            
            // Update our session state with the results
            this.sessionState.hasSession = sessionData.hasSession;
            this.sessionState.hasBIK = sessionData.hasBIK;
            this.sessionState.hasDPoP = sessionData.hasDPoP;
            this.sessionState.hasUsername = sessionData.hasUsername;
            this.sessionState.username = sessionData.username;
            
            // Load persisted authentication state
            await this.loadPersistedAuthenticationState();
            
            // Update UI status based on detailed session information
            this.updateSessionStatusWithDetails(sessionData);
            
            logger.info('Session setup completed successfully');
            
        } catch (error) {
            logger.error('Failed to setup session:', error);
            this.updateSessionStatus('error', 'Session Setup Failed', error.message);
        }
    }
    
    async loadPersistedAuthenticationState() {
        try {
            const authStatus = await DpopFun.get(CONFIG.STORAGE.KEYS.AUTH_STATUS);
            const authMethod = await DpopFun.get(CONFIG.STORAGE.KEYS.AUTH_METHOD);

            if (authStatus && authStatus.value) {
                this.sessionState.isAuthenticated = true;
                this.sessionState.authenticationMethod = authMethod?.value || 'unknown';
                logger.info(`Loaded persisted authentication state: ${this.sessionState.authenticationMethod}`);
            }
        } catch (error) {
            logger.error('Failed to load persisted authentication state:', error);
        }
    }

    async updateAuthenticationStatus(method) {
        this.sessionState.isAuthenticated = true;
        this.sessionState.authenticationMethod = method;

        // Persist authentication state to IndexedDB
        try {
            await DpopFun.set(CONFIG.STORAGE.KEYS.AUTH_STATUS, true);
            await DpopFun.set(CONFIG.STORAGE.KEYS.AUTH_METHOD, method);
            logger.info(`Authentication state persisted: ${method}`);
        } catch (error) {
            logger.error('Failed to persist authentication state:', error);
        }

        logger.info(`User authenticated with: ${method}`);

        // Show logout button after successful authentication
        document.getElementById('logoutBtn').style.display = 'block';

        // Refresh session status to show authentication
        this.refreshSessionStatus();
    }
    
    updateSessionStatus(status, title, detail) {
        const indicator = document.getElementById('sessionStatusIndicator');
        indicator.className = `status-indicator ${status}`;
        
        const titleEl = indicator.querySelector('.status-title');
        const detailEl = indicator.querySelector('.status-detail');
        
        if (titleEl) titleEl.textContent = title;
        if (detailEl) detailEl.textContent = detail;
    }

    updateSessionStatusWithDetails(sessionData) {
        const { details, hasUsername, username } = sessionData;
        
        if (!sessionData.hasSession) {
            // Check if this is due to a mismatch that was cleared
            if (details.localBIK || details.localDPoP) {
                this.updateSessionStatus('warning', 'Session Cleared', 'Client/server mismatch detected - server session cleared, creating fresh session');
            } else {
                this.updateSessionStatus('error', 'No Session', 'No server session found');
            }
            return;
        }

        // Build detailed status message
        let status = 'success';
        let title = 'Session Status';
        let detail = '';

        // Server session status
        if (details.serverSession) {
            const sessionType = details.sessionType === 'new' ? ' (new)' : details.sessionType === 'restored' ? ' (restored)' : '';
            detail += `✅ Server session found${sessionType}\n`;
        } else {
            detail += '❌ No server session\n';
            status = 'error';
        }

        // BIK status
        if (details.serverBIK && details.localBIK) {
            if (details.bikMatch) {
                const bikType = details.bikType === 'new' ? ' (new)' : details.bikType === 'restored' ? ' (restored)' : '';
                detail += `✅ BIK: Server + Local (matched)${bikType}\n`;
            } else {
                detail += '⚠️ BIK: Server + Local (mismatch)\n';
                status = 'warning';
            }
        } else if (details.serverBIK && !details.localBIK) {
            detail += '⚠️ BIK: Server only (local missing)\n';
            status = 'warning';
        } else if (!details.serverBIK && details.localBIK) {
            detail += '⚠️ BIK: Local only (server missing)\n';
            status = 'warning';
        } else {
            detail += '❌ BIK: Not found\n';
        }

        // DPoP status
        if (details.serverDPoP && details.localDPoP) {
            if (details.dpopWorking) {
                const dpopType = details.dpopType === 'new' ? ' (new)' : details.dpopType === 'restored' ? ' (restored)' : '';
                detail += `✅ DPoP: Server + Local (working)${dpopType}\n`;
            } else {
                detail += '⚠️ DPoP: Server + Local (not working)\n';
                status = 'warning';
            }
        } else if (details.serverDPoP && !details.localDPoP) {
            detail += '⚠️ DPoP: Server only (local missing)\n';
            status = 'warning';
        } else if (!details.serverDPoP && details.localDPoP) {
            detail += '⚠️ DPoP: Local only (server missing)\n';
            status = 'warning';
        } else {
            detail += '❌ DPoP: Not found\n';
        }

        // Username status
        if (hasUsername) {
            const usernameStr = typeof username === 'string' ? username : (username?.username || username?.value || JSON.stringify(username));
            detail += `✅ Username: ${usernameStr}\n`;
        } else {
            detail += '❌ Username: Not set\n';
        }

        // Authentication status (displayed last)
        if (this.sessionState.isAuthenticated && this.sessionState.authenticationMethod) {
            detail += `🔐 Authenticated with ${this.sessionState.authenticationMethod}\n`;
        } else if (sessionData.user_authenticated && sessionData.username) {
            // Server-side authentication status
            const usernameStr = typeof sessionData.username === 'string' ? sessionData.username : (sessionData.username?.username || sessionData.username?.value || JSON.stringify(sessionData.username));
            detail += `🔐 Server authenticated: ${usernameStr}\n`;
        } else {
            detail += '❌ Authentication: Not authenticated\n';
        }

        // Overall readiness
        if (this.sessionState.isAuthenticated && this.sessionState.authenticationMethod) {
            title = `✅ Authenticated with ${this.sessionState.authenticationMethod}`;
        } else if (details.dpopWorking && hasUsername) {
            title = 'Session Ready';
        } else if (details.dpopWorking) {
            title = 'DPoP Ready';
        } else if (details.serverBIK && details.localBIK) {
            title = 'BIK Ready';
            detail += '\n🔗 Ready for DPoP binding';
        } else if (details.serverSession) {
            title = 'Session Ready';
            detail += '\n🔑 Ready for BIK registration';
        } else {
            title = 'Session Error';
            detail += '\n❌ Session setup needed';
        }

        this.updateSessionStatus(status, title, detail.trim());
        
        // Show/hide test API button based on DPoP status
        this.updateTestApiButton(sessionData.hasDPoP && sessionData.hasSession);
        
        // Show logout button if there's a username in the session
        if (hasUsername) {
            const logoutBtn = document.getElementById('logoutBtn');
            logger.info('Showing logout button, hasUsername:', hasUsername, 'logoutBtn:', logoutBtn);
            if (logoutBtn) {
                logoutBtn.style.display = 'block';
            } else {
                logger.error('Logout button element not found!');
            }
        }
        
        // Load signal data when session is ready
        if (sessionData.hasSession && sessionData.hasDPoP) {
            this.loadSignalSummary();
        }
    }
    
    updateJourneyAvailability() {
        const newUserBtn = document.getElementById('startNewUserBtn');
        const desktopPasskeyBtn = document.getElementById('startDesktopPasskeyBtn');
        const faceLoginBtn = document.getElementById('startFaceLoginBtn');
        const mobilePasskeyBtn = document.getElementById('startMobilePasskeyBtn');
        
        // New user journey - always available
        newUserBtn.disabled = false;
        
        // Login journeys require BIK and username
        const canLogin = this.sessionState.hasSession && this.sessionState.hasBIK && this.sessionState.hasUsername;
        
        desktopPasskeyBtn.disabled = !canLogin;
        faceLoginBtn.disabled = !canLogin;
        mobilePasskeyBtn.disabled = !canLogin;
        
        // Update button text for passkey support
        if (!this.checkPasskeySupport()) {
            desktopPasskeyBtn.textContent = 'Passkeys Not Supported';
            mobilePasskeyBtn.textContent = 'Passkeys Not Supported';
        }
    }
    
    checkPasskeySupport() {
        return window.PublicKeyCredential && 
               typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
    }
    
    updateTestApiButton(isDPoPReady) {
        const sessionActions = document.getElementById('sessionActions');
        const testApiBtn = document.getElementById('testApiBtn');
        
        if (isDPoPReady) {
            // Show the test API button and enable it
            sessionActions.style.display = 'flex';
            testApiBtn.disabled = false;
        } else {
            // Hide the test API button
            sessionActions.style.display = 'none';
            testApiBtn.disabled = true;
        }
    }
    
    /**
     * Setup modal event handlers
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

        // Signal details modal handlers
        const signalModal = document.getElementById('signalDetailsModal');
        const signalCloseBtn = document.getElementById('signalModalClose');

        // Close signal modal handlers
        if (signalCloseBtn) {
            signalCloseBtn.addEventListener('click', () => {
                this.hideSignalModal();
            });
        }

        // Close signal modal when clicking outside
        if (signalModal) {
            signalModal.addEventListener('click', (e) => {
                if (e.target === signalModal) {
                    this.hideSignalModal();
                }
            });
        }

        // Close signal modal with Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape' && signalModal && signalModal.classList.contains('show')) {
                this.hideSignalModal();
            }
        });
    }
    
    async startJourney(journeyType) {
        try {
            logger.info(`Starting ${journeyType} journey...`);
            
            // Hide journey selection
            document.getElementById('journeySelection').style.display = 'none';
            
            // Show journey content
            document.getElementById('journeyContent').style.display = 'block';
            
            this.currentJourney = this.journeyDefinitions[journeyType];
            this.currentStep = 0;
            
            // Update journey header
            document.getElementById('journeyTitle').textContent = this.currentJourney.title;
            document.getElementById('journeyDescription').textContent = this.currentJourney.description;
            
            // Show logout button for login journeys
            if (journeyType !== 'newUser') {
                document.getElementById('logoutBtn').style.display = 'block';
            }
            
            // Render steps
            this.renderSteps();
            
            // Start first step
            await this.executeCurrentStep();
            
        } catch (error) {
            logger.error(`Failed to start ${journeyType} journey:`, error);
        }
    }
    
    renderSteps() {
        const stepsContainer = document.getElementById('journeySteps');
        stepsContainer.innerHTML = '';
        
        this.currentJourney.steps.forEach((step, index) => {
            const stepEl = document.createElement('div');
            stepEl.className = 'step';
            stepEl.id = `step-${step.id}`;
            
            if (index < this.currentStep) {
                stepEl.classList.add('completed');
            } else if (index === this.currentStep) {
                stepEl.classList.add('active');
            }
            
            stepEl.innerHTML = `
                <div class="step-header">
                    <div class="step-number">${index + 1}</div>
                    <h3 class="step-title">${step.title}</h3>
                </div>
                <p class="step-description">${step.description}</p>
                <div class="step-content"></div>
                <div class="step-actions"></div>
            `;
            
            stepsContainer.appendChild(stepEl);
        });
    }
    
    async executeCurrentStep() {
        logger.info(`executeCurrentStep called, currentStep: ${this.currentStep}, total steps: ${this.currentJourney.steps.length}`);
        
        if (this.currentStep >= this.currentJourney.steps.length) {
            logger.info('All steps completed, calling completeJourney()');
            await this.completeJourney();
            return;
        }
        
        const step = this.currentJourney.steps[this.currentStep];
        const stepEl = document.getElementById(`step-${step.id}`);
        
        logger.info(`Executing step: ${step.title}`);
        logger.info(`Step element:`, stepEl);
        
        if (!stepEl) {
            logger.error(`Step element not found for step: ${step.id}`);
            return;
        }
        
        try {
            await step.action();
        } catch (error) {
            logger.error(`Step ${step.title} failed:`, error);
            this.showStepError(stepEl, error.message);
        }
    }
    
    async completeStep() {
        logger.info(`Completing step ${this.currentStep}: ${this.currentJourney.steps[this.currentStep].title}`);
        
        const stepEl = document.getElementById(`step-${this.currentJourney.steps[this.currentStep].id}`);
        stepEl.classList.remove('active');
        stepEl.classList.add('completed');
        
        this.currentStep++;
        logger.info(`Moving to step ${this.currentStep}`);
        
        if (this.currentStep < this.currentJourney.steps.length) {
            const nextStepEl = document.getElementById(`step-${this.currentJourney.steps[this.currentStep].id}`);
            logger.info(`Next step element found:`, nextStepEl);
            nextStepEl.classList.add('active');
            logger.info(`Next step: ${this.currentJourney.steps[this.currentStep].title}`);
        } else {
            logger.info('No more steps, completing journey');
        }
        
        await this.executeCurrentStep();
    }
    
    showStepError(stepEl, message) {
        const contentEl = stepEl.querySelector('.step-content');
        contentEl.innerHTML = `
            <div class="error-message">
                <strong>Error:</strong> ${message}
            </div>
            <div class="step-actions">
                <button class="btn primary" onclick="journeysController.retryCurrentStep()">Retry</button>
                <button class="btn secondary" onclick="journeysController.cancelJourney()">Cancel</button>
            </div>
        `;
    }
    
    async retryCurrentStep() {
        await this.executeCurrentStep();
    }
    
    cancelJourney() {
        this.currentJourney = null;
        this.currentStep = 0;
        
        document.getElementById('journeyContent').style.display = 'none';
        document.getElementById('journeySelection').style.display = 'grid';
        document.getElementById('logoutBtn').style.display = 'none';
        
        logger.info('Journey cancelled');
    }
    
    async completeJourney() {
        logger.info('Journey completed successfully!');
        
        // Show logout button after completing any journey
        document.getElementById('logoutBtn').style.display = 'block';
        
        // Show completion message
        const actionsContainer = document.getElementById('journeyActions');
        actionsContainer.innerHTML = `
            <div class="step completed">
                <div class="step-header">
                    <div class="step-number">✓</div>
                    <h3 class="step-title">Journey Complete!</h3>
                </div>
                <p class="step-description">You have successfully completed the ${this.currentJourney.title}.</p>
                <div class="step-actions">
                    <button class="btn primary" onclick="journeysController.startNewJourney()">Start New Journey</button>
                    <button class="btn secondary" onclick="journeysController.returnToSelection()">Return to Selection</button>
                </div>
            </div>
        `;
    }
    
    startNewJourney() {
        this.cancelJourney();
        this.updateJourneyAvailability();
    }
    
    returnToSelection() {
        this.cancelJourney();
    }
    
    // Journey Step Implementations
    async registerBrowserIdentity() {
        const stepEl = document.getElementById('step-browserIdentity');
        const contentEl = stepEl.querySelector('.step-content');
        
        // Check if we already have a session with BIK and DPoP
        if (this.sessionState.hasSession && this.sessionState.hasBIK && this.sessionState.hasDPoP) {
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Browser identity already registered and DPoP bound!</p>
                </div>
            `;
            
            logger.info('Browser identity already registered');
            await this.completeStep();
            return;
        }
        
        contentEl.innerHTML = `
            <div class="step-status">
                <p>Registering browser identity and binding DPoP...</p>
            </div>
        `;
        
        try {
            // Use the core session setup logic
            const sessionData = await DpopFun.setupSession();
            
            // Update session state
            this.sessionState.hasSession = sessionData.hasSession;
            this.sessionState.hasBIK = sessionData.hasBIK;
            this.sessionState.hasDPoP = sessionData.hasDPoP;
            
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Browser identity registered and DPoP bound successfully!</p>
                </div>
            `;
            
            logger.info('Browser identity registered successfully');
            await this.completeStep();
            
        } catch (error) {
            throw new Error(`Failed to register browser identity: ${error.message}`);
        }
    }
    
    async createUsername() {
        const stepEl = document.getElementById('step-username');
        const contentEl = stepEl.querySelector('.step-content');
        
        contentEl.innerHTML = `
            <div class="username-form">
                <input type="text" id="stepUsernameInput" placeholder="Enter your username" maxlength="50">
                <div class="step-actions">
                    <button class="btn primary" id="createUsernameBtn">Create New Username</button>
                    <button class="btn secondary" id="useExistingUsernameBtn">Use Existing Username</button>
                </div>
                <div id="stepUsernameError" class="error-message" style="display: none;"></div>
            </div>
        `;
        
        // Create new username
        const createBtn = document.getElementById('createUsernameBtn');
        logger.info('createUsernameBtn element found:', createBtn);
        
        if (!createBtn) {
            logger.error('createUsernameBtn not found!');
            return;
        }
        
        createBtn.addEventListener('click', async () => {
            logger.info('createUsernameBtn clicked!');
            const username = document.getElementById('stepUsernameInput').value.trim();
            const errorEl = document.getElementById('stepUsernameError');

            if (!username) {
                errorEl.textContent = 'Username is required';
                errorEl.style.display = 'block';
                return;
            }

            try {
                const response = await fetch('/onboarding/username', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ username })
                });

                if (response.ok) {
                    this.sessionState.hasUsername = true;
                    this.sessionState.username = username;
            
                    contentEl.innerHTML = `
                        <div class="step-status success">
                            <p>✓ Username "${username}" created successfully!</p>
                        </div>
                    `;
                    
                    logger.info(`Username "${username}" created successfully`);
                    logger.info(`Completing username step, current step: ${this.currentStep}`);

                    await this.completeStep();
                    
                } else {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Failed to create username');
                }

            } catch (error) {
                errorEl.textContent = error.message;
                errorEl.style.display = 'block';
            }
        });

        // Use existing username
        const useExistingBtn = document.getElementById('useExistingUsernameBtn');
        logger.info('useExistingUsernameBtn element found:', useExistingBtn);
        
        if (!useExistingBtn) {
            logger.error('useExistingUsernameBtn not found!');
            return;
        }
        
        useExistingBtn.addEventListener('click', async () => {
            logger.info('useExistingUsernameBtn clicked!');
            const username = document.getElementById('stepUsernameInput').value.trim();
            const errorEl = document.getElementById('stepUsernameError');
            
            logger.info('Username value:', username);
            
            if (!username) {
                logger.info('No username provided');
                errorEl.textContent = 'Username is required';
                errorEl.style.display = 'block';
                return;
            }
            
            logger.info('Making request to /onboarding/signin');
            try {
                const response = await fetch('/onboarding/signin', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify({ username })
                });
                
                logger.info('Response status:', response.status);
                if (response.ok) {
                    logger.info('Response OK, updating session state');
                    this.sessionState.hasUsername = true;
                    this.sessionState.username = username;
                    
                    logger.info('Updating content HTML');
                    contentEl.innerHTML = `
                        <div class="step-status success">
                            <p>✓ Username "${username}" verified!</p>
                        </div>
                    `;
                    
                    logger.info(`Username "${username}" verified`);
                    logger.info(`Completing username step, current step: ${this.currentStep}`);

                    logger.info('About to call completeStep()');
                    await this.completeStep();
                    logger.info('completeStep() completed');
                    
                } else {
                    const errorData = await response.json();
                    throw new Error(errorData.detail || 'Username not found');
                }
                
            } catch (error) {
                logger.error('Error in useExistingUsernameBtn handler:', error);
                errorEl.textContent = error.message;
                errorEl.style.display = 'block';
            }
        });
    }
    
    async registerPasskey() {
        logger.info('registerPasskey() method called');
        const stepEl = document.getElementById('step-passkey');
        const contentEl = stepEl.querySelector('.step-content');
        
        logger.info('Step element found:', stepEl);
        logger.info('Content element found:', contentEl);
        
        if (!this.checkPasskeySupport()) {
            contentEl.innerHTML = `
                <div class="step-status">
                    <p>Passkeys are not supported by this browser. Skipping this step.</p>
                </div>
            `;
            await this.completeStep();
            return;
        }
        
        const passkeyHTML = `
            <div class="step-status">
                <p>Registering passkey...</p>
                <p>Follow the prompts on your device to create a passkey.</p>
            </div>
            <div class="step-actions">
                <button class="btn primary" id="registerPasskeyBtn">Register Passkey</button>
                <button class="btn secondary" id="skipPasskeyBtn">Skip</button>
            </div>
        `;
        
        logger.info('Setting passkey HTML content');
        contentEl.innerHTML = passkeyHTML;
        logger.info('Content set, checking if buttons exist:', document.getElementById('registerPasskeyBtn'));
        
        document.getElementById('registerPasskeyBtn').addEventListener('click', async () => {
            try {
                await Passkeys.registerPasskey();
                
                this.sessionState.hasPasskey = true;
                
                contentEl.innerHTML = `
                    <div class="step-status success">
                        <p>✓ Passkey registered successfully!</p>
                    </div>
                `;
                
                logger.info('Passkey registered successfully');
                await this.completeStep();
                
            } catch (error) {
                contentEl.innerHTML = `
                    <div class="step-status error">
                        <p>Failed to register passkey: ${error.message}</p>
                        <div class="step-actions">
                            <button class="btn primary" onclick="journeysController.retryCurrentStep()">Retry</button>
                            <button class="btn secondary" onclick="journeysController.skipCurrentStep()">Skip</button>
                        </div>
                    </div>
                `;
            }
        });
        
        document.getElementById('skipPasskeyBtn').addEventListener('click', () => {
            this.skipCurrentStep();
        });
    }
    
    async registerFace() {
        const stepEl = document.getElementById('step-face');
        const contentEl = stepEl.querySelector('.step-content');
        
        contentEl.innerHTML = `
            <div class="face-capture-container">
                <div id="faceStartPhase">
                    <h3>Register Face</h3>
                    <p>Click the button below to start face registration. This will use your camera to capture and register your face for authentication.</p>
                    <div class="step-actions" style="margin-top: 1rem;">
                        <button class="btn primary" id="startFaceBtn">Start Face Registration</button>
                        ${this.currentJourney.steps[this.currentStep].optional ? '<button class="btn secondary" id="skipFaceBtn">Skip</button>' : ''}
                    </div>
                </div>
                
                <div id="faceCapturePhase" style="display: none;">
                    <div class="face-capture-status">
                        <span class="face-status-text" id="status">Initializing camera...</span>
                    </div>

                    <div class="face-capture-row">
                        <div class="face-capture-col">
                            <div class="face-preview-wrap">
                                <video id="video" playsinline muted></video>
                                <canvas id="canvas"></canvas>
                                <div class="face-overlay"></div>
                            </div>
                        </div>
                        <div class="face-capture-col">
                            <div class="face-prompt" id="prompt">Ready.</div>
                            <div class="face-chips">
                                <div class="face-chip" id="chipFace">Face detected</div>
                                <div class="face-chip" id="chipCenter">Center face</div>
                                <div class="face-chip" id="chipLeft">Turn LEFT</div>
                                <div class="face-chip" id="chipRight">Turn RIGHT</div>
                            </div>
                            <div class="face-result" id="resultBox">
                                <div><strong>Processing face registration...</strong></div>
                                <div style="margin-top:6px;">
                                    <span class="face-pill" id="pillDuration">-- s</span>
                                    <span class="face-pill" id="pillSize">-- KB</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Handle start face registration button
        document.getElementById('startFaceBtn').addEventListener('click', async () => {
            await this.startFaceRegistration();
        });
        
        // Handle skip button (only if it exists)
        const skipBtn = document.getElementById('skipFaceBtn');
        if (skipBtn) {
            skipBtn.addEventListener('click', () => {
                this.skipCurrentStep();
            });
        }
    }
    
    async startFaceRegistration() {
        try {
            logger.info('Starting face registration process...');
            
            // Show face capture phase
            document.getElementById('faceStartPhase').style.display = 'none';
            document.getElementById('faceCapturePhase').style.display = 'block';
            
            // Disable start button
            const startBtn = document.getElementById('startFaceBtn');
            startBtn.disabled = true;
            startBtn.textContent = 'Initializing...';
            
            // Import and initialize face capture using the same approach as index.html
            const faceCaptureModule = await import('./face-capture.js');
            window.faceCapture = new faceCaptureModule.FaceCaptureInline('register');
            await window.faceCapture.init();
            
            // Auto-start the face capture process
            await window.faceCapture.startCapture();
            
            logger.info('Face registration started');
            
            // Listen for completion by checking the status element periodically
            const checkCompletion = () => {
                const statusEl = document.getElementById('status');
                if (statusEl) {
                    const statusText = statusEl.textContent || statusEl.innerText;
                    if (statusText.includes('Face registered ✓') || statusText.includes('Face verified ✓')) {
                        this.sessionState.hasFace = true;
                        logger.info('Face registered successfully');
                        this.completeStep();
                        return;
                    }
                }
                // Check again in 500ms
                setTimeout(checkCompletion, 500);
            };
            
            // Start checking for completion after 2 seconds
            setTimeout(checkCompletion, 2000);
            
        } catch (error) {
            logger.error('Failed to initialize face capture:', error);
            
            // Show error and re-enable start button
            const startBtn = document.getElementById('startFaceBtn');
            startBtn.disabled = false;
            startBtn.textContent = 'Start Face Registration';
            
            // Show error message
            document.getElementById('faceStartPhase').innerHTML = `
                <div class="step-status error">
                    <p>Failed to initialize face capture: ${error.message}</p>
                    <div class="step-actions">
                        <button class="btn primary" id="retryFaceBtn">Retry</button>
                        <button class="btn secondary" id="skipFaceBtn">Skip</button>
                    </div>
                </div>
            `;
            
            // Re-add event listeners
            document.getElementById('retryFaceBtn').addEventListener('click', async () => {
                await this.startFaceRegistration();
            });
            document.getElementById('skipFaceBtn').addEventListener('click', () => {
                this.skipCurrentStep();
            });
        }
    }
    
    async linkMobileDevice() {
        const stepEl = document.getElementById('step-mobile');
        const contentEl = stepEl.querySelector('.step-content');
        
        // Create a container for the LinkingService to render into
        contentEl.innerHTML = '<div id="mobileLinkingContainer"></div>';
        
        // Use LinkingService's built-in UI rendering with camera functionality
        const { LinkingService } = await import('./services/LinkingService.js');
        const { DpopFunService } = await import('./services/DpopFunService.js');
        
        // Create DpopFunService instance
        const dpopFunService = new DpopFunService();
        this.linkingService = new LinkingService(dpopFunService);
        
        // Render the mobile linking step using LinkingService's built-in UI
        this.linkingService.renderMobileLinkingStep(
            'mobileLinkingContainer',
            this.currentJourney.steps[this.currentStep].optional,
            () => this.completeStep(), // onStepComplete
            () => this.skipCurrentStep() // onStepSkip
        );
    }
    
    
    
    async restoreBrowserIdentity() {
        const stepEl = document.getElementById('step-browserIdentity');
        const contentEl = stepEl.querySelector('.step-content');
        
        if (this.sessionState.hasSession && this.sessionState.hasBIK && this.sessionState.hasDPoP) {
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Browser identity already active!</p>
                </div>
            `;
            await this.completeStep();
            return;
        }
        
        // Try to restore what we can
        contentEl.innerHTML = `
            <div class="step-status">
                <p>Restoring browser identity...</p>
            </div>
        `;
        
        try {
            // Check if we need to restore session tokens
            if (this.sessionState.hasDPoP) {
                await DpopFun.restoreSessionTokens();
                logger.info('Session tokens restored successfully');
            }
            
            // If we don't have a complete session, we need to complete the setup
            if (!this.sessionState.hasSession || !this.sessionState.hasBIK || !this.sessionState.hasDPoP) {
                throw new Error('Incomplete browser identity. Please complete the new user journey first.');
            }
            
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Browser identity restored successfully!</p>
                </div>
            `;
            
            logger.info('Browser identity restored successfully');
            await this.completeStep();
            
        } catch (error) {
            throw new Error(`Failed to restore browser identity: ${error.message}`);
        }
    }
    
    async loginWithPasskey() {
        const stepEl = document.getElementById('step-login');
        const contentEl = stepEl.querySelector('.step-content');
        
        // Always show username input field, prepopulate if username exists
        const currentUsername = this.sessionState.hasUsername ? 
            (typeof this.sessionState.username === 'string' ? this.sessionState.username : 
             (this.sessionState.username?.username || this.sessionState.username?.value || '')) : '';
        
        contentEl.innerHTML = `
            <div class="step-status">
            </div>
            <div class="step-actions">
                <div class="input-group">
                    <input 
                        type="text" 
                        id="usernameInputPasskey" 
                        placeholder="Enter username" 
                        value="${currentUsername}"
                        class="form-input"
                    >
                    <button class="btn primary" id="loginWithPasskeyBtn">Login with Passkey</button>
                </div>
                <div id="loginErrorPasskey" class="error-message" style="display: none;"></div>
            </div>
        `;
        
        // Add event listener for the login button
        const loginBtn = document.getElementById('loginWithPasskeyBtn');
        if (loginBtn) {
            loginBtn.addEventListener('click', async () => {
                const username = document.getElementById('usernameInputPasskey').value.trim();
                const errorEl = document.getElementById('loginErrorPasskey');
                
                if (!username) {
                    errorEl.textContent = 'Username is required';
                    errorEl.style.display = 'block';
                    return;
                }
                
                try {
                    // First, submit the username
                    const response = await fetch('/onboarding/signin', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        credentials: 'include',
                        body: JSON.stringify({ username })
                    });
                    
                    if (response.ok) {
                        const responseData = await response.json();
                        
                        this.sessionState.hasUsername = true;
                        this.sessionState.username = username;
                        
                        // Update the step content to show username success and start passkey auth
                        if (responseData.status === 'already_linked') {
                            contentEl.innerHTML = `
                                <div class="step-status success">
                                    <p>✓ Username "${username}" already linked to session!</p>
                                    <p>🔐 Authenticating with passkey...</p>
                                </div>
                            `;
                        } else {
                            contentEl.innerHTML = `
                                <div class="step-status success">
                                    <p>✓ Username "${username}" verified!</p>
                                    <p>🔐 Authenticating with passkey...</p>
                                </div>
                            `;
                        }
                        
                        // Update session status display without reinitializing session
                        this.updateSessionStatus();
                        
                        // Now authenticate with passkey
                        try {
                            await this.performPasskeyAuthentication();
                            
                            // Update UI to show success
                            contentEl.innerHTML = `
                                <div class="step-status success">
                                    <p>✓ Username "${username}" verified!</p>
                                    <p>✓ Passkey authentication successful!</p>
                                </div>
                            `;
                            
                            // Update authentication status
                            this.updateAuthenticationStatus('desktop passkey');
                            
                            // Complete the journey
                            await this.completeJourney();
                            
                        } catch (passkeyError) {
                            // Show passkey error
                            contentEl.innerHTML = `
                                <div class="step-status error">
                                    <p>✓ Username "${username}" verified!</p>
                                    <p>❌ Passkey authentication failed: ${passkeyError.message}</p>
                                </div>
                            `;
                            throw passkeyError;
                        }
                        
                    } else {
                        const errorData = await response.json();
                        throw new Error(errorData.detail || 'Username not found');
                    }
                    
                } catch (error) {
                    errorEl.textContent = error.message;
                    errorEl.style.display = 'block';
                }
            });
        }
    }
    
    async performPasskeyAuthentication() {
        // Check if passkey is registered for this user
        let hasPasskey = false;
        let authOptions = null;
        try {
            authOptions = await Passkeys.getAuthOptions();
            hasPasskey = !!(authOptions.allowCredentials && authOptions.allowCredentials.length);
            logger.info(`Passkey check: hasPasskey=${hasPasskey} rpId=${authOptions?.rpId}`);
        } catch (e) {
            logger.info(`Passkey check failed: ${e.message || e}`);
            hasPasskey = false;
        }
        
        if (!hasPasskey) {
            throw new Error('No passkey registered for this user. You need to register a passkey first.');
        }
        
        // Perform passkey authentication
        await Passkeys.authenticatePasskey(authOptions);
        logger.info('Passkey authentication successful');
    }
    
    async enterUsername() {
        const stepEl = document.getElementById('step-username');
        const contentEl = stepEl.querySelector('.step-content');
        
        if (this.sessionState.hasUsername) {
            const usernameStr = typeof this.sessionState.username === 'string' ? this.sessionState.username : 
                (this.sessionState.username?.username || this.sessionState.username?.value || 'Unknown');
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Username "${usernameStr}" found!</p>
                </div>
            `;
            await this.completeStep();
            return;
        }
        
        // Show username entry interface
        document.getElementById('usernameEntrySection').style.display = 'block';
        this.pendingUsernameStep = true;
    }
    
    async continueWithUsername() {
        const username = document.getElementById('usernameInput').value.trim();
        const errorEl = document.getElementById('usernameError');
        
        if (!username) {
            errorEl.textContent = 'Username is required';
            errorEl.style.display = 'block';
            return;
        }
        
        try {
            // Check if username exists
            const response = await fetch('/onboarding/signin', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ username })
            });
            
            if (response.ok) {
                this.sessionState.hasUsername = true;
                this.sessionState.username = username;
                
                document.getElementById('usernameEntrySection').style.display = 'none';
                document.getElementById('usernameInput').value = '';
                errorEl.style.display = 'none';
                
                if (this.pendingUsernameStep) {
                    const stepEl = document.getElementById('step-username');
                    const contentEl = stepEl.querySelector('.step-content');
                    
                    contentEl.innerHTML = `
                        <div class="step-status success">
                            <p>✓ Username "${username}" verified!</p>
                        </div>
                    `;
                    
                    logger.info(`Username "${username}" verified`);
                    this.pendingUsernameStep = false;
                    await this.completeStep();
                }
                
            } else {
                const errorData = await response.json();
                throw new Error(errorData.detail || 'Username not found');
            }
            
        } catch (error) {
            errorEl.textContent = error.message;
            errorEl.style.display = 'block';
        }
    }
    
    cancelUsernameEntry() {
        document.getElementById('usernameEntrySection').style.display = 'none';
        document.getElementById('usernameInput').value = '';
        document.getElementById('usernameError').style.display = 'none';
        this.pendingUsernameStep = false;
    }
    
    async authenticateWithPasskey() {
        const stepEl = document.getElementById('step-passkey');
        const contentEl = stepEl.querySelector('.step-content');
        
        contentEl.innerHTML = `
            <div class="step-status">
                <p>Authenticating with passkey...</p>
                <p>Follow the prompts on your device to authenticate.</p>
            </div>
        `;
        
        try {
            await Passkeys.authenticatePasskey();
            
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Passkey authentication successful!</p>
                </div>
            `;
            
            logger.info('Passkey authentication successful');
            await this.completeStep();
            
        } catch (error) {
            throw new Error(`Passkey authentication failed: ${error.message}`);
        }
    }
    
    async authenticateWithFace() {
        const stepEl = document.getElementById('step-face');
        const contentEl = stepEl.querySelector('.step-content');
        
        contentEl.innerHTML = `
            <div class="face-capture-container">
                <div id="faceStartPhase">
                    <h3>Authenticate with Face</h3>
                    <p>Click the button below to start face authentication. This will use your camera to verify your identity.</p>
                    <div class="step-actions" style="margin-top: 1rem;">
                        <button class="btn primary" id="startFaceBtn">Start Face Authentication</button>
                        ${this.currentJourney.steps[this.currentStep].optional ? '<button class="btn secondary" id="skipFaceBtn">Skip</button>' : ''}
                    </div>
                </div>
                
                <div id="faceCapturePhase" style="display: none;">
                    <div class="face-capture-status">
                        <span class="face-status-text" id="status">Initializing camera...</span>
                    </div>

                    <div class="face-capture-row">
                        <div class="face-capture-col">
                            <div class="face-preview-wrap">
                                <video id="video" playsinline muted></video>
                                <canvas id="canvas"></canvas>
                                <div class="face-overlay"></div>
                            </div>
                        </div>
                        <div class="face-capture-col">
                            <div class="face-prompt" id="prompt">Ready.</div>
                            <div class="face-chips">
                                <div class="face-chip" id="chipFace">Face detected</div>
                                <div class="face-chip" id="chipCenter">Center face</div>
                                <div class="face-chip" id="chipLeft">Turn LEFT</div>
                                <div class="face-chip" id="chipRight">Turn RIGHT</div>
                            </div>
                            <div class="face-result" id="resultBox">
                                <div><strong>Processing face verification...</strong></div>
                                <div style="margin-top:6px;">
                                    <span class="face-pill" id="pillDuration">-- s</span>
                                    <span class="face-pill" id="pillSize">-- KB</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
        
        // Handle start face authentication button
        document.getElementById('startFaceBtn').addEventListener('click', async () => {
            await this.startFaceAuthentication();
        });
        
        // Handle skip button (only if it exists)
        const skipBtn = document.getElementById('skipFaceBtn');
        if (skipBtn) {
            skipBtn.addEventListener('click', () => {
                this.skipCurrentStep();
            });
        }
    }
    
    async startFaceAuthentication() {
        try {
            logger.info('Starting face authentication process...');
            
            // Show face capture phase
            document.getElementById('faceStartPhase').style.display = 'none';
            document.getElementById('faceCapturePhase').style.display = 'block';
            
            // Disable start button
            const startBtn = document.getElementById('startFaceBtn');
            startBtn.disabled = true;
            startBtn.textContent = 'Initializing...';
            
            // Import and initialize face capture using the same approach as index.html
            const faceCaptureModule = await import('./face-capture.js');
            window.faceCapture = new faceCaptureModule.FaceCaptureInline('verify');
            await window.faceCapture.init();
            
            // Auto-start the face capture process
            await window.faceCapture.startCapture();
            
            logger.info('Face verification started');
            
            // Listen for completion by checking the status element periodically
            const checkCompletion = () => {
                const statusEl = document.getElementById('status');
                if (statusEl) {
                    const statusText = statusEl.textContent || statusEl.innerText;
                    if (statusText.includes('Face verified ✓') || statusText.includes('Face registered ✓')) {
                        logger.info('Face authentication successful');
                        this.completeStep();
                        return;
                    }
                }
                // Check again in 500ms
                setTimeout(checkCompletion, 500);
            };
            
            // Start checking for completion after 2 seconds
            setTimeout(checkCompletion, 2000);
            
        } catch (error) {
            logger.error('Failed to initialize face capture:', error);
            
            // Show error and re-enable start button
            const startBtn = document.getElementById('startFaceBtn');
            startBtn.disabled = false;
            startBtn.textContent = 'Start Face Authentication';
            
            // Show error message
            document.getElementById('faceStartPhase').innerHTML = `
                <div class="step-status error">
                    <p>Failed to initialize face capture: ${error.message}</p>
                    <div class="step-actions">
                        <button class="btn primary" id="retryFaceBtn">Retry</button>
                        <button class="btn secondary" id="skipFaceBtn">Skip</button>
                    </div>
                </div>
            `;
            
            // Re-add event listeners
            document.getElementById('retryFaceBtn').addEventListener('click', async () => {
                await this.startFaceAuthentication();
            });
            document.getElementById('skipFaceBtn').addEventListener('click', () => {
                this.skipCurrentStep();
            });
        }
    }
    
    async authenticateWithMobilePasskey() {
        const stepEl = document.getElementById('step-mobile');
        const contentEl = stepEl.querySelector('.step-content');
        
        contentEl.innerHTML = `
            <div class="mobile-auth-container">
                <p>Mobile passkey authentication functionality would be implemented here...</p>
                <div class="step-actions">
                    <button class="btn primary" onclick="journeysController.completeStep()">Complete Authentication</button>
                </div>
            </div>
        `;
        
        logger.info('Mobile passkey authentication initiated');
    }
    
    async skipCurrentStep() {
        const step = this.currentJourney.steps[this.currentStep];
        if (step.optional) {
            logger.info(`Skipping optional step: ${step.title}`);
            await this.completeStep();
        } else {
            throw new Error('Cannot skip required step');
        }
    }
    
    async logout() {
        try {
            // Clear client-side data
            await DpopFun.clientFlush();
            
            // Clear session state
            this.sessionState = {
                hasSession: false,
                hasBIK: false,
                hasDPoP: false,
                hasUsername: false,
                hasPasskey: false,
                hasFace: false,
                isAuthenticated: false,
                authenticationMethod: null
            };
            
            // Reset UI
            this.cancelJourney();
            await this.checkSessionStatus();
            this.updateJourneyAvailability();
            
            logger.info('Logged out successfully');
            
        } catch (error) {
            logger.error('Logout failed:', error);
        }
    }
    
    /**
     * Handle server flush button click
     */
    async handleServerFlush() {
        const button = document.getElementById('serverFlushBtn');
        const originalText = button.textContent;
        
        try {
            // Disable button and show loading state
            button.disabled = true;
            button.textContent = '🔄 Flushing...';
            
            logger.info('Server flush initiated by user');
            
            // Call the server flush function
            const success = await DpopFun.clearServerSession();
            
            if (success) {
                logger.info('Server flush completed successfully');
                
                // Update session status to reflect cleared state
                this.sessionState.hasSession = false;
                this.sessionState.hasBIK = false;
                this.sessionState.hasDPoP = false;
                this.sessionState.hasUsername = false;
                this.sessionState.username = null;
                this.sessionState.isAuthenticated = false;
                this.sessionState.authenticationMethod = null;
                
                // Update UI
                this.updateSessionStatus('warning', 'Server Cleared', 'Server session data has been cleared');
                this.updateJourneyAvailability();
                
                // Show success message
                button.textContent = '✅ Cleared';
                setTimeout(() => {
                    button.textContent = originalText;
                    button.disabled = false;
                }, 2000);
            } else {
                throw new Error('Server flush failed');
            }
            
        } catch (error) {
            logger.error('Server flush failed:', error);
            
            // Show error state
            button.textContent = '❌ Failed';
            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
            }, 2000);
            
            // Update UI to show error
            this.updateSessionStatus('error', 'Flush Failed', `Server flush failed: ${error.message}`);
        }
    }
    
    /**
     * Handle client flush button click
     */
    async handleClientFlush() {
        const button = document.getElementById('clientFlushBtn');
        const originalText = button.textContent;
        
        try {
            // Disable button and show loading state
            button.disabled = true;
            button.textContent = '🔄 Flushing...';
            
            logger.info('Client flush initiated by user');
            
            // Call the client flush function
            await DpopFun.clientFlush();
            
            logger.info('Client flush completed successfully');
            
            // Update session status to reflect cleared state
            this.sessionState.hasSession = false;
            this.sessionState.hasBIK = false;
            this.sessionState.hasDPoP = false;
            this.sessionState.hasUsername = false;
            this.sessionState.username = null;
            this.sessionState.isAuthenticated = false;
            this.sessionState.authenticationMethod = null;
            
            // Update UI
            this.updateSessionStatus('warning', 'Client Cleared', 'Client session data and IndexedDB have been cleared');
            this.updateJourneyAvailability();
            
            // Show success message
            button.textContent = '✅ Cleared';
            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
            }, 2000);
            
        } catch (error) {
            logger.error('Client flush failed:', error);
            
            // Show error state
            button.textContent = '❌ Failed';
            setTimeout(() => {
                button.textContent = originalText;
                button.disabled = false;
            }, 2000);
            
            // Update UI to show error
            this.updateSessionStatus('error', 'Flush Failed', `Client flush failed: ${error.message}`);
        }
    }
    
    /**
     * Handle test API button click - show modal
     */
    handleTestAPI() {
        this.showApiModal();
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

            const message = apiMessage.value.trim() || 'Hello from DPoP-Fun Journeys!';
            
            const testData = {
                message: message,
                timestamp: new Date().toISOString(),
                userAgent: navigator.userAgent
            };

            // Capture request details before making the request
            const requestDetails = await this.captureRequestDetails(testData);
            
            const response = await DpopFun.dpopFunFetch('/api/echo', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify(testData)
            });

            // Create response details (dpopFunFetch returns parsed JSON, not Response object)
            const responseDetails = {
                status: 200,
                statusText: 'OK',
                headers: {
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Allow-Origin': 'http://localhost:8000',
                    'Content-Length': JSON.stringify(response).length.toString(),
                    'Content-Type': 'application/json',
                    'DPoP-Nonce': 'Updated by server (see logs)',
                    'Server': 'uvicorn',
                    'Set-Cookie': 'dpop-fun_session=<updated-session>; Path=/; HttpOnly; SameSite=Lax',
                    'X-Request-ID': 'req_' + Math.random().toString(36).substr(2, 9)
                },
                body: response,
                timestamp: new Date().toISOString(),
                note: 'dpopFunFetch returns parsed JSON, not Response object - headers are simulated based on typical server response'
            };

            // Display request details
            clientRequest.innerHTML = JSON.stringify(requestDetails, null, 2);
            clientRequest.className = 'response-box info';

            // Display response details
            apiResponse.innerHTML = JSON.stringify(responseDetails, null, 2);
            apiResponse.className = 'response-box success';

            logger.info('API access successful - DPoP token working!');
            logger.info(`Response: ${JSON.stringify(response, null, 2)}`);

        } catch (error) {
            // Display error
            apiResponse.innerHTML = `Error: ${error.message}`;
            apiResponse.className = 'response-box error';
            clientRequest.innerHTML = 'Request details unavailable due to error';
            clientRequest.className = 'response-box error';

            logger.error(`API access failed: ${error.message}`);
        } finally {
            sendBtn.disabled = false;
            sendBtn.textContent = 'Send Request';
        }
    }
    
    /**
     * Capture request details including actual DPoP and nonce headers
     */
    async captureRequestDetails(testData) {
        try {
            // Get current session info
            const sessionStatus = await DpopFun.getSessionStatus();
            
            // Get actual DPoP token and binding token
            const dpopToken = await this.generateDPoPTokenForDisplay();
            const bindToken = await DpopFun.get(CONFIG.STORAGE.KEYS.BIND);
            
            // Get current session cookie (this would be sent automatically by browser)
            const sessionCookie = document.cookie.split(';').find(c => c.trim().startsWith('dpop-fun_session='));
            
            return {
                url: '/api/echo',
                method: 'POST',
                headers: {
                    'Accept': '*/*',
                    'Accept-Encoding': 'gzip, deflate, br, zstd',
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Cache-Control': 'no-cache',
                    'Connection': 'keep-alive',
                    'Content-Length': JSON.stringify(testData).length.toString(),
                    'Content-Type': 'application/json',
                    'Cookie': sessionCookie ? sessionCookie.trim() : 'dpop-fun_session=<session-token>',
                    'DPoP': dpopToken,
                    'DPoP-Bind': bindToken?.value || 'No binding token',
                    'Host': 'localhost:8000',
                    'Origin': window.location.origin,
                    'Pragma': 'no-cache',
                    'Sec-Ch-Ua': '"Chromium";v="140", "Not=A?Brand";v="24", "Google Chrome";v="140"',
                    'Sec-Ch-Ua-Mobile': '?0',
                    'Sec-Ch-Ua-Platform': '"macOS"',
                    'Sec-Fetch-Dest': 'empty',
                    'Sec-Fetch-Mode': 'cors',
                    'Sec-Fetch-Site': 'same-origin',
                    'User-Agent': navigator.userAgent
                },
                body: testData,
                session: {
                    valid: sessionStatus?.valid || false,
                    bik_registered: sessionStatus?.bik_registered || false,
                    dpop_bound: sessionStatus?.dpop_bound || false
                },
                timestamp: new Date().toISOString()
            };
        } catch (error) {
            return {
                url: '/api/echo',
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'DPoP': 'Error retrieving details',
                    'DPoP-Bind': 'Error retrieving binding token'
                },
                body: testData,
                error: error.message,
                timestamp: new Date().toISOString()
            };
        }
    }

    /**
     * Generate DPoP token for display purposes
     */
    async generateDPoPTokenForDisplay() {
        try {
            // Get current DPoP key using the same method as ensureDPoP
            const dpopRecord = await idbGet(STORES.KEYS, CONFIG.STORAGE.KEYS.DPOP_CURRENT);
            const nonceRecord = await DpopFun.get(CONFIG.STORAGE.KEYS.DPOP_NONCE);
            
            if (!dpopRecord || !dpopRecord.privateKey || !dpopRecord.publicJwk) {
                return 'No DPoP key available';
            }
            
            if (!nonceRecord?.value) {
                return 'No DPoP nonce available';
            }
            
            // Create a DPoP proof for display (this mimics what dpopFunFetch does internally)
            const dpopProof = await DpopFun.createDpopProof({ 
                url: '/api/echo', 
                method: 'POST', 
                nonce: nonceRecord.value,
                privateKey: dpopRecord.privateKey, 
                publicJwk: dpopRecord.publicJwk 
            });
            return dpopProof;
        } catch (error) {
            logger.error('Failed to generate DPoP token for display:', error);
            return 'Error generating DPoP token';
        }
    }

    /**
     * Load and display signal summary data
     */
    async loadSignalSummary() {
        try {
            logger.info('Collecting client-side fingerprint data for signal summary...');
            
            // Collect fingerprint data client-side
            const fingerprint = await FingerprintService.collectFingerprint('desktop');
            
            if (fingerprint && Object.keys(fingerprint).length > 0) {
                logger.info('Fingerprint data collected successfully');
                this.displaySignalSummary(fingerprint, 'desktop');
                
                // Optionally send to server for storage
                try {
                    await FingerprintService.sendFingerprintToServer(fingerprint);
                    logger.info('Fingerprint data sent to server');
                } catch (error) {
                    logger.warn('Failed to send fingerprint to server:', error);
                    // Continue anyway - local display is more important
                }
            } else {
                logger.warn('No fingerprint data collected');
                this.hideSignalSummary();
            }
        } catch (error) {
            logger.error('Failed to collect signal summary:', error);
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
     * Handle signal details button click
     */
    async handleSignalDetails() {
        try {
            logger.info('Opening signal details modal...');
            
            // Try to get existing server fingerprint data first (simpler approach)
            try {
                const response = await fetch('/session/fingerprint-data', {
                    credentials: 'include'
                });
                
                if (response.ok) {
                    const data = await response.json();
                    logger.info('Server response data:', data);
                    logger.info('Server response keys:', Object.keys(data || {}));
                    
                    // Check different possible data structures
                    let fingerprint = null;
                    if (data.fingerprint) {
                        fingerprint = data.fingerprint;
                    } else if (data.desktop && data.desktop.fingerprint) {
                        fingerprint = data.desktop.fingerprint;
                    } else if (data.mobile && data.mobile.fingerprint) {
                        fingerprint = data.mobile.fingerprint;
                    } else if (Array.isArray(data) && data.length > 0) {
                        // If data is an array, take the first item
                        fingerprint = data[0];
                    }
                    
                    logger.info('Extracted fingerprint:', fingerprint);
                    logger.info('Fingerprint keys:', Object.keys(fingerprint || {}));
                    
                    if (fingerprint && Object.keys(fingerprint).length > 0) {
                        this.showSignalModal(fingerprint);
                        return;
                    } else {
                        logger.warn('No valid fingerprint data found in server response');
                    }
                }
            } catch (error) {
                logger.warn('Failed to fetch existing fingerprint data:', error);
            }
            
            // Fallback: collect fresh client-side data
            logger.info('Collecting fresh client-side fingerprint data...');
            const fingerprint = await FingerprintService.collectFingerprint('desktop');
            logger.info('Client-side fingerprint collected:', Object.keys(fingerprint || {}));
            
            if (fingerprint && Object.keys(fingerprint).length > 0) {
                this.showSignalModal(fingerprint);
            } else {
                logger.warn('No fingerprint data available for signal details');
                this.showSignalModal(null);
            }
        } catch (error) {
            logger.error('Failed to collect signal details:', error);
            this.showSignalModal(null);
        }
    }

    /**
     * Show signal details modal
     */
    showSignalModal(fingerprint) {
        const modal = document.getElementById('signalDetailsModal');
        const content = document.getElementById('signalDetailsContent');
        
        if (!modal || !content) {
            logger.error('Signal modal elements not found');
            return;
        }

        if (fingerprint && Object.keys(fingerprint).length > 0) {
            logger.info('Displaying signal modal with fingerprint data');
            // Generate detailed signal content
            content.innerHTML = this.generateSignalDetailsHTML(fingerprint);
        } else {
            logger.warn('No fingerprint data available, showing error message');
            content.innerHTML = '<div class="loading-text">Failed to load signal data - No fingerprint data available</div>';
        }

        // Show modal
        modal.style.display = 'flex';
        modal.classList.add('show');
    }

    /**
     * Hide signal details modal
     */
    hideSignalModal() {
        const modal = document.getElementById('signalDetailsModal');
        if (modal) {
            modal.style.display = 'none';
            modal.classList.remove('show');
        }
    }

    /**
     * Generate detailed signal HTML content
     */
    generateSignalDetailsHTML(fingerprint) {
        try {
            if (!fingerprint) {
                logger.error('Fingerprint data is null or undefined');
                return '<div class="loading-text">No fingerprint data available</div>';
            }

            logger.info('Generating HTML for fingerprint with keys:', Object.keys(fingerprint));
            let html = '';

            // Location & Environment
            html += '<div class="signal-section">';
            html += '<h4>🌍 Location & Environment</h4>';
            html += `<div class="signal-item"><span class="signal-label">Timezone:</span><span class="signal-value">${fingerprint.timezone || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Language:</span><span class="signal-value">${fingerprint.language || 'Unknown'}</span></div>`;
            
            if (fingerprint.geolocation) {
                html += `<div class="signal-item"><span class="signal-label">Country:</span><span class="signal-value">${fingerprint.geolocation.country || 'Unknown'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">City:</span><span class="signal-value">${fingerprint.geolocation.city || 'Unknown'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">Region:</span><span class="signal-value">${fingerprint.geolocation.region || 'Unknown'}</span></div>`;
            }
            html += '</div>';

            // Device Information
            html += '<div class="signal-section">';
            html += '<h4>💻 Device Information</h4>';
            html += `<div class="signal-item"><span class="signal-label">Device Type:</span><span class="signal-value">${fingerprint.deviceType || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Platform:</span><span class="signal-value">${fingerprint.platform || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Hardware Concurrency:</span><span class="signal-value">${fingerprint.hardwareConcurrency || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Device Memory:</span><span class="signal-value">${fingerprint.deviceMemory || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Cookie Enabled:</span><span class="signal-value">${fingerprint.cookieEnabled ? 'Yes' : 'No'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Do Not Track:</span><span class="signal-value">${fingerprint.doNotTrack || 'Unknown'}</span></div>`;
            html += '</div>';

            // Browser Details
            html += '<div class="signal-section">';
            html += '<h4>🌐 Browser Details</h4>';
            html += `<div class="signal-item"><span class="signal-label">User Agent:</span><span class="signal-value">${fingerprint.userAgent || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">WebGL Vendor:</span><span class="signal-value">${fingerprint.webglVendor || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">WebGL Renderer:</span><span class="signal-value">${fingerprint.webglRenderer || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Color Depth:</span><span class="signal-value">${fingerprint.colorDepth || 'Unknown'}</span></div>`;
            html += `<div class="signal-item"><span class="signal-label">Screen Resolution:</span><span class="signal-value">${fingerprint.screenResolution || 'Unknown'}</span></div>`;
            html += '</div>';

            // Security & Automation
            html += '<div class="signal-section">';
            html += '<h4>🔒 Security & Automation</h4>';
            if (fingerprint.automation) {
                html += `<div class="signal-item"><span class="signal-label">WebDriver:</span><span class="signal-value">${fingerprint.automation.webdriver ? 'Detected' : 'Not Detected'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">Headless UA:</span><span class="signal-value">${fingerprint.automation.headlessUA ? 'Detected' : 'Not Detected'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">Plugins Count:</span><span class="signal-value">${fingerprint.automation.pluginsLength || 'Unknown'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">MIME Types Count:</span><span class="signal-value">${fingerprint.automation.mimeTypesLength || 'Unknown'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">Visibility State:</span><span class="signal-value">${fingerprint.automation.visibilityState || 'Unknown'}</span></div>`;
                html += `<div class="signal-item"><span class="signal-label">Has Focus:</span><span class="signal-value">${fingerprint.automation.hasFocus ? 'Yes' : 'No'}</span></div>`;
            } else {
                html += '<div class="signal-item"><span class="signal-label">Automation Data:</span><span class="signal-value">Not Available</span></div>';
            }
            html += '</div>';

            logger.info('HTML generated successfully, length:', html.length);
            return html;
        } catch (error) {
            logger.error('Error generating signal HTML:', error);
            return `<div class="loading-text">Error generating signal data: ${error.message}</div>`;
        }
    }

}

// Initialize the journeys controller
const journeysController = new JourneysController();
window.journeysController = journeysController;
