/**
 * Journeys Page Controller
 * Provides user-friendly interfaces for different authentication flows
 */

import { Logger } from './components/Logger.js';
import * as DpopFun from './dpop-fun.js';
import * as Passkeys from './passkeys.js';
import { generateQRCode } from './utils/qr-generator.js';

class JourneysController {
    constructor() {
        this.logger = new Logger('logContainer');
        this.currentJourney = null;
        this.currentStep = 0;
        this.sessionState = {
            hasSession: false,
            hasBIK: false,
            hasDPoP: false,
            hasUsername: false,
            hasPasskey: false,
            hasFace: false
        };
        
        this.journeyDefinitions = {
            newUser: {
                title: 'New User Registration',
                description: 'Create a new account with username, passkey, face, and mobile device',
                steps: [
                    {
                        id: 'browserIdentity',
                        title: 'Register Browser Identity',
                        description: 'Create and bind your browser identity key (BIK) to this session',
                        action: () => this.registerBrowserIdentity()
                    },
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
                        id: 'browserIdentity',
                        title: 'Restore Browser Identity',
                        description: 'Restore your browser identity key (BIK)',
                        action: () => this.restoreBrowserIdentity()
                    },
                    {
                        id: 'username',
                        title: 'Enter Username',
                        description: 'Enter your username to continue',
                        action: () => this.enterUsername()
                    },
                    {
                        id: 'passkey',
                        title: 'Authenticate with Passkey',
                        description: 'Use your passkey to sign in',
                        action: () => this.authenticateWithPasskey()
                    }
                ]
            },
            faceLogin: {
                title: 'Face Recognition Login',
                description: 'Sign in using facial recognition',
                steps: [
                    {
                        id: 'browserIdentity',
                        title: 'Restore Browser Identity',
                        description: 'Restore your browser identity key (BIK)',
                        action: () => this.restoreBrowserIdentity()
                    },
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
                        id: 'browserIdentity',
                        title: 'Restore Browser Identity',
                        description: 'Restore your browser identity key (BIK)',
                        action: () => this.restoreBrowserIdentity()
                    },
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
    
    async getSessionStatus() {
        try {
            const response = await fetch('/session/status', {
                method: 'GET',
                credentials: 'include'
            });
            
            if (response.ok) {
                return await response.json();
            } else {
                return { valid: false, state: null, bik_registered: false, dpop_bound: false, ttl_seconds: 0 };
            }
        } catch (error) {
            this.logger.error('Failed to get session status:', error);
            return { valid: false, state: null, bik_registered: false, dpop_bound: false, ttl_seconds: 0 };
        }
    }
    
    async init() {
        try {
            this.logger.info('Initializing Journeys Controller...');
            this.setupEventListeners();
            await this.checkSessionStatus();
            this.updateJourneyAvailability();
            this.logger.info('Journeys Controller initialized successfully');
        } catch (error) {
            this.logger.error('Failed to initialize Journeys Controller:', error);
        }
    }
    
    setupEventListeners() {
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
        
        // Clear logs
        document.getElementById('clearLogsBtn').addEventListener('click', () => this.logger.clear());
    }
    
    async checkSessionStatus() {
        try {
            this.logger.info('Checking session status...');
            
            // Check if we have a valid session
            const sessionStatus = await this.getSessionStatus();
            this.logger.debug('Session status:', sessionStatus);
            
            if (sessionStatus && sessionStatus.valid) {
                this.sessionState.hasSession = true;
                this.updateSessionStatus('loading', 'Restoring Session...', 'Found existing session, restoring browser identity and DPoP binding');
                
                if (sessionStatus.bik_registered) {
                    this.sessionState.hasBIK = true;
                }
                
                if (sessionStatus.dpop_bound) {
                    this.sessionState.hasDPoP = true;
                    
                    // Restore session state for DPoP-bound sessions
                    try {
                        await DpopFun.restoreSessionTokens();
                        this.logger.info('Session tokens restored successfully');
                    } catch (error) {
                        this.logger.warn('Failed to restore session tokens:', error);
                    }
                }
                
                // Check for existing username
                try {
                    const userResponse = await fetch('/onboarding/current-user', {
                        credentials: 'include'
                    });
                    
                    if (userResponse.ok) {
                        const userData = await userResponse.json();
                        this.sessionState.hasUsername = true;
                        this.sessionState.username = userData.username;
                        this.logger.info('Found existing username:', userData.username);
                    }
                } catch (error) {
                    this.logger.debug('No existing username found');
                }
                
                // Check for existing passkeys
                try {
                    const passkeyResponse = await Passkeys.getAuthOptions();
                    if (passkeyResponse) {
                        this.sessionState.hasPasskey = true;
                    }
                } catch (error) {
                    this.logger.debug('No passkeys found');
                }
                
                // Update status based on what we found
                if (this.sessionState.hasDPoP && this.sessionState.hasUsername) {
                    this.updateSessionStatus('success', 'Session Restored', 'Browser identity, DPoP binding, and username restored');
                } else if (this.sessionState.hasDPoP) {
                    this.updateSessionStatus('success', 'Session Restored', 'Browser identity and DPoP binding restored');
                } else if (this.sessionState.hasBIK) {
                    this.updateSessionStatus('success', 'Session Restored', 'Browser identity restored, DPoP binding needed');
                } else {
                    this.updateSessionStatus('success', 'Session Restored', 'Basic session restored, browser identity needed');
                }
                
            } else {
                this.logger.info('No valid session found - creating new session');
                this.updateSessionStatus('loading', 'Creating New Session...', 'Initializing new browser identity and session');
                
                // Automatically create a new session
                await this.createNewSession();
            }
            
        } catch (error) {
            this.logger.error('Failed to check session status:', error);
            this.updateSessionStatus('error', 'Session Check Failed', error.message);
        }
    }
    
    async createNewSession() {
        try {
            // Initialize session
            await DpopFun.sessionInit();
            this.sessionState.hasSession = true;
            
            // Register browser identity
            await DpopFun.bikRegisterStep();
            this.sessionState.hasBIK = true;
            
            // Bind DPoP
            await DpopFun.dpopBindStep();
            this.sessionState.hasDPoP = true;
            
            this.updateSessionStatus('success', 'New Session Created', 'Browser identity registered and DPoP token bound successfully');
            this.logger.success('New session created successfully');
            
        } catch (error) {
            this.logger.error('Failed to create new session:', error);
            this.updateSessionStatus('error', 'Session Creation Failed', error.message);
            this.sessionState.hasSession = false;
            this.sessionState.hasBIK = false;
            this.sessionState.hasDPoP = false;
        }
    }
    
    updateSessionStatus(status, title, detail) {
        const indicator = document.getElementById('sessionStatusIndicator');
        indicator.className = `status-indicator ${status}`;
        
        const titleEl = indicator.querySelector('.status-title');
        const detailEl = indicator.querySelector('.status-detail');
        
        if (titleEl) titleEl.textContent = title;
        if (detailEl) detailEl.textContent = detail;
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
    
    async startJourney(journeyType) {
        try {
            this.logger.info(`Starting ${journeyType} journey...`);
            
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
            this.logger.error(`Failed to start ${journeyType} journey:`, error);
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
        if (this.currentStep >= this.currentJourney.steps.length) {
            await this.completeJourney();
            return;
        }
        
        const step = this.currentJourney.steps[this.currentStep];
        const stepEl = document.getElementById(`step-${step.id}`);
        
        this.logger.info(`Executing step: ${step.title}`);
        
        try {
            await step.action();
        } catch (error) {
            this.logger.error(`Step ${step.title} failed:`, error);
            this.showStepError(stepEl, error.message);
        }
    }
    
    async completeStep() {
        const stepEl = document.getElementById(`step-${this.currentJourney.steps[this.currentStep].id}`);
        stepEl.classList.remove('active');
        stepEl.classList.add('completed');
        
        this.currentStep++;
        
        if (this.currentStep < this.currentJourney.steps.length) {
            const nextStepEl = document.getElementById(`step-${this.currentJourney.steps[this.currentStep].id}`);
            nextStepEl.classList.add('active');
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
        
        this.logger.info('Journey cancelled');
    }
    
    async completeJourney() {
        this.logger.success('Journey completed successfully!');
        
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
            
            this.logger.info('Browser identity already registered');
            await this.completeStep();
            return;
        }
        
        contentEl.innerHTML = `
            <div class="step-status">
                <p>Registering browser identity and binding DPoP...</p>
            </div>
        `;
        
        try {
            // Initialize session and register BIK if not already done
            if (!this.sessionState.hasSession) {
                await DpopFun.sessionInit();
                this.sessionState.hasSession = true;
            }
            
            if (!this.sessionState.hasBIK) {
                await DpopFun.bikRegisterStep();
                this.sessionState.hasBIK = true;
            }
            
            if (!this.sessionState.hasDPoP) {
                await DpopFun.dpopBindStep();
                this.sessionState.hasDPoP = true;
            }
            
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Browser identity registered and DPoP bound successfully!</p>
                </div>
            `;
            
            this.logger.success('Browser identity registered successfully');
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
                    <button class="btn primary" id="submitUsernameBtn">Create Username</button>
                </div>
                <div id="stepUsernameError" class="error-message" style="display: none;"></div>
            </div>
        `;
        
        document.getElementById('submitUsernameBtn').addEventListener('click', async () => {
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
                    
                    this.logger.success(`Username "${username}" created successfully`);
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
    }
    
    async registerPasskey() {
        const stepEl = document.getElementById('step-passkey');
        const contentEl = stepEl.querySelector('.step-content');
        
        if (!this.checkPasskeySupport()) {
            contentEl.innerHTML = `
                <div class="step-status">
                    <p>Passkeys are not supported by this browser. Skipping this step.</p>
                </div>
            `;
            await this.completeStep();
            return;
        }
        
        contentEl.innerHTML = `
            <div class="step-status">
                <p>Registering passkey...</p>
                <p>Follow the prompts on your device to create a passkey.</p>
            </div>
            <div class="step-actions">
                <button class="btn primary" id="registerPasskeyBtn">Register Passkey</button>
                <button class="btn secondary" id="skipPasskeyBtn">Skip</button>
            </div>
        `;
        
        document.getElementById('registerPasskeyBtn').addEventListener('click', async () => {
            try {
                await Passkeys.registerPasskey();
                
                this.sessionState.hasPasskey = true;
                
                contentEl.innerHTML = `
                    <div class="step-status success">
                        <p>✓ Passkey registered successfully!</p>
                    </div>
                `;
                
                this.logger.success('Passkey registered successfully');
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
            this.logger.info('Starting face registration process...');
            
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
            
            this.logger.info('Face registration started');
            
            // Listen for completion by checking the status element periodically
            const checkCompletion = () => {
                const statusEl = document.getElementById('status');
                if (statusEl) {
                    const statusText = statusEl.textContent || statusEl.innerText;
                    if (statusText.includes('Face registered ✓') || statusText.includes('Face verified ✓')) {
                        this.sessionState.hasFace = true;
                        this.logger.success('Face registered successfully');
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
            this.logger.error('Failed to initialize face capture:', error);
            
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
        
        contentEl.innerHTML = `
            <div class="mobile-link-container">
                <div id="qrPhase">
                    <h3>Link Mobile Device</h3>
                    <p>Click the button below to generate a QR code for mobile device linking.</p>
                    <div class="step-actions" style="margin-top: 1rem;">
                        <button class="btn primary" id="startLinkBtn">Start Mobile Linking</button>
                        ${this.currentJourney.steps[this.currentStep].optional ? '<button class="btn secondary" id="skipMobileBtn">Skip</button>' : ''}
                    </div>
                    <div id="qrContainer" class="qr-container" style="display: none;">
                        <h3>Scan QR Code with Mobile Device</h3>
                        <div class="qr-code" id="qrcode"></div>
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
                                <div class="single-input hidden" id="singleInputContainer">
                                    <input type="text" id="singleInput" placeholder="Enter 8-character code (e.g., 8X2J-Q9K3)" maxlength="10" autocomplete="one-time-code">
                                </div>
                                <div class="verify-actions">
                                    <button class="btn btn-primary" type="submit">Verify & continue</button>
                                    <button class="btn btn-secondary" type="button" id="useCamBtn">Use camera instead</button>
                                    <button class="btn btn-secondary" type="button" id="toggleInputBtn">Single field</button>
                                </div>
                                <div class="verify-status" id="codeStatus">Code expires ~60s after it appears on your phone.</div>
                            </form>
                        </div>

                        <!-- Camera scan (jsQR) -->
                        <div class="verify-card hidden" id="camCard">
                            <h2 class="verify-card-title">Scan QR from your phone</h2>
                            <div class="camera-container">
                                <video id="video" class="verify-video" playsinline></video>
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
        
        // Handle start link button
        document.getElementById('startLinkBtn').addEventListener('click', async () => {
            await this.startMobileLinking();
        });
        
        // Handle skip button (only if it exists)
        const skipBtn = document.getElementById('skipMobileBtn');
        if (skipBtn) {
            skipBtn.addEventListener('click', () => {
                this.skipCurrentStep();
            });
        }
    }
    
    async startMobileLinking() {
        try {
            this.logger.info('Starting mobile linking process...');
            
            // Show QR code container
            document.getElementById('qrContainer').style.display = 'block';
            document.getElementById('qrStatus').textContent = 'Generating QR code...';
            
            // Disable start button
            const startBtn = document.getElementById('startLinkBtn');
            startBtn.disabled = true;
            startBtn.textContent = 'Creating QR...';
            
            // Use LinkingService like index.html does
            const { LinkingService } = await import('./services/LinkingService.js');
            const { DpopFunService } = await import('./services/DpopFunService.js');
            
            // Create DpopFunService instance like AppController does
            const dpopFunService = new DpopFunService();
            const linkingService = new LinkingService(dpopFunService);
            
            // Start linking using the same service as index.html
            const linkData = await linkingService.startLinking();
            
            this.logger.success('Cross-device linking started', linkData);
            
            // Display link information
            document.getElementById('linkId').textContent = linkData.linkId;
            document.getElementById('qrUrl').textContent = linkData.qr_url;
            
            // Generate QR code with AprilTag overlay (same as index.html)
            this.createQRCode(linkData.qr_url, linkData.linkId);
            
            // Start monitoring using the same SSE approach as index.html
            this.monitorLinkingStatusWithSSE(linkData.linkId, linkingService);
            
            // Update button to show success
            startBtn.textContent = 'QR created!';
            startBtn.classList.add('success');
            
        } catch (error) {
            this.logger.error('Failed to start mobile linking:', error);
            document.getElementById('qrStatus').textContent = `Error: ${error.message}`;
            
            // Re-enable start button on error
            const startBtn = document.getElementById('startLinkBtn');
            startBtn.disabled = false;
            startBtn.textContent = 'Start Mobile Linking';
            startBtn.classList.remove('success');
        }
    }
    
    createQRCode(qrData, linkId) {
        // Use shared QR generation utility
        generateQRCode('qrcode', qrData, linkId, (status) => {
            document.getElementById('qrStatus').textContent = status;
        });
    }
    
    /**
     * Monitor linking status using SSE (same as index.html)
     * @param {string} linkId - Link ID
     * @param {LinkingService} linkingService - Linking service instance
     */
    monitorLinkingStatusWithSSE(linkId, linkingService) {
        const onStatusUpdate = (status) => {
            // Handle different message types (same as index.html)
            if (status.type === 'status') {
                this.logger.info(`Linking status: ${status.status}`, status);
                
                if (status.status === 'scanned') {
                    this.updateQRStatus('scanned');
                    // Mobile device has scanned QR, show verification UI
                    this.showVerificationPhase(linkId);
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

        // Use SSE monitoring (same as index.html)
        linkingService.monitorStatus(linkId, onStatusUpdate, onError, 'sse');
    }

    /**
     * Handle linking completion (same as index.html)
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
            
            this.logger.success('Cross-device linking completed successfully');
            this.logger.info('Redirecting to verify page to enter BC code...');
            
            // Redirect to verify page to enter BC code (same as index.html)
            setTimeout(() => {
                window.location.href = '/verify';
            }, 1000);
            
        } catch (error) {
            this.logger.error('Linking completion failed:', error);
        }
    }

    /**
     * Handle linking failure (same as index.html)
     * @param {string} error - Error message
     */
    handleLinkingFailed(error) {
        this.updateQRStatus('failed');
        this.logger.error('Cross-device linking failed', error);
    }

    /**
     * Update QR status display (same as index.html)
     * @param {string} status - Status ('scanned', 'completed', 'failed')
     */
    updateQRStatus(status) {
        const statusElement = document.getElementById('qrStatus');
        if (!statusElement) return;
        
        switch (status) {
            case 'scanned':
                statusElement.textContent = 'QR code scanned! Enter verification code...';
                statusElement.className = 'qr-status qr-status-scanned';
                break;
            case 'completed':
                statusElement.textContent = 'Mobile device linked successfully!';
                statusElement.className = 'qr-status qr-status-completed';
                break;
            case 'failed':
                statusElement.textContent = 'Linking failed';
                statusElement.className = 'qr-status qr-status-failed';
                break;
            default:
                statusElement.textContent = 'Waiting for mobile scan...';
                statusElement.className = 'qr-status';
        }
    }
    
    showVerificationPhase(linkId) {
        // Hide QR phase and show verification phase
        document.getElementById('qrPhase').style.display = 'none';
        document.getElementById('verifyPhase').style.display = 'block';
        
        // Initialize verification UI (similar to verify.html)
        this.initializeVerificationUI(linkId);
    }
    
    initializeVerificationUI(linkId) {
        this.logger.info('Initializing verification UI for linkId:', linkId);
        
        // Initialize code input boxes
        this.initializeCodeInputs();
        
        // Set up form submission
        const codeForm = document.getElementById('codeForm');
        if (codeForm) {
            codeForm.addEventListener('submit', (e) => {
                e.preventDefault();
                this.handleCodeSubmission(linkId);
            });
        }
        
        // Set up camera toggle buttons
        const useCamBtn = document.getElementById('useCamBtn');
        const stopCamBtn = document.getElementById('stopCamBtn');
        const toggleInputBtn = document.getElementById('toggleInputBtn');
        
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
        
        if (toggleInputBtn) {
            toggleInputBtn.addEventListener('click', () => {
                this.toggleInputMode();
            });
        }
        
        this.logger.info('Verification UI initialized');
    }
    
    initializeCodeInputs() {
        const codeBoxesEl = document.getElementById('codeBoxes');
        if (!codeBoxesEl) return;
        
        // Clear existing inputs
        codeBoxesEl.innerHTML = '';
        
        // Create 8 individual input boxes (4-4 format)
        const groups = [4, 4];
        groups.forEach((len, gi) => {
            for (let i = 0; i < len; i++) {
                const inp = document.createElement('input');
                inp.inputMode = 'latin';
                inp.maxLength = 1;
                inp.autocomplete = 'one-time-code';
                inp.style.width = '3rem';
                inp.style.height = '3rem';
                inp.style.textAlign = 'center';
                inp.style.fontSize = '1.25rem';
                inp.style.fontWeight = '600';
                inp.style.border = '2px solid var(--border)';
                inp.style.borderRadius = 'var(--radius-lg)';
                inp.style.background = 'var(--background)';
                inp.style.color = 'var(--text)';
                inp.style.transition = 'border-color var(--transition-fast)';
                
                // Handle individual character input
                inp.addEventListener('input', (e) => {
                    e.target.value = this.normalizeCode(e.target.value).slice(0, 1);
                    if (e.target.value) {
                        // Find next input element
                        let nextEl = e.target.nextElementSibling;
                        while (nextEl && nextEl.tagName !== 'INPUT') {
                            nextEl = nextEl.nextElementSibling;
                        }
                        if (nextEl) nextEl.focus();
                    }
                });
                
                // Handle paste of full code
                inp.addEventListener('paste', (e) => {
                    e.preventDefault();
                    const pastedText = this.normalizeCode(e.clipboardData.getData('text'));
                    if (pastedText.length >= 8) {
                        const inputs = codeBoxesEl.querySelectorAll('input');
                        for (let j = 0; j < Math.min(pastedText.length, inputs.length); j++) {
                            inputs[j].value = pastedText[j];
                        }
                        // Focus the last input
                        if (inputs.length > 0) {
                            inputs[inputs.length - 1].focus();
                        }
                    }
                });
                
                codeBoxesEl.appendChild(inp);
                
                // Add spacer after 4th input
                if (i === 3 && gi === 0) {
                    const spacer = document.createElement('div');
                    spacer.textContent = '-';
                    spacer.style.fontSize = '1.5rem';
                    spacer.style.fontWeight = '600';
                    spacer.style.color = 'var(--text-secondary)';
                    spacer.style.margin = '0 0.5rem';
                    spacer.style.display = 'flex';
                    spacer.style.alignItems = 'center';
                    codeBoxesEl.appendChild(spacer);
                }
            }
        });
    }
    
    normalizeCode(str) {
        return str.replace(/[^A-Z0-9]/gi, '').toUpperCase();
    }
    
    async handleCodeSubmission(linkId) {
        const codeBoxesEl = document.getElementById('codeBoxes');
        const inputs = codeBoxesEl.querySelectorAll('input');
        const code = Array.from(inputs).map(inp => inp.value).join('');
        
        if (code.length !== 8) {
            this.updateCodeStatus('Please enter the complete 8-character code', 'err');
            return;
        }
        
        this.updateCodeStatus('Verifying code...', 'status');
        
        try {
            // First, redeem the bootstrap code
            const redeemResponse = await fetch('/device/redeem', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                credentials: 'include',
                body: JSON.stringify({ bc: code })
            });
            
            if (!redeemResponse.ok) {
                throw new Error(await redeemResponse.text() || 'Code rejected');
            }
            
            const { dpop_nonce, link_id } = await redeemResponse.json();
            this.logger.info('Bootstrap code redeemed successfully', { dpop_nonce, link_id });
            
            // Now finalize the link with DPoP proof
            await DpopFun.dpopFunFetch('/link/finalize', {
                method: 'POST',
                body: JSON.stringify({ dpop_nonce })
            });
            
            this.updateCodeStatus('Mobile device linked successfully!', 'status');
            this.sessionState.hasMobile = true;
            await this.completeStep();
        } catch (error) {
            this.logger.error('Code submission failed:', error);
            this.updateCodeStatus(`Verification failed: ${error.message}`, 'err');
        }
    }
    
    updateCodeStatus(message, type = '') {
        const statusEl = document.getElementById('codeStatus');
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.className = `verify-status ${type}`;
        }
    }
    
    switchToCamera() {
        document.getElementById('codeCard').classList.add('hidden');
        document.getElementById('camCard').classList.remove('hidden');
        this.startCameraScan();
    }
    
    switchToCodeInput() {
        document.getElementById('camCard').classList.add('hidden');
        document.getElementById('codeCard').classList.remove('hidden');
        this.stopCameraScan();
    }
    
    toggleInputMode() {
        const codeBoxes = document.getElementById('codeBoxes');
        const singleInputContainer = document.getElementById('singleInputContainer');
        const toggleBtn = document.getElementById('toggleInputBtn');
        
        if (codeBoxes.classList.contains('hidden')) {
            codeBoxes.classList.remove('hidden');
            singleInputContainer.classList.add('hidden');
            toggleBtn.textContent = 'Single field';
        } else {
            codeBoxes.classList.add('hidden');
            singleInputContainer.classList.remove('hidden');
            toggleBtn.textContent = 'Individual boxes';
        }
    }
    
    startCameraScan() {
        // TODO: Implement camera scanning with jsQR
        this.logger.info('Camera scanning not yet implemented');
        this.updateCamStatus('Camera scanning not yet implemented', 'err');
    }
    
    stopCameraScan() {
        // TODO: Stop camera scanning
        this.logger.info('Stopping camera scan');
    }
    
    updateCamStatus(message, type = '') {
        const statusEl = document.getElementById('camStatus');
        if (statusEl) {
            statusEl.textContent = message;
            statusEl.className = `verify-status status ${type}`;
        }
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
                this.logger.info('Session tokens restored successfully');
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
            
            this.logger.success('Browser identity restored successfully');
            await this.completeStep();
            
        } catch (error) {
            throw new Error(`Failed to restore browser identity: ${error.message}`);
        }
    }
    
    async enterUsername() {
        const stepEl = document.getElementById('step-username');
        const contentEl = stepEl.querySelector('.step-content');
        
        if (this.sessionState.hasUsername) {
            contentEl.innerHTML = `
                <div class="step-status success">
                    <p>✓ Username "${this.sessionState.username}" found!</p>
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
                    
                    this.logger.success(`Username "${username}" verified`);
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
            
            this.logger.success('Passkey authentication successful');
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
            this.logger.info('Starting face authentication process...');
            
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
            
            this.logger.info('Face verification started');
            
            // Listen for completion by checking the status element periodically
            const checkCompletion = () => {
                const statusEl = document.getElementById('status');
                if (statusEl) {
                    const statusText = statusEl.textContent || statusEl.innerText;
                    if (statusText.includes('Face verified ✓') || statusText.includes('Face registered ✓')) {
                        this.logger.success('Face authentication successful');
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
            this.logger.error('Failed to initialize face capture:', error);
            
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
        
        this.logger.info('Mobile passkey authentication initiated');
    }
    
    async skipCurrentStep() {
        const step = this.currentJourney.steps[this.currentStep];
        if (step.optional) {
            this.logger.info(`Skipping optional step: ${step.title}`);
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
                hasFace: false
            };
            
            // Reset UI
            this.cancelJourney();
            await this.checkSessionStatus();
            this.updateJourneyAvailability();
            
            this.logger.info('Logged out successfully');
            
        } catch (error) {
            this.logger.error('Logout failed:', error);
        }
    }
}

// Initialize the journeys controller
const journeysController = new JourneysController();
window.journeysController = journeysController;
