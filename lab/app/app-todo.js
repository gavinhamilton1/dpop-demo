/**
 * DPoP Lab - Student Implementation File
 * 
 * This file contains the main application logic for the DPoP lab.
 * Students should implement the TODO sections to complete the lab.
 */

class DPoPLab {
    constructor() {
        this.state = {
            hasSession: false,
            hasBIK: false,
            hasDPoP: false,
            hasPasskey: false,
            isLinked: false
        };
        
        this.currentLinkId = null;
        
        this.initializeEventListeners();
        this.log('[INFO] DPoP Lab initialized. Ready to implement security controls!');
    }

    initializeEventListeners() {
        // Step 1: Session & BIK
        document.getElementById('initBtn').addEventListener('click', () => this.initializeSession());
        document.getElementById('bikBtn').addEventListener('click', () => this.registerBIK());

        // Step 2: DPoP Binding
        document.getElementById('dpopBtn').addEventListener('click', () => this.bindDPoP());

        // Step 3: Testing
        document.getElementById('testBtn').addEventListener('click', () => this.testAPI());

        // Step 4: WebAuthn Passkey
        document.getElementById('regBtn').addEventListener('click', () => this.registerPasskey());
        document.getElementById('authBtn').addEventListener('click', () => this.authenticatePasskey());

        // Step 5: Cross-Device Linking
        document.getElementById('linkBtn').addEventListener('click', () => this.startLinking());
        document.getElementById('completeLinkBtn').addEventListener('click', () => this.completeLinkManually());
    }

    // ============================================================================
    // STEP 1: Browser Identity Key (BIK) Registration
    // ============================================================================

    async initializeSession() {
        this.setLoading('initBtn', 'Initializing...');
        
        try {
            this.log('[INFO] Starting session initialization...');
            
            // TODO: Step 1.1 - Call /session/init endpoint
            // Hint: Use DPoPLabUtils.APIUtils.post('/session/init', { browser_uuid: 'lab-browser-' + Date.now() })
            
            // TODO: Step 1.2 - Store CSRF token and reg_nonce in IndexedDB
            // Hint: Use DPoPLabUtils.StorageManager to store the response data
            
            // TODO: Step 1.3 - Update state and UI
            // Hint: Set this.state.hasSession = true and call this.updateState()
            
            this.setSuccess('initBtn', 'Session initialized!');
            this.log('[SUCCESS] Session initialized successfully');
            
        } catch (error) {
            this.setError('initBtn', 'Initialization failed');
            this.log('[ERROR] Session initialization failed:', error);
        }
    }

    async registerBIK() {
        this.setLoading('bikBtn', 'Registering BIK...');
        
        try {
            this.log('[INFO] Starting BIK registration...');
            
            // TODO: Step 1.4 - Generate EC key pair using Web Crypto API
            // Hint: Use DPoPLabUtils.CryptoUtils.generateKeyPair()
            
            // TODO: Step 1.5 - Store BIK keys in IndexedDB
            // Hint: Store both private key and public JWK
            
            // TODO: Step 1.6 - Get stored nonce from IndexedDB
            // Hint: Retrieve the reg_nonce that was stored during session initialization
            
            // TODO: Step 1.7 - Create BIK JWS with nonce and public key
            // Hint: Use DPoPLabUtils.DPoPUtils.createBIKJWS(nonce, privateKey, publicJwk)
            
            // TODO: Step 1.8 - Send BIK registration to server
            // Hint: Use DPoPLabUtils.APIUtils.post('/browser/register', jws, { 'X-CSRF-Token': csrfToken })
            
            // TODO: Step 1.9 - Update state and UI
            // Hint: Set this.state.hasBIK = true and call this.updateState()
            
            this.setSuccess('bikBtn', 'BIK registered!');
            this.log('[SUCCESS] BIK registered successfully');
            
        } catch (error) {
            this.setError('bikBtn', 'BIK registration failed');
            this.log('[ERROR] BIK registration failed:', error);
        }
    }

    // ============================================================================
    // STEP 2: DPoP Binding
    // ============================================================================

    async bindDPoP() {
        this.setLoading('dpopBtn', 'Binding DPoP...');
        
        try {
            this.log('[INFO] Starting DPoP binding...');
            
            // TODO: Step 2.1 - Generate DPoP key pair
            // Hint: Use DPoPLabUtils.CryptoUtils.generateKeyPair()
            
            // TODO: Step 2.2 - Store DPoP keys in IndexedDB
            // Hint: Store both private key and public JWK with key ID 'dpop_current'
            
            // TODO: Step 2.3 - Create DPoP proof JWT
            // Hint: Use DPoPLabUtils.DPoPUtils.createDPoPProof(url, method, nonce, privateKey, publicJwk)
            // Note: For initial binding, nonce is null
            
            // TODO: Step 2.4 - Send DPoP binding request to server
            // Hint: Use DPoPLabUtils.APIUtils.post('/dpop/bind', dpopJwt, { 'X-CSRF-Token': csrfToken })
            
            // TODO: Step 2.5 - Store binding token and nonce
            // Hint: Store the response.bind token and any DPoP-Nonce header
            
            // TODO: Step 2.6 - Update state and UI
            // Hint: Set this.state.hasDPoP = true and call this.updateState()
            
            this.setSuccess('dpopBtn', 'DPoP bound!');
            this.log('[SUCCESS] DPoP bound successfully');
            
        } catch (error) {
            this.setError('dpopBtn', 'DPoP binding failed');
            this.log('[ERROR] DPoP binding failed:', error);
        }
    }

    // ============================================================================
    // STEP 3: Testing
    // ============================================================================

    async testAPI() {
        this.setLoading('testBtn', 'Testing...');
        
        try {
            this.log('[INFO] Starting API test with DPoP...');
            
            // TODO: Step 3.1 - Get stored DPoP key and binding token
            // Hint: Retrieve DPoP keys and binding token from IndexedDB
            
            // TODO: Step 3.2 - Create DPoP proof for API request
            // Hint: Use DPoPLabUtils.DPoPUtils.createDPoPProof with the API endpoint URL
            
            // TODO: Step 3.3 - Send API request with DPoP proof
            // Hint: Use DPoPLabUtils.APIUtils.post with DPoP and DPoP-Bind headers
            
            this.setSuccess('testBtn', 'Test passed!');
            this.log('[SUCCESS] API test with DPoP successful');
            
        } catch (error) {
            this.setError('testBtn', 'Test failed');
            this.log('[ERROR] API test failed:', error);
        }
    }

    // ============================================================================
    // STEP 4: WebAuthn Passkey Support
    // ============================================================================

    async registerPasskey() {
        this.setLoading('regBtn', 'Registering passkey...');
        
        try {
            this.log('[INFO] Starting passkey registration...');
            
            // TODO: Step 4.1 - Check WebAuthn support
            // Hint: Use DPoPLabUtils.WebAuthnUtils.isSupported()
            
            // TODO: Step 4.2 - Get registration options from server
            // Hint: Use DPoPLabUtils.APIUtils.post('/webauthn/registration/options')
            
            // TODO: Step 4.3 - Create WebAuthn credentials
            // Hint: Use DPoPLabUtils.WebAuthnUtils.createCredentials(options)
            
            // TODO: Step 4.4 - Send attestation to server for verification
            // Hint: Convert credential to JSON and send to /webauthn/registration/verify
            
            // TODO: Step 4.5 - Update state and UI
            // Hint: Set this.state.hasPasskey = true and call this.updateState()
            
            this.setSuccess('regBtn', 'Passkey registered!');
            this.log('[SUCCESS] Passkey registered successfully');
            
        } catch (error) {
            this.setError('regBtn', 'Passkey registration failed');
            this.log('[ERROR] Passkey registration failed:', error);
        }
    }

    async authenticatePasskey() {
        this.setLoading('authBtn', 'Authenticating...');
        
        try {
            this.log('[INFO] Starting passkey authentication...');
            
            // TODO: Step 4.6 - Get authentication options from server
            // Hint: Use DPoPLabUtils.APIUtils.post('/webauthn/authentication/options')
            
            // TODO: Step 4.7 - Get WebAuthn assertion
            // Hint: Use DPoPLabUtils.WebAuthnUtils.getCredentials(options)
            
            // TODO: Step 4.8 - Send assertion to server for verification
            // Hint: Convert assertion to JSON and send to /webauthn/authentication/verify
            
            this.setSuccess('authBtn', 'Authenticated!');
            this.log('[SUCCESS] Passkey authentication successful');
            
        } catch (error) {
            this.setError('authBtn', 'Authentication failed');
            this.log('[ERROR] Passkey authentication failed:', error);
        }
    }

    // ============================================================================
    // STEP 5: Cross-Device Linking
    // ============================================================================

    async startLinking() {
        this.setLoading('linkBtn', 'Starting linking...');
        
        try {
            this.log('[INFO] Starting cross-device linking...');
            
            // TODO: Step 5.1 - Request link initiation from server
            // Hint: Use DPoPLabUtils.APIUtils.post('/link/start')
            
            // TODO: Step 5.2 - Generate QR code for mobile device
            // Hint: Use DPoPLabUtils.QRCodeUtils.generateQRCode(response.link_url, 'qrCode')
            
            // TODO: Step 5.3 - Show QR container and start polling
            // Hint: Display QR code and call this.pollForLinkCompletion(response.link_id)
            
        } catch (error) {
            this.setError('linkBtn', 'Linking failed');
            this.log('[ERROR] Cross-device linking failed:', error);
        }
    }

    async pollForLinkCompletion(linkId) {
        // TODO: Step 5.4 - Implement polling for link completion
        // Hint: Poll /link/status/{linkId} every 5 seconds until status is 'linked'
        // Use a maximum of 60 attempts (5 minutes) with setTimeout
    }

    async completeLinkManually() {
        // TODO: Step 5.5 - Implement manual link completion for testing
        // Hint: Call /link/complete/{linkId} with device information
    }

    // ============================================================================
    // Utility Methods (Provided - No changes needed)
    // ============================================================================

    updateState() {
        // Enable/disable buttons based on state
        document.getElementById('bikBtn').disabled = !this.state.hasSession;
        document.getElementById('dpopBtn').disabled = !this.state.hasBIK;
        document.getElementById('testBtn').disabled = !this.state.hasDPoP;
        document.getElementById('regBtn').disabled = !this.state.hasDPoP;
        document.getElementById('authBtn').disabled = !this.state.hasDPoP;
        document.getElementById('linkBtn').disabled = !this.state.hasDPoP;
        
        // Update status messages
        this.updateStatus('bikStatus', this.state.hasSession ? 'Ready to register BIK' : 'Complete session initialization first');
        this.updateStatus('dpopStatus', this.state.hasBIK ? 'Ready to bind DPoP' : 'Complete BIK registration first');
        this.updateStatus('testStatus', this.state.hasDPoP ? 'Ready to test API' : 'Complete DPoP binding first');
        this.updateStatus('passkeyStatus', this.state.hasDPoP ? 'Ready to register passkey' : 'Complete DPoP binding first');
        this.updateStatus('linkStatus', this.state.hasDPoP ? 'Ready to start linking' : 'Complete DPoP binding first');
    }

    setLoading(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = true;
        button.className = 'loading';
    }

    setSuccess(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = false;
        button.className = 'success';
    }

    setError(buttonId, text) {
        const button = document.getElementById(buttonId);
        button.textContent = text;
        button.disabled = false;
        button.className = 'error';
    }

    updateStatus(elementId, message) {
        const element = document.getElementById(elementId);
        element.textContent = message;
        element.className = 'status info';
    }

    log(message, data = null) {
        const logContainer = document.getElementById('logContainer');
        const timestamp = new Date().toLocaleTimeString();
        const logEntry = document.createElement('div');
        logEntry.textContent = `[${timestamp}] ${message}`;
        if (data) {
            logEntry.textContent += ` ${JSON.stringify(data)}`;
        }
        logContainer.appendChild(logEntry);
        logContainer.scrollTop = logContainer.scrollHeight;
        
        // Also log to console
        console.log(message, data);
    }
}

// Initialize the lab when the page loads
document.addEventListener('DOMContentLoaded', () => {
    new DPoPLab();
});
