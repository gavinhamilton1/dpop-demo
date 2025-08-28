// DPoP Lab - Main Application
// Participants will implement each step to build a complete DPoP security system

class DPoPLab {
    constructor() {
        this.state = {
            hasSession: false,
            hasBIK: false,
            hasDPoP: false,
            hasPasskey: false,
            isLinked: false
        };
        
        this.init();
    }

    init() {
        this.setupEventListeners();
        this.log('[INFO] DPoP Lab initialized. Ready to implement security controls!');
    }

    setupEventListeners() {
        // Step 1: BIK Registration
        document.getElementById('initBtn').addEventListener('click', () => this.initializeSession());
        document.getElementById('bikBtn').addEventListener('click', () => this.registerBIK());

        // Step 2: DPoP Binding
        document.getElementById('dpopBtn').addEventListener('click', () => this.bindDPoP());

        // Step 3: WebAuthn Passkey
        document.getElementById('regBtn').addEventListener('click', () => this.registerPasskey());
        document.getElementById('authBtn').addEventListener('click', () => this.authenticatePasskey());

        // Step 4: Cross-Device Linking
        document.getElementById('linkBtn').addEventListener('click', () => this.startLinking());

        // Testing
        document.getElementById('testBtn').addEventListener('click', () => this.testAPI());
    }

    // ============================================================================
    // STEP 1: Browser Identity Key (BIK) Registration
    // ============================================================================

    async initializeSession() {
        this.setLoading('initBtn', 'Initializing...');
        
        try {
            // TODO: Implement session initialization
            // 1. Call /session/init endpoint
            // 2. Store CSRF token and reg_nonce
            // 3. Update state
            
            this.log('[INFO] Session initialization - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.state.hasSession = true;
            this.updateState();
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
            // TODO: Implement BIK registration
            // 1. Generate EC key pair using Web Crypto API
            // 2. Store private key in IndexedDB
            // 3. Create JWS with public key
            // 4. Send to /browser/register endpoint
            // 5. Update state
            
            this.log('[INFO] BIK registration - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.state.hasBIK = true;
            this.updateState();
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
            // TODO: Implement DPoP binding
            // 1. Generate DPoP key pair
            // 2. Create DPoP JWT with required claims
            // 3. Send to /dpop/bind endpoint
            // 4. Store binding token
            // 5. Update state
            
            this.log('[INFO] DPoP binding - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.state.hasDPoP = true;
            this.updateState();
            this.setSuccess('dpopBtn', 'DPoP bound!');
            this.log('[SUCCESS] DPoP bound successfully');
            
        } catch (error) {
            this.setError('dpopBtn', 'DPoP binding failed');
            this.log('[ERROR] DPoP binding failed:', error);
        }
    }

    // ============================================================================
    // STEP 3: WebAuthn Passkey Support
    // ============================================================================

    async registerPasskey() {
        this.setLoading('regBtn', 'Registering passkey...');
        
        try {
            // TODO: Implement passkey registration
            // 1. Check WebAuthn support
            // 2. Get registration options from server
            // 3. Create credentials with navigator.credentials.create()
            // 4. Send attestation to server
            // 5. Update state
            
            this.log('[INFO] Passkey registration - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.state.hasPasskey = true;
            this.updateState();
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
            // TODO: Implement passkey authentication
            // 1. Get authentication options from server
            // 2. Get credentials with navigator.credentials.get()
            // 3. Send assertion to server
            // 4. Verify authentication result
            
            this.log('[INFO] Passkey authentication - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.setSuccess('authBtn', 'Authenticated!');
            this.log('[SUCCESS] Passkey authentication successful');
            
        } catch (error) {
            this.setError('authBtn', 'Authentication failed');
            this.log('[ERROR] Passkey authentication failed:', error);
        }
    }

    // ============================================================================
    // STEP 4: Cross-Device Linking
    // ============================================================================

    async startLinking() {
        this.setLoading('linkBtn', 'Starting linking...');
        
        try {
            // TODO: Implement cross-device linking
            // 1. Call /link/start endpoint
            // 2. Generate QR code with linking URL
            // 3. Establish WebSocket connection
            // 4. Handle linking status updates
            // 5. Update state when linked
            
            this.log('[INFO] Cross-device linking - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.state.isLinked = true;
            this.updateState();
            this.setSuccess('linkBtn', 'Device linked!');
            this.log('[SUCCESS] Cross-device linking established');
            
        } catch (error) {
            this.setError('linkBtn', 'Linking failed');
            this.log('[ERROR] Cross-device linking failed:', error);
        }
    }

    // ============================================================================
    // Testing
    // ============================================================================

    async testAPI() {
        this.setLoading('testBtn', 'Testing...');
        
        try {
            // TODO: Implement API testing with DPoP
            // 1. Create DPoP proof for API request
            // 2. Send request to /api/test endpoint
            // 3. Verify response
            // 4. Display results
            
            this.log('[INFO] API testing with DPoP - TODO: Implement');
            
            // Placeholder implementation
            await new Promise(resolve => setTimeout(resolve, 1000));
            
            this.setSuccess('testBtn', 'Test passed!');
            this.log('[SUCCESS] API test with DPoP successful');
            
        } catch (error) {
            this.setError('testBtn', 'Test failed');
            this.log('[ERROR] API test failed:', error);
        }
    }

    // ============================================================================
    // Utility Methods
    // ============================================================================

    updateState() {
        // Enable/disable buttons based on state
        document.getElementById('bikBtn').disabled = !this.state.hasSession;
        document.getElementById('dpopBtn').disabled = !this.state.hasBIK;
        document.getElementById('regBtn').disabled = !this.state.hasDPoP;
        document.getElementById('authBtn').disabled = !this.state.hasDPoP;
        document.getElementById('linkBtn').disabled = !this.state.hasPasskey;
        document.getElementById('testBtn').disabled = !this.state.isLinked;
        
        // Update status messages
        this.updateStatus('bikStatus', this.state.hasSession ? 'Ready to register BIK' : 'Complete session initialization first');
        this.updateStatus('dpopStatus', this.state.hasBIK ? 'Ready to bind DPoP' : 'Complete BIK registration first');
        this.updateStatus('passkeyStatus', this.state.hasDPoP ? 'Ready to register passkey' : 'Complete DPoP binding first');
        this.updateStatus('linkStatus', this.state.hasPasskey ? 'Ready to start linking' : 'Complete passkey registration first');
        this.updateStatus('testStatus', this.state.isLinked ? 'Ready to test API' : 'Complete all steps first');
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
