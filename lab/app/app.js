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
            // 1. Call /session/init endpoint
            const response = await DPoPLabUtils.APIUtils.post('/session/init', {
                browser_uuid: 'lab-browser-' + Date.now()
            });
            
            // 2. Store CSRF token and reg_nonce
            const storage = new DPoPLabUtils.StorageManager();
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.CSRF, value: response.csrf });
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.REG_NONCE, value: response.reg_nonce });
            
            this.state.hasSession = true;
            this.updateState();
            this.setSuccess('initBtn', 'Session initialized!');
            this.log('[SUCCESS] Session initialized successfully', response);
            
        } catch (error) {
            this.setError('initBtn', 'Initialization failed');
            this.log('[ERROR] Session initialization failed:', error);
        }
    }

    async registerBIK() {
        this.setLoading('bikBtn', 'Registering BIK...');
        
        try {
            // 1. Generate EC key pair using Web Crypto API
            const keyPair = await DPoPLabUtils.CryptoUtils.generateKeyPair();
            
            // 2. Store private key in IndexedDB
            const storage = new DPoPLabUtils.StorageManager();
            await storage.put('keys', {
                id: DPoPLabUtils.STORAGE_KEYS.BIK_CURRENT,
                privateKey: keyPair.privateKey,
                publicJwk: await DPoPLabUtils.CryptoUtils.exportPublicKey(keyPair.publicKey)
            });
            
            // 3. Get stored nonce
            const nonceRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.REG_NONCE);
            const nonce = nonceRecord.value;
            
            // 4. Create JWS with public key
            const publicJwk = await DPoPLabUtils.CryptoUtils.exportPublicKey(keyPair.publicKey);
            const jws = await DPoPLabUtils.DPoPUtils.createBIKJWS(nonce, keyPair.privateKey, publicJwk);
            
            // 5. Send to /browser/register endpoint
            const csrfRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.CSRF);
            const response = await DPoPLabUtils.APIUtils.post('/browser/register', jws, {
                'X-CSRF-Token': csrfRecord.value
            });
            
            this.state.hasBIK = true;
            this.updateState();
            this.setSuccess('bikBtn', 'BIK registered!');
            this.log('[SUCCESS] BIK registered successfully', response);
            
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
            // 1. Generate DPoP key pair
            const dpopKeyPair = await DPoPLabUtils.CryptoUtils.generateKeyPair();
            
            // 2. Store DPoP keys
            const storage = new DPoPLabUtils.StorageManager();
            await storage.put('keys', {
                id: DPoPLabUtils.STORAGE_KEYS.DPoP_CURRENT,
                privateKey: dpopKeyPair.privateKey,
                publicJwk: await DPoPLabUtils.CryptoUtils.exportPublicKey(dpopKeyPair.publicKey)
            });
            
            // 3. Create DPoP JWT with required claims
            const publicJwk = await DPoPLabUtils.CryptoUtils.exportPublicKey(dpopKeyPair.publicKey);
            const dpopJwt = await DPoPLabUtils.DPoPUtils.createDPoPProof(
                'http://localhost:8000/dpop/bind',
                'POST',
                null, // no nonce for initial binding
                dpopKeyPair.privateKey,
                publicJwk
            );
            
            // 4. Send to /dpop/bind endpoint
            const csrfRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.CSRF);
            const response = await DPoPLabUtils.APIUtils.post('/dpop/bind', dpopJwt, {
                'X-CSRF-Token': csrfRecord.value
            });
            
            // 5. Store binding token and nonce
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.BIND_TOKEN, value: response.bind });
            if (response.headers && response.headers['DPoP-Nonce']) {
                await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.DPoP_NONCE, value: response.headers['DPoP-Nonce'] });
            }
            
            this.state.hasDPoP = true;
            this.updateState();
            this.setSuccess('dpopBtn', 'DPoP bound!');
            this.log('[SUCCESS] DPoP bound successfully', response);
            
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
            // 1. Check WebAuthn support
            if (!DPoPLabUtils.WebAuthnUtils.isSupported()) {
                throw new Error('WebAuthn not supported in this browser');
            }
            
            // 2. Get registration options from server
            const options = await DPoPLabUtils.APIUtils.post('/webauthn/registration/options');
            
            // 3. Create credentials with navigator.credentials.create()
            const credential = await DPoPLabUtils.WebAuthnUtils.createCredentials(options);
            
            // 4. Send attestation to server
            const attestation = DPoPLabUtils.WebAuthnUtils.credentialToJSON(credential);
            const response = await DPoPLabUtils.APIUtils.post('/webauthn/registration/verify', attestation);
            
            this.state.hasPasskey = true;
            this.updateState();
            this.setSuccess('regBtn', 'Passkey registered!');
            this.log('[SUCCESS] Passkey registered successfully', response);
            
        } catch (error) {
            this.setError('regBtn', 'Passkey registration failed');
            this.log('[ERROR] Passkey registration failed:', error);
        }
    }

    async authenticatePasskey() {
        this.setLoading('authBtn', 'Authenticating...');
        
        try {
            // 1. Get authentication options from server
            const options = await DPoPLabUtils.APIUtils.post('/webauthn/authentication/options');
            
            // 2. Get credentials with navigator.credentials.get()
            const assertion = await DPoPLabUtils.WebAuthnUtils.getCredentials(options);
            
            // 3. Send assertion to server
            const assertionData = DPoPLabUtils.WebAuthnUtils.credentialToJSON(assertion);
            const response = await DPoPLabUtils.APIUtils.post('/webauthn/authentication/verify', assertionData);
            
            this.setSuccess('authBtn', 'Authenticated!');
            this.log('[SUCCESS] Passkey authentication successful', response);
            
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
            // 1. Call /link/start endpoint
            const response = await DPoPLabUtils.APIUtils.post('/link/start');
            
            // 2. Generate QR code with linking URL
            await DPoPLabUtils.QRCodeUtils.generateQRCode(response.link_url, 'qrCode');
            
            // 3. Show QR container
            document.getElementById('qrContainer').style.display = 'block';
            
            // 4. Establish WebSocket connection (simplified for lab)
            // In a real implementation, you would establish a WebSocket connection
            // and handle real-time status updates
            
            // 5. Simulate linking completion after a delay
            setTimeout(async () => {
                try {
                    // Simulate mobile device completing the link
                    await DPoPLabUtils.APIUtils.post(`/link/complete/${response.link_id}`, {
                        device_type: 'mobile',
                        user_agent: navigator.userAgent,
                        timestamp: Date.now()
                    });
                    
                    this.state.isLinked = true;
                    this.updateState();
                    this.setSuccess('linkBtn', 'Device linked!');
                    this.log('[SUCCESS] Cross-device linking established');
                    
                    // Hide QR code
                    document.getElementById('qrContainer').style.display = 'none';
                    
                } catch (error) {
                    this.log('[ERROR] Linking completion failed:', error);
                }
            }, 3000); // Simulate 3-second linking process
            
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
            // 1. Get stored DPoP key and binding token
            const storage = new DPoPLabUtils.StorageManager();
            const dpopRecord = await storage.get('keys', DPoPLabUtils.STORAGE_KEYS.DPoP_CURRENT);
            const bindRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.BIND_TOKEN);
            const nonceRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.DPoP_NONCE);
            
            if (!dpopRecord || !bindRecord) {
                throw new Error('DPoP keys or binding token not found');
            }
            
            // 2. Create DPoP proof for API request
            const dpopProof = await DPoPLabUtils.DPoPUtils.createDPoPProof(
                'http://localhost:8000/api/test',
                'POST',
                nonceRecord?.value || null,
                dpopRecord.privateKey,
                dpopRecord.publicJwk
            );
            
            // 3. Send request to /api/test endpoint
            const response = await DPoPLabUtils.APIUtils.post('/api/test', {
                message: 'Hello from DPoP Lab!',
                timestamp: Date.now()
            }, {
                'DPoP': dpopProof,
                'DPoP-Bind': bindRecord.value
            });
            
            this.setSuccess('testBtn', 'Test passed!');
            this.log('[SUCCESS] API test with DPoP successful', response);
            
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
