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
            
            // Step 1.1 - Call /session/init endpoint
            this.log('[INFO] Calling /session/init endpoint...');
            const response = await DPoPLabUtils.APIUtils.post('/session/init', {
                browser_uuid: 'lab-browser-' + Date.now()
            });
            this.log('[INFO] Server response received', { 
                csrf_length: response.csrf?.length || 0,
                nonce_length: response.reg_nonce?.length || 0,
                state: response.state 
            });
            
            // Step 1.2 - Store CSRF token and reg_nonce
            this.log('[INFO] Storing session data in IndexedDB...');
            const storage = new DPoPLabUtils.StorageManager();
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.CSRF, value: response.csrf });
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.REG_NONCE, value: response.reg_nonce });
            this.log('[INFO] Session data stored successfully');
            
            // Step 1.3 - Update state and UI
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
            this.log('[INFO] Starting BIK registration...');
            
            // Step 1.4 - Generate EC key pair using Web Crypto API
            this.log('[INFO] Generating EC key pair using Web Crypto API...');
            const keyPair = await DPoPLabUtils.CryptoUtils.generateKeyPair();
            this.log('[INFO] Key pair generated successfully');
            
            // Step 1.5 - Store BIK keys in IndexedDB
            this.log('[INFO] Storing BIK keys in IndexedDB...');
            const storage = new DPoPLabUtils.StorageManager();
            const publicJwk = await DPoPLabUtils.CryptoUtils.exportPublicKey(keyPair.publicKey);
            await storage.put('keys', {
                id: DPoPLabUtils.STORAGE_KEYS.BIK_CURRENT,
                privateKey: keyPair.privateKey,
                publicJwk: publicJwk
            });
            this.log('[INFO] BIK keys stored successfully');
            
            // Step 1.6 - Get stored nonce
            this.log('[INFO] Retrieving registration nonce from storage...');
            const nonceRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.REG_NONCE);
            const nonce = nonceRecord.value;
            this.log('[INFO] Nonce retrieved', { nonce_length: nonce?.length || 0 });
            
            // Step 1.7 - Create BIK JWS with nonce and public key
            this.log('[INFO] Creating BIK JWS with nonce and public key...');
            const jws = await DPoPLabUtils.DPoPUtils.createBIKJWS(nonce, keyPair.privateKey, publicJwk);
            this.log('[INFO] BIK JWS created successfully');
            
            // Step 1.8 - Send to /browser/register endpoint
            this.log('[INFO] Sending BIK registration to server...');
            const csrfRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.CSRF);
            const response = await DPoPLabUtils.APIUtils.post('/browser/register', jws, {
                'X-CSRF-Token': csrfRecord.value
            });
            this.log('[INFO] Server verified BIK registration', { bik_jkt: response.bik_jkt });
            
            // Step 1.9 - Update state and UI
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
            this.log('[INFO] Starting DPoP binding...');
            
            // Step 2.1 - Generate DPoP key pair
            this.log('[INFO] Generating DPoP key pair...');
            const dpopKeyPair = await DPoPLabUtils.CryptoUtils.generateKeyPair();
            this.log('[INFO] DPoP key pair generated successfully');
            
            // Step 2.2 - Store DPoP keys
            this.log('[INFO] Storing DPoP keys in IndexedDB...');
            const storage = new DPoPLabUtils.StorageManager();
            const publicJwk = await DPoPLabUtils.CryptoUtils.exportPublicKey(dpopKeyPair.publicKey);
            await storage.put('keys', {
                id: DPoPLabUtils.STORAGE_KEYS.DPoP_CURRENT,
                privateKey: dpopKeyPair.privateKey,
                publicJwk: publicJwk
            });
            this.log('[INFO] DPoP keys stored successfully');
            
            // Step 2.3 - Create DPoP JWT with required claims
            this.log('[INFO] Creating DPoP proof JWT...');
            const dpopJwt = await DPoPLabUtils.DPoPUtils.createDPoPProof(
                'http://localhost:8000/dpop/bind',
                'POST',
                null, // no nonce for initial binding
                dpopKeyPair.privateKey,
                publicJwk
            );
            this.log('[INFO] DPoP proof JWT created successfully');
            
            // Step 2.4 - Send to /dpop/bind endpoint
            this.log('[INFO] Sending DPoP binding request to server...');
            const csrfRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.CSRF);
            const response = await DPoPLabUtils.APIUtils.post('/dpop/bind', dpopJwt, {
                'X-CSRF-Token': csrfRecord.value
            });
            this.log('[INFO] Server verified DPoP binding', { 
                bind_token_length: response.bind?.length || 0,
                has_nonce: !!(response.headers && response.headers['DPoP-Nonce'])
            });
            
            // Step 2.5 - Store binding token and nonce
            this.log('[INFO] Storing DPoP binding data...');
            await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.BIND_TOKEN, value: response.bind });
            if (response.headers && response.headers['DPoP-Nonce']) {
                await storage.put('meta', { id: DPoPLabUtils.STORAGE_KEYS.DPoP_NONCE, value: response.headers['DPoP-Nonce'] });
                this.log('[INFO] DPoP nonce stored for future requests');
            }
            this.log('[INFO] DPoP binding data stored successfully');
            
            // Step 2.6 - Update state and UI
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
    // STEP 3: Testing
    // ============================================================================

    async testAPI() {
        this.setLoading('testBtn', 'Testing...');
        
        try {
            this.log('[INFO] Starting API test with DPoP...');
            
            // Step 3.1 - Get stored DPoP key and binding token
            this.log('[INFO] Retrieving DPoP keys and binding token from storage...');
            const storage = new DPoPLabUtils.StorageManager();
            const dpopRecord = await storage.get('keys', DPoPLabUtils.STORAGE_KEYS.DPoP_CURRENT);
            const bindRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.BIND_TOKEN);
            const nonceRecord = await storage.get('meta', DPoPLabUtils.STORAGE_KEYS.DPoP_NONCE);
            
            if (!dpopRecord || !bindRecord) {
                throw new Error('DPoP keys or binding token not found');
            }
            this.log('[INFO] DPoP credentials retrieved successfully');
            
            // Step 3.2 - Create DPoP proof for API request
            this.log('[INFO] Creating DPoP proof for API request...');
            const dpopProof = await DPoPLabUtils.DPoPUtils.createDPoPProof(
                'http://localhost:8000/api/test',
                'POST',
                nonceRecord?.value || null,
                dpopRecord.privateKey,
                dpopRecord.publicJwk
            );
            this.log('[INFO] DPoP proof created successfully');
            
            // Step 3.3 - Send request to /api/test endpoint
            this.log('[INFO] Sending API request with DPoP proof...');
            const response = await DPoPLabUtils.APIUtils.post('/api/test', {
                message: 'Hello from DPoP Lab!',
                timestamp: Date.now()
            }, {
                'DPoP': dpopProof,
                'DPoP-Bind': bindRecord.value
            });
            this.log('[INFO] Server verified DPoP proof and processed request', { 
                status: response.status || 'success',
                message: response.message 
            });
            
            this.setSuccess('testBtn', 'Test passed!');
            this.log('[SUCCESS] API test with DPoP successful', response);
            
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
            
            // Step 4.1 - Check WebAuthn support
            this.log('[INFO] Checking WebAuthn support...');
            if (!DPoPLabUtils.WebAuthnUtils.isSupported()) {
                throw new Error('WebAuthn not supported in this browser');
            }
            this.log('[INFO] WebAuthn is supported');
            
            // Step 4.2 - Get registration options from server
            this.log('[INFO] Requesting registration options from server...');
            const options = await DPoPLabUtils.APIUtils.post('/webauthn/registration/options');
            this.log('[INFO] Registration options received', { 
                challenge_length: options.challenge?.length || 0,
                rp_id: options.rpId,
                user_verification: options.userVerification 
            });
            
            // Step 4.3 - Create credentials with navigator.credentials.create()
            this.log('[INFO] Creating WebAuthn credentials...');
            const credential = await DPoPLabUtils.WebAuthnUtils.createCredentials(options);
            this.log('[INFO] WebAuthn credentials created successfully');
            
            // Step 4.4 - Send attestation to server
            this.log('[INFO] Sending attestation to server for verification...');
            const attestation = DPoPLabUtils.WebAuthnUtils.credentialToJSON(credential);
            const response = await DPoPLabUtils.APIUtils.post('/webauthn/registration/verify', attestation);
            this.log('[INFO] Server verified attestation', { credential_id: response.credential_id });
            
            // Step 4.5 - Update state and UI
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
            this.log('[INFO] Starting passkey authentication...');
            
            // Step 4.6 - Get authentication options from server
            this.log('[INFO] Requesting authentication options from server...');
            const options = await DPoPLabUtils.APIUtils.post('/webauthn/authentication/options');
            this.log('[INFO] Authentication options received', { 
                challenge_length: options.challenge?.length || 0,
                rp_id: options.rpId,
                allow_credentials_count: options.allowCredentials?.length || 0 
            });
            
            // Step 4.7 - Get credentials with navigator.credentials.get()
            this.log('[INFO] Getting WebAuthn assertion...');
            const assertion = await DPoPLabUtils.WebAuthnUtils.getCredentials(options);
            this.log('[INFO] WebAuthn assertion received successfully');
            
            // Step 4.8 - Send assertion to server
            this.log('[INFO] Sending assertion to server for verification...');
            const assertionData = DPoPLabUtils.WebAuthnUtils.credentialToJSON(assertion);
            const response = await DPoPLabUtils.APIUtils.post('/webauthn/authentication/verify', assertionData);
            this.log('[INFO] Server verified assertion', { user_id: response.user_id });
            
            this.setSuccess('authBtn', 'Authenticated!');
            this.log('[SUCCESS] Passkey authentication successful', response);
            
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
            
            // Step 5.1 - Call /link/start endpoint
            this.log('[INFO] Requesting link initiation from server...');
            const response = await DPoPLabUtils.APIUtils.post('/link/start');
            this.log('[INFO] Link initiated', { 
                link_id: response.link_id,
                link_url_length: response.link_url?.length || 0 
            });
            
            // Step 5.2 - Generate QR code with linking URL
            this.log('[INFO] Generating QR code for mobile device...');
            await DPoPLabUtils.QRCodeUtils.generateQRCode(response.link_url, 'qrCode');
            this.log('[INFO] QR code generated successfully');
            
            // Step 5.3 - Show QR container and manual completion button
            document.getElementById('qrContainer').style.display = 'block';
            document.getElementById('completeLinkBtn').style.display = 'inline-block';
            document.getElementById('completeLinkBtn').disabled = false;
            this.log('[INFO] QR code displayed for mobile scanning');
            
            // Step 5.4 - Start polling for link completion
            this.log('[INFO] Starting to poll for link completion...');
            this.currentLinkId = response.link_id; // Store for manual completion
            this.pollForLinkCompletion(response.link_id);
            
        } catch (error) {
            this.setError('linkBtn', 'Linking failed');
            this.log('[ERROR] Cross-device linking failed:', error);
        }
    }

    async pollForLinkCompletion(linkId) {
        const maxAttempts = 60; // 5 minutes max (60 * 5 seconds)
        let attempts = 0;
        
        const poll = async () => {
            try {
                attempts++;
                this.log(`[INFO] Checking link status (attempt ${attempts}/${maxAttempts})...`);
                
                const response = await DPoPLabUtils.APIUtils.get(`/link/status/${linkId}`);
                
                if (response.status === 'linked') {
                    this.log('[INFO] Link completed by mobile device!');
                    this.state.isLinked = true;
                    this.updateState();
                    this.setSuccess('linkBtn', 'Device linked!');
                    this.log('[SUCCESS] Cross-device linking established', response);
                    
                    // Hide QR code and manual completion button
                    document.getElementById('qrContainer').style.display = 'none';
                    document.getElementById('completeLinkBtn').style.display = 'none';
                    this.log('[INFO] QR code and manual completion button hidden after successful linking');
                    return;
                }
                
                if (attempts >= maxAttempts) {
                    this.log('[WARN] Link polling timed out after 5 minutes');
                    this.setError('linkBtn', 'Linking timed out');
                    document.getElementById('qrContainer').style.display = 'none';
                    document.getElementById('completeLinkBtn').style.display = 'none';
                    return;
                }
                
                // Continue polling every 5 seconds
                setTimeout(poll, 5000);
                
            } catch (error) {
                this.log('[ERROR] Link status check failed:', error);
                if (attempts >= maxAttempts) {
                    this.setError('linkBtn', 'Linking failed');
                    document.getElementById('qrContainer').style.display = 'none';
                    document.getElementById('completeLinkBtn').style.display = 'none';
                } else {
                    // Retry after 5 seconds
                    setTimeout(poll, 5000);
                }
            }
        };
        
        // Start polling
        poll();
    }

    async completeLinkManually() {
        if (!this.currentLinkId) {
            this.log('[ERROR] No active link to complete');
            return;
        }
    
        this.setLoading('completeLinkBtn', 'Completing...');
        
        try {
            this.log('[INFO] Manually completing link...');
            
            // Step 5.5 - Simulate mobile device completing the link
            const response = await DPoPLabUtils.APIUtils.post(`/link/complete/${this.currentLinkId}`, {
                device_type: 'mobile',
                user_agent: navigator.userAgent,
                timestamp: Date.now()
            });
            
            this.log('[INFO] Manual link completion successful', response);
            
            // The polling function will detect the completion and update the UI
            // But we can also update immediately for better UX
            this.state.isLinked = true;
            this.updateState();
            this.setSuccess('linkBtn', 'Device linked!');
            this.setSuccess('completeLinkBtn', 'Completed!');
            
            // Hide QR code and manual completion button
            document.getElementById('qrContainer').style.display = 'none';
            document.getElementById('completeLinkBtn').style.display = 'none';
            
            this.log('[SUCCESS] Manual link completion successful');
            
        } catch (error) {
            this.setError('completeLinkBtn', 'Completion failed');
            this.log('[ERROR] Manual link completion failed:', error);
        }
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
