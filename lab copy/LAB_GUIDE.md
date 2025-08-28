# DPoP Lab Implementation Guide

This guide provides step-by-step instructions for implementing each component of the DPoP security system.

## 🎯 Overview

You will implement a complete browser identity and security system with:
- Browser Identity Key (BIK) registration
- DPoP (Demonstration of Proof-of-Possession) binding
- WebAuthn passkey support
- Cross-device linking

## 📋 Prerequisites

- Lab application running on http://localhost:8000
- Modern browser with WebAuthn support
- Basic JavaScript knowledge
- Understanding of cryptographic concepts

## 🚀 Step-by-Step Implementation

### Step 1: Browser Identity Key (BIK) Registration

**Objective**: Generate a non-exportable cryptographic key pair to establish browser identity.

**Implementation in `app.js`**:

Replace the `initializeSession()` method:

```javascript
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
```

Replace the `registerBIK()` method:

```javascript
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
```

**Key Concepts**:
- Non-exportable keys prevent key theft
- Key thumbprint provides unique identification
- JWS proves possession of private key
- Nonce prevents replay attacks

### Step 2: DPoP Binding

**Objective**: Create a DPoP proof that cryptographically binds browser identity to session tokens.

**Implementation**:

Replace the `bindDPoP()` method:

```javascript
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
```

**Key Concepts**:
- DPoP tokens are JWTs with specific claims
- `jti` (JWT ID) must be unique per request
- `htm` (HTTP method) and `htu` (HTTP URI) prevent replay
- `iat` (issued at) prevents timing attacks

### Step 3: WebAuthn Passkey Support

**Objective**: Add passwordless authentication using device biometrics or security keys.

**Implementation**:

Replace the `registerPasskey()` method:

```javascript
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
```

Replace the `authenticatePasskey()` method:

```javascript
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
```

**Key Concepts**:
- WebAuthn uses public key cryptography
- User verification (biometric, PIN, etc.)
- Attestation for key authenticity
- Cross-platform compatibility

### Step 4: Cross-Device Linking

**Objective**: Enable secure communication between devices for VDI and step-up authentication.

**Implementation**:

Replace the `startLinking()` method:

```javascript
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
```

**Key Concepts**:
- QR codes for easy device pairing
- WebSocket for real-time communication
- Cryptographic verification of device identity
- Secure data sharing between devices

### Step 5: API Testing

**Objective**: Test the complete implementation with DPoP-protected API calls.

**Implementation**:

Replace the `testAPI()` method:

```javascript
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
```

**Key Concepts**:
- DPoP proof must be included in API requests
- Binding token proves session ownership
- Nonce prevents replay attacks
- Server verifies DPoP before processing request

## 🧪 Testing Your Implementation

After implementing each step:

1. **Click each button in sequence**
2. **Check the log for success messages**
3. **Verify button states change to green**
4. **Test the complete flow end-to-end**

## 🔍 Debugging Tips

- **Check browser console** for JavaScript errors
- **Inspect IndexedDB** in Developer Tools → Application → Storage
- **Monitor network requests** in Developer Tools → Network
- **Verify cryptographic operations** are working correctly
- **Check WebAuthn support** in your browser

## 🎯 Success Criteria

You've successfully completed the lab when:

- ✅ All buttons show green checkmarks
- ✅ Log shows successful completion of each step
- ✅ API test returns successful response
- ✅ Cross-device linking establishes connection
- ✅ You understand the security benefits of each component

## 🚀 Next Steps

After completing the lab:

1. **Explore advanced DPoP features** (nonce challenges, token refresh)
2. **Implement additional security controls** (rate limiting, audit logging)
3. **Integrate with enterprise systems** (OAuth 2.0, SAML)
4. **Apply concepts to your own applications**

## 📚 Additional Resources

- [DPoP RFC 9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [WebAuthn Specification](https://www.w3.org/TR/webauthn/)
- [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
- [JWT RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)

Congratulations on completing the DPoP Lab! 🎉
