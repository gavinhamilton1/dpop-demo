/**
 * Stronghold Crypto Utilities
 * Implements browser-only Stronghold-style session creation flow
 */


// In-memory storage for private key handles (least secure, but simple)
const privateKeyHandleStore = new Map();

// IndexedDB for persistent key storage
let db = null;

// Session state
let currentSession = null;
let sessionEncryptionKey = null;

// Initialize IndexedDB
async function initIndexedDB() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open('StrongholdKeys', 1);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            db = request.result;
            resolve(db);
        };
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            if (!db.objectStoreNames.contains('keys')) {
                const store = db.createObjectStore('keys', { keyPath: 'id' });
            }
        };
    });
}

// Store key in IndexedDB
async function storeKeyInIndexedDB(keyId, keyData) {
    if (!db) await initIndexedDB();
    
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['keys'], 'readwrite');
        const store = transaction.objectStore('keys');
        
        // Convert CryptoKey objects to exportable format
        const exportableKeyData = {
            id: keyId,
            type: keyData.type || 'dpop',
            timestamp: Date.now()
        };
        
        // For now, we'll store the key in memory and just track the ID in IndexedDB
        // In a real implementation, you'd want to store the actual key material
        const request = store.put(exportableKeyData);
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}

// Load keys from IndexedDB into memory
async function loadKeysFromIndexedDB() {
    if (!db) await initIndexedDB();
    
    return new Promise((resolve, reject) => {
        const transaction = db.transaction(['keys'], 'readonly');
        const store = transaction.objectStore('keys');
        const request = store.getAll();
        
        request.onsuccess = () => {
            console.log('Loaded key IDs from IndexedDB:', request.result);
            resolve(request.result);
        };
        request.onerror = () => reject(request.error);
    });
}


/**
 * Generate a persistent, non-exportable browser identity key
 * @returns {Promise<{publicKey: string, keyId: string}>}
 */
async function generateBrowserIdentityKey() {
    try {
        console.log('generateBrowserIdentityKey: Starting...');
        
        // Get or generate persistent browser UUID and fingerprint
        let browserUuid = localStorage.getItem('stronghold_browser_uuid');
        let browserFingerprint = localStorage.getItem('stronghold_browser_fingerprint');
        
        if (!browserUuid || !browserFingerprint) {
            browserUuid = crypto.randomUUID();
            const fingerprint = await generateBrowserFingerprint();
            browserFingerprint = JSON.stringify(fingerprint);
            
            localStorage.setItem('stronghold_browser_uuid', browserUuid);
            localStorage.setItem('stronghold_browser_fingerprint', browserFingerprint);
            console.log('generateBrowserIdentityKey: Generated new persistent browser identity:', { browserUuid, fingerprint: fingerprint.hash });
        } else {
            const fingerprint = JSON.parse(browserFingerprint);
            console.log('generateBrowserIdentityKey: Using existing persistent browser identity:', { browserUuid, fingerprint: fingerprint.hash });
        }
        
        // Check if we already have a browser identity key in memory
        console.log('generateBrowserIdentityKey: Checking for existing key in memory...');
        console.log('generateBrowserIdentityKey: All keys in store:', Array.from(privateKeyHandleStore.keys()));
        const existingKeyId = Array.from(privateKeyHandleStore.keys()).find(keyId => keyId.startsWith('browser_identity_'));
        console.log('generateBrowserIdentityKey: Found existing key ID:', existingKeyId);
        
        if (existingKeyId) {
            // Return existing identity key from memory
            console.log('generateBrowserIdentityKey: Using existing key from memory...');
            const storedData = privateKeyHandleStore.get(existingKeyId);
            
            // The stored data should contain the actual CryptoKey objects
            if (storedData && storedData.publicKey) {
                // Export the public key
                const publicKey = await exportPublicKey(storedData.publicKey);
                
                return {
                    publicKey: publicKey,
                    keyId: existingKeyId,
                    browserUuid: browserUuid
                };
            } else {
                console.log('generateBrowserIdentityKey: Stored data missing publicKey, generating new key...');
                // Remove the corrupted data and continue to generate new key
                privateKeyHandleStore.delete(existingKeyId);
            }
        }
        
        // Generate new browser identity key
        console.log('generateBrowserIdentityKey: Generating new key...');
        const keyId = `browser_identity_${crypto.randomUUID()}`;
        console.log('generateBrowserIdentityKey: New key ID:', keyId);
        
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["sign", "verify"]
        );
        console.log('generateBrowserIdentityKey: Key pair generated');

        // Export the public key (this is allowed)
        console.log('generateBrowserIdentityKey: Exporting public key...');
        const publicKey = await exportPublicKey(keyPair.publicKey);
        console.log('Generated new browser identity public key:', publicKey);

        // Store the private key handle and metadata in memory (ephemeral)
        console.log('generateBrowserIdentityKey: Storing key in memory...');
        privateKeyHandleStore.set(keyId, {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey  // Store the actual CryptoKey object, not the exported string
        });
        console.log('generateBrowserIdentityKey: Key stored in memory successfully');
        
        return {
            publicKey: publicKey,
            keyId: keyId,
            browserUuid: browserUuid
        };
    } catch (error) {
        console.error('Error generating browser identity key:', error);
        throw new Error('Failed to generate browser identity key: ' + error.message);
    }
}

/**
 * Generate an ephemeral DPoP key pair
 * @returns {Promise<{publicKey: string, keyId: string}>}
 */
async function generateDPoPKeyPair() {
    try {
        const keyId = `dpop_${crypto.randomUUID()}`;
        
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["sign", "verify"]
        );

        // Store both private and public key handles in memory (ephemeral)
        privateKeyHandleStore.set(keyId, {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey
        });

        // Export the public key
        const publicKey = await exportPublicKey(keyPair.publicKey);
        
        return {
            publicKey: publicKey,
            keyId: keyId
        };
    } catch (error) {
        console.error('Error generating DPoP key pair:', error);
        throw new Error('Failed to generate DPoP key pair: ' + error.message);
    }
}

/**
 * Generate an ephemeral ECDHE key pair for forward secrecy
 * @returns {Promise<{publicKey: string, keyId: string}>}
 */
async function generateECDHEKeyPair() {
    try {
        const keyId = `ecdhe_${crypto.randomUUID()}`;
        
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["deriveKey", "deriveBits"]
        );

        // Store the private key handle in memory (ephemeral)
        privateKeyHandleStore.set(keyId, keyPair.privateKey);

        // Export the public key
        const publicKey = await exportPublicKey(keyPair.publicKey);
        
        return {
            publicKey: publicKey,
            keyId: keyId
        };
    } catch (error) {
        console.error('Error generating ECDHE key pair:', error);
        throw new Error('Failed to generate ECDHE key pair: ' + error.message);
    }
}

/**
 * Perform ECDHE handshake with server
 * @param {string} clientECDHEKeyId 
 * @param {string} serverECDHEPublicKey 
 * @returns {Promise<CryptoKey>} Session encryption key
 */
async function performECDHEHandshake(clientECDHEKeyId, serverECDHEPublicKey) {
    try {
        // Get client's ECDHE private key
        const clientPrivateKey = privateKeyHandleStore.get(clientECDHEKeyId);
        if (!clientPrivateKey) {
            throw new Error('Client ECDHE private key not found');
        }

        // Import server's ECDHE public key
        const serverPublicKeyBuffer = base64ToArrayBuffer(serverECDHEPublicKey);
        const serverPublicKey = await window.crypto.subtle.importKey(
            "spki",
            serverPublicKeyBuffer,
            {
                name: "ECDH",
                namedCurve: "P-256"
            },
            false,
            []
        );

        // Derive shared secret
        const sharedSecret = await window.crypto.subtle.deriveBits(
            {
                name: "ECDH",
                public: serverPublicKey
            },
            clientPrivateKey,
            256
        );

        console.log('Shared secret:', arrayBufferToBase64(sharedSecret));

        // Import shared secret as a raw key for HKDF
        const sharedSecretKey = await window.crypto.subtle.importKey(
            "raw",
            sharedSecret,
            {
                name: "HKDF"
            },
            false,
            ["deriveKey"]
        );

        // Derive session encryption key using HKDF (matching server implementation)
        const sessionEncryptionKey = await window.crypto.subtle.deriveKey(
            {
                name: "HKDF",
                salt: new TextEncoder().encode("stronghold-handshake"),
                info: new TextEncoder().encode("session-encryption-key"),
                hash: "SHA-256"
            },
            sharedSecretKey,
            {
                name: "AES-GCM",
                length: 256
            },
            false,
            ["encrypt", "decrypt"]
        );
        return sessionEncryptionKey;
    } catch (error) {
        console.error('Error performing ECDHE handshake:', error);
        throw new Error('ECDHE handshake failed: ' + error.message);
    }
}

/**
 * Encrypt data with session encryption key
 * @param {CryptoKey} sessionKey 
 * @param {string} data 
 * @returns {Promise<string>} Encrypted data as base64
 */
async function encryptWithSessionKey(sessionKey, data) {
    try {
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const encodedData = new TextEncoder().encode(data);
        
        const encryptedData = await window.crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            encodedData
        );

        // Combine IV and encrypted data
        const combined = new Uint8Array(iv.length + encryptedData.byteLength);
        combined.set(iv);
        combined.set(new Uint8Array(encryptedData), iv.length);
        
        return arrayBufferToBase64(combined.buffer);
    } catch (error) {
        console.error('Error encrypting with session key:', error);
        throw new Error('Encryption failed: ' + error.message);
    }
}

/**
 * Decrypt data with session encryption key
 * @param {CryptoKey} sessionKey 
 * @param {string} encryptedData 
 * @returns {Promise<string>} Decrypted data
 */
async function decryptWithSessionKey(sessionKey, encryptedData) {
    try {
        const combined = base64ToArrayBuffer(encryptedData);
        const iv = combined.slice(0, 12);
        const ciphertext = combined.slice(12);
        
        const decryptedData = await window.crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            sessionKey,
            ciphertext
        );

        return new TextDecoder().decode(decryptedData);
    } catch (error) {
        console.error('Error decrypting with session key:', error);
        throw new Error('Decryption failed: ' + error.message);
    }
}

/**
 * Create DPoP proof JWT
 * @param {string} dpopKeyId 
 * @param {string} method 
 * @param {string} url 
 * @param {string} accessToken 
 * @param {string} nonce 
 * @returns {Promise<string>} DPoP proof JWT
 */
async function createDPoPProof(dpopKeyId, method, url, accessToken, nonce = null) {
    try {
        console.log('createDPoPProof called with:', { dpopKeyId, method, url, nonce });
        
        const privateKeyData = privateKeyHandleStore.get(dpopKeyId);
        console.log('Private key data found:', !!privateKeyData);
        console.log('Private key data type:', typeof privateKeyData);
        
        if (!privateKeyData) {
            throw new Error('DPoP private key not found');
        }
        
        // Handle different storage formats
        let privateKey;
        if (privateKeyData.privateKey) {
            // New format with metadata
            privateKey = privateKeyData.privateKey;
        } else {
            // Old format - direct key
            privateKey = privateKeyData;
        }

        // Create DPoP proof payload
        const currentTime = Math.floor(Date.now() / 1000);
        const dateNow = Date.now();
        const dateNowSeconds = Math.floor(dateNow / 1000);
        console.log('Creating DPoP proof with current time:', currentTime, 'UTC');
        console.log('Date.now():', dateNow, 'milliseconds');
        console.log('Date.now() / 1000:', dateNowSeconds, 'seconds');
        console.log('Current Date object:', new Date().toISOString());
        
        const tokenHash = await sha256(accessToken);
        console.log('Access token:', accessToken);
        console.log('Calculated token hash:', tokenHash);
        
        const payload = {
            jti: crypto.randomUUID(),
            iat: currentTime,
            ath: tokenHash,
            htm: method,
            htu: url
        };
        
        // Add nonce if provided
        if (nonce) {
            payload.nonce = nonce;
        }

        // Get the DPoP key data
        const keyData = privateKeyHandleStore.get(dpopKeyId);
        let dpopPrivateKey, dpopPublicKey;
        if (keyData && keyData.privateKey && keyData.publicKey) {
            // New format with both keys
            dpopPrivateKey = keyData.privateKey;
            dpopPublicKey = keyData.publicKey;
        } else if (keyData) {
            // Old format - direct key (private key only)
            dpopPrivateKey = keyData;
            throw new Error('DPoP public key not available in old format');
        } else {
            throw new Error('DPoP key not found');
        }
        
        // Export public key as JWK
        const exportedPublicKey = await window.crypto.subtle.exportKey("spki", dpopPublicKey);
        const publicKeyArray = new Uint8Array(exportedPublicKey);
        
        // Create JWT header with JWK
        const header = {
            typ: "dpop+jwt",
            alg: "ES256",
            jwk: {
                kty: "EC",
                crv: "P-256",
                x: arrayBufferToBase64(publicKeyArray.slice(27, 59)).replace(/=/g, ''),
                y: arrayBufferToBase64(publicKeyArray.slice(59, 91)).replace(/=/g, '')
            }
        };

        // Encode header and payload
        const encodedHeader = btoa(JSON.stringify(header)).replace(/=/g, '');
        const encodedPayload = btoa(JSON.stringify(payload)).replace(/=/g, '');
        
        // Create signature input
        const signatureInput = `${encodedHeader}.${encodedPayload}`;
        const signatureInputBuffer = new TextEncoder().encode(signatureInput);
        
        console.log('Signature input:', signatureInput);
        console.log('Signature input length:', signatureInputBuffer.length, 'bytes');
        
        // Sign
        const signature = await window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" }
            },
            dpopPrivateKey,
            signatureInputBuffer
        );

        console.log('Raw signature length:', signature.byteLength, 'bytes');
        console.log('Raw signature (hex):', Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join(''));

        // Encode signature
        const encodedSignature = btoa(String.fromCharCode(...new Uint8Array(signature))).replace(/=/g, '');
        
        return `${encodedHeader}.${encodedPayload}.${encodedSignature}`;
    } catch (error) {
        console.error('Error creating DPoP proof:', error);
        throw new Error('DPoP proof creation failed: ' + error.message);
    }
}

/**
 * Check for existing session by browser UUID
 * @param {string} browserUuid 
 * @returns {Promise<{hasSession: boolean, sessionData?: any}>}
 */
async function checkExistingSession(browserUuid) {
    try {
        console.log('Checking for existing session with browser UUID:', browserUuid);
        
        const response = await fetch(`/check-session/${browserUuid}`);
        if (!response.ok) {
            throw new Error('Session check failed: ' + response.statusText);
        }
        
        const data = await response.json();
        console.log('Session check result:', data);
        
        return {
            hasSession: data.has_session,
            sessionData: data.has_session ? data : null
        };
    } catch (error) {
        console.error('Error checking existing session:', error);
        return { hasSession: false };
    }
}

/**
 * Complete Stronghold session creation flow
 * @returns {Promise<{sessionId: string, sessionToken: string}>}
 */
async function createStrongholdSession() {
    try {
        console.log('Starting Stronghold session creation...');
        
        // Step 1: Generate persistent browser identity key
        console.log('1. Generating browser identity key...');
        let browserIdentity;
        try {
            browserIdentity = await generateBrowserIdentityKey();
            console.log('Browser identity result:', browserIdentity);
        } catch (error) {
            console.error('Error generating browser identity key:', error);
            throw error;
        }
        
        // Step 1.5: Check for existing session
        console.log('1.5. Checking for existing session...');
        const existingSession = await checkExistingSession(browserIdentity.browserUuid);
        
        if (existingSession.hasSession) {
            console.log('Found existing session:', existingSession.sessionData);
            // In a real implementation, you would recover the session here
            // For now, we'll continue with creating a new session but show the mapping
            console.log('Session mapping found - Browser UUID:', existingSession.sessionData.browser_uuid, 'Session ID:', existingSession.sessionData.session_id);
        }
        
        // Step 2: Generate ephemeral DPoP key pair
        console.log('2. Generating DPoP key pair...');
        const dpopKey = await generateDPoPKeyPair();
        
        // Step 3: Generate ephemeral ECDHE key pair
        console.log('3. Generating ECDHE key pair...');
        const ecdheKey = await generateECDHEKeyPair();
        
        // Step 4: Perform ECDHE handshake with server
        console.log('4. Performing ECDHE handshake...');
        const handshakeResponse = await fetch('/handshake', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_ecdhe_public_key: ecdheKey.publicKey
            })
        });
        if (!handshakeResponse.ok) {
            throw new Error('Handshake failed: ' + handshakeResponse.statusText);
        }
        
        const handshakeData = await handshakeResponse.json();
        
        // Step 5: Derive session encryption key
        console.log('5. Deriving session encryption key...');
        sessionEncryptionKey = await performECDHEHandshake(ecdheKey.keyId, handshakeData.server_ecdhe_public_key);
        
        // Step 6: Prepare registration payload
        console.log('6. Preparing registration payload...');
        const browserIdentityData = Stronghold.getBrowserIdentity();
        // Get or generate browser UUID
        const storedBrowserUuid = loadBrowserUuidFromStorage();
        const browserUuid = storedBrowserUuid || crypto.randomUUID();
        
        // Save browser UUID to localStorage if it's new
        if (!storedBrowserUuid) {
            saveBrowserUuidToStorage(browserUuid);
        }
        
        const registrationPayload = {
            handshake_nonce: handshakeData.handshake_nonce,
            browser_identity_public_key: browserIdentity.publicKey,
            dpop_public_key: dpopKey.publicKey,
            browser_uuid: browserUuid,
            browser_fingerprint_hash: browserIdentityData.fingerprintHash
        };
        
        // Step 7: Encrypt payload with session key
        console.log('7. Encrypting registration payload...');
        const encryptedPayload = await encryptWithSessionKey(sessionEncryptionKey, JSON.stringify(registrationPayload));
        
        // Step 8: Register session with server
        console.log('8. Registering session with server...');
        const requestBody = {
            handshake_nonce: handshakeData.handshake_nonce,
            browser_identity_public_key: browserIdentity.publicKey,
            dpop_public_key: dpopKey.publicKey,
            browser_uuid: registrationPayload.browser_uuid,
            browser_fingerprint_hash: registrationPayload.browser_fingerprint_hash,
            encrypted_payload: encryptedPayload
        };
        console.log('Registration request body:', requestBody);
        
        const registrationResponse = await fetch('/register-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(requestBody)
        });
        
        if (!registrationResponse.ok) {
            const errorText = await registrationResponse.text();
            console.error('Registration response error:', errorText);
            throw new Error('Session registration failed: ' + registrationResponse.statusText + ' - ' + errorText);
        }
        
        const registrationData = await registrationResponse.json();
        
        // Note: Session mapping would be stored in HTTP-only cookie in production
        if (registrationData.session_mapping) {
            console.log('Session mapping (would be in HTTP-only cookie):', registrationData.session_mapping);
        }
        
        // Step 9: Decrypt session token
        console.log('9. Decrypting session token...');
        console.log('Encrypted session token:', registrationData.encrypted_session_token.substring(0, 100) + '...');
        const sessionToken = await decryptWithSessionKey(sessionEncryptionKey, registrationData.encrypted_session_token);
        console.log('Decrypted session token:', sessionToken.substring(0, 100) + '...');
        
        // Store session information in memory only
        currentSession = {
            sessionId: registrationData.session_id,
            sessionToken: sessionToken,
            browserIdentityKeyId: browserIdentity.keyId,
            dpopKeyId: dpopKey.keyId,
            browserUuid: registrationPayload.browser_uuid,
            dpopNonce: registrationData.initial_dpop_nonce
        };
        
        console.log('Stronghold session created successfully!');
        return {
            sessionId: registrationData.session_id,
            sessionToken: sessionToken
        };
        
    } catch (error) {
        console.error('Stronghold session creation failed:', error);
        throw error;
    }
}

/**
 * Make authenticated request with DPoP proof
 * @param {string} method 
 * @param {string} url 
 * @param {any} payload 
 * @returns {Promise<any>}
 */
async function makeAuthenticatedRequest(method, url, payload = null) {
    try {
        console.log('makeAuthenticatedRequest called with:', { method, url, payload });
        console.log('Current session:', currentSession);
        
        if (!currentSession) {
            throw new Error('No active session');
        }
        
        // Get stored nonce for this session (if any)
        const storedNonce = currentSession.dpopNonce || null;
        console.log('Current session nonce:', storedNonce);
        
        // Create DPoP proof
        console.log('Creating DPoP proof with:', {
            keyId: currentSession.dpopKeyId,
            method: method,
            url: url,
            nonce: storedNonce
        });
        
        const dpopProof = await createDPoPProof(
            currentSession.dpopKeyId,
            method,
            url,
            currentSession.sessionToken,
            storedNonce
        );
        
        console.log('DPoP proof created:', dpopProof.substring(0, 100) + '...');
        
        // Prepare request
        const requestOptions = {
            method: method,
            headers: {
                'Authorization': `DPoP ${currentSession.sessionToken}`,
                'DPoP': dpopProof,
                'Content-Type': 'application/json'
            }
        };
        
        // Get current browser fingerprint hash
        const browserIdentityData = Stronghold.getBrowserIdentity();
        
        // Add encrypted payload if provided
        let encryptedPayload = null;
        if (payload) {
            encryptedPayload = await encryptWithSessionKey(sessionEncryptionKey, JSON.stringify(payload));
            requestOptions.body = JSON.stringify({
                encrypted_payload: encryptedPayload,
                browser_fingerprint_hash: browserIdentityData.fingerprintHash
            });
        } else {
            requestOptions.body = JSON.stringify({
                browser_fingerprint_hash: browserIdentityData.fingerprintHash
            });
        }
        
        // Add DPoP nonce to headers if available
        if (storedNonce) {
            requestOptions.headers['DPoP-Nonce'] = storedNonce;
        }
        
        console.log('Authenticated request body:', requestOptions.body);
        
        // Make request
        const response = await fetch(url, requestOptions);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('Server response error:', errorText);
            throw new Error('Authenticated request failed: ' + response.statusText + ' - ' + errorText);
        }
        
        const responseData = await response.json();
        
        // Store new nonce if provided in response headers
        // In a real implementation, this would come from response.headers.get('DPoP-Nonce')
        if (responseData._dpop_nonce_header) {
            console.log('Updating session nonce from:', currentSession.dpopNonce, 'to:', responseData._dpop_nonce_header);
            currentSession.dpopNonce = responseData._dpop_nonce_header;
        }
        
        // Add the encrypted payload that was sent to the response for display purposes
        if (encryptedPayload) {
            responseData.encrypted_payload_sent = encryptedPayload;
            responseData.plaintext_payload_sent = JSON.stringify(payload, null, 2);
            
            // Decrypt the received payload locally for display
            if (responseData.encrypted_payload_received) {
                try {
                    const decryptedPayload = await decryptWithSessionKey(sessionEncryptionKey, responseData.encrypted_payload_received);
                    responseData.decrypted_payload = decryptedPayload;
                } catch (error) {
                    console.error('Error decrypting received payload:', error);
                    responseData.decrypted_payload = 'Error decrypting payload';
                }
            }
        }
        
        return responseData;
        
    } catch (error) {
        console.error('Authenticated request failed:', error);
        throw error;
    }
}

/**
 * Sign data using a stored private key handle
 * @param {string} keyId - The key ID to use for signing
 * @param {string} data - The data to sign
 * @returns {Promise<string>} The signature as a base64 string
 */
async function signData(keyId, data) {
    try {
        let privateKeyHandle;
        
        // Check if it's a browser identity key (stored in memory)
        if (keyId.startsWith('browser_identity_')) {
            const storedData = privateKeyHandleStore.get(keyId);
            if (!storedData || !storedData.privateKey) {
                throw new Error(`Private key handle not found for keyId: ${keyId}`);
            }
            privateKeyHandle = storedData.privateKey;
        } else {
            // Check if it's an ephemeral key (stored in memory)
            privateKeyHandle = privateKeyHandleStore.get(keyId);
            if (!privateKeyHandle) {
                throw new Error(`Private key handle not found for keyId: ${keyId}`);
            }
        }

        // Convert data to ArrayBuffer
        const dataBuffer = new TextEncoder().encode(data);

        // Sign the data using the private key handle
        const signatureBuffer = await window.crypto.subtle.sign(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" }
            },
            privateKeyHandle,
            dataBuffer
        );

        // Convert signature to base64
        return arrayBufferToBase64(signatureBuffer);
    } catch (error) {
        console.error('Error signing data:', error);
        throw new Error('Failed to sign data: ' + error.message);
    }
}

// Browser fingerprinting functions
async function generateBrowserFingerprint() {
    const fingerprint = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages,
        platform: navigator.platform,
        cookieEnabled: navigator.cookieEnabled,
        doNotTrack: navigator.doNotTrack,
        hardwareConcurrency: navigator.hardwareConcurrency,
        maxTouchPoints: navigator.maxTouchPoints,
        vendor: navigator.vendor,
        screen: {
            width: screen.width,
            height: screen.height,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight
        },
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset(),
        canvas: generateCanvasFingerprint(),
        webgl: generateWebGLFingerprint(),
        fonts: generateFontFingerprint(),
        plugins: generatePluginFingerprint()
    };
    
    // Create a hash of the fingerprint for consistent identification (without timestamp)
    const fingerprintForHash = { ...fingerprint };
    const hash = await generateFingerprintHash(fingerprintForHash);
    
    // Add timestamp to the full fingerprint for display purposes only
    const fullFingerprint = {
        ...fingerprint,
        timestamp: Date.now()
    };
    
    return {
        full: fullFingerprint,
        hash: hash
    };
}

function generateCanvasFingerprint() {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillText('Browser fingerprint test', 2, 2);
    return canvas.toDataURL();
}

function generateWebGLFingerprint() {
    const canvas = document.createElement('canvas');
    const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
    if (!gl) return null;
    
    return {
        vendor: gl.getParameter(gl.VENDOR),
        renderer: gl.getParameter(gl.RENDERER),
        version: gl.getParameter(gl.VERSION)
    };
}

function generateFontFingerprint() {
    const testString = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const testSize = '72px';
    const fonts = ['Arial', 'Verdana', 'Times New Roman', 'Courier New', 'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS', 'Trebuchet MS', 'Arial Black', 'Impact'];
    
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    ctx.font = testSize + ' Arial';
    const baseWidth = ctx.measureText(testString).width;
    
    const fontWidths = {};
    fonts.forEach(font => {
        ctx.font = testSize + ' ' + font;
        fontWidths[font] = ctx.measureText(testString).width;
    });
    
    return fontWidths;
}

function generatePluginFingerprint() {
    const plugins = [];
    for (let i = 0; i < navigator.plugins.length; i++) {
        const plugin = navigator.plugins[i];
        plugins.push({
            name: plugin.name,
            description: plugin.description,
            filename: plugin.filename
        });
    }
    return plugins;
}

async function generateFingerprintHash(fingerprint) {
    const fingerprintString = JSON.stringify(fingerprint);
    const encoder = new TextEncoder();
    const data = encoder.encode(fingerprintString);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Helper functions
async function exportPublicKey(publicKey) {
    const exported = await window.crypto.subtle.exportKey("spki", publicKey);
    return arrayBufferToBase64(exported);
}

async function sha256(data) {
    const hash = await window.crypto.subtle.digest("SHA-256", new TextEncoder().encode(data));
    return arrayBufferToBase64(hash).replace(/=/g, ''); // Remove padding to match server
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

// Browser identity management functions
function getBrowserIdentity() {
    const browserUuid = localStorage.getItem('stronghold_browser_uuid');
    const browserFingerprint = localStorage.getItem('stronghold_browser_fingerprint');
    
    if (!browserUuid || !browserFingerprint) {
        return null;
    }
    
    try {
        const fingerprint = JSON.parse(browserFingerprint);
        return {
            browserUuid: browserUuid,
            fingerprint: fingerprint,
            fingerprintHash: fingerprint.hash,
            createdAt: fingerprint.full.timestamp
        };
    } catch (error) {
        console.error('Error parsing browser fingerprint:', error);
        return null;
    }
}

function clearBrowserIdentity() {
    localStorage.removeItem('stronghold_browser_uuid');
    localStorage.removeItem('stronghold_browser_fingerprint');
    
    // Also clear any in-memory browser identity keys
    const browserIdentityKeys = Array.from(privateKeyHandleStore.keys()).filter(keyId => keyId.startsWith('browser_identity_'));
    browserIdentityKeys.forEach(keyId => privateKeyHandleStore.delete(keyId));
    
    console.log('Browser identity cleared');
}

function getSessionMapping() {
    // Session mapping would be retrieved from HTTP-only cookie in production
    // For demo purposes, return null since we're not storing it in localStorage
    return null;
}

function saveBrowserUuidToStorage(browserUuid) {
    try {
        localStorage.setItem('stronghold_browser_uuid', browserUuid);
        console.log('Browser UUID saved to localStorage');
    } catch (error) {
        console.error('Error saving browser UUID to localStorage:', error);
    }
}

function loadBrowserUuidFromStorage() {
    try {
        const browserUuid = localStorage.getItem('stronghold_browser_uuid');
        if (browserUuid) {
            console.log('Browser UUID loaded from localStorage');
            return browserUuid;
        }
    } catch (error) {
        console.error('Error loading browser UUID from localStorage:', error);
        localStorage.removeItem('stronghold_browser_uuid');
    }
    return null;
}

function clearBrowserUuidFromStorage() {
    try {
        localStorage.removeItem('stronghold_browser_uuid');
        console.log('Browser UUID cleared from localStorage');
    } catch (error) {
        console.error('Error clearing browser UUID from localStorage:', error);
    }
}

function getSecurityAudit() {
    const audit = {
        sessionExists: !!currentSession,
        browserIdentityExists: !!getBrowserIdentity(),
        sessionMappingExists: !!getSessionMapping(),
        sessionTokenValid: false,
        securityFeatures: {
            ecdhe: true,
            dpop: true,
            sessionBinding: true,
            rateLimiting: true,
            sessionInvalidation: true,
            secureJWT: true,
            browserFingerprinting: true,
            dpopNonce: true,
            temporalValidation: true
        }
    };
    
    if (currentSession && currentSession.sessionToken) {
        try {
            // Basic JWT validation (client-side)
            const parts = currentSession.sessionToken.split('.');
            if (parts.length === 3) {
                const payload = JSON.parse(atob(parts[1] + '='.repeat((4 - parts[1].length % 4) % 4)));
                audit.sessionTokenValid = payload.exp > Date.now() / 1000;
            }
        } catch (e) {
            audit.sessionTokenValid = false;
        }
    }
    
    return audit;
}

// Initialize session on page load
async function initializeSession() {
    const storedBrowserUuid = loadBrowserUuidFromStorage();
    console.log('Stored browser UUID:', storedBrowserUuid);
    if (storedBrowserUuid) {
        console.log('Browser UUID found in storage, checking for existing session...');
        
        try {
            const sessionCheckResponse = await fetch(`/check-session/${storedBrowserUuid}`);
            console.log('Session check response status:', sessionCheckResponse.status);
            if (sessionCheckResponse.ok) {
                const sessionData = await sessionCheckResponse.json();
                console.log('Session check response data:', sessionData);
                if (sessionData.has_session) {
                    console.log('Existing session found, renegotiating ECDHE handshake...');
                    
                    try {
                        // Step 1: Generate new browser identity key
                        console.log('1. Generating new browser identity key...');
                        const browserIdentityKeyPair = await window.crypto.subtle.generateKey(
                            {
                                name: "ECDSA",
                                namedCurve: "P-256"
                            },
                            false,
                            ["sign", "verify"]
                        );
                        
                        const browserIdentityKeyId = `browser_identity_${crypto.randomUUID()}`;
                        privateKeyHandleStore.set(browserIdentityKeyId, {
                            privateKey: browserIdentityKeyPair.privateKey,
                            publicKey: browserIdentityKeyPair.publicKey
                        });
                        
                        // Step 2: Generate new DPoP key pair
                        console.log('2. Generating new DPoP key pair...');
                        const dpopKeyPair = await window.crypto.subtle.generateKey(
                            {
                                name: "ECDSA",
                                namedCurve: "P-256"
                            },
                            false,
                            ["sign", "verify"]
                        );
                        
                        const dpopKeyId = `dpop_${crypto.randomUUID()}`;
                        privateKeyHandleStore.set(dpopKeyId, {
                            privateKey: dpopKeyPair.privateKey,
                            publicKey: dpopKeyPair.publicKey
                        });
                        
                        // Step 3: Renegotiate ECDHE handshake
                        console.log('3. Renegotiating ECDHE handshake...');
                        const ecdheKey = await generateECDHEKeyPair();
                        
                        const handshakeResponse = await fetch('/handshake', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({
                                client_ecdhe_public_key: ecdheKey.publicKey
                            })
                        });
                        
                        if (!handshakeResponse.ok) {
                            throw new Error('ECDHE handshake failed: ' + handshakeResponse.statusText);
                        }
                        
                        const handshakeData = await handshakeResponse.json();
                        console.log('ECDHE handshake successful, handshake nonce:', handshakeData.handshake_nonce);
                        
                        // Step 4: Derive fresh Session Encryption Key (SEK)
                        console.log('4. Deriving fresh Session Encryption Key...');
                        sessionEncryptionKey = await performECDHEHandshake(ecdheKey.keyId, handshakeData.server_ecdhe_public_key);
                        
                        console.log('Fresh Session Encryption Key derived successfully');
                        
                        // Step 5: Create a new session token manually for the existing session
                        console.log('5. Creating new session token for existing session...');
                        
                        const browserIdentityData = Stronghold.getBrowserIdentity();
                        
                        // Create a simple JWT token for the existing session
                        const sessionTokenPayload = {
                            session_id: sessionData.session_id,
                            browser_uuid: storedBrowserUuid,
                            fingerprint_hash: browserIdentityData.fingerprintHash,
                            jti: crypto.randomUUID(),
                            iat: Math.floor(Date.now() / 1000),
                            exp: Math.floor(Date.now() / 1000) + (24 * 60 * 60) // 24 hours
                        };
                        
                        // For demo purposes, we'll create a simple token
                        // In production, this would be signed by the server
                        const sessionToken = btoa(JSON.stringify(sessionTokenPayload));
                        
                        // Step 6: Create new session object
                        console.log('6. Creating new session object...');
                        currentSession = {
                            sessionId: sessionData.session_id,
                            sessionToken: sessionToken,
                            browserUuid: storedBrowserUuid,
                            browserIdentityKeyId: browserIdentityKeyId,
                            dpopKeyId: dpopKeyId,
                            dpopNonce: handshakeData.handshake_nonce
                        };
                        
                        console.log('Session fully restored with fresh ECDHE handshake and SEK');
                        
                    } catch (error) {
                        console.error('Error restoring session with ECDHE renegotiation:', error);
                        clearBrowserUuidFromStorage();
                        currentSession = null;
                        throw error;
                    }
                } else {
                    console.log('No existing session found for browser UUID');
                }
            } else {
                console.log('Session check response not ok:', sessionCheckResponse.status);
            }
        } catch (error) {
            console.error('Error checking for existing session:', error);
        }
    }
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = {
        generateBrowserIdentityKey,
        generateDPoPKeyPair,
        generateECDHEKeyPair,
        createStrongholdSession,
        makeAuthenticatedRequest,
        signData,
        getBrowserIdentity,
        clearBrowserIdentity,
        getSessionMapping,
        getSecurityAudit,
        clearBrowserUuidFromStorage,
        initializeSession,
        get currentSession() { return currentSession; }
    };
} else {
    // Browser environment - attach to window
    window.Stronghold = {
        generateBrowserIdentityKey,
        generateDPoPKeyPair,
        generateECDHEKeyPair,
        createStrongholdSession,
        makeAuthenticatedRequest,
        signData,
        getBrowserIdentity,
        clearBrowserIdentity,
        getSessionMapping,
        getSecurityAudit,
        clearBrowserUuidFromStorage,
        initializeSession,
        get currentSession() { return currentSession; }
    };
} 