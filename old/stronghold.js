/**
 * Stronghold Crypto Utilities
 * Implements browser-only Stronghold-style session creation flow
 */

// In-memory storage for session private key handles
const privateKeyHandleStore = new Map();

// Session state
let currentSession = null;
let sessionEncryptionKey = null;

// IndexedDB database name and version
const DB_NAME = 'StrongholdCryptoDB';
const DB_VERSION = 2; // Incremented to trigger schema upgrade
const KEY_STORE = 'cryptoKeys';
const BROWSER_UUID_KEY = 'browser_uuid';

// Global database connection
let dbConnection = null;
let dbInitPromise = null;

// Configuration
const STRONGHOLD_CONFIG = {
    dpop_key_expiration: 1000 * 60 * 60 * 24 * 1, // 1 day
    browser_identity_key_expiration: 1000 * 60 * 60 * 24 * 5, // 5 days
    session_encryption_key_expiration: 1000 * 60 * 60 * 24 * 1, // 1 day
    session_idle_timeout: 1000 * 60 * 15, // 15 minutes
    dpop_key_name: 'dpop_key',
    browser_identity_key_name: 'browser_identity_key',
    session_encryption_key_name: 'session_encryption_key',
    browser_uuid_name: 'browser_uuid',
}

async function invalidateSession() {
    const response = await fetch('/invalidate-session', {
        method: 'POST',
        credentials: 'include',
    });
    
    // Get browser UUID before clearing
    const browserUuid = await getBrowserUuid();
    
    // Clear browser UUID
    await deleteBrowserUuid();
    currentSession = null;
    
    // Clear all keys for this browser UUID
    if (browserUuid) {
        await clearKeysByBrowserUuid(browserUuid);
    }
    
    return response;
}   

// Initialize session on page load
async function initializeSession() {
    // Clean up any expired keys first
    currentSession = null;
    try {
        await cleanupExpiredKeys();
    } catch (error) {
        console.warn('Failed to cleanup expired keys:', error);
    }
    
    const storedBrowserUuid = await getBrowserUuid();
    console.log('Stored browser UUID:', storedBrowserUuid);
    if (storedBrowserUuid) {
        console.log('Browser UUID found in storage, checking for existing browser identity and DPoP keys...');
        
        // Get all keys for this browser UUID
        const allKeys = await getKeysByBrowserUuid(storedBrowserUuid);
        const storedBrowserIdentityKey = allKeys.find(key => key.type === 'browser_identity');
        const storedDPoPKey = allKeys.find(key => key.type === 'dpop');
        
        if (storedBrowserIdentityKey && storedDPoPKey) {
            console.log('Existing browser identity and DPoP keys found...');
            
            // Validate key expiration
            if (!isKeyValid(storedBrowserIdentityKey)) {
                console.log('Browser identity key has expired, clearing...');
                await clearKeysByBrowserUuid(storedBrowserUuid);
                throw new Error('Browser identity key expired');
            }
            
            if (!isKeyValid(storedDPoPKey)) {
                console.log('DPoP key has expired, clearing...');
                await clearKeysByBrowserUuid(storedBrowserUuid);
                throw new Error('DPoP key expired');
            }
            
            console.log('Keys are valid and not expired, validating session details with server...');
            
            // Load keys into memory for validation
            privateKeyHandleStore.set(storedBrowserIdentityKey.keyId, {
                privateKey: storedBrowserIdentityKey.keyHandle.privateKey,
                publicKey: storedBrowserIdentityKey.keyHandle.publicKey
            });
            
            privateKeyHandleStore.set(storedDPoPKey.keyId, {
                privateKey: storedDPoPKey.keyHandle.privateKey,
                publicKey: storedDPoPKey.keyHandle.publicKey
            });
            
            // Step 1: Check if server has a session for this browser UUID
            const sessionCheckResponse = await fetch(`/check-session/${storedBrowserUuid}`);
            console.log('Session check response:', sessionCheckResponse);
            
            if (sessionCheckResponse.ok) {
                const sessionData = await sessionCheckResponse.json();
                console.log('Session check response data:', sessionData);
                
                if (sessionData.has_session) {
                    console.log('Existing valid session found, validating key possession...');
                    
                    // Step 2: Request challenge to validate key possession
                    try {
                        const challengeData = await requestSessionChallenge(storedBrowserUuid);
                        console.log('Challenge received for key validation:', challengeData);
                        
                        // Step 3: Sign the challenge with browser identity key to prove possession
                        const challengeSignature = await signChallenge(challengeData.challenge);
                        console.log('Challenge signed with browser identity key');
                        
                        // Step 4: Verify challenge and restore session
                        const verificationData = await verifySessionChallenge(
                            challengeData.session_id,
                            challengeData.challenge,
                            challengeSignature
                        );
                        console.log('Challenge verified successfully:', verificationData);
                        
                        // Step 4.5: Validate DPoP key locally (just ensure we can create a proof)
                        console.log('Validating DPoP key locally...');
                        try {
                            // Just create a DPoP proof locally to ensure the key works
                            const testDpopProof = await createDPoPProof(
                                storedDPoPKey.keyId,
                                'POST',
                                '/verify-dpop',
                                null
                            );
                            console.log('DPoP key validation successful - proof created locally');
                        } catch (error) {
                            console.error('DPoP key validation failed:', error);
                            console.log('DPoP key validation failed, but continuing with session restoration...');
                            console.log('Note: DPoP key will be validated when making actual authenticated requests');
                            // Don't throw error, just log it
                        }
                        
                        // Step 5: Check for stored session encryption key
                        const storedSessionEncryptionKey = await getSessionEncryptionKey(storedBrowserUuid);
                        
                        // Step 6: If no stored SEK, perform ECDHE handshake to establish fresh one
                        let sessionEncryptionKey = storedSessionEncryptionKey;
                        let sekSource = storedSessionEncryptionKey ? 'Retrieved from Storage' : 'Not Available';
                        
                        // Validate SEK expiration if it exists
                        if (storedSessionEncryptionKey) {
                            const allKeys = await getKeysByBrowserUuid(storedBrowserUuid);
                            const sekKey = allKeys.find(key => key.type === 'session_encryption_key');
                            if (sekKey && !isKeyValid(sekKey)) {
                                console.log('Session encryption key has expired, will perform fresh handshake...');
                                sessionEncryptionKey = null;
                                sekSource = 'Not Available';
                            }
                        }
                        
                        if (!sessionEncryptionKey) {
                            console.log('No stored session encryption key found, performing ECDHE handshake...');
                            
                            // Generate ECDHE key pair
                            const ecdheKey = await generateECDHEKeyPair();
                            
                            // Perform handshake
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
                            
                            // Derive fresh Session Encryption Key
                            sessionEncryptionKey = await performECDHEHandshake(ecdheKey.keyId, handshakeData.server_ecdhe_public_key);
                            
                            // Store the new SEK
                            await storeSessionEncryptionKey(sessionEncryptionKey, storedBrowserUuid);
                            
                            // Update server session with new encryption key
                            const keyUpdateResponse = await fetch('/update-session-key', {
                                method: 'POST',
                                headers: {
                                    'Content-Type': 'application/json'
                                },
                                credentials: 'include',
                                body: JSON.stringify({
                                    handshake_nonce: handshakeData.handshake_nonce
                                })
                            });
                            
                            if (!keyUpdateResponse.ok) {
                                console.warn('Failed to update session key on server, but continuing...');
                            } else {
                                console.log('Session key updated successfully on server');
                            }
                            
                            sekSource = 'Fresh ECDHE Handshake';
                        }
                        
                        // Step 7: Create session object
                        currentSession = {
                            sessionId: verificationData.session_id,
                            browserUuid: storedBrowserUuid,
                            browserIdentityKeyId: storedBrowserIdentityKey.keyId,
                            dpopKeyId: storedDPoPKey.keyId,
                            sessionEncryptionKey: sessionEncryptionKey,
                            dpopNonce: null,  // Will be obtained on first authenticated request
                            sekSource: sekSource
                        };
                        
                        console.log('Session restored successfully with key validation!');
                        
                                            } catch (error) {
                            console.error('Key validation failed:', error);
                            console.log('Key validation failed, tearing down invalid session...');
                            await invalidateSession();
                            throw error;
                        }
                } else {
                    console.log('No existing session found for browser UUID');
                }
            } else {
                console.log('Session check response not ok:', sessionCheckResponse.status);
            }

        } else {
            console.log('No existing browser identity or DPoP keys found for server session, tearing down session...');
            const invalidateResponse = await invalidateSession();
            console.log('Invalidate response:', invalidateResponse);
        }
    } else {
        console.log('No browser UUID found, this must be our first time here...');
    }

    if (!currentSession) {
        console.log('No valid session found, creating new Stronghold session...');
        const strongholdSession = await createStrongholdSession();   
        console.log('Stronghold session created:', strongholdSession);
        currentSession = strongholdSession;
        return;
    }

}





/**
 * Initialize IndexedDB for key storage
 * @returns {Promise<IDBDatabase>}
 */
async function initIndexedDB() {
    // Return existing connection if available
    if (dbConnection) {
        return dbConnection;
    }
    
    // Return existing promise if initialization is in progress
    if (dbInitPromise) {
        return dbInitPromise;
    }
    
    // Create new initialization promise
    dbInitPromise = new Promise((resolve, reject) => {
        const request = indexedDB.open(DB_NAME, DB_VERSION);
        
        request.onerror = () => {
            dbInitPromise = null;
            reject(request.error);
        };
        
        request.onsuccess = () => {
            dbConnection = request.result;
            dbInitPromise = null;
            resolve(dbConnection);
        };
        
        request.onupgradeneeded = (event) => {
            const db = event.target.result;
            
            // Create object store for crypto keys
            if (!db.objectStoreNames.contains(KEY_STORE)) {
                const keyStore = db.createObjectStore(KEY_STORE, { keyPath: 'keyId' });
                keyStore.createIndex('type', 'type', { unique: false });
                keyStore.createIndex('browserUuid', 'browserUuid', { unique: false });
            }
            
            // Create object store for browser UUID
            if (!db.objectStoreNames.contains('browserData')) {
                const browserStore = db.createObjectStore('browserData', { keyPath: 'key' });
            }
        };
    });
    
    return dbInitPromise;
}

/**
 * Get the crypto keys object store for read/write operations
 * @returns {Promise<IDBObjectStore>}
 */
async function getCryptoKeyStore(mode = 'readwrite') {
    const db = await initIndexedDB();
    const transaction = db.transaction([KEY_STORE], mode);
    return transaction.objectStore(KEY_STORE);
}

/**
 * Get the browser data object store for read/write operations
 * @returns {Promise<IDBObjectStore>}
 */
async function getBrowserDataStore(mode = 'readwrite') {
    const db = await initIndexedDB();
    const transaction = db.transaction(['browserData'], mode);
    return transaction.objectStore('browserData');
}

/**
 * Store a CryptoKey pair in IndexedDB
 * @param {string} keyId - Unique identifier for the key
 * @param {CryptoKey} privateKey - The private key to store
 * @param {CryptoKey} publicKey - The public key to store
 * @param {string} type - Type of key (e.g., 'browser_identity', 'dpop')
 * @param {string} browserUuid - Associated browser UUID
 * @returns {Promise<void>}
 */
async function storeCryptoKey(keyId, privateKey, publicKey, type, browserUuid) {
    try {
        const store = await getCryptoKeyStore('readwrite');
        
        // Store the key pair as a single keyHandle object
        await new Promise((resolve, reject) => {
            const request = store.put({
                keyId,
                keyHandle: {
                    privateKey,
                    publicKey
                },
                type,
                browserUuid,
                createdAt: Date.now()
            });
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
        
        console.log(`Stored ${type} key pair with ID: ${keyId}`);
    } catch (error) {
        console.error('Error storing crypto key:', error);
        throw error;
    }
}

/**
 * Retrieve a CryptoKey pair from IndexedDB
 * @param {string} keyId - Unique identifier for the key
 * @returns {Promise<{keyHandle: {privateKey: CryptoKey, publicKey: CryptoKey}, type: string, browserUuid: string, createdAt: number} | null>}
 */
async function getCryptoKey(keyId) {
    try {
        const store = await getCryptoKeyStore('readonly');
        
        return new Promise((resolve, reject) => {
            const request = store.get(keyId);
            
            request.onsuccess = () => {
                const result = request.result;
                if (result) {
                    console.log(`Retrieved ${result.type} key pair with ID: ${keyId}`);
                    resolve({
                        keyHandle: result.keyHandle,
                        type: result.type,
                        browserUuid: result.browserUuid,
                        createdAt: result.createdAt
                    });
                } else {
                    console.log(`No key found with ID: ${keyId}`);
                    resolve(null);
                }
            };
            
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error retrieving crypto key:', error);
        throw error;
    }
}

/**
 * Get all keys for a specific browser UUID
 * @param {string} browserUuid - Browser UUID to search for
 * @returns {Promise<Array>}
 */
async function getKeysByBrowserUuid(browserUuid) {
    try {
        const store = await getCryptoKeyStore('readonly');
        const index = store.index('browserUuid');
        
        return new Promise((resolve, reject) => {
            const request = index.getAll(browserUuid);
            
            request.onsuccess = () => {
                console.log(`Retrieved ${request.result.length} keys for browser UUID: ${browserUuid}`);
                resolve(request.result);
            };
            
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error retrieving keys by browser UUID:', error);
        throw error;
    }
}

/**
 * Delete a CryptoKey from IndexedDB
 * @param {string} keyId - Unique identifier for the key
 * @returns {Promise<void>}
 */
async function deleteCryptoKey(keyId) {
    try {
        const db = await initIndexedDB();
        const transaction = db.transaction([KEY_STORE], 'readwrite');
        const store = transaction.objectStore(KEY_STORE);
        
        await new Promise((resolve, reject) => {
            const request = store.delete(keyId);
            
            request.onsuccess = () => {
                console.log(`Deleted key with ID: ${keyId}`);
                resolve();
            };
            
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error deleting crypto key:', error);
        throw error;
    }
}

/**
 * Clear all keys for a specific browser UUID
 * @param {string} browserUuid - Browser UUID to clear keys for
 * @returns {Promise<void>}
 */
async function clearKeysByBrowserUuid(browserUuid) {
    try {
        const keys = await getKeysByBrowserUuid(browserUuid);
        const store = await getCryptoKeyStore('readwrite');
        
        for (const key of keys) {
            await new Promise((resolve, reject) => {
                const request = store.delete(key.keyId);
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });
        }
        
        console.log(`Cleared ${keys.length} keys for browser UUID: ${browserUuid}`);
    } catch (error) {
        console.error('Error clearing keys by browser UUID:', error);
        throw error;
    }
}

/**
 * Clean up expired keys from IndexedDB
 * @returns {Promise<number>} Number of expired keys removed
 */
async function cleanupExpiredKeys() {
    try {
        const store = await getCryptoKeyStore('readwrite');
        
        const allKeys = await new Promise((resolve, reject) => {
            const request = store.getAll();
            request.onsuccess = () => resolve(request.result);
            request.onerror = () => reject(request.error);
        });
        
        const dpopKeyExpiration = STRONGHOLD_CONFIG.dpop_key_expiration;
        const browserIdentityKeyExpiration = STRONGHOLD_CONFIG.browser_identity_key_expiration;
        const sessionEncryptionKeyExpiration = STRONGHOLD_CONFIG.session_encryption_key_expiration;
        const expiredKeys = allKeys.filter(key => {
            const keyAge = Date.now() - key.createdAt;
            if (key.type === STRONGHOLD_CONFIG.dpop_key_name) {
                return keyAge >= dpopKeyExpiration;
            } else if (key.type === STRONGHOLD_CONFIG.browser_identity_key_name) {
                return keyAge >= browserIdentityKeyExpiration;
            } else if (key.type === STRONGHOLD_CONFIG.session_encryption_key_name) {
                return keyAge >= sessionEncryptionKeyExpiration;
            }
            return false;
        });
        
        let removedCount = 0;
        for (const expiredKey of expiredKeys) {
            await new Promise((resolve, reject) => {
                const request = store.delete(expiredKey.keyId);
                request.onsuccess = () => {
                    removedCount++;
                    resolve();
                };
                request.onerror = () => reject(request.error);
            });
        }
        
        if (removedCount > 0) {
            console.log(`Cleaned up ${removedCount} expired keys from IndexedDB`);
        }
        
        return removedCount;
    } catch (error) {
        console.error('Error cleaning up expired keys:', error);
        throw error;
    }
}

/**
 * Verify key expiration and clean up if needed
 * @param {Object} key - Key object from IndexedDB
 * @returns {boolean} True if key is valid, false if expired
 */
function isKeyValid(key) {
    const keyAge = Date.now() - key.createdAt;
    const twoDaysInMs = 2 * 24 * 60 * 60 * 1000; // 2 days in milliseconds
    return keyAge < twoDaysInMs;
}

/**
 * Store session encryption key directly in IndexedDB
 * @param {CryptoKey} sessionEncryptionKey 
 * @param {string} browserUuid 
 */
async function storeSessionEncryptionKey(sessionEncryptionKey, browserUuid) {
    try {
        const store = await getCryptoKeyStore('readwrite');
        
        const keyId = `session_encryption_key_${browserUuid}`;
        
        await new Promise((resolve, reject) => {
            const request = store.put({
                keyId: keyId,
                keyHandle: {
                    sessionEncryptionKey: sessionEncryptionKey
                },
                type: 'session_encryption_key',
                browserUuid: browserUuid,
                createdAt: Date.now()
            });
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
        
        console.log('Session encryption key stored in IndexedDB');
    } catch (error) {
        console.error('Error storing session encryption key:', error);
        throw error;
    }
}

/**
 * Get session encryption key from IndexedDB
 * @param {string} browserUuid 
 * @returns {Promise<CryptoKey | null>}
 */
async function getSessionEncryptionKey(browserUuid) {
    try {
        const store = await getCryptoKeyStore('readonly');
        
        const keyId = `session_encryption_key_${browserUuid}`;
        const request = store.get(keyId);
        
        return new Promise((resolve, reject) => {
            request.onsuccess = () => {
                const result = request.result;
                if (result && result.type === 'session_encryption_key') {
                    console.log('Found session encryption key in IndexedDB');
                    resolve(result.keyHandle.sessionEncryptionKey);
                } else {
                    console.log('No session encryption key found in IndexedDB');
                    resolve(null);
                }
            };
            
            request.onerror = () => {
                reject(new Error('Failed to get session encryption key from IndexedDB'));
            };
        });
    } catch (error) {
        console.error('Error getting session encryption key:', error);
        throw error;
    }
}



/**
 * Store browser UUID in IndexedDB
 * @param {string} browserUuid - The browser UUID to store
 * @returns {Promise<void>}
 */
async function storeBrowserUuid(browserUuid) {
    try {
        const store = await getBrowserDataStore('readwrite');
        
        await new Promise((resolve, reject) => {
            const request = store.put({
                key: BROWSER_UUID_KEY,
                value: browserUuid,
                createdAt: Date.now()
            });
            
            request.onsuccess = () => resolve();
            request.onerror = () => reject(request.error);
        });
        
        console.log('Browser UUID stored in IndexedDB');
    } catch (error) {
        console.error('Error storing browser UUID:', error);
        throw error;
    }
}

/**
 * Retrieve browser UUID from IndexedDB
 * @returns {Promise<string | null>}
 */
async function getBrowserUuid() {
    try {
        const store = await getBrowserDataStore('readonly');
        
        return new Promise((resolve, reject) => {
            const request = store.get(BROWSER_UUID_KEY);
            
            request.onsuccess = () => {
                const result = request.result;
                if (result) {
                    console.log('Browser UUID retrieved from IndexedDB');
                    resolve(result.value);
                } else {
                    console.log('No browser UUID found in IndexedDB');
                    resolve(null);
                }
            };
            
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error retrieving browser UUID:', error);
        throw error;
    }
}

/**
 * Delete browser UUID from IndexedDB
 * @returns {Promise<void>}
 */
async function deleteBrowserUuid() {
    try {
        const store = await getBrowserDataStore('readwrite');
        
        await new Promise((resolve, reject) => {
            const request = store.delete(BROWSER_UUID_KEY);
            
            request.onsuccess = () => {
                console.log('Browser UUID deleted from IndexedDB');
                resolve();
            };
            
            request.onerror = () => reject(request.error);
        });
    } catch (error) {
        console.error('Error deleting browser UUID:', error);
        throw error;
    }
}

/**
 * Generate a persistent, non-exportable browser identity key
 * @returns {Promise<{publicKey: string, keyId: string, browserUuid: string}>}
 */
async function generateBrowserIdentityKey() {
    try {
        console.log('generateBrowserIdentityKey: Starting...');
        
        // Get or generate persistent browser UUID
        let browserUuid = await getBrowserUuid();
        
        if (!browserUuid) {
            browserUuid = crypto.randomUUID();
            await storeBrowserUuid(browserUuid);
            console.log('generateBrowserIdentityKey: Generated new persistent browser UUID:', browserUuid);
        } else {
            console.log('generateBrowserIdentityKey: Using existing persistent browser UUID:', browserUuid);
        }
        
        // First, try to load existing keys from IndexedDB for this browser UUID
        console.log('generateBrowserIdentityKey: Checking for existing keys in IndexedDB...');
        const existingKeys = await getKeysByBrowserUuid(browserUuid);
        const browserIdentityKey = existingKeys.find(key => {
            if (key.type === 'browser_identity') {
                // Check if key is still valid (not expired)
                return isKeyValid(key);
            }
            return false;
        });
        
        if (browserIdentityKey) {
            console.log('generateBrowserIdentityKey: Found valid existing browser identity key in IndexedDB');
            
            // Load the key into memory for use
            privateKeyHandleStore.set(browserIdentityKey.keyId, {
                privateKey: browserIdentityKey.keyHandle.privateKey,
                publicKey: browserIdentityKey.keyHandle.publicKey
            });
            
            // Export the public key for return
            const publicKey = await exportPublicKey(browserIdentityKey.keyHandle.publicKey);
            
            return {
                publicKey: publicKey,
                keyId: browserIdentityKey.keyId,
                browserUuid: browserUuid
            };
        }
        
        // Check if we already have a browser identity key in memory
        console.log('generateBrowserIdentityKey: Checking for existing key in memory...');
        const existingKeyId = Array.from(privateKeyHandleStore.keys()).find(keyId => keyId.startsWith('browser_identity_'));
        
        if (existingKeyId) {
            console.log('generateBrowserIdentityKey: Using existing key from memory...');
            const storedData = privateKeyHandleStore.get(existingKeyId);
            
            if (storedData && storedData.publicKey) {
                const publicKey = await exportPublicKey(storedData.publicKey);
                return {
                    publicKey: publicKey,
                    keyId: existingKeyId,
                    browserUuid: browserUuid
                };
            } else {
                console.log('generateBrowserIdentityKey: Stored data missing publicKey, generating new key...');
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

        // Store the key in memory for immediate use
        console.log('generateBrowserIdentityKey: Storing key in memory...');
        privateKeyHandleStore.set(keyId, {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey
        });
        
        // Persist the key to IndexedDB for future page loads
        console.log('generateBrowserIdentityKey: Persisting key to IndexedDB...');
        await storeCryptoKey(keyId, keyPair.privateKey, keyPair.publicKey, 'browser_identity', browserUuid);
        
        console.log('generateBrowserIdentityKey: Key stored successfully');
        
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
 * Generate a DPoP key pair for session authentication
 * @returns {Promise<{publicKey: string, keyId: string}>}
 */
async function generateDPoPKeyPair() {
    try {
        // Get browser UUID for key association
        const browserUuid = await getBrowserUuid();
        if (!browserUuid) {
            throw new Error('Browser UUID not found - cannot generate DPoP key');
        }
        
        // First, try to load existing DPoP keys from IndexedDB for this browser UUID
        console.log('generateDPoPKeyPair: Checking for existing DPoP keys in IndexedDB...');
        const existingKeys = await getKeysByBrowserUuid(browserUuid);
        const validDPoPKey = existingKeys.find(key => {
            if (key.type === 'dpop') {
                // Check if key is still valid (not expired)
                return isKeyValid(key);
            }
            return false;
        });
        
        if (validDPoPKey) {
            console.log('generateDPoPKeyPair: Found valid existing DPoP key in IndexedDB');
            
            // Load the key into memory for use
            privateKeyHandleStore.set(validDPoPKey.keyId, {
                privateKey: validDPoPKey.keyHandle.privateKey,
                publicKey: validDPoPKey.keyHandle.publicKey
            });
            
            // Export the public key for return
            const publicKey = await exportPublicKey(validDPoPKey.keyHandle.publicKey);
            
            return {
                publicKey: publicKey,
                keyId: validDPoPKey.keyId
            };
        }
        
        // Check if we already have a DPoP key in memory
        console.log('generateDPoPKeyPair: Checking for existing key in memory...');
        const existingKeyId = Array.from(privateKeyHandleStore.keys()).find(keyId => keyId.startsWith('dpop_'));
        
        if (existingKeyId) {
            console.log('generateDPoPKeyPair: Using existing key from memory...');
            const storedData = privateKeyHandleStore.get(existingKeyId);
            
            if (storedData && storedData.publicKey) {
                const publicKey = await exportPublicKey(storedData.publicKey);
                return {
                    publicKey: publicKey,
                    keyId: existingKeyId
                };
            } else {
                console.log('generateDPoPKeyPair: Stored data missing publicKey, generating new key...');
                privateKeyHandleStore.delete(existingKeyId);
            }
        }
        
        // Generate new DPoP key pair
        console.log('generateDPoPKeyPair: Generating new key...');
        const keyId = `dpop_${crypto.randomUUID()}`;
        console.log('generateDPoPKeyPair: New key ID:', keyId);
        
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["sign", "verify"]
        );

        // Store the key in memory for immediate use
        console.log('generateDPoPKeyPair: Storing key in memory...');
        privateKeyHandleStore.set(keyId, {
            privateKey: keyPair.privateKey,
            publicKey: keyPair.publicKey
        });
        
        // Persist the key to IndexedDB with expiration
        console.log('generateDPoPKeyPair: Persisting key to IndexedDB...');
        await storeCryptoKey(keyId, keyPair.privateKey, keyPair.publicKey, 'dpop', browserUuid);

        // Export the public key
        const publicKey = await exportPublicKey(keyPair.publicKey);
        console.log('Generated new DPoP public key:', publicKey);
        
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
            false,  // Keep non-extractable for security
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
 * @param {string} nonce 
 * @returns {Promise<string>} DPoP proof JWT
 */
async function createDPoPProof(dpopKeyId, method, url, nonce = null) {
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
        
        // No access token hash needed - using session-based authentication
        
        const payload = {
            jti: crypto.randomUUID(),
            iat: currentTime,
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
        
        // Step 5.5: Get or generate browser UUID
        console.log('5.5. Getting or generating browser UUID...');
        const storedBrowserUuid = await getBrowserUuid();
        const browserUuid = storedBrowserUuid || crypto.randomUUID();
        
        // Save browser UUID to IndexedDB if it's new
        if (!storedBrowserUuid) {
            await storeBrowserUuid(browserUuid);
        }
        
        // Step 5.6: Store session encryption key for persistence
        console.log('5.6. Storing session encryption key...');
        await storeSessionEncryptionKey(sessionEncryptionKey, browserUuid);
        
        // Step 6: Prepare registration payload
        console.log('6. Preparing registration payload...');
        const browserIdentityData = await Stronghold.getBrowserIdentity();
        
        const registrationPayload = {
            handshake_nonce: handshakeData.handshake_nonce,
            browser_identity_public_key: browserIdentity.publicKey,
            browser_uuid: browserUuid
        };
        
        // Step 7: Encrypt payload with session key
        console.log('7. Encrypting registration payload...');
        const encryptedPayload = await encryptWithSessionKey(sessionEncryptionKey, JSON.stringify(registrationPayload));
        
        // Step 8: Create DPoP proof for registration
        console.log('8. Creating DPoP proof for registration...');
        const registrationDpopProof = await createDPoPProof(
            dpopKey.keyId,
            'POST',
            '/register-session',
            null  // No nonce for initial registration
        );
        
        // Step 9: Register session with server
        console.log('9. Registering session with server...');
        const requestBody = {
            handshake_nonce: handshakeData.handshake_nonce,
            browser_identity_public_key: browserIdentity.publicKey,
            browser_uuid: registrationPayload.browser_uuid,
            encrypted_payload: encryptedPayload
        };
        console.log('Registration request body:', requestBody);
        
        const registrationResponse = await fetch('/register-session', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'DPoP': registrationDpopProof
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
        
        // Store session information in memory only
        currentSession = {
            sessionId: registrationData.session_id,
            browserIdentityKeyId: browserIdentity.keyId,
            dpopKeyId: dpopKey.keyId,
            browserUuid: registrationPayload.browser_uuid,
            sessionEncryptionKey: sessionEncryptionKey,
            dpopNonce: registrationData.initial_dpop_nonce,
            sekSource: 'Fresh ECDHE Handshake'
        };
        
        console.log('Stronghold session created successfully!');
        return {
            sessionId: registrationData.session_id
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
            storedNonce
        );
        
        console.log('DPoP proof created:', dpopProof.substring(0, 100) + '...');
        
        // Prepare request
        const requestOptions = {
            method: method,
            headers: {
                'DPoP': dpopProof,
                'Content-Type': 'application/json'
            },
            credentials: 'include'  // Include cookies for session management
        };
        
        // Get current browser identity
        const browserIdentityData = await Stronghold.getBrowserIdentity();
        
        // Add encrypted payload if provided
        let encryptedPayload = null;
        if (payload) {
            if (!currentSession.sessionEncryptionKey) {
                throw new Error('No session encryption key available');
            }
            encryptedPayload = await encryptWithSessionKey(currentSession.sessionEncryptionKey, JSON.stringify(payload));
            requestOptions.body = JSON.stringify({
                encrypted_payload: encryptedPayload
            });
        } else {
            requestOptions.body = JSON.stringify({});
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
            
            // Check if this is a DPoP key mismatch error
            if (response.status === 401 && errorText.includes('Invalid DPoP proof')) {
                console.log('DPoP key mismatch detected, regenerating DPoP key...');
                
                // Regenerate DPoP key
                const newDpopKey = await generateDPoPKeyPair();
                
                // Update session with new DPoP key
                currentSession.dpopKeyId = newDpopKey.keyId;
                
                // Retry the request with the new DPoP key
                console.log('Retrying request with new DPoP key...');
                
                // Create new DPoP proof with new key
                const newDpopProof = await createDPoPProof(
                    newDpopKey.keyId,
                    method,
                    url,
                    storedNonce
                );
                
                // Update request options
                requestOptions.headers['DPoP'] = newDpopProof;
                
                // Retry the request
                const retryResponse = await fetch(url, requestOptions);
                
                if (!retryResponse.ok) {
                    const retryErrorText = await retryResponse.text();
                    console.error('Retry failed:', retryErrorText);
                    throw new Error('Authenticated request failed after DPoP key regeneration: ' + retryResponse.statusText + ' - ' + retryErrorText);
                }
                
                // Use the retry response
                const responseData = await retryResponse.json();
                
                // Update response data with new DPoP proof
                responseData.dpop_proof = newDpopProof;
                
                // Store new nonce from retry response headers
                const dpopNonce = retryResponse.headers.get('DPoP-Nonce');
                if (dpopNonce) {
                    console.log('Updating session nonce from:', currentSession.dpopNonce, 'to:', dpopNonce);
                    currentSession.dpopNonce = dpopNonce;
                }
                
                // Add response headers for display purposes
                responseData.response_headers = {
                    'DPoP-Nonce': dpopNonce || 'Not set'
                };
                
                // Add the encrypted payload that was sent to the response for display purposes
                if (encryptedPayload) {
                    responseData.encrypted_payload_sent = encryptedPayload;
                    responseData.plaintext_payload_sent = JSON.stringify(payload, null, 2);
                    
                    // Decrypt the server response payload locally for display
                    if (responseData.encrypted_payload) {
                        try {
                            const decryptedPayload = await decryptWithSessionKey(currentSession.sessionEncryptionKey, responseData.encrypted_payload);
                            responseData.decrypted_payload = decryptedPayload;
                        } catch (error) {
                            console.error('Error decrypting server payload:', error);
                            responseData.decrypted_payload = 'Error decrypting server payload';
                        }
                    }
                }
                
                return responseData;
            }
            
            throw new Error('Authenticated request failed: ' + response.statusText + ' - ' + errorText);
        }
        
        // Handle successful response
        const responseData = await response.json();
        
        // Store new nonce from response headers as per RFC 9449
        const dpopNonce = response.headers.get('DPoP-Nonce');
        if (dpopNonce) {
            console.log('Updating session nonce from:', currentSession.dpopNonce, 'to:', dpopNonce);
            currentSession.dpopNonce = dpopNonce;
        }
        
        // Add the encrypted payload that was sent to the response for display purposes
        if (encryptedPayload) {
            responseData.encrypted_payload_sent = encryptedPayload;
            responseData.plaintext_payload_sent = JSON.stringify(payload, null, 2);
            
            // Decrypt the server response payload locally for display
            if (responseData.encrypted_payload) {
                try {
                    const decryptedPayload = await decryptWithSessionKey(currentSession.sessionEncryptionKey, responseData.encrypted_payload);
                    responseData.decrypted_payload = decryptedPayload;
                } catch (error) {
                    console.error('Error decrypting server payload:', error);
                    responseData.decrypted_payload = 'Error decrypting server payload';
                }
            }
        }
        
        // Add response headers for display purposes
        responseData.response_headers = {
            'DPoP-Nonce': dpopNonce || 'Not set'
        };
        
        // Add DPoP proof for display purposes
        responseData.dpop_proof = dpopProof;
        
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
async function getBrowserIdentity() {
    const browserUuid = await getBrowserUuid();
    
    if (!browserUuid) {
        return null;
    }
    
    try {
        // Generate or get existing browser identity key
        const browserIdentityKey = await generateBrowserIdentityKey();
        
        // Generate DPoP key
        const dpopKey = await generateDPoPKeyPair();
        
        return {
            browserUuid: browserUuid,
            keysCreatedAt: Date.now(),
            browserIdentityKeyId: browserIdentityKey.keyId,
            dpopKeyId: dpopKey.keyId
        };
    } catch (error) {
        console.error('Error getting browser identity:', error);
        return null;
    }
}

async function clearBrowserIdentity() {
    try {
        // Get the browser UUID before clearing it
        const browserUuid = await getBrowserUuid();
        
        // Clear IndexedDB browser UUID
        await deleteBrowserUuid();
        
        // Clear in-memory browser identity keys
        const browserIdentityKeys = Array.from(privateKeyHandleStore.keys()).filter(keyId => keyId.startsWith('browser_identity_'));
        browserIdentityKeys.forEach(keyId => privateKeyHandleStore.delete(keyId));
        
        // Clear IndexedDB keys for this browser UUID
        if (browserUuid) {
            await clearKeysByBrowserUuid(browserUuid);
        }
        
        console.log('Browser identity cleared from memory and IndexedDB');
    } catch (error) {
        console.error('Error clearing browser identity:', error);
        throw error;
    }
}

function getSessionMapping() {
    // Session mapping would be retrieved from HTTP-only cookie in production
    // For demo purposes, return null since we're not storing it in localStorage
    return null;
}

async function getSecurityAudit() {
    const browserIdentity = await getBrowserIdentity();
    const audit = {
        sessionExists: !!currentSession,
        browserIdentityExists: !!browserIdentity,
        sessionMappingExists: !!getSessionMapping(),
        sessionTokenValid: false,
        securityFeatures: {
            ecdhe: true,
            dpop: true,
            sessionBinding: true,
            rateLimiting: true,
            sessionInvalidation: true,
            secureJWT: true,
            browserIdentity: true,
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


/**
 * Request a challenge for session restoration
 * @param {string} browserUuid 
 * @returns {Promise<Object>}
 */
async function requestSessionChallenge(browserUuid) {
    try {
        console.log('Requesting challenge for session restoration...');
        
        const response = await fetch('/request-challenge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                browser_uuid: browserUuid
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error('Challenge request failed: ' + response.statusText + ' - ' + errorText);
        }
        
        const challengeData = await response.json();
        console.log('Challenge received:', challengeData);
        
        return challengeData;
        
    } catch (error) {
        console.error('Error requesting challenge:', error);
        throw error;
    }
}

/**
 * Verify challenge signature and restore session
 * @param {string} sessionId 
 * @param {string} challenge 
 * @param {string} signature 
 * @returns {Promise<Object>}
 */
async function verifySessionChallenge(sessionId, challenge, signature) {
    try {
        console.log('Verifying challenge signature...');
        
        const response = await fetch('/verify-challenge', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                session_id: sessionId,
                challenge: challenge,
                signature: signature
            })
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error('Challenge verification failed: ' + response.statusText + ' - ' + errorText);
        }
        
        const verificationData = await response.json();
        console.log('Challenge verified successfully:', verificationData);
        
        return verificationData;
        
    } catch (error) {
        console.error('Error verifying challenge:', error);
        throw error;
    }
}

/**
 * Sign a challenge with the browser identity private key
 * @param {string} challenge 
 * @returns {Promise<string>}
 */
async function signChallenge(challenge) {
    try {
        console.log('Signing challenge with browser identity key...');
        
        // Get the browser identity key
        const browserIdentityKey = await generateBrowserIdentityKey();
        
        // Get the private key from the store using the key ID
        const storedData = privateKeyHandleStore.get(browserIdentityKey.keyId);
        if (!storedData || !storedData.privateKey) {
            throw new Error('Browser identity private key not found in memory');
        }
        
        // Sign the challenge
        const signature = await signData(browserIdentityKey.keyId, challenge);
        
        console.log('Challenge signed successfully');
        return signature;
        
    } catch (error) {
        console.error('Error signing challenge:', error);
        throw error;
    }
}

/**
 * Get debug data from server for testing and debugging
 * @returns {Promise<Object>}
 */
async function getDebugData() {
    try {
        console.log('Requesting debug data from server...');
        
        const response = await fetch('/debug/data', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            const errorText = await response.text();
            throw new Error('Debug data request failed: ' + response.statusText + ' - ' + errorText);
        }
        
        const debugData = await response.json();
        console.log('Debug data received:', debugData);
        
        return debugData;
        
    } catch (error) {
        console.error('Error getting debug data:', error);
        throw error;
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
        requestSessionChallenge,
        verifySessionChallenge,
        signChallenge,
        getDebugData,
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
        initializeSession,
        requestSessionChallenge,
        verifySessionChallenge,
        signChallenge,
        getDebugData,
        cleanupExpiredKeys,
        isKeyValid,
        clearKeysByBrowserUuid,
        storeBrowserUuid,
        getBrowserUuid,
        deleteBrowserUuid,
        storeSessionEncryptionKey,
        getSessionEncryptionKey,
        invalidateSession,
        get currentSession() { return currentSession; }
    };
} 