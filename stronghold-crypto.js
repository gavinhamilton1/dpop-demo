/**
 * Crypto utilities for device registration demo
 * Uses Web Crypto API for secure key generation
 */

// In-memory storage for private key handles (in production, use more secure storage)
const privateKeyHandleStore = new Map();

/**
 * Generate a non-exportable private key and return the public key
 * @returns {Promise<string>} The public key as a base64-encoded string
 */
async function generateKeyPair() {
    try {
        // Generate a key pair using ECDSA with P-256 curve
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["sign", "verify"] // key usages
        );

        // Export the public key
        const publicKeyBuffer = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );

        const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
        
        return publicKeyBase64;
    } catch (error) {
        console.error('Error generating key pair:', error);
        throw new Error('Failed to generate key pair: ' + error.message);
    }
}

/**
 * Generate a key pair and return both public key and key ID
 * The private key handle is stored and can be retrieved using the keyId
 * @returns {Promise<{publicKey: string, keyId: string}>}
 */
async function generateKeyPairWithId() {
    try {
        // Generate a unique key ID first
        const keyId = crypto.randomUUID();
        
        // Generate the key pair
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false, // extractable = false (non-exportable)
            ["sign", "verify"] // key usages
        );

        // Store the private key handle with the keyId
        privateKeyHandleStore.set(keyId, keyPair.privateKey);

        // Export the public key
        const publicKeyBuffer = await window.crypto.subtle.exportKey(
            "spki",
            keyPair.publicKey
        );

        const publicKeyBase64 = arrayBufferToBase64(publicKeyBuffer);
        
        return {
            publicKey: publicKeyBase64,
            keyId: keyId
        };
    } catch (error) {
        console.error('Error generating key pair with ID:', error);
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
        // Get the private key handle from storage
        const privateKeyHandle = privateKeyHandleStore.get(keyId);
        if (!privateKeyHandle) {
            throw new Error(`Private key handle not found for keyId: ${keyId}`);
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

/**
 * Verify a signature using a public key
 * @param {string} publicKey - The public key as base64 string
 * @param {string} signature - The signature as base64 string
 * @param {string} data - The original data
 * @returns {Promise<boolean>} True if signature is valid
 */
async function verifySignature(publicKey, signature, data) {
    try {
        // Import the public key
        const publicKeyBuffer = base64ToArrayBuffer(publicKey);
        const importedPublicKey = await window.crypto.subtle.importKey(
            "spki",
            publicKeyBuffer,
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            false,
            ["verify"]
        );

        // Convert data and signature to ArrayBuffer
        const dataBuffer = new TextEncoder().encode(data);
        const signatureBuffer = base64ToArrayBuffer(signature);

        // Verify the signature
        return await window.crypto.subtle.verify(
            {
                name: "ECDSA",
                hash: { name: "SHA-256" }
            },
            importedPublicKey,
            signatureBuffer,
            dataBuffer
        );
    } catch (error) {
        console.error('Error verifying signature:', error);
        return false;
    }
}

/**
 * Convert ArrayBuffer to base64 string
 * @param {ArrayBuffer} buffer 
 * @returns {string} Base64 encoded string
 */
function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/**
 * Convert base64 string to ArrayBuffer
 * @param {string} base64 
 * @returns {ArrayBuffer}
 */
function base64ToArrayBuffer(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
}

/**
 * Validate if a string looks like a valid public key
 * @param {string} publicKey 
 * @returns {boolean} True if the public key format looks valid
 */
function validatePublicKey(publicKey) {
    if (!publicKey || typeof publicKey !== 'string') {
        return false;
    }
    
    // Basic validation - check if it's a reasonable length and base64-like
    if (publicKey.length < 50 || publicKey.length > 1000) {
        return false;
    }
    
    // Check if it's valid base64
    try {
        atob(publicKey);
        return true;
    } catch (e) {
        return false;
    }
}

/**
 * Format a public key for display (truncate if too long)
 * @param {string} publicKey 
 * @param {number} maxLength 
 * @returns {string} Formatted public key string
 */
function formatPublicKey(publicKey, maxLength = 50) {
    if (!publicKey) return '';
    
    if (publicKey.length <= maxLength) {
        return publicKey;
    }
    
    return publicKey.substring(0, maxLength) + '...';
}

// Export functions for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    // Node.js environment
    module.exports = {
        generateKeyPair,
        generateKeyPairWithId,
        signData,
        verifySignature,
        validatePublicKey,
        formatPublicKey
    };
} else {
    // Browser environment - attach to window
    window.CryptoUtils = {
        generateKeyPair,
        generateKeyPairWithId,
        signData,
        verifySignature,
        validatePublicKey,
        formatPublicKey
    };
} 