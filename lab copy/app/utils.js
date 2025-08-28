// DPoP Lab Utilities
// Helper functions for cryptographic operations and storage

// ============================================================================
// IndexedDB Storage Utilities
// ============================================================================

class StorageManager {
    constructor() {
        this.dbName = 'DPoPLabDB';
        this.version = 1;
        this.stores = {
            keys: 'keys',
            meta: 'meta'
        };
    }

    async init() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open(this.dbName, this.version);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
            
            request.onupgradeneeded = (event) => {
                const db = event.target.result;
                
                // Create stores
                if (!db.objectStoreNames.contains(this.stores.keys)) {
                    db.createObjectStore(this.stores.keys, { keyPath: 'id' });
                }
                if (!db.objectStoreNames.contains(this.stores.meta)) {
                    db.createObjectStore(this.stores.meta, { keyPath: 'id' });
                }
            };
        });
    }

    async get(storeName, id) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readonly');
            const store = transaction.objectStore(storeName);
            const request = store.get(id);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async put(storeName, data) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.put(data);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async delete(storeName, id) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.delete(id);
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async clear(storeName) {
        const db = await this.init();
        return new Promise((resolve, reject) => {
            const transaction = db.transaction([storeName], 'readwrite');
            const store = transaction.objectStore(storeName);
            const request = store.clear();
            
            request.onerror = () => reject(request.error);
            request.onsuccess = () => resolve(request.result);
        });
    }

    async wipe() {
        const db = await this.init();
        await Promise.all([
            this.clear(this.stores.keys),
            this.clear(this.stores.meta)
        ]);
    }
}

// ============================================================================
// Cryptographic Utilities
// ============================================================================

class CryptoUtils {
    static async generateKeyPair() {
        return await crypto.subtle.generateKey(
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false, // extractable
            ['sign', 'verify']
        );
    }

    static async exportPublicKey(publicKey) {
        const exported = await crypto.subtle.exportKey('jwk', publicKey);
        return {
            kty: exported.kty,
            crv: exported.crv,
            x: exported.x,
            y: exported.y
        };
    }

    static async sign(data, privateKey) {
        const encoder = new TextEncoder();
        const message = encoder.encode(data);
        const signature = await crypto.subtle.sign(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            privateKey,
            message
        );
        return this.arrayBufferToBase64Url(signature);
    }

    static async verify(signature, data, publicKey) {
        const encoder = new TextEncoder();
        const message = encoder.encode(data);
        const signatureBuffer = this.base64UrlToArrayBuffer(signature);
        
        return await crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: { name: 'SHA-256' }
            },
            publicKey,
            signatureBuffer,
            message
        );
    }

    static arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlToArrayBuffer(base64Url) {
        const base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(base64 + padding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }

    static generateNonce() {
        const array = new Uint8Array(18);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64Url(array);
    }

    static generateJti() {
        const array = new Uint8Array(16);
        crypto.getRandomValues(array);
        return this.arrayBufferToBase64Url(array);
    }
}

// ============================================================================
// JWT Utilities
// ============================================================================

class JWTUtils {
    static createJWT(header, payload, privateKey) {
        return new Promise(async (resolve, reject) => {
            try {
                const encodedHeader = this.base64UrlEncode(JSON.stringify(header));
                const encodedPayload = this.base64UrlEncode(JSON.stringify(payload));
                
                const data = `${encodedHeader}.${encodedPayload}`;
                const signature = await CryptoUtils.sign(data, privateKey);
                
                resolve(`${data}.${signature}`);
            } catch (error) {
                reject(error);
            }
        });
    }

    static base64UrlEncode(str) {
        return btoa(str)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlDecode(str) {
        const base64 = str
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        return atob(base64 + padding);
    }
}

// ============================================================================
// DPoP Utilities
// ============================================================================

class DPoPUtils {
    static async createDPoPProof(url, method, nonce, privateKey, publicJwk) {
        const now = Math.floor(Date.now() / 1000);
        const jti = CryptoUtils.generateJti();
        
        const header = {
            typ: 'dpop+jwt',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        const payload = {
            htm: method,
            htu: url,
            iat: now,
            jti: jti
        };
        
        if (nonce) {
            payload.nonce = nonce;
        }
        
        return await JWTUtils.createJWT(header, payload, privateKey);
    }

    static async createBIKJWS(nonce, privateKey, publicJwk) {
        const now = Math.floor(Date.now() / 1000);
        
        const header = {
            typ: 'bik-reg+jws',
            alg: 'ES256',
            jwk: publicJwk
        };
        
        const payload = {
            nonce: nonce,
            iat: now
        };
        
        return await JWTUtils.createJWT(header, payload, privateKey);
    }
}

// ============================================================================
// WebAuthn Utilities
// ============================================================================

class WebAuthnUtils {
    static isSupported() {
        return window.PublicKeyCredential !== undefined;
    }

    static async createCredentials(options) {
        try {
            // Convert base64 challenge to ArrayBuffer
            if (options.challenge) {
                options.challenge = this.base64UrlToArrayBuffer(options.challenge);
            }
            
            // Convert user.id from base64 to ArrayBuffer
            if (options.user && options.user.id) {
                options.user.id = this.base64UrlToArrayBuffer(options.user.id);
            }
            
            const credential = await navigator.credentials.create({
                publicKey: options
            });
            return credential;
        } catch (error) {
            throw new Error(`WebAuthn creation failed: ${error.message}`);
        }
    }

    static async getCredentials(options) {
        try {
            // Convert base64 challenge to ArrayBuffer
            if (options.challenge) {
                options.challenge = this.base64UrlToArrayBuffer(options.challenge);
            }
            
            // Convert credential IDs from base64 to ArrayBuffer
            if (options.allowCredentials) {
                options.allowCredentials = options.allowCredentials.map(cred => ({
                    ...cred,
                    id: this.base64UrlToArrayBuffer(cred.id)
                }));
            }
            
            const assertion = await navigator.credentials.get({
                publicKey: options
            });
            return assertion;
        } catch (error) {
            throw new Error(`WebAuthn authentication failed: ${error.message}`);
        }
    }

    static credentialToJSON(credential) {
        if (credential instanceof ArrayBuffer) {
            return this.arrayBufferToBase64Url(credential);
        } else if (credential instanceof Array) {
            return credential.map(c => this.credentialToJSON(c));
        } else if (credential instanceof Object) {
            const obj = {};
            for (let key in credential) {
                obj[key] = this.credentialToJSON(credential[key]);
            }
            return obj;
        } else {
            return credential;
        }
    }

    static arrayBufferToBase64Url(buffer) {
        const bytes = new Uint8Array(buffer);
        let binary = '';
        for (let i = 0; i < bytes.byteLength; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary)
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
    }

    static base64UrlToArrayBuffer(base64Url) {
        const base64 = base64Url
            .replace(/-/g, '+')
            .replace(/_/g, '/');
        const padding = '='.repeat((4 - base64.length % 4) % 4);
        const binary = atob(base64 + padding);
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) {
            bytes[i] = binary.charCodeAt(i);
        }
        return bytes.buffer;
    }
}

// ============================================================================
// QR Code Utilities
// ============================================================================

class QRCodeUtils {
    static async generateQRCode(text, elementId) {
        // Simple QR code generation using a library
        // In a real implementation, you might use a library like qrcode.js
        
        const element = document.getElementById(elementId);
        if (!element) {
            throw new Error(`Element with id '${elementId}' not found`);
        }
        
        // For lab purposes, create a simple text representation
        element.innerHTML = `
            <div style="border: 2px solid #000; padding: 10px; display: inline-block; font-family: monospace; font-size: 8px; line-height: 8px;">
                <div>QR Code for:</div>
                <div style="word-break: break-all; max-width: 200px;">${text}</div>
            </div>
        `;
        
        return true;
    }
}

// ============================================================================
// API Utilities
// ============================================================================

class APIUtils {
    static async request(url, options = {}) {
        const defaultOptions = {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            },
            credentials: 'include'
        };
        
        const finalOptions = { ...defaultOptions, ...options };
        
        try {
            const response = await fetch(url, finalOptions);
            
            if (!response.ok) {
                throw new Error(`HTTP ${response.status}: ${response.statusText}`);
            }
            
            const contentType = response.headers.get('content-type');
            if (contentType && contentType.includes('application/json')) {
                return await response.json();
            } else {
                return await response.text();
            }
        } catch (error) {
            throw new Error(`API request failed: ${error.message}`);
        }
    }

    static async get(url, headers = {}) {
        return this.request(url, { method: 'GET', headers });
    }

    static async post(url, data = null, headers = {}) {
        const options = { method: 'POST', headers };
        
        if (data) {
            if (typeof data === 'string') {
                options.body = data;
                options.headers['Content-Type'] = 'text/plain';
            } else {
                options.body = JSON.stringify(data);
            }
        }
        
        return this.request(url, options);
    }
}

// ============================================================================
// Constants
// ============================================================================

const STORAGE_KEYS = {
    BIK_CURRENT: 'bik_current',
    DPoP_CURRENT: 'dpop_current',
    CSRF: 'csrf',
    REG_NONCE: 'reg_nonce',
    BIND_TOKEN: 'bind_token',
    DPoP_NONCE: 'dpop_nonce'
};

// ============================================================================
// Export utilities for use in the lab
// ============================================================================

window.DPoPLabUtils = {
    StorageManager,
    CryptoUtils,
    JWTUtils,
    DPoPUtils,
    WebAuthnUtils,
    QRCodeUtils,
    APIUtils,
    STORAGE_KEYS
};
