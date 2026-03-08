/**
 * Example JavaScript integration for Rust WASM AI Detection
 * 
 * This shows how to integrate the WASM module into the existing
 * AIDetectionService.js
 */

// ==================== WASM Module Loading ====================

let wasmModule = null;
let wasmInitialized = false;

/**
 * Initialize WASM module
 */
async function initWASM() {
    if (wasmInitialized && wasmModule) {
        return wasmModule;
    }

    try {
        // Import the WASM module (wasm-pack generates this)
        const wasmImport = await import('/public/wasm/ai-detection.js');
        
        // Initialize with the WASM binary
        await wasmImport.default('/public/wasm/ai-detection.wasm');
        
        wasmModule = wasmImport;
        wasmInitialized = true;
        
        console.log('WASM AI Detection module loaded');
        return wasmModule;
    } catch (error) {
        console.error('Failed to load WASM module:', error);
        throw new Error('WASM module initialization failed');
    }
}

// ==================== Browser Data Collection ====================

/**
 * Collect browser data to pass to WASM
 */
function collectBrowserData() {
    const data = {
        user_agent: navigator.userAgent || '',
        platform: navigator.platform || '',
        languages: navigator.languages ? navigator.languages.join(',') : '',
        plugins: Array.from(navigator.plugins || []).map(p => p.name).join(','),
        webdriver: navigator.webdriver === true,
        screen_width: screen.width || 0,
        screen_height: screen.height || 0,
        color_depth: screen.colorDepth || 0,
        device_pixel_ratio: window.devicePixelRatio || 1.0,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone || '',
        canvas_fingerprint: getCanvasFingerprint(),
        audio_fingerprint: '', // Set by audio fingerprinting
        font_fingerprint: '',  // Set by font fingerprinting
    };

    return data;
}

/**
 * Get canvas fingerprint
 */
function getCanvasFingerprint() {
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.textBaseline = 'alphabetic';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);
        ctx.fillStyle = '#069';
        ctx.fillText('AI detection test 🔐', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('AI detection test 🔐', 4, 17);
        
        return canvas.toDataURL();
    } catch (e) {
        return '';
    }
}

// ==================== WASM Detection ====================

/**
 * Run AI detection using WASM module
 */
async function detectWithWASM() {
    // Ensure WASM is initialized
    if (!wasmInitialized) {
        await initWASM();
    }

    // Collect browser data
    const browserDataObj = collectBrowserData();
    
    // Create WASM BrowserData object
    const { BrowserData, detect_ai } = wasmModule;
    const browserData = new BrowserData();
    
    // Set properties
    browserData.user_agent = browserDataObj.user_agent;
    browserData.platform = browserDataObj.platform;
    browserData.languages = browserDataObj.languages;
    browserData.plugins = browserDataObj.plugins;
    browserData.webdriver = browserDataObj.webdriver;
    browserData.screen_width = browserDataObj.screen_width;
    browserData.screen_height = browserDataObj.screen_height;
    browserData.color_depth = browserDataObj.color_depth;
    browserData.device_pixel_ratio = browserDataObj.device_pixel_ratio;
    browserData.timezone = browserDataObj.timezone;
    browserData.canvas_fingerprint = browserDataObj.canvas_fingerprint;
    browserData.audio_fingerprint = browserDataObj.audio_fingerprint;
    browserData.font_fingerprint = browserDataObj.font_fingerprint;

    // Run detection
    const result = detect_ai(browserData);

    // Convert to plain object
    return {
        detected: result.detected(),
        reasons: Array.from(result.reasons()),
        severity: result.severity()
    };
}

// ==================== Call-Home Verification ====================

/**
 * Verify WASM execution with server
 */
async function verifyWithServer(sessionId, detectionResult) {
    const { generate_proof } = wasmModule;
    
    // Generate proof token
    const timestamp = Date.now();
    const proof = generate_proof(sessionId, timestamp);

    try {
        const response = await fetch('/ai-detection/verify', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            credentials: 'include',
            body: JSON.stringify({
                sessionId,
                proof,
                timestamp,
                detectionResults: detectionResult
            })
        });

        if (!response.ok) {
            throw new Error(`Verification failed: ${response.status}`);
        }

        const verification = await response.json();
        return verification;
    } catch (error) {
        console.error('Call-home verification failed:', error);
        return {
            verified: false,
            message: 'Verification request failed',
            allowed: false
        };
    }
}

// ==================== Main Detection Function ====================

/**
 * Complete AI detection flow with WASM and call-home verification
 */
export async function detectAIWithWASM(sessionId) {
    try {
        // Initialize WASM if needed
        await initWASM();

        // Run detection
        const detectionResult = await detectWithWASM();

        // Verify with server (call-home)
        const verification = await verifyWithServer(sessionId, detectionResult);

        // Check results
        if (!verification.verified) {
            return {
                detected: true,
                reasons: ['WASM verification failed'],
                severity: 3,
                verificationFailed: true
            };
        }

        if (verification.detectionResults?.detected) {
            return {
                detected: true,
                reasons: verification.detectionResults.reasons || detectionResult.reasons,
                severity: verification.detectionResults.severity || detectionResult.severity,
                verificationFailed: false
            };
        }

        // All good
        return {
            detected: false,
            reasons: [],
            severity: 0,
            verificationFailed: false
        };

    } catch (error) {
        console.error('WASM detection failed:', error);
        return {
            detected: true,
            reasons: ['WASM detection error: ' + error.message],
            severity: 3,
            verificationFailed: true
        };
    }
}

// ==================== Integration with Existing Service ====================

/**
 * Example of how to integrate with existing AIDetectionService
 */
export class AIDetectionServiceWASM {
    constructor() {
        this.detected = false;
        this.detectionReasons = [];
        this.wasmReady = false;
    }

    async initialize() {
        try {
            await initWASM();
            this.wasmReady = true;
            return true;
        } catch (error) {
            console.error('Failed to initialize WASM:', error);
            return false;
        }
    }

    async detect(sessionId) {
        if (!this.wasmReady) {
            const initialized = await this.initialize();
            if (!initialized) {
                return {
                    detected: true,
                    reasons: ['WASM module failed to initialize']
                };
            }
        }

        const result = await detectAIWithWASM(sessionId);
        
        this.detected = result.detected;
        this.detectionReasons = result.reasons;

        return result;
    }

    blockApplication(reasons) {
        // Use existing blockApplication method from AIDetectionService
        // This would be imported/merged with existing implementation
        console.error('🚫 AI Browser Detection:', reasons);
        // ... blocking logic ...
    }
}

