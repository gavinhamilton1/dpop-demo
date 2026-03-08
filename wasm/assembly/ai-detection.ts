/**
 * AI Detection WebAssembly Module
 * 
 * This module contains AI browser detection logic compiled to WASM.
 * The embedded secret is compiled into the binary at build time.
 * 
 * Build: npm run asbuild
 */

// ==================== CONFIGURATION ====================
// Embedded secret (set at build time via environment variable)
// Format: AI_DETECT_SECRET_v{version}_{random}
// This will be replaced during build process
const EMBEDDED_SECRET: string = "AI_DETECT_SECRET_v1_EMBEDDED_AT_BUILD_TIME";

// ==================== TYPES ====================

// Browser data passed from JavaScript
export class BrowserData {
    userAgent: string = "";
    platform: string = "";
    languages: string = "";
    plugins: string = "";
    webdriver: bool = false;
    screenWidth: i32 = 0;
    screenHeight: i32 = 0;
    colorDepth: i32 = 0;
    devicePixelRatio: f64 = 0;
    timezone: string = "";
    canvasFingerprint: string = "";
    audioFingerprint: string = "";
    fontFingerprint: string = "";
}

// Detection result
export class DetectionResult {
    detected: bool = false;
    reasons: string = ""; // JSON array of reasons
    severity: i32 = 0; // 0 = none, 1 = low, 2 = medium, 3 = high
}

// ==================== UTILITY FUNCTIONS ====================

function contains(str: string, substr: string): bool {
    const strLen = str.length;
    const substrLen = substr.length;
    if (substrLen > strLen) return false;
    
    for (let i = 0; i <= strLen - substrLen; i++) {
        let match = true;
        for (let j = 0; j < substrLen; j++) {
            if (str.charCodeAt(i + j) !== substr.charCodeAt(j)) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

function toLowerCase(str: string): string {
    let result = "";
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        if (char >= 65 && char <= 90) { // A-Z
            result += String.fromCharCode(char + 32);
        } else {
            result += String.fromCharCode(char);
        }
    }
    return result;
}

// Simple hash function (SHA-256 would be better but this is a simplified version)
function simpleHash(input: string): string {
    // This is a placeholder - in production, use a proper crypto library
    // For AssemblyScript, we'd use crypto library or implement SHA-256
    let hash: i64 = 0;
    for (let i = 0; i < input.length; i++) {
        const char = input.charCodeAt(i);
        hash = ((hash << 5) - hash) + char;
        hash = hash & hash; // Convert to 32-bit integer
    }
    // Convert to hex string (simplified)
    return hash.toString(16);
}

// ==================== DETECTION LOGIC ====================

/**
 * Check automation framework keywords in user agent
 */
function checkAutomationFrameworks(browserData: BrowserData, reasons: string[]): bool {
    const ua = toLowerCase(browserData.userAgent);
    const automationKeywords = [
        "selenium", "webdriver", "puppeteer", "playwright",
        "headless", "phantomjs", "chromedriver", "geckodriver",
        "automation", "bot", "crawler", "scraper"
    ];
    
    for (let i = 0; i < automationKeywords.length; i++) {
        if (contains(ua, automationKeywords[i])) {
            reasons.push(`Automation framework detected: ${automationKeywords[i]}`);
            return true;
        }
    }
    
    if (browserData.webdriver) {
        reasons.push("WebDriver property detected");
        return true;
    }
    
    return false;
}

/**
 * Check for AI browsers (Comet, etc.)
 */
function checkAIBrowsers(browserData: BrowserData, reasons: string[]): bool {
    const ua = toLowerCase(browserData.userAgent);
    
    // Check for Comet Browser
    if (contains(ua, "comet") || contains(browserData.userAgent, "Comet")) {
        reasons.push("Comet Browser detected");
        return true;
    }
    
    // Check for other AI browsers
    const aiBrowsers = [
        "antigravity", "perplexity", "arc.*ai", "brave.*leo",
        "opera.*aria", "bing.*chat", "bing.*ai"
    ];
    
    for (let i = 0; i < aiBrowsers.length; i++) {
        if (contains(ua, aiBrowsers[i])) {
            reasons.push(`AI browser detected: ${aiBrowsers[i]}`);
            return true;
        }
    }
    
    return false;
}

/**
 * Check for headless browser indicators
 */
function checkHeadlessIndicators(browserData: BrowserData, reasons: string[]): bool {
    // Missing plugins
    if (browserData.plugins.length === 0 && contains(browserData.userAgent, "Chrome")) {
        reasons.push("Headless browser: No plugins in Chrome");
        return true;
    }
    
    // Invalid screen dimensions
    if (browserData.screenWidth === 0 || browserData.screenHeight === 0) {
        reasons.push("Headless browser: Invalid screen dimensions");
        return true;
    }
    
    // Missing color depth
    if (browserData.colorDepth < 16) {
        reasons.push("Headless browser: Unusual color depth");
        return true;
    }
    
    return false;
}

/**
 * Check canvas fingerprinting anomalies
 */
function checkCanvasFingerprint(browserData: BrowserData, reasons: string[]): bool {
    if (browserData.canvasFingerprint.length < 100) {
        reasons.push("Canvas fingerprint anomaly detected");
        return true;
    }
    return false;
}

/**
 * Check audio fingerprinting anomalies
 */
function checkAudioFingerprint(browserData: BrowserData, reasons: string[]): bool {
    if (browserData.audioFingerprint.length === 0) {
        reasons.push("Audio fingerprint missing (possible automation)");
        return true;
    }
    return false;
}

/**
 * Check font fingerprinting anomalies
 */
function checkFontFingerprint(browserData: BrowserData, reasons: string[]): bool {
    if (browserData.fontFingerprint.length < 50) {
        reasons.push("Font fingerprint anomaly (possible automation)");
        return true;
    }
    return false;
}

// ==================== MAIN DETECTION FUNCTION ====================

/**
 * Main detection function - runs all checks
 * @param browserData - Browser properties collected from JavaScript
 * @returns DetectionResult with detection status and reasons
 */
export function detectAI(browserData: BrowserData): DetectionResult {
    const result = new DetectionResult();
    const reasons: string[] = [];
    let detected = false;
    
    // Run all detection checks
    detected = checkAutomationFrameworks(browserData, reasons) || detected;
    detected = checkAIBrowsers(browserData, reasons) || detected;
    detected = checkHeadlessIndicators(browserData, reasons) || detected;
    detected = checkCanvasFingerprint(browserData, reasons) || detected;
    detected = checkAudioFingerprint(browserData, reasons) || detected;
    detected = checkFontFingerprint(browserData, reasons) || detected;
    
    result.detected = detected;
    result.severity = detected ? (reasons.length > 3 ? 3 : reasons.length) : 0;
    
    // Convert reasons array to JSON string
    let reasonsJson = "[";
    for (let i = 0; i < reasons.length; i++) {
        if (i > 0) reasonsJson += ",";
        reasonsJson += `"${reasons[i]}"`;
    }
    reasonsJson += "]";
    result.reasons = reasonsJson;
    
    return result;
}

// ==================== CALL-HOME PROOF GENERATION ====================

/**
 * Generate proof token for call-home verification
 * Combines embedded secret with session ID and timestamp
 * 
 * @param sessionId - Session identifier
 * @param timestamp - Unix timestamp (milliseconds)
 * @returns Proof token (hash of secret + sessionId + timestamp)
 */
export function generateProof(sessionId: string, timestamp: i64): string {
    // Combine: secret:sessionId:timestamp
    const proofData = `${EMBEDDED_SECRET}:${sessionId}:${timestamp}`;
    
    // Generate hash (simplified - use proper SHA-256 in production)
    return simpleHash(proofData);
}

/**
 * Verify that a proof token matches expected value
 * (Server-side verification is primary, this is just for debugging)
 */
export function verifyProof(proof: string, sessionId: string, timestamp: i64): bool {
    const expectedProof = generateProof(sessionId, timestamp);
    return proof === expectedProof;
}

// ==================== SECRET ACCESS (INTERNAL ONLY) ====================

/**
 * Get embedded secret (for debugging/verification purposes)
 * NOTE: In production, this should NOT be exported or accessible
 * The secret should only be used internally for proof generation
 */
export function getEmbeddedSecret(): string {
    return EMBEDDED_SECRET;
}

