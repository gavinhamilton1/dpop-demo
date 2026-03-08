//! AI Detection WebAssembly Module
//!
//! This module contains AI browser detection logic compiled to WASM.
//! The embedded secret is compiled into the binary at build time via environment variable.
//!
//! Build: wasm-pack build --target web --release
//!
//! The secret is embedded at compile time via the AI_DETECTION_SECRET environment variable.
//! If not set, it will use a default (which should be changed in production).

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};

// Embedded secret (set at compile time via build script or environment variable)
// If not set during build, this will use a default (which should be changed)
// Build with: AI_DETECTION_SECRET=your-secret wasm-pack build
const EMBEDDED_SECRET: &str = option_env!("AI_DETECTION_SECRET")
    .unwrap_or("AI_DETECT_SECRET_v1_DEFAULT_CHANGE_ME");

// ==================== TYPES ====================

/// Browser data passed from JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct BrowserData {
    pub user_agent: String,
    pub platform: String,
    pub languages: String,
    pub plugins: String,
    pub webdriver: bool,
    pub screen_width: u32,
    pub screen_height: u32,
    pub color_depth: u32,
    pub device_pixel_ratio: f64,
    pub timezone: String,
    pub canvas_fingerprint: String,
    pub audio_fingerprint: String,
    pub font_fingerprint: String,
}

#[wasm_bindgen]
impl BrowserData {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            user_agent: String::new(),
            platform: String::new(),
            languages: String::new(),
            plugins: String::new(),
            webdriver: false,
            screen_width: 0,
            screen_height: 0,
            color_depth: 0,
            device_pixel_ratio: 0.0,
            timezone: String::new(),
            canvas_fingerprint: String::new(),
            audio_fingerprint: String::new(),
            font_fingerprint: String::new(),
        }
    }

    #[wasm_bindgen(getter)]
    pub fn user_agent(&self) -> String {
        self.user_agent.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_user_agent(&mut self, value: String) {
        self.user_agent = value;
    }

    #[wasm_bindgen(getter)]
    pub fn platform(&self) -> String {
        self.platform.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_platform(&mut self, value: String) {
        self.platform = value;
    }

    #[wasm_bindgen(getter)]
    pub fn languages(&self) -> String {
        self.languages.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_languages(&mut self, value: String) {
        self.languages = value;
    }

    #[wasm_bindgen(getter)]
    pub fn plugins(&self) -> String {
        self.plugins.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_plugins(&mut self, value: String) {
        self.plugins = value;
    }

    #[wasm_bindgen(getter)]
    pub fn webdriver(&self) -> bool {
        self.webdriver
    }

    #[wasm_bindgen(setter)]
    pub fn set_webdriver(&mut self, value: bool) {
        self.webdriver = value;
    }

    #[wasm_bindgen(getter)]
    pub fn screen_width(&self) -> u32 {
        self.screen_width
    }

    #[wasm_bindgen(setter)]
    pub fn set_screen_width(&mut self, value: u32) {
        self.screen_width = value;
    }

    #[wasm_bindgen(getter)]
    pub fn screen_height(&self) -> u32 {
        self.screen_height
    }

    #[wasm_bindgen(setter)]
    pub fn set_screen_height(&mut self, value: u32) {
        self.screen_height = value;
    }

    #[wasm_bindgen(getter)]
    pub fn color_depth(&self) -> u32 {
        self.color_depth
    }

    #[wasm_bindgen(setter)]
    pub fn set_color_depth(&mut self, value: u32) {
        self.color_depth = value;
    }

    #[wasm_bindgen(getter)]
    pub fn device_pixel_ratio(&self) -> f64 {
        self.device_pixel_ratio
    }

    #[wasm_bindgen(setter)]
    pub fn set_device_pixel_ratio(&mut self, value: f64) {
        self.device_pixel_ratio = value;
    }

    #[wasm_bindgen(getter)]
    pub fn timezone(&self) -> String {
        self.timezone.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_timezone(&mut self, value: String) {
        self.timezone = value;
    }

    #[wasm_bindgen(getter)]
    pub fn canvas_fingerprint(&self) -> String {
        self.canvas_fingerprint.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_canvas_fingerprint(&mut self, value: String) {
        self.canvas_fingerprint = value;
    }

    #[wasm_bindgen(getter)]
    pub fn audio_fingerprint(&self) -> String {
        self.audio_fingerprint.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_audio_fingerprint(&mut self, value: String) {
        self.audio_fingerprint = value;
    }

    #[wasm_bindgen(getter)]
    pub fn font_fingerprint(&self) -> String {
        self.font_fingerprint.clone()
    }

    #[wasm_bindgen(setter)]
    pub fn set_font_fingerprint(&mut self, value: String) {
        self.font_fingerprint = value;
    }
}

/// Detection result returned to JavaScript
#[derive(Debug, Clone, Serialize, Deserialize)]
#[wasm_bindgen]
pub struct DetectionResult {
    detected: bool,
    reasons: Vec<String>,
    severity: u8,
}

#[wasm_bindgen]
impl DetectionResult {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            detected: false,
            reasons: Vec::new(),
            severity: 0,
        }
    }

    #[wasm_bindgen(getter)]
    pub fn detected(&self) -> bool {
        self.detected
    }

    #[wasm_bindgen(getter)]
    pub fn reasons(&self) -> js_sys::Array {
        self.reasons
            .iter()
            .map(|r| JsValue::from_str(r))
            .collect()
    }

    #[wasm_bindgen(getter)]
    pub fn severity(&self) -> u8 {
        self.severity
    }
}

// ==================== DETECTION LOGIC ====================

/// Check for automation framework keywords in user agent
fn check_automation_frameworks(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    let ua_lower = browser_data.user_agent.to_lowercase();
    let automation_keywords = vec![
        "selenium", "webdriver", "puppeteer", "playwright",
        "headless", "phantomjs", "chromedriver", "geckodriver",
        "automation", "bot", "crawler", "scraper",
        "webdriverio", "testcafe",
    ];

    for keyword in automation_keywords {
        if ua_lower.contains(keyword) {
            reasons.push(format!("Automation framework detected: {}", keyword));
            return true;
        }
    }

    if browser_data.webdriver {
        reasons.push("WebDriver property detected".to_string());
        return true;
    }

    false
}

/// Check for AI browsers (Comet, Antigravity, etc.)
fn check_ai_browsers(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    let ua_lower = browser_data.user_agent.to_lowercase();
    let ua = &browser_data.user_agent;

    // Check for Comet Browser
    if ua_lower.contains("comet") || ua.contains("Comet") || ua.contains("CometBrowser") {
        reasons.push("Comet Browser detected".to_string());
        return true;
    }

    // Check for other AI browsers
    let ai_browsers = vec![
        ("antigravity", "Google Antigravity AI detected"),
        ("perplexity", "Perplexity AI browser detected"),
        ("arc.*ai", "Arc Browser AI detected"),
        ("brave.*leo", "Brave Leo AI detected"),
        ("opera.*aria", "Opera Aria AI detected"),
        ("bing.*chat", "Bing Chat AI browser detected"),
        ("bing.*ai", "Bing AI browser detected"),
    ];

    for (pattern, message) in ai_browsers {
        if ua_lower.contains(pattern) {
            reasons.push(message.to_string());
            return true;
        }
    }

    false
}

/// Check for headless browser indicators
fn check_headless_indicators(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    // Missing plugins in Chrome
    if browser_data.plugins.is_empty() && browser_data.user_agent.contains("Chrome") {
        reasons.push("Headless browser: No plugins in Chrome".to_string());
        return true;
    }

    // Invalid screen dimensions
    if browser_data.screen_width == 0 || browser_data.screen_height == 0 {
        reasons.push("Headless browser: Invalid screen dimensions".to_string());
        return true;
    }

    // Missing color depth
    if browser_data.color_depth < 16 {
        reasons.push("Headless browser: Unusual color depth".to_string());
        return true;
    }

    // Suspicious device pixel ratio
    if browser_data.device_pixel_ratio < 0.5 || browser_data.device_pixel_ratio > 5.0 {
        reasons.push("Headless browser: Suspicious device pixel ratio".to_string());
        return true;
    }

    false
}

/// Check canvas fingerprinting anomalies
fn check_canvas_fingerprint(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    if browser_data.canvas_fingerprint.len() < 100 {
        reasons.push("Canvas fingerprint anomaly detected".to_string());
        return true;
    }
    false
}

/// Check audio fingerprinting anomalies
fn check_audio_fingerprint(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    if browser_data.audio_fingerprint.is_empty() {
        reasons.push("Audio fingerprint missing (possible automation)".to_string());
        return true;
    }
    false
}

/// Check font fingerprinting anomalies
fn check_font_fingerprint(browser_data: &BrowserData, reasons: &mut Vec<String>) -> bool {
    if browser_data.font_fingerprint.len() < 50 {
        reasons.push("Font fingerprint anomaly (possible automation)".to_string());
        return true;
    }
    false
}

// ==================== MAIN DETECTION FUNCTION ====================

/// Main detection function - runs all checks
/// 
/// # Arguments
/// * `browser_data` - Browser properties collected from JavaScript
/// 
/// # Returns
/// DetectionResult with detection status and reasons
#[wasm_bindgen]
pub fn detect_ai(browser_data: &BrowserData) -> DetectionResult {
    let mut reasons = Vec::new();
    let mut detected = false;

    // Run all detection checks
    detected = check_automation_frameworks(browser_data, &mut reasons) || detected;
    detected = check_ai_browsers(browser_data, &mut reasons) || detected;
    detected = check_headless_indicators(browser_data, &mut reasons) || detected;
    detected = check_canvas_fingerprint(browser_data, &mut reasons) || detected;
    detected = check_audio_fingerprint(browser_data, &mut reasons) || detected;
    detected = check_font_fingerprint(browser_data, &mut reasons) || detected;

    let severity = if detected {
        match reasons.len() {
            0 => 0,
            1 => 1,
            2..=3 => 2,
            _ => 3,
        }
    } else {
        0
    };

    DetectionResult {
        detected,
        reasons,
        severity,
    }
}

// ==================== CALL-HOME PROOF GENERATION ====================

/// Generate proof token for call-home verification
/// 
/// Combines embedded secret with session ID and timestamp, then hashes with SHA-256
/// 
/// # Arguments
/// * `session_id` - Session identifier
/// * `timestamp` - Unix timestamp (milliseconds)
/// 
/// # Returns
/// Proof token (hex-encoded SHA-256 hash of secret:sessionId:timestamp)
#[wasm_bindgen]
pub fn generate_proof(session_id: &str, timestamp: u64) -> String {
    // Combine: secret:sessionId:timestamp
    let proof_data = format!("{}:{}:{}", EMBEDDED_SECRET, session_id, timestamp);

    // Generate SHA-256 hash
    let mut hasher = Sha256::new();
    hasher.update(proof_data.as_bytes());
    let hash = hasher.finalize();

    // Return hex-encoded hash
    hex::encode(hash)
}

/// Verify that a proof token matches expected value
/// (Server-side verification is primary, this is just for debugging/testing)
#[wasm_bindgen]
pub fn verify_proof(proof: &str, session_id: &str, timestamp: u64) -> bool {
    let expected_proof = generate_proof(session_id, timestamp);
    proof == expected_proof
}

// ==================== SECRET ACCESS (FOR DEBUGGING) ====================

/// Get embedded secret (for debugging/verification purposes)
/// 
/// WARNING: In production, this should NOT be accessible or exported.
/// The secret should only be used internally for proof generation.
#[wasm_bindgen]
pub fn get_embedded_secret() -> String {
    EMBEDDED_SECRET.to_string()
}

// ==================== WASM BINDINGS INIT ====================

#[wasm_bindgen(start)]
pub fn main() {
    // Initialize WASM module if needed
}

