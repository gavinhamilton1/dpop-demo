/**
 * AI Browser Detection Service
 * 
 * Detects AI-driven browsers, automation frameworks, and browser extensions
 * that may be used for automated access. Blocks the application if AI is detected.
 */

class AIDetectionService {
    constructor() {
        this.detected = false;
        this.detectionReasons = [];
    }

    /**
     * Run all detection checks
     * @returns {Object} { detected: boolean, reasons: string[] }
     */
    async detect() {
        this.detectionReasons = [];

        // Check 1: Known automation framework indicators
        this.checkAutomationFrameworks();

        // Check 2: AI-specific browsers (Comet, etc.)
        this.checkAIBrowsers();

        // Check 3: Headless browser indicators
        this.checkHeadlessBrowser();

        // Check 4: Browser extension APIs (AI plugins may expose these)
        this.checkExtensionAPIs();

        // Check 4: Navigator property inconsistencies
        this.checkNavigatorInconsistencies();

        // Check 5: WebDriver property (Selenium/automation)
        this.checkWebDriver();

        // Check 6: Chrome DevTools Protocol indicators
        this.checkCDPIndicators();

        // Check 7: Plugin detection (AI browser extensions)
        await this.checkPlugins();

        // Check 8: User agent anomalies
        this.checkUserAgent();

        // Check 9: Permissions API anomalies
        await this.checkPermissions();

        // Check 10: Canvas fingerprinting anomalies
        this.checkCanvasFingerprint();

        // Check 11: Battery API anomalies
        await this.checkBatteryAPI();

        // Check 12: Audio context fingerprinting
        this.checkAudioFingerprint();

        // Check 13: Font fingerprinting
        await this.checkFontFingerprint();

        // Check 14: WebRTC leak detection
        await this.checkWebRTC();

        // Check 15: Connection type detection
        this.checkConnectionType();

        // Check 16: Service worker detection
        await this.checkServiceWorkers();

        // Check 17: Performance/timing analysis
        this.checkPerformanceAnomalies();

        // Check 18: Media device detection
        await this.checkMediaDevices();

        // Check 19: Worker thread detection
        this.checkWorkers();

        // Check 20: Screen and window property anomalies
        this.checkScreenProperties();

        this.detected = this.detectionReasons.length > 0;

        return {
            detected: this.detected,
            reasons: this.detectionReasons
        };
    }

    /**
     * Check for known automation frameworks
     */
    checkAutomationFrameworks() {
        const userAgent = navigator.userAgent.toLowerCase();
        const automationKeywords = [
            'selenium',
            'webdriver',
            'puppeteer',
            'playwright',
            'headless',
            'phantomjs',
            'chromedriver',
            'geckodriver',
            'automation',
            'bot',
            'crawler',
            'scraper',
            'selenium-webdriver',
            'webdriverio',
            'testcafe'
        ];

        for (const keyword of automationKeywords) {
            if (userAgent.includes(keyword)) {
                this.detectionReasons.push(`Automation framework detected in user agent: ${keyword}`);
                return;
            }
        }

        // Check for automation-specific properties
        if (window.navigator.webdriver === true) {
            this.detectionReasons.push('WebDriver property detected (automation framework)');
        }

        // Check for Puppeteer
        if (window.navigator.__proto__.webdriver !== undefined) {
            this.detectionReasons.push('Puppeteer/automation framework detected');
        }

        // Check for Playwright
        if (window.playwright || window.__playwright) {
            this.detectionReasons.push('Playwright automation framework detected');
        }
    }

    /**
     * Check for AI-specific browsers (Comet Browser, etc.)
     */
    checkAIBrowsers() {
        const userAgent = navigator.userAgent.toLowerCase();
        
        // Known AI browser identifiers
        const aiBrowsers = [
            { name: 'Comet Browser', patterns: ['comet', 'cometbrowser', 'perplexity-comet'] },
            { name: 'Arc Browser AI', patterns: ['arc-browser', 'thebrowsercompany'] },
            { name: 'Brave Leo', patterns: ['brave', 'leo-ai'] },
            { name: 'Opera Aria', patterns: ['opera', 'aria-ai'] },
            { name: 'Bing Chat Browser', patterns: ['bingchat', 'bing-ai'] },
            { name: 'DuckDuckGo AI', patterns: ['duckduckgo-ai'] }
        ];

        for (const browser of aiBrowsers) {
            for (const pattern of browser.patterns) {
                if (userAgent.includes(pattern)) {
                    // Double-check it's actually an AI browser identifier, not just a word
                    if (pattern === 'comet' || pattern === 'brave' || pattern === 'opera') {
                        // These could be false positives, check for AI-related context
                        if (userAgent.includes('ai') || userAgent.includes('assistant') || 
                            userAgent.includes('chat') || navigator.userAgent.includes('Comet Browser')) {
                            this.detectionReasons.push(`AI browser detected: ${browser.name}`);
                            return;
                        }
                    } else {
                        this.detectionReasons.push(`AI browser detected: ${browser.name}`);
                        return;
                    }
                }
            }
        }

        // Check for Comet Browser's MCP API (Model Context Protocol)
        // Comet exposes this API for AI extensions to execute local commands
        if (window.mcp || window.__mcp || window.comet || window.__comet) {
            this.detectionReasons.push('Comet Browser MCP API detected (AI browser)');
        }

        // Check for Comet-specific properties
        if (window.navigator.userAgent.includes('Comet') || 
            (window.chrome && window.chrome.runtime && window.chrome.runtime.id && 
             window.chrome.runtime.id.includes('comet'))) {
            this.detectionReasons.push('Comet Browser detected via user agent or extension ID');
        }
    }

    /**
     * Check for headless browser indicators
     */
    checkHeadlessBrowser() {
        // Headless Chrome indicators
        if (!navigator.plugins || navigator.plugins.length === 0) {
            if (navigator.userAgent.includes('Chrome')) {
                this.detectionReasons.push('Headless browser detected: No plugins in Chrome');
            }
        }

        // Missing languages
        if (!navigator.languages || navigator.languages.length === 0) {
            this.detectionReasons.push('Headless browser detected: Missing language preferences');
        }

        // Missing permissions
        if (navigator.permissions && navigator.permissions.query) {
            navigator.permissions.query({ name: 'notifications' }).then(result => {
                if (result.state === 'denied' && navigator.userAgent.includes('Chrome')) {
                    // This might indicate headless, but don't fail on this alone
                }
            }).catch(() => {});
        }

        // Check for missing WebGL
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        if (!gl) {
            this.detectionReasons.push('Headless browser detected: Missing WebGL support');
        }

        // Screen dimensions check
        if (screen.width === 0 || screen.height === 0) {
            this.detectionReasons.push('Headless browser detected: Invalid screen dimensions');
        }

        // Window outer dimensions
        if (window.outerWidth === 0 || window.outerHeight === 0) {
            this.detectionReasons.push('Headless browser detected: Invalid window dimensions');
        }
    }

    /**
     * Check for browser extension APIs that AI plugins might use
     */
    checkExtensionAPIs() {
        // Check for Chrome extension APIs (some AI tools inject these)
        if (window.chrome && window.chrome.runtime) {
            try {
                // Try to access extension ID - if it fails, might be automation
                if (window.chrome.runtime.id && window.chrome.runtime.id.includes('ai') || 
                    window.chrome.runtime.id && window.chrome.runtime.id.includes('automation')) {
                    this.detectionReasons.push('AI/automation browser extension detected via Chrome runtime API');
                }
            } catch (e) {
                // Some automation frameworks break extension access
            }
        }

        // Check for injected AI-related global objects
        const aiKeywords = [
            'openai',
            'chatgpt',
            'claude',
            'bard',
            'gemini',
            'anthropic',
            'automation',
            'bot',
            'ai_extension',
            'aiExtension',
            'aiBrowser',
            'ai_browser',
            'antigravity',
            'antigravityAI',
            'antigravity_ai',
            'comet',
            'cometAI',
            'perplexity'
        ];

        for (const keyword of aiKeywords) {
            if (window[keyword] || window[keyword.toUpperCase()] || window[`_${keyword}`]) {
                this.detectionReasons.push(`AI-related object detected in window: ${keyword}`);
            }
        }

        // Specifically check for Google's Antigravity AI extension
        // Antigravity is a Chrome extension for development that uses AI
        if (window.chrome && window.chrome.runtime) {
            try {
                // Check extension IDs that might be Antigravity
                const extensionId = window.chrome.runtime.id;
                if (extensionId) {
                    // Common Antigravity extension ID patterns (these may change, but checking)
                    if (extensionId.includes('antigravity') || 
                        extensionId.includes('google-ai') ||
                        extensionId.includes('gemini-dev')) {
                        this.detectionReasons.push('Google Antigravity AI extension detected');
                    }
                }

                // Check for Antigravity-specific APIs or properties
                if (window.chrome.runtime.getManifest) {
                    try {
                        const manifest = window.chrome.runtime.getManifest();
                        if (manifest && (
                            manifest.name && manifest.name.toLowerCase().includes('antigravity') ||
                            manifest.description && manifest.description.toLowerCase().includes('antigravity')
                        )) {
                            this.detectionReasons.push('Google Antigravity AI extension detected via manifest');
                        }
                    } catch (e) {
                        // Can't access manifest, that's okay
                    }
                }
            } catch (e) {
                // Extension API access failed, might indicate automation
            }
        }

        // Check for known AI browser extension patterns
        if (document.querySelector('script[src*="ai"]') || 
            document.querySelector('script[src*="automation"]') ||
            document.querySelector('script[src*="bot"]')) {
            this.detectionReasons.push('AI/automation script detected in DOM');
        }
    }

    /**
     * Check for navigator property inconsistencies
     */
    checkNavigatorInconsistencies() {
        // Check if navigator properties are inconsistent
        const hasUserAgent = 'userAgent' in navigator;
        const hasPlatform = 'platform' in navigator;
        const hasLanguage = 'language' in navigator;
        const hasVendor = 'vendor' in navigator;

        if (!hasUserAgent || !hasPlatform || !hasLanguage || !hasVendor) {
            this.detectionReasons.push('Navigator properties incomplete (possible automation)');
        }

        // Check for spoofed navigator
        try {
            const desc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
            if (desc && !desc.configurable) {
                this.detectionReasons.push('Non-configurable webdriver property detected');
            }
        } catch (e) {
            // Ignore
        }
    }

    /**
     * Check for WebDriver property
     */
    checkWebDriver() {
        // Standard WebDriver check
        if (navigator.webdriver === true) {
            this.detectionReasons.push('WebDriver property is true (automation detected)');
        }

        // Try to detect if webdriver was deleted and re-added (common evasion technique)
        const webdriverDesc = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
        if (webdriverDesc) {
            // Some automation tools delete and redefine webdriver
            try {
                delete navigator.webdriver;
                if (navigator.webdriver === undefined) {
                    Object.defineProperty(navigator, 'webdriver', {
                        get: () => false
                    });
                }
            } catch (e) {
                // If we can't modify it, might be automation
                this.detectionReasons.push('WebDriver property is non-configurable (suspicious)');
            }
        }
    }

    /**
     * Check for Chrome DevTools Protocol indicators
     */
    checkCDPIndicators() {
        // CDP often exposes __chrome and __puppeteer
        if (window.__chrome || window.__puppeteer || window.__playwright) {
            this.detectionReasons.push('Chrome DevTools Protocol indicators detected');
        }

        // Check for known CDP-related properties
        if (window.chrome && window.chrome.runtime && window.chrome.runtime.onConnect) {
            // Some automation tools leave CDP traces
            try {
                // This is just a check, not modifying anything
                const descriptor = Object.getOwnPropertyDescriptor(window, '__puppeteer_evaluation__');
                if (descriptor) {
                    this.detectionReasons.push('Puppeteer evaluation script detected');
                }
            } catch (e) {
                // Ignore errors
            }
        }
    }

    /**
     * Check browser plugins for AI-related extensions
     */
    async checkPlugins() {
        if (navigator.plugins) {
            for (let i = 0; i < navigator.plugins.length; i++) {
                const plugin = navigator.plugins[i];
                const pluginName = plugin.name.toLowerCase();
                const pluginDesc = plugin.description.toLowerCase();

                const aiKeywords = [
                    'ai',
                    'automation',
                    'bot',
                    'selenium',
                    'puppeteer',
                    'playwright',
                    'webdriver',
                    'headless',
                    'antigravity',
                    'comet',
                    'perplexity',
                    'gemini',
                    'chatgpt',
                    'claude',
                    'aria',
                    'leo'
                ];

                // Check for specific known AI plugin/extension names
                const specificAIPlugins = [
                    'Google Antigravity',
                    'Antigravity AI',
                    'Comet Browser',
                    'Perplexity AI',
                    'ChatGPT Extension',
                    'Claude Extension',
                    'Gemini Extension',
                    'Brave Leo',
                    'Opera Aria'
                ];

                for (const pluginName of specificAIPlugins) {
                    if (plugin.name.includes(pluginName) || plugin.description.includes(pluginName)) {
                        this.detectionReasons.push(`Known AI plugin/extension detected: ${plugin.name}`);
                        return;
                    }
                }

                for (const keyword of aiKeywords) {
                    if (pluginName.includes(keyword) || pluginDesc.includes(keyword)) {
                        this.detectionReasons.push(`AI/automation plugin detected: ${plugin.name}`);
                        return;
                    }
                }
            }
        }
    }

    /**
     * Check user agent for anomalies and AI browser identifiers
     */
    checkUserAgent() {
        const ua = navigator.userAgent;
        const uaLower = ua.toLowerCase();

        // Missing user agent
        if (!ua || ua.length < 10) {
            this.detectionReasons.push('Invalid or missing user agent');
            return;
        }

        // Check for specific AI browser user agent strings
        // Comet Browser typically includes "Comet" or "Perplexity" in user agent
        if (ua.includes('Comet') || ua.includes('CometBrowser') || 
            (ua.includes('Perplexity') && uaLower.includes('comet'))) {
            this.detectionReasons.push('Comet Browser detected in user agent');
        }

        // Check for other AI browser identifiers in user agent
        const aiBrowserUAPatterns = [
            { pattern: /antigravity/i, name: 'Antigravity AI' },
            { pattern: /arc.*ai|thebrowsercompany/i, name: 'Arc Browser AI' },
            { pattern: /brave.*leo|leo.*ai/i, name: 'Brave Leo AI' },
            { pattern: /opera.*aria|aria.*ai/i, name: 'Opera Aria AI' },
            { pattern: /bing.*chat|bing.*ai/i, name: 'Bing Chat AI Browser' }
        ];

        for (const { pattern, name } of aiBrowserUAPatterns) {
            if (pattern.test(ua)) {
                this.detectionReasons.push(`${name} detected in user agent`);
            }
        }

        // User agent doesn't match platform
        const platform = navigator.platform.toLowerCase();
        if (platform.includes('win') && !ua.includes('Windows')) {
            this.detectionReasons.push('User agent/platform mismatch detected');
        }
        if (platform.includes('mac') && !ua.includes('Mac')) {
            this.detectionReasons.push('User agent/platform mismatch detected');
        }
        if (platform.includes('linux') && !ua.includes('Linux')) {
            this.detectionReasons.push('User agent/platform mismatch detected');
        }
    }

    /**
     * Check permissions API for anomalies
     */
    async checkPermissions() {
        if (!navigator.permissions || !navigator.permissions.query) {
            return;
        }

        try {
            // In headless browsers, permissions might behave differently
            const result = await navigator.permissions.query({ name: 'notifications' });
            // Just checking if it works, not using the result to fail
        } catch (e) {
            // Some automation tools break the permissions API
            if (e.message && e.message.includes('not supported')) {
                // This is normal for some browsers
            } else {
                // Suspicious error
                this.detectionReasons.push('Permissions API anomaly detected');
            }
        }
    }

    /**
     * Check canvas fingerprint for anomalies
     */
    checkCanvasFingerprint() {
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            
            // Draw some text
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.textBaseline = 'alphabetic';
            ctx.fillStyle = '#f60';
            ctx.fillRect(125, 1, 62, 20);
            ctx.fillStyle = '#069';
            ctx.fillText('AI detection test 🔐', 2, 15);
            ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
            ctx.fillText('AI detection test 🔐', 4, 17);

            const fingerprint = canvas.toDataURL();
            
            // In headless/automated browsers, canvas might produce consistent or empty fingerprints
            if (!fingerprint || fingerprint.length < 100) {
                this.detectionReasons.push('Canvas fingerprint anomaly detected');
            }
        } catch (e) {
            this.detectionReasons.push('Canvas fingerprinting failed (possible automation)');
        }
    }

    /**
     * Check Battery API for anomalies (headless browsers often report incorrectly)
     */
    async checkBatteryAPI() {
        if (navigator.getBattery) {
            try {
                const battery = await navigator.getBattery();
                // In headless browsers, battery might always report charging or have weird values
                if (battery) {
                    // Automation tools often report battery incorrectly
                    if (battery.level === 1 && battery.charging === false) {
                        // Suspicious: 100% battery but not charging
                        this.detectionReasons.push('Battery API reports suspicious values (possible automation)');
                    }
                    // Some automation tools don't implement battery events properly
                    if (battery.addEventListener && typeof battery.addEventListener !== 'function') {
                        this.detectionReasons.push('Battery API missing event listeners (possible automation)');
                    }
                }
            } catch (e) {
                // Some automation tools break the Battery API
                if (e.name !== 'NotSupportedError' && e.name !== 'SecurityError') {
                    this.detectionReasons.push('Battery API error (possible automation)');
                }
            }
        }
    }

    /**
     * Check audio context fingerprinting for anomalies
     */
    checkAudioFingerprint() {
        try {
            const AudioContext = window.AudioContext || window.webkitAudioContext;
            if (!AudioContext) {
                return;
            }

            const audioContext = new AudioContext();
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gainNode = audioContext.createGain();
            const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);

            gainNode.gain.value = 0; // Mute audio
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(audioContext.destination);

            oscillator.start(0);
            scriptProcessor.onaudioprocess = (e) => {
                const samples = e.inputBuffer.getChannelData(0);
                const sum = samples.reduce((a, b) => a + Math.abs(b), 0);
                
                // Automation tools often produce different audio fingerprints
                if (sum === 0 || isNaN(sum) || !isFinite(sum)) {
                    this.detectionReasons.push('Audio fingerprinting anomaly detected (possible automation)');
                }
                
                oscillator.stop();
                audioContext.close();
            };

            // Timeout for safety
            setTimeout(() => {
                try {
                    oscillator.stop();
                    audioContext.close();
                } catch (e) {}
            }, 1000);
        } catch (e) {
            // Some automation tools break the Audio API
            this.detectionReasons.push('Audio fingerprinting failed (possible automation)');
        }
    }

    /**
     * Check font fingerprinting for anomalies
     */
    async checkFontFingerprint() {
        try {
            // Check for common fonts that should be available
            const testFonts = [
                'Arial', 'Times New Roman', 'Courier New', 'Verdana', 
                'Georgia', 'Palatino', 'Garamond', 'Bookman', 'Comic Sans MS',
                'Trebuchet MS', 'Impact', 'Lucida Console', 'Tahoma'
            ];

            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            const testString = 'abcdefghijklmnopqrstuvwxyz0123456789';
            const baseline = [];

            // Get baseline measurements with a known font
            ctx.font = '72px monospace';
            const baselineWidth = ctx.measureText(testString).width;

            let missingFonts = 0;
            for (const font of testFonts) {
                ctx.font = `72px "${font}", monospace`;
                const width = ctx.measureText(testString).width;
                
                // If width matches baseline exactly, font likely not loaded
                if (Math.abs(width - baselineWidth) < 0.1) {
                    missingFonts++;
                }
            }

            // Automation tools often report fewer available fonts
            if (missingFonts > testFonts.length * 0.7) {
                this.detectionReasons.push('Font fingerprinting indicates missing fonts (possible automation)');
            }
        } catch (e) {
            // Font detection failed
            this.detectionReasons.push('Font fingerprinting failed (possible automation)');
        }
    }

    /**
     * Check WebRTC for IP leaks and automation indicators
     */
    async checkWebRTC() {
        try {
            const RTCPeerConnection = window.RTCPeerConnection || 
                                     window.webkitRTCPeerConnection || 
                                     window.mozRTCPeerConnection;
            
            if (!RTCPeerConnection) {
                return;
            }

            // Create a peer connection to check for WebRTC behavior
            const pc = new RTCPeerConnection({
                iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
            });

            // Automation tools often have different WebRTC behavior
            let candidateFound = false;
            pc.onicecandidate = (event) => {
                if (event.candidate) {
                    candidateFound = true;
                    // Check candidate for suspicious patterns
                    if (event.candidate.candidate.includes('127.0.0.1') || 
                        event.candidate.candidate.includes('localhost')) {
                        this.detectionReasons.push('WebRTC reports localhost (possible automation/proxy)');
                    }
                } else {
                    // ICE gathering complete
                    if (!candidateFound && pc.localDescription) {
                        this.detectionReasons.push('WebRTC ICE gathering anomaly (possible automation)');
                    }
                    pc.close();
                }
            };

            // Create an offer to trigger ICE gathering
            await pc.createDataChannel('test');
            const offer = await pc.createOffer();
            await pc.setLocalDescription(offer);

            // Timeout for cleanup
            setTimeout(() => {
                try {
                    pc.close();
                } catch (e) {}
            }, 5000);
        } catch (e) {
            // Some automation tools break WebRTC
            if (e.name !== 'NotSupportedError' && e.name !== 'SecurityError') {
                this.detectionReasons.push('WebRTC API error (possible automation)');
            }
        }
    }

    /**
     * Check connection type for anomalies
     */
    checkConnectionType() {
        if (navigator.connection || navigator.mozConnection || navigator.webkitConnection) {
            const connection = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
            
            // Automation tools often report unusual connection types
            if (connection) {
                // Check for impossible or suspicious values
                if (connection.effectiveType === 'slow-2g' && connection.downlink > 0.5) {
                    this.detectionReasons.push('Connection type mismatch detected (possible automation)');
                }
                
                // Some automation tools don't properly implement connection API
                if (connection.downlink === 0 && connection.effectiveType !== 'offline') {
                    this.detectionReasons.push('Connection API reports suspicious values (possible automation)');
                }
            }
        }
    }

    /**
     * Check for automation-related service workers
     */
    async checkServiceWorkers() {
        if ('serviceWorker' in navigator) {
            try {
                const registrations = await navigator.serviceWorker.getRegistrations();
                
                for (const registration of registrations) {
                    // Check for automation-related service worker names
                    const scope = registration.scope.toLowerCase();
                    const keywords = ['automation', 'selenium', 'puppeteer', 'playwright', 'bot', 'ai', 'test'];
                    
                    for (const keyword of keywords) {
                        if (scope.includes(keyword)) {
                            this.detectionReasons.push(`Automation-related service worker detected: ${registration.scope}`);
                            return;
                        }
                    }
                }
            } catch (e) {
                // Some automation tools break service worker API
                if (e.name !== 'SecurityError') {
                    this.detectionReasons.push('Service Worker API error (possible automation)');
                }
            }
        }
    }

    /**
     * Check performance and timing for anomalies
     */
    checkPerformanceAnomalies() {
        try {
            // Check for suspiciously fast or perfectly timed operations
            const perf = window.performance;
            if (perf && perf.now) {
                const start = perf.now();
                
                // Do some work
                let sum = 0;
                for (let i = 0; i < 10000; i++) {
                    sum += Math.random();
                }
                
                const end = perf.now();
                const duration = end - start;
                
                // Automation tools might report impossibly fast or perfectly consistent times
                if (duration < 0.1) {
                    // Suspiciously fast (might indicate virtual environment)
                    this.detectionReasons.push('Performance timing anomaly: operations too fast (possible automation)');
                }
            }

            // Check for missing performance timing entries (automation tools often skip these)
            if (perf && perf.getEntriesByType) {
                const navigationEntries = perf.getEntriesByType('navigation');
                if (navigationEntries.length === 0 && document.readyState === 'complete') {
                    this.detectionReasons.push('Missing performance navigation entries (possible automation)');
                }
            }
        } catch (e) {
            // Performance API error
            this.detectionReasons.push('Performance API error (possible automation)');
        }
    }

    /**
     * Check media devices for anomalies
     */
    async checkMediaDevices() {
        if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
            try {
                const devices = await navigator.mediaDevices.enumerateDevices();
                
                // Automation tools often report different or missing media devices
                const videoDevices = devices.filter(d => d.kind === 'videoinput');
                const audioDevices = devices.filter(d => d.kind === 'audioinput');
                
                // In headless browsers, there are often no media devices
                if (videoDevices.length === 0 && audioDevices.length === 0) {
                    // This could be normal, but combined with other indicators, it's suspicious
                    // Don't fail on this alone
                }
                
                // Check for suspicious device IDs (automation tools often use generic IDs)
                for (const device of devices) {
                    if (device.deviceId && (
                        device.deviceId === 'default' ||
                        device.deviceId.includes('virtual') ||
                        device.deviceId.includes('fake') ||
                        device.deviceId.length < 10
                    )) {
                        this.detectionReasons.push('Suspicious media device ID detected (possible automation)');
                        return;
                    }
                }
            } catch (e) {
                // Some automation tools break media device enumeration
                if (e.name !== 'NotAllowedError' && e.name !== 'SecurityError') {
                    this.detectionReasons.push('Media devices API error (possible automation)');
                }
            }
        }
    }

    /**
     * Check for automation-related web workers
     */
    checkWorkers() {
        // Check if Worker API is available and behaves correctly
        if (typeof Worker !== 'undefined') {
            try {
                // Create a test worker to check for anomalies
                const workerCode = `self.onmessage = function(e) { self.postMessage(e.data); }`;
                const blob = new Blob([workerCode], { type: 'application/javascript' });
                const workerUrl = URL.createObjectURL(blob);
                const worker = new Worker(workerUrl);
                
                let responded = false;
                worker.onmessage = (e) => {
                    responded = true;
                    worker.terminate();
                    URL.revokeObjectURL(workerUrl);
                };
                
                worker.postMessage('test');
                
                // Some automation tools don't properly support workers
                setTimeout(() => {
                    if (!responded) {
                        this.detectionReasons.push('Web Worker anomaly detected (possible automation)');
                    }
                    try {
                        worker.terminate();
                        URL.revokeObjectURL(workerUrl);
                    } catch (e) {}
                }, 1000);
            } catch (e) {
                // Worker creation failed - suspicious
                this.detectionReasons.push('Web Worker API error (possible automation)');
            }
        }
    }

    /**
     * Check screen and window properties for anomalies
     */
    checkScreenProperties() {
        // Check for inconsistent screen properties
        if (screen.availWidth === 0 || screen.availHeight === 0) {
            this.detectionReasons.push('Invalid screen dimensions detected (possible automation)');
        }

        // Check for mismatch between screen and window dimensions
        if (window.innerWidth > screen.width || window.innerHeight > screen.height) {
            this.detectionReasons.push('Window dimensions exceed screen dimensions (possible automation)');
        }

        // Check for missing or unusual color depth
        if (screen.colorDepth < 16 || screen.pixelDepth < 16) {
            this.detectionReasons.push('Unusual color depth detected (possible automation)');
        }

        // Check for device pixel ratio anomalies
        if (window.devicePixelRatio && (window.devicePixelRatio < 0.5 || window.devicePixelRatio > 5)) {
            this.detectionReasons.push('Suspicious device pixel ratio (possible automation)');
        }

        // Check for orientation lock support (headless browsers often lack this)
        if (screen.orientation && typeof screen.orientation.lock !== 'function') {
            // This is actually normal in many browsers, so we won't fail on this alone
        }
    }

    /**
     * Show blocking message and prevent app from running
     */
    blockApplication(reasons) {
        // Create blocking overlay
        const overlay = document.createElement('div');
        overlay.id = 'ai-detection-block';
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: linear-gradient(135deg, #1e1e2e 0%, #2d2d44 100%);
            z-index: 999999;
            display: flex;
            align-items: center;
            justify-content: center;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            color: #fff;
        `;

        const content = document.createElement('div');
        content.style.cssText = `
            max-width: 600px;
            padding: 40px;
            background: rgba(0, 0, 0, 0.7);
            border-radius: 16px;
            border: 2px solid #ff4444;
            box-shadow: 0 8px 32px rgba(255, 68, 68, 0.3);
            text-align: center;
        `;

        const icon = document.createElement('div');
        icon.innerHTML = '🚫';
        icon.style.cssText = `
            font-size: 64px;
            margin-bottom: 20px;
        `;

        const title = document.createElement('h1');
        title.textContent = 'AI Browser Detected';
        title.style.cssText = `
            font-size: 28px;
            margin: 0 0 20px 0;
            color: #ff4444;
        `;

        const message = document.createElement('p');
        message.textContent = 'This application cannot run in AI-driven browsers, automation frameworks, or browser extensions that modify browser behavior for automated access.';
        message.style.cssText = `
            font-size: 16px;
            line-height: 1.6;
            margin: 0 0 30px 0;
            color: #e0e0e0;
        `;

        const reasonsList = document.createElement('div');
        reasonsList.style.cssText = `
            background: rgba(255, 68, 68, 0.1);
            border-left: 4px solid #ff4444;
            padding: 15px;
            margin: 20px 0;
            text-align: left;
            border-radius: 4px;
        `;

        const reasonsTitle = document.createElement('strong');
        reasonsTitle.textContent = 'Detection Reasons:';
        reasonsTitle.style.cssText = `
            display: block;
            margin-bottom: 10px;
            color: #ff6666;
        `;
        reasonsList.appendChild(reasonsTitle);

        const reasonsUL = document.createElement('ul');
        reasonsUL.style.cssText = `
            margin: 0;
            padding-left: 20px;
            color: #e0e0e0;
            font-size: 14px;
        `;

        reasons.forEach(reason => {
            const li = document.createElement('li');
            li.textContent = reason;
            li.style.marginBottom = '8px';
            reasonsUL.appendChild(li);
        });
        reasonsList.appendChild(reasonsUL);

        const instruction = document.createElement('p');
        instruction.textContent = 'Please use a standard, unmodified browser without automation tools or AI extensions.';
        instruction.style.cssText = `
            font-size: 14px;
            color: #aaa;
            margin-top: 30px;
            font-style: italic;
        `;

        content.appendChild(icon);
        content.appendChild(title);
        content.appendChild(message);
        content.appendChild(reasonsList);
        content.appendChild(instruction);
        overlay.appendChild(content);
        document.body.appendChild(overlay);

        // Prevent all interaction
        document.body.style.overflow = 'hidden';
        
        // Remove all other content
        const allElements = document.body.children;
        for (let i = 0; i < allElements.length; i++) {
            if (allElements[i] !== overlay) {
                allElements[i].style.display = 'none';
            }
        }

        // Log to console for debugging
        console.error('🚫 AI Browser Detection:', reasons);
    }
}

// Export singleton instance
const aiDetectionService = new AIDetectionService();

export default aiDetectionService;

