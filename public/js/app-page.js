/**
 * App Page Controller
 * Handles the /app page functionality for linked device sessions
 * This is separate from the main app.js which handles the home page
 */

class AppPageController {
    constructor() {
        this.linkId = null;
        this.signatureShare = null;
        this.connectionMonitor = null;
    }

    /**
     * Initialize the app page
     */
    async initialize() {
        try {
            console.log('🚀 Initializing App Page...');
            
            // Get session info from URL params
            this.extractUrlParams();
            
            // Set up the page
            this.setupPage();
            
            // Load fingerprint data
            await this.loadFingerprintData();
            
            // Initialize signature sharing if linkId is available
            if (this.linkId) {
                await this.initializeSignatureSharing();
            } else {
                this.updateScribbleStatus('No link ID provided', 'error');
            }
            
            // Set up global functions
            this.setupGlobalFunctions();
            
            console.log('✅ App Page initialized successfully');
            
        } catch (error) {
            console.error('❌ Failed to initialize App Page:', error);
            this.showError('Failed to initialize app page: ' + error.message);
        }
    }

    /**
     * Extract parameters from URL
     */
    extractUrlParams() {
        const urlParams = new URLSearchParams(window.location.search);
        this.linkId = urlParams.get('lid') || urlParams.get('linkId') || null;
        console.log('📱 Link ID:', this.linkId);
    }

    /**
     * Set up basic page elements
     */
    setupPage() {
        const linkedAt = new Date().toLocaleString();
        const linkedAtElement = document.getElementById('linkedAt');
        if (linkedAtElement) {
            linkedAtElement.textContent = linkedAt;
        }
    }

    /**
     * Load and display fingerprint data for both desktop and mobile
     */
    async loadFingerprintData() {
        try {
            console.log('🔍 Loading fingerprint data...');
            
            const response = await fetch('/session/fingerprint-data', {
                credentials: 'include'
            });
            
            if (!response.ok) {
                throw new Error(`Failed to load fingerprint data: ${response.status}`);
            }
            
            const data = await response.json();
            console.log('📊 Fingerprint data received:', data);
            
            // Display desktop fingerprint
            this.displayDesktopFingerprint(data.desktop);
            
            // Display mobile fingerprint
            this.displayMobileFingerprint(data.mobile);
            
        } catch (error) {
            console.error('❌ Failed to load fingerprint data:', error);
            this.showFingerprintError('Failed to load fingerprint data: ' + error.message);
        }
    }

    /**
     * Display desktop fingerprint data
     */
    displayDesktopFingerprint(desktopData) {
        const elementId = 'desktopFingerprintSummary';
        
        if (!desktopData.fingerprint || Object.keys(desktopData.fingerprint).length === 0) {
            this.showNoDataMessage(elementId, 'No desktop fingerprint data available');
        } else {
            this.displayFingerprintData(desktopData.fingerprint, desktopData.device_type, elementId);
        }
    }

    /**
     * Display mobile fingerprint data
     */
    displayMobileFingerprint(mobileData) {
        const elementId = 'mobileFingerprintSummary';
        
        if (!mobileData.linked) {
            this.showNoDataMessage(elementId, 'No mobile session linked yet');
        } else if (!mobileData.fingerprint || Object.keys(mobileData.fingerprint).length === 0) {
            this.showNoDataMessage(elementId, 'No mobile fingerprint data available');
        } else {
            this.displayFingerprintData(mobileData.fingerprint, mobileData.device_type, elementId);
        }
    }

    /**
     * Display fingerprint data in a formatted way
     */
    displayFingerprintData(fingerprint, deviceType = 'unknown', targetElementId) {
        const summaryEl = document.getElementById(targetElementId);
        if (!summaryEl) {
            console.warn(`Element ${targetElementId} not found`);
            return;
        }
        
        const info = this.formatFingerprintInfo(fingerprint, deviceType);
        const html = this.generateFingerprintHTML(info);
        
        summaryEl.innerHTML = html;
        console.log(`✅ Displayed fingerprint data for ${deviceType}`);
    }

    /**
     * Format fingerprint information for display
     */
    formatFingerprintInfo(fingerprint, deviceType) {
        return {
            'Device Type': deviceType.charAt(0).toUpperCase() + deviceType.slice(1),
            'User Agent': fingerprint.userAgent || 'Unknown',
            'Screen Resolution': fingerprint.screenResolution || 'Unknown',
            'Platform': fingerprint.platform || 'Unknown',
            'Language': fingerprint.language || 'Unknown',
            'Timezone': fingerprint.timezone || 'Unknown',
            'IP Address': fingerprint.ip_address || 'Unknown',
            'Collection Time': fingerprint.timestamp ? new Date(fingerprint.timestamp).toLocaleString() : 'Unknown'
        };
    }

    /**
     * Generate HTML for fingerprint display
     */
    generateFingerprintHTML(info) {
        let html = '<div class="fingerprint-category">';
        html += '<div class="fingerprint-category-title">Device Information</div>';
        
        for (const [label, value] of Object.entries(info)) {
            html += `<div class="fingerprint-item">
                <span class="fingerprint-label">${label}:</span>
                <span class="fingerprint-value">${value}</span>
            </div>`;
        }
        
        html += '</div>';
        return html;
    }

    /**
     * Show "no data" message
     */
    showNoDataMessage(elementId, message) {
        const element = document.getElementById(elementId);
        if (element) {
            element.innerHTML = `<div class="fingerprint-loading">${message}</div>`;
        }
    }

    /**
     * Show fingerprint error
     */
    showFingerprintError(message) {
        const desktopEl = document.getElementById('desktopFingerprintSummary');
        const mobileEl = document.getElementById('mobileFingerprintSummary');
        
        if (desktopEl) {
            desktopEl.innerHTML = `<div class="fingerprint-loading">${message}</div>`;
        }
        if (mobileEl) {
            mobileEl.innerHTML = `<div class="fingerprint-loading">${message}</div>`;
        }
    }

    /**
     * Initialize signature sharing functionality
     */
    async initializeSignatureSharing() {
        try {
            console.log('🔗 Initializing signature sharing...');
            this.updateScribbleStatus('Connecting to mobile device...', 'connecting');
            
            // Import and initialize signature sharing
            const { SignatureShare } = await import('/src/signature-share.js');
            this.signatureShare = new SignatureShare();
            
            // Initialize for desktop (viewing)
            this.signatureShare.initDesktop(this.linkId);
            
            // Set up WebSocket connection monitoring
            this.setupConnectionMonitoring();
            
            this.updateScribbleStatus('Connected! Draw on your mobile device to see it here.', 'connected');
            console.log('✅ Signature sharing initialized');
            
        } catch (error) {
            console.error('❌ Failed to initialize signature sharing:', error);
            this.updateScribbleStatus('Failed to connect to mobile device', 'error');
        }
    }

    /**
     * Set up WebSocket connection monitoring
     */
    setupConnectionMonitoring() {
        if (this.connectionMonitor) {
            clearInterval(this.connectionMonitor);
        }
        
        this.connectionMonitor = setInterval(() => {
            this.checkConnectionStatus();
        }, 2000);
    }

    /**
     * Check WebSocket connection status
     */
    checkConnectionStatus() {
        if (!this.signatureShare || !this.signatureShare.websocket) {
            return;
        }
        
        const ws = this.signatureShare.websocket;
        
        if (ws.readyState === WebSocket.OPEN) {
            this.updateScribbleStatus('Connected! Draw on your mobile device to see it here.', 'connected');
        } else if (ws.readyState === WebSocket.CONNECTING) {
            this.updateScribbleStatus('Connecting to mobile device...', 'connecting');
        } else {
            this.updateScribbleStatus('Connection lost. Mobile device may have disconnected.', 'error');
        }
    }

    /**
     * Update scribble status display
     */
    updateScribbleStatus(message, status) {
        const statusIndicator = document.querySelector('.status-indicator');
        const statusText = document.querySelector('.status-text');
        
        if (statusIndicator && statusText) {
            statusText.textContent = message;
            
            // Update indicator color based on status
            statusIndicator.className = 'status-indicator';
            if (status === 'connected') {
                statusIndicator.classList.add('connected');
            } else if (status === 'error') {
                statusIndicator.classList.add('error');
            }
        }
    }

    /**
     * Set up global functions that need to be accessible from HTML
     */
    setupGlobalFunctions() {
        // Global function for killing session
        window.killSession = async () => {
            await this.killSession();
        };
    }

    /**
     * Kill the current session
     */
    async killSession() {
        console.log('💀 Kill session requested');
        
        if (!confirm('Are you sure you want to kill this session? This will terminate the connection completely.')) {
            return;
        }
        
        try {
            // Close any WebSocket connections
            if (this.signatureShare && this.signatureShare.websocket) {
                this.signatureShare.websocket.close();
            }
            
            // Call server endpoint to kill the session
            const response = await fetch('/session/kill', {
                method: 'POST',
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                alert('Session killed successfully. Redirecting to home page.');
                window.location.href = '/';
            } else {
                alert('Failed to kill session. Please try again.');
            }
            
        } catch (error) {
            console.error('❌ Error killing session:', error);
            alert('Error killing session. Please try again.');
        }
    }

    /**
     * Show error message
     */
    showError(message) {
        console.error('🚨 App Page Error:', message);
        // Could add UI error display here if needed
    }

    /**
     * Cleanup resources
     */
    cleanup() {
        if (this.connectionMonitor) {
            clearInterval(this.connectionMonitor);
            this.connectionMonitor = null;
        }
        
        if (this.signatureShare && this.signatureShare.websocket) {
            this.signatureShare.websocket.close();
        }
        
        console.log('🧹 App Page cleaned up');
    }
}

// Initialize the app page when DOM is ready
document.addEventListener('DOMContentLoaded', async () => {
    const appPageController = new AppPageController();
    await appPageController.initialize();
    
    // Make controller available globally for debugging
    window.appPageController = appPageController;
    
    // Cleanup on page unload
    window.addEventListener('beforeunload', () => {
        appPageController.cleanup();
    });
});

// Auto-close after 10 seconds if opened in popup
if (window.opener) {
    setTimeout(() => {
        window.close();
    }, 10000);
}
