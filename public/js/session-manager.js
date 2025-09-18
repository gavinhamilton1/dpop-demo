/**
 * Session Manager - Handles session status and TTL display
 */

class SessionManager {
    constructor() {
        this.isInitialized = false;
        
        this.init();
    }
    
    init() {
        console.log('SessionManager initializing...');
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            console.log('DOM still loading, waiting for DOMContentLoaded...');
            document.addEventListener('DOMContentLoaded', () => {
                console.log('DOMContentLoaded fired, setting up components...');
                this.setupSessionStatus();
                this.setupSignalModal();
                this.setupFlushButtons();
            });
        } else {
            console.log('DOM already ready, setting up components immediately...');
            this.setupSessionStatus();
            this.setupSignalModal();
            this.setupFlushButtons();
        }
    }
    
    setupSessionStatus() {
        // Initialize session status
        this.updateSessionStatus('Initializing session...', 'Checking for existing browser identity and session', 'loading');
        
        // Simulate session initialization
        setTimeout(() => {
            this.updateSessionStatus('Session Restored', ' Welcome back! Browser identity registered and DPoP bound successfully.', 'reconnect');
            this.showSignalSummary();
        }, 2000);
    }
    
    updateSessionStatus(text, detail, status = 'loading') {
        const statusIndicator = document.getElementById('sessionStatusIndicator');
        const statusTitle = document.querySelector('#sessionStatusIndicator .status-title');
        const statusDetail = document.querySelector('#sessionStatusIndicator .status-detail');
        
        if (statusTitle) statusTitle.textContent = text;
        if (statusDetail) statusDetail.textContent = detail;
        
        if (statusIndicator) {
            // Remove existing status classes
            statusIndicator.classList.remove('loading', 'new-session', 'reconnect', 'error');
            // Add new status class
            statusIndicator.classList.add(status);
        }
    }
    
    
    // Public method to update session status from other scripts
    setSessionStatus(text, detail, status = 'loading') {
        this.updateSessionStatus(text, detail, status);
    }
    
    // Simulate new session creation
    simulateNewSession() {
        this.updateSessionStatus('Session Created', 'Welcome! New browser identity registered and DPoP binding established.', 'new-session');
        this.showSignalSummary();
    }
    
    // Simulate session restoration
    simulateSessionRestore() {
        this.updateSessionStatus('Session Restored', 'Welcome back! Browser identity and DPoP binding active.', 'reconnect');
        this.showSignalSummary();
    }
    
    showSignalSummary() {
        const signalSummary = document.getElementById('signalSummary');
        if (signalSummary) {
            signalSummary.style.display = 'block';
            this.updateSignalData();
        }
    }
    
    updateSignalData() {
        // Detect if running on localhost
        const isLocalhost = window.location.hostname === 'localhost' || 
                           window.location.hostname === '127.0.0.1' ||
                           window.location.hostname.startsWith('192.168.') ||
                           window.location.hostname.startsWith('10.') ||
                           window.location.hostname.startsWith('172.');
        
        // Simulate signal data collection
        const signalData = {
            location: {
                city: isLocalhost ? 'Local Development' : 'San Francisco',
                region: isLocalhost ? 'Local Development' : 'California',
                country: isLocalhost ? 'Local Development' : 'United States',
                timezone: isLocalhost ? 'Local Development' : 'America/Los_Angeles'
            },
            device: {
                platform: 'macOS',
                language: 'en-US'
            },
            browser: {
                name: 'Chrome',
                version: '140.0.0.0',
                engine: 'Blink'
            },
            network: {
                connection: 'WiFi',
                speed: 'Fast'
            }
        };
        
        // Update signal summary display
        this.updateSignalSummary(signalData);
        this.updateSignalDetails(signalData);
    }
    
    updateSignalSummary(data) {
        const signalLocation = document.getElementById('signalLocation');
        const signalDevice = document.getElementById('signalDevice');
        const signalBrowser = document.getElementById('signalBrowser');
        
        if (signalLocation) {
            signalLocation.textContent = `${data.location.city}, ${data.location.region}`;
        }
        if (signalDevice) {
            signalDevice.textContent = data.device.platform;
        }
        if (signalBrowser) {
            signalBrowser.textContent = `${data.browser.name} ${data.browser.version}`;
        }
    }
    
    updateSignalDetails(data) {
        const signalDetailsContent = document.getElementById('signalDetailsContent');
        if (signalDetailsContent) {
            signalDetailsContent.innerHTML = `
                <div class="signal-detail-section">
                    <h4 class="signal-detail-title">📍 Location</h4>
                    <div class="signal-detail-grid">
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">City:</span>
                            <span class="signal-detail-value">${data.location.city}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Region:</span>
                            <span class="signal-detail-value">${data.location.region}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Country:</span>
                            <span class="signal-detail-value">${data.location.country}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Timezone:</span>
                            <span class="signal-detail-value">${data.location.timezone}</span>
                        </div>
                    </div>
                </div>
                
                <div class="signal-detail-section">
                    <h4 class="signal-detail-title">💻 Device</h4>
                    <div class="signal-detail-grid">
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Platform:</span>
                            <span class="signal-detail-value">${data.device.platform}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Language:</span>
                            <span class="signal-detail-value">${data.device.language}</span>
                        </div>
                    </div>
                </div>
                
                <div class="signal-detail-section">
                    <h4 class="signal-detail-title">🌐 Browser</h4>
                    <div class="signal-detail-grid">
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Name:</span>
                            <span class="signal-detail-value">${data.browser.name}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Version:</span>
                            <span class="signal-detail-value">${data.browser.version}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Engine:</span>
                            <span class="signal-detail-value">${data.browser.engine}</span>
                        </div>
                    </div>
                </div>
                
                <div class="signal-detail-section">
                    <h4 class="signal-detail-title">🌍 Network</h4>
                    <div class="signal-detail-grid">
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Connection:</span>
                            <span class="signal-detail-value">${data.network.connection}</span>
                        </div>
                        <div class="signal-detail-item">
                            <span class="signal-detail-label">Speed:</span>
                            <span class="signal-detail-value">${data.network.speed}</span>
                        </div>
                    </div>
                </div>
            `;
        }
    }
    
    // Setup signal details modal
    setupSignalModal() {
        const signalDetailsBtn = document.getElementById('signalDetailsBtn');
        const signalModal = document.getElementById('signalDetailsModal');
        const signalModalClose = document.getElementById('signalModalClose');
        
        if (signalDetailsBtn && signalModal) {
            signalDetailsBtn.addEventListener('click', () => {
                signalModal.style.display = 'block';
            });
        }
        
        if (signalModalClose && signalModal) {
            signalModalClose.addEventListener('click', () => {
                signalModal.style.display = 'none';
            });
        }
        
        // Close modal when clicking outside
        if (signalModal) {
            signalModal.addEventListener('click', (e) => {
                if (e.target === signalModal) {
                    signalModal.style.display = 'none';
                }
            });
        }
    }
    
    setupFlushButtons() {
        console.log('Setting up flush buttons...');
        const flushBtn = document.getElementById('flushBtn');
        const clientFlushBtn = document.getElementById('clientFlushBtn');
        
        console.log('Found buttons:', { flushBtn: !!flushBtn, clientFlushBtn: !!clientFlushBtn });
        
        if (flushBtn) {
            flushBtn.addEventListener('click', () => this.handleServerFlush());
            console.log('Server flush button event listener added');
            // Test if button is clickable
            flushBtn.style.cursor = 'pointer';
            console.log('Server flush button styles:', {
                disabled: flushBtn.disabled,
                cursor: flushBtn.style.cursor,
                display: getComputedStyle(flushBtn).display,
                visibility: getComputedStyle(flushBtn).visibility
            });
        } else {
            console.error('Server flush button not found');
        }
        
        if (clientFlushBtn) {
            clientFlushBtn.addEventListener('click', () => this.handleClientFlush());
            console.log('Client flush button event listener added');
            // Test if button is clickable
            clientFlushBtn.style.cursor = 'pointer';
            console.log('Client flush button styles:', {
                disabled: clientFlushBtn.disabled,
                cursor: clientFlushBtn.style.cursor,
                display: getComputedStyle(clientFlushBtn).display,
                visibility: getComputedStyle(clientFlushBtn).visibility
            });
        } else {
            console.error('Client flush button not found');
        }
    }
    
    async handleServerFlush() {
        console.log('Server flush button clicked');
        const flushBtn = document.getElementById('flushBtn');
        if (flushBtn) {
            flushBtn.disabled = true;
            flushBtn.textContent = 'Flushing...';
        }
        
        try {
            console.log('Sending flush request to server...');
            const response = await fetch('/_admin/flush', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            console.log('Server response:', response.status, response.statusText);
            
            if (response.ok) {
                const result = await response.json();
                console.log('Server flush successful:', result);
                
                // Clear session cookie on client side
                document.cookie = 'dpop-fun_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                
                alert('Server data cleared successfully! Reloading page for new session...');
                
                // Reload the page to start fresh
                setTimeout(() => {
                    window.location.reload();
                }, 1000);
            } else {
                throw new Error(`Server flush failed: ${response.status}`);
            }
        } catch (error) {
            console.error('Server flush error:', error);
            alert('Server flush failed: ' + error.message);
        } finally {
            if (flushBtn) {
                flushBtn.disabled = false;
                flushBtn.textContent = 'Server Flush';
            }
        }
    }
    
    async handleClientFlush() {
        console.log('Client flush button clicked');
        const clientFlushBtn = document.getElementById('clientFlushBtn');
        if (clientFlushBtn) {
            clientFlushBtn.disabled = true;
            clientFlushBtn.textContent = 'Flushing...';
        }
        
        try {
            console.log('Starting client data cleanup...');
            
            // Clear IndexedDB using the proper idbWipe function
            if ('indexedDB' in window) {
                console.log('Clearing IndexedDB...');
                try {
                    // Import and use the idbWipe function
                    const { idbWipe } = await import('./idb.js');
                    await idbWipe();
                    console.log('IndexedDB cleared successfully');
                } catch (error) {
                    console.error('Failed to clear IndexedDB:', error);
                    // Fallback to manual deletion
                    await new Promise((resolve, reject) => {
                        const deleteRequest = indexedDB.deleteDatabase('dpop-fun');
                        deleteRequest.onsuccess = () => {
                            console.log('IndexedDB cleared successfully (fallback)');
                            resolve();
                        };
                        deleteRequest.onerror = () => {
                            console.error('Failed to clear IndexedDB (fallback)');
                            reject(new Error('Failed to clear IndexedDB'));
                        };
                        deleteRequest.onblocked = () => {
                            console.warn('IndexedDB delete blocked - closing connections');
                            resolve(); // Continue anyway
                        };
                    });
                }
            } else {
                console.log('IndexedDB not available');
            }
            
            // Clear localStorage
            console.log('Clearing localStorage...');
            localStorage.clear();
            
            // Clear sessionStorage
            console.log('Clearing sessionStorage...');
            sessionStorage.clear();
            
            // Clear cookies (if possible)
                    console.log('Clearing cookies...');
                    // Clear specific session cookie
                    document.cookie = 'dpop-fun_session=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;';
                    // Clear all other cookies
                    document.cookie.split(";").forEach(function(c) {
                        document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
                    });
            
            console.log('Client data cleared successfully');
            alert('Client data cleared successfully!');
            
        } catch (error) {
            console.error('Client flush error:', error);
            alert('Client flush failed: ' + error.message);
        } finally {
            if (clientFlushBtn) {
                clientFlushBtn.disabled = false;
                clientFlushBtn.textContent = 'Client Flush';
            }
        }
    }
}

// Initialize session manager when script loads
console.log('Creating SessionManager instance...');
const sessionManager = new SessionManager();
console.log('SessionManager instance created:', sessionManager);

// Export for use in other modules
window.SessionManager = sessionManager;
