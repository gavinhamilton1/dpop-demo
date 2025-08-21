// public/app.js
import * as Stronghold from '/src/stronghold.js';
import * as Passkeys from '/src/passkeys.js';

(function () {
  console.log('[init] app.js starting');
  
  // Enhanced logging
  const logContainer = document.getElementById('logContainer');
  
  const addLog = (message, type = 'info') => {
    const logEntry = document.createElement('div');
    logEntry.className = `log-entry ${type}`;
    logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logContainer.appendChild(logEntry);
    logContainer.scrollTop = logContainer.scrollHeight;
    console.log(`[${type.toUpperCase()}] ${message}`);
  };

  // Button management with status feedback
  const enableButton = (id) => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
      btn.classList.remove('disabled');
      
      // Restore original text for passkey buttons
      if (id === 'regBtn') {
        btn.innerHTML = '📝 Register Passkey';
        btn.title = '';
      } else if (id === 'authBtn') {
        btn.innerHTML = '🔐 Authenticate Passkey';
        btn.title = '';
      } else {
        btn.innerHTML = btn.getAttribute('data-original-text') || btn.innerHTML;
      }
    }
  };

  const disableButton = (id) => {
    const btn = document.getElementById(id);
    if (btn) btn.disabled = true;
  };

  const setButtonLoading = (id, loadingText = 'Loading...') => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = true;
      btn.classList.add('loading');
      btn.setAttribute('data-original-text', btn.innerHTML);
      btn.innerHTML = `⏳ ${loadingText}`;
    }
  };

  const setButtonSuccess = (id, successText = 'Complete!') => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
      btn.classList.add('success');
      btn.innerHTML = `✓ ${successText}`;
      // Reset after 2 seconds
      setTimeout(() => {
        btn.classList.remove('success');
        const originalText = btn.getAttribute('data-original-text') || btn.innerHTML.replace(/^✓ [^!]*! /, '');
        btn.innerHTML = `${originalText} <span class="btn-status-icon success">✓</span>`;
        // Keep the checkmark permanently
      }, 2000);
    }
  };

  const setButtonError = (id, errorText = 'Failed') => {
    const btn = document.getElementById(id);
    if (btn) {
      btn.disabled = false;
      btn.classList.remove('loading');
      btn.classList.add('error');
      btn.innerHTML = `✗ ${errorText}`;
      // Reset after 3 seconds
      setTimeout(() => {
        btn.classList.remove('error');
        const originalText = btn.getAttribute('data-original-text') || btn.innerHTML.replace(/^✗ [^!]*! /, '');
        btn.innerHTML = `${originalText} <span class="btn-status-icon error">✗</span>`;
        // Keep the error mark permanently
      }, 3000);
    }
  };

  // Initialize all buttons as disabled except the first one
  const buttons = ['bikBtn', 'dpopBtn', 'apiBtn', 'regBtn', 'authBtn', 'linkBtn'];
  buttons.forEach(disableButton);

  // Passkey support detection
  let passkeySupport = { hasAPI: false, uvp: false };

  // Function to check passkey support and update UI
  const checkPasskeySupport = async () => {
    try {
      addLog('Checking passkey support...', 'info');
      passkeySupport = await Passkeys.checkSupport();
      
      if (!passkeySupport.hasAPI) {
        addLog('WebAuthn API not supported - passkeys disabled', 'warning');
        disablePasskeyButtons('WebAuthn API not supported');
      } else if (!passkeySupport.uvp) {
        addLog('User-verifying platform authenticator not available - passkeys disabled', 'warning');
        disablePasskeyButtons('No biometric/security key available');
      } else {
        addLog('Passkey support confirmed - biometric/security key available', 'success');
      }
    } catch (error) {
      addLog(`Passkey support check failed: ${error.message}`, 'error');
      disablePasskeyButtons('Support check failed');
    }
  };

  // Function to disable passkey buttons with reason
  const disablePasskeyButtons = (reason) => {
    const regBtn = document.getElementById('regBtn');
    const authBtn = document.getElementById('authBtn');
    
    if (regBtn) {
      regBtn.disabled = true;
      regBtn.title = `Disabled: ${reason}`;
      regBtn.classList.add('disabled');
      regBtn.innerHTML = `📝 Register Passkey <span class="disabled-reason">(${reason})</span>`;
    }
    
    if (authBtn) {
      authBtn.disabled = true;
      authBtn.title = `Disabled: ${reason}`;
      authBtn.classList.add('disabled');
      authBtn.innerHTML = `🔐 Authenticate Passkey <span class="disabled-reason">(${reason})</span>`;
    }
  };

  // ---------- Button Handlers ----------
  
  // 1. Initialize Session
  const initBtn = document.getElementById('initBtn');
  if (initBtn) {
    initBtn.onclick = async () => {
      try {
        setButtonLoading('initBtn', 'Initializing...');
        addLog('Initializing browser session...', 'info');
        
        const res = await Stronghold.sessionInit({ sessionInitUrl: '/session/init' });
        
        setButtonSuccess('initBtn', 'Initialized!');
        addLog('Session initialized successfully', 'success');
        enableButton('bikBtn');
        
        addLog('Ready to register browser identity', 'info');
      } catch (e) {
        setButtonError('initBtn', 'Failed');
        addLog(`Session initialization failed: ${e.message}`, 'error');
      }
    };
  }

  // 2. Register Browser Identity
  const bikBtn = document.getElementById('bikBtn');
  if (bikBtn) {
    bikBtn.onclick = async () => {
      try {
        setButtonLoading('bikBtn', 'Registering...');
        addLog('Registering browser identity key...', 'info');
        
        const res = await Stronghold.bikRegisterStep({ bikRegisterUrl: '/browser/register' });
        
        setButtonSuccess('bikBtn', 'Registered!');
        addLog('Browser identity registered successfully', 'success');
        enableButton('dpopBtn');
        
        addLog('Ready to bind DPoP token', 'info');
      } catch (e) {
        setButtonError('bikBtn', 'Failed');
        addLog(`Browser identity registration failed: ${e.message}`, 'error');
      }
    };
  }

  // 3. Bind DPoP Token
  const dpopBtn = document.getElementById('dpopBtn');
  if (dpopBtn) {
    dpopBtn.onclick = async () => {
      // Prevent re-clicking if already successful
      if (dpopBtn.classList.contains('success')) {
        addLog('DPoP token already bound - no action needed', 'info');
        return;
      }
      
      try {
        setButtonLoading('dpopBtn', 'Binding...');
        addLog('Binding DPoP token...', 'info');
        
        const state = await Stronghold.dpopBindStep({ dpopBindUrl: '/dpop/bind' });
        
        setButtonSuccess('dpopBtn', 'Bound!');
        addLog('DPoP token bound successfully', 'success');
        enableButton('apiBtn');
        enableButton('linkBtn');
        
        // Only enable passkey buttons if supported
        if (passkeySupport.hasAPI && passkeySupport.uvp) {
          enableButton('regBtn');
          enableButton('authBtn');
        }
        
        // Update service worker if available
        if (navigator.serviceWorker?.controller) {
          navigator.serviceWorker.controller.postMessage({
            type: 'stronghold/bind',
            bind: state.bind,
            dpopKeyId: state.dpopKeyId,
            nonce: state.nonce
          });
          addLog('Service worker updated with DPoP binding', 'info');
        }
        
        addLog('Ready to test API access and manage passkeys', 'info');
      } catch (e) {
        setButtonError('dpopBtn', 'Failed');
        addLog(`DPoP binding failed: ${e.message}`, 'error');
      }
    };
  }

  // 4. Test API Access
  const apiBtn = document.getElementById('apiBtn');
  const apiModal = document.getElementById('apiModal');
  const closeApiModal = document.getElementById('closeApiModal');
  const cancelApiRequest = document.getElementById('cancelApiRequest');
  const sendApiRequest = document.getElementById('sendApiRequest');
  const apiMessage = document.getElementById('apiMessage');
  const apiResponse = document.getElementById('apiResponse');
  const clientRequest = document.getElementById('clientRequest');

  if (apiBtn) {
    apiBtn.onclick = () => {
      // Show modal
      apiModal.style.display = 'block';
      apiResponse.innerHTML = '<em>Click "Send Request" to test the API...</em>';
      apiResponse.className = 'response-box';
      clientRequest.innerHTML = '<em>Request details will appear here...</em>';
      clientRequest.className = 'response-box';
    };
  }

  // Close modal handlers
  if (closeApiModal) {
    closeApiModal.onclick = () => {
      apiModal.style.display = 'none';
    };
  }

  if (cancelApiRequest) {
    cancelApiRequest.onclick = () => {
      apiModal.style.display = 'none';
    };
  }

  // Close modal when clicking outside
  if (apiModal) {
    apiModal.onclick = (e) => {
      if (e.target === apiModal) {
        apiModal.style.display = 'none';
      }
    };
  }

  // Close modal with Escape key
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && apiModal.style.display === 'block') {
      apiModal.style.display = 'none';
    }
  });

  // Send API request
  if (sendApiRequest) {
    sendApiRequest.onclick = async () => {
      try {
        sendApiRequest.disabled = true;
        sendApiRequest.textContent = 'Sending...';
        apiResponse.innerHTML = 'Sending request...';
        apiResponse.className = 'response-box';
        clientRequest.innerHTML = 'Preparing request...';
        clientRequest.className = 'response-box';
        
        addLog('Testing API access with DPoP token...', 'info');
        
        const message = apiMessage.value.trim() || 'Hello from Browser Identity & DPoP Security Demo!';
        
        // Capture request details before making the request
        const requestDetails = await captureRequestDetails(message);
        
        const j = await Stronghold.strongholdFetch('/api/echo', { 
          method: 'POST', 
          body: { 
            message: message,
            timestamp: new Date().toISOString(),
            demo: 'DPoP-protected API call'
          } 
        });
        
        // Display request details
        clientRequest.innerHTML = JSON.stringify(requestDetails, null, 2);
        clientRequest.className = 'response-box info';
        
        // Display response in modal
        apiResponse.innerHTML = JSON.stringify(j, null, 2);
        apiResponse.className = 'response-box success';
        
        setButtonSuccess('apiBtn', 'Working!');
        addLog('API access successful - DPoP token working!', 'success');
        addLog(`Response: ${JSON.stringify(j, null, 2)}`, 'info');
        addLog('DPoP cryptographic binding verified', 'success');
        
      } catch (e) {
        // Display error in modal
        apiResponse.innerHTML = `Error: ${e.message}`;
        apiResponse.className = 'response-box error';
        clientRequest.innerHTML = 'Request details unavailable due to error';
        clientRequest.className = 'response-box error';
        
        setButtonError('apiBtn', 'Failed');
        addLog(`API access failed: ${e.message}`, 'error');
      } finally {
        sendApiRequest.disabled = false;
        sendApiRequest.textContent = 'Send Request';
      }
    };
  }

  // Function to capture request details including DPoP
  async function captureRequestDetails(message) {
    try {
                      // Get current DPoP state
                const dpopNonce = await Stronghold.getDpopNonce();
                const bindToken = await Stronghold.getBindToken();
                
                // Get browser identity key info (without exposing private key)
                const bik = await Stronghold.getBIK();
                
                // Ensure nonce is a string or undefined
                const nonceValue = typeof dpopNonce === 'string' ? dpopNonce : undefined;
                
                // Create the actual DPoP proof that will be used
                const dpopProof = await Stronghold.createDpopProof({
                  url: window.location.origin + '/api/echo',
                  method: 'POST',
                  nonce: nonceValue,
                  privateKey: bik.privateKey,
                  publicJwk: bik.publicJwk
                });
      
      return {
        timestamp: new Date().toISOString(),
        url: '/api/echo',
        method: 'POST',
        requestBody: {
          message: message,
          timestamp: new Date().toISOString(),
          demo: 'DPoP-protected API call'
        },
        headers: {
          'Content-Type': 'application/json',
          'DPoP': dpopProof,
          'DPoP-Bind': bindToken || 'Not bound'
        },
        dpopDetails: {
          nonce: dpopNonce || 'Not set',
          proofStructure: {
            header: dpopProof.split('.')[0],
            payload: dpopProof.split('.')[1],
            signature: dpopProof.split('.')[2] ? `${dpopProof.split('.')[2].substring(0, 20)}...` : 'None'
          },
          browserIdentityKey: {
            kid: bik?.publicJwk?.kid || 'Not available',
            kty: bik?.publicJwk?.kty || 'Not available',
            crv: bik?.publicJwk?.crv || 'Not available',
            publicKeyThumbprint: bik?.publicJwk ? await Stronghold.jwkThumbprint(bik.publicJwk) : 'Not available'
          }
        }
      };
    } catch (error) {
      return {
        error: 'Failed to capture request details',
        details: error.message,
        timestamp: new Date().toISOString()
      };
    }
  }

  // 5. Register Passkey
  const regBtn = document.getElementById('regBtn');
  if (regBtn) {
    regBtn.onclick = async () => {
      // Check passkey support first
      if (!passkeySupport.hasAPI || !passkeySupport.uvp) {
        addLog('Passkey registration attempted but not supported on this device', 'warning');
        return;
      }

      try {
        setButtonLoading('regBtn', 'Creating...');
        addLog('Starting passkey registration...', 'info');
        
        // Check for existing passkeys
        let pre = null;
        try { 
          pre = await Passkeys.getAuthOptions(); 
        } catch {}
        const existing = pre?.allowCredentials?.length || 0;
        
        if (existing > 0) {
          const proceed = confirm(`You already have ${existing} passkey(s) for this account on this device.\nCreate another?`);
          if (!proceed) {
            setButtonError('regBtn', 'Cancelled');
            addLog('Passkey registration cancelled by user', 'warning');
            return;
          }
        }
        
        const res = await Passkeys.registerPasskey();
        
        setButtonSuccess('regBtn', 'Created!');
        addLog('Passkey registered successfully!', 'success');
        
        addLog('Ready to authenticate with passkey', 'info');
      } catch (e) {
        setButtonError('regBtn', 'Failed');
        addLog(`Passkey registration failed: ${e.message}`, 'error');
      }
    };
  }

  // 6. Authenticate with Passkey
  const authBtn = document.getElementById('authBtn');
  if (authBtn) {
    authBtn.onclick = async () => {
      // Check passkey support first
      if (!passkeySupport.hasAPI || !passkeySupport.uvp) {
        addLog('Passkey authentication attempted but not supported on this device', 'warning');
        return;
      }

      try {
        setButtonLoading('authBtn', 'Verifying...');
        addLog('Starting passkey authentication...', 'info');
        
        const pre = await Passkeys.getAuthOptions();
        const count = pre?.allowCredentials?.length || 0;
        
        if (count === 0) {
          const go = confirm(
            "No passkey is registered for this account on this device.\nWould you like to create one now?"
          );
          if (!go) {
            setButtonError('authBtn', 'No Passkey');
            addLog('Passkey authentication cancelled - no passkey available', 'warning');
            return;
          }
          
          // Register first, then authenticate
          await Passkeys.registerPasskey();
          const pre2 = await Passkeys.getAuthOptions();
          const res2 = await Passkeys.authenticatePasskey(pre2);
          
          setButtonSuccess('authBtn', 'Verified!');
          addLog('Passkey authentication successful (post-registration)', 'success');
        } else {
          const res = await Passkeys.authenticatePasskey(pre);
          
          setButtonSuccess('authBtn', 'Verified!');
          addLog('Passkey authentication successful!', 'success');
        }
        
        addLog('Identity verified with device biometrics/security key', 'success');
      } catch (e) {
        setButtonError('authBtn', 'Failed');
        addLog(`Passkey authentication failed: ${e.message}`, 'error');
      }
    };
  }

  // 7. Start Cross-Device Link
  const linkBtn = document.getElementById('linkBtn');
  if (linkBtn) {
    linkBtn.onclick = async () => {
      try {
        setButtonLoading('linkBtn', 'Creating QR...');
        addLog('Starting cross-device linking...', 'info');
        
        const r = await Stronghold.strongholdFetch('/link/start', { method: 'POST' });
        const linkId = r.linkId || r.rid || r.id;
        const url = r.qr_url || r.url;
        
        if (!linkId || !url) {
          throw new Error('link/start returned unexpected payload');
        }
        
        setButtonLoading('linkBtn', 'QR Ready - Waiting for scan...');
        addLog('QR code generated successfully', 'success');
        
        // Create QR code display
        const qrContainer = document.createElement('div');
        qrContainer.className = 'qr-container';
        qrContainer.innerHTML = `
          <h3>📱 Scan with your mobile device camera</h3>
          <div class="qr-code" id="link-qr"></div>
          <div style="margin-top: 1rem; font-family: monospace; word-break: break-all; color: var(--text-muted);">
            ${url}
          </div>
          <div style="margin-top: 1rem;">
            <strong>Status:</strong> <span id="link-status">pending</span>
          </div>
        `;
        
        // Insert after the demo sequence
        const demoSequence = document.querySelector('.demo-sequence');
        demoSequence.parentNode.insertBefore(qrContainer, demoSequence.nextSibling);
        
        // Render QR code
        if ('QRCode' in window) {
          new QRCode(document.getElementById('link-qr'), { 
            text: url, 
            width: 200, 
            height: 200, 
            correctLevel: QRCode.CorrectLevel.M 
          });
        } else {
          addLog('QR code library not loaded - displaying URL only', 'warning');
        }
        
        // Start monitoring link status
        monitorLinkStatus(linkId);
        
        addLog('Cross-device linking initiated - scan QR code with mobile device', 'info');
      } catch (e) {
        setButtonError('linkBtn', 'Failed');
        addLog(`Cross-device linking failed: ${e.message}`, 'error');
      }
    };
  }

  // ---------- Admin Buttons ----------
  
  // Server Flush
  const flushBtn = document.getElementById('flushBtn');
  if (flushBtn) {
    flushBtn.onclick = async () => {
      try {
        setButtonLoading('flushBtn', 'Flushing...');
        addLog('Flushing server state...', 'info');
        
        const r = await fetch('/_admin/flush', { method: 'POST' });
        const result = await r.json();
        
        setButtonSuccess('flushBtn', 'Flushed!');
        addLog('Server state flushed successfully', 'success');
        addLog(`Result: ${JSON.stringify(result, null, 2)}`, 'info');
        
        // Clear any existing QR codes
        const qrContainer = document.querySelector('.qr-container');
        if (qrContainer) qrContainer.remove();
        
        // Reset buttons
        buttons.forEach(disableButton);
        
      } catch (e) {
        setButtonError('flushBtn', 'Failed');
        addLog(`Server flush failed: ${e.message}`, 'error');
      }
    };
  }

  // Client Flush
  const clientFlushBtn = document.getElementById('clientFlushBtn');
  if (clientFlushBtn) {
    clientFlushBtn.onclick = async () => {
      try {
        setButtonLoading('clientFlushBtn', 'Flushing...');
        addLog('Flushing client state...', 'info');
        
        const r = await Stronghold.clientFlush({ unregisterSW: false });
        
        setButtonSuccess('clientFlushBtn', 'Flushed!');
        addLog('Client state flushed successfully', 'success');
        addLog(`Result: ${JSON.stringify(r, null, 2)}`, 'info');
        
        // Clear any existing QR codes
        const qrContainer = document.querySelector('.qr-container');
        if (qrContainer) qrContainer.remove();
        
        // Reset buttons
        buttons.forEach(disableButton);
        
      } catch (e) {
        setButtonError('clientFlushBtn', 'Failed');
        addLog(`Client flush failed: ${e.message}`, 'error');
      }
    };
  }

  // Service Worker Register
  const swRegBtn = document.getElementById('swRegBtn');
  if (swRegBtn) {
    swRegBtn.onclick = async () => {
      try {
        setButtonLoading('swRegBtn', 'Registering...');
        addLog('Registering service worker...', 'info');
        
        if (!('serviceWorker' in navigator)) {
          throw new Error('Service Worker not supported');
        }
        
        const reg = await navigator.serviceWorker.register('/stronghold-sw.js', { type: 'module' });
        await navigator.serviceWorker.ready;
        
        setButtonSuccess('swRegBtn', 'Registered!');
        addLog('Service worker registered successfully', 'success');
        addLog(`Scope: ${reg.scope}`, 'info');
        
        if (navigator.serviceWorker.controller) {
          addLog('Service worker is controlling this page', 'success');
        } else {
          addLog('Service worker installed but no controller yet. Reload once to allow takeover.', 'warning');
        }
        
      } catch (e) {
        setButtonError('swRegBtn', 'Failed');
        addLog(`Service worker registration failed: ${e.message}`, 'error');
      }
    };
  }

  // Service Worker Unregister
  const swUnregBtn = document.getElementById('swUnregBtn');
  if (swUnregBtn) {
    swUnregBtn.onclick = async () => {
      try {
        setButtonLoading('swUnregBtn', 'Unregistering...');
        addLog('Unregistering service workers...', 'info');
        
        if (!('serviceWorker' in navigator)) {
          throw new Error('Service Worker not supported');
        }
        
        const regs = await navigator.serviceWorker.getRegistrations();
        let count = 0;
        for (const r of regs) { 
          if (await r.unregister()) count++; 
        }
        
        setButtonSuccess('swUnregBtn', 'Unregistered!');
        addLog(`Service workers unregistered: ${count}`, 'success');
        
        if (navigator.serviceWorker.controller) {
          addLog('Note: this tab remains controlled until reload/navigation.', 'warning');
        }
        
      } catch (e) {
        setButtonError('swUnregBtn', 'Failed');
        addLog(`Service worker unregistration failed: ${e.message}`, 'error');
      }
    };
  }

  // Test Service Worker Echo
  const echoSWBtn = document.getElementById('echoSWBtn');
  if (echoSWBtn) {
    echoSWBtn.onclick = async () => {
      try {
        setButtonLoading('echoSWBtn', 'Testing...');
        addLog('Testing service worker echo...', 'info');
        
        const r = await fetch('/api/echo', {
          method: 'POST',
          body: JSON.stringify({ hello: 'world', via: 'service-worker' }),
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include'
        });
        const j = await r.json().catch(() => ({}));
        
        if (r.ok) {
          setButtonSuccess('echoSWBtn', 'Success!');
          addLog('Service worker echo successful', 'success');
          addLog(`Response: ${JSON.stringify(j, null, 2)}`, 'info');
          addLog(`Nonce: ${r.headers.get('DPoP-Nonce')}`, 'info');
        } else {
          setButtonError('echoSWBtn', 'Failed');
          addLog('Service worker echo failed', 'error');
          addLog(`Response: ${JSON.stringify(j, null, 2)}`, 'error');
        }
        
      } catch (e) {
        setButtonError('echoSWBtn', 'Failed');
        addLog(`Service worker echo failed: ${e.message}`, 'error');
      }
    };
  }

  // ---------- Helper Functions ----------
  
  // Link status monitoring with SSE as primary, polling as fallback
  let _currentLinkId = null;
  let _eventSource = null;
  let _pollAbort = { on: false };
  
  async function monitorLinkStatus(linkId) {
    // Stop any existing monitoring
    stopLinkMonitoring();
    
    _currentLinkId = linkId;
    addLog(`Starting link status monitoring for: ${linkId}`, 'info');
    
    // Try SSE first
    if ('EventSource' in window) {
      try {
        addLog('Starting SSE monitoring for link status...', 'info');
        const sseUrl = `/link/events/${encodeURIComponent(linkId)}`;
        addLog(`SSE URL: ${sseUrl}`, 'info');
        _eventSource = new EventSource(sseUrl);
        
        _eventSource.onopen = () => {
          addLog('SSE connection opened successfully', 'success');
        };
        
        _eventSource.onmessage = (event) => {
          addLog(`SSE message received: ${event.data}`, 'info');
          try {
            const data = JSON.parse(event.data);
            addLog(`Parsed SSE data: ${JSON.stringify(data)}`, 'info');
            updateLinkStatus(data);
            
            if ((data.status === 'linked' && data.applied) || data.status === 'expired') {
              stopLinkMonitoring();
              if (data.status === 'linked') {
                setButtonSuccess('linkBtn', 'Linked!');
                addLog('Cross-device linking completed successfully!', 'success');
              } else {
                setButtonError('linkBtn', 'Expired');
                addLog('Cross-device linking expired', 'warning');
              }
            }
          } catch (e) {
            addLog(`Failed to parse SSE data: ${e.message}`, 'error');
          }
        };
        
        _eventSource.onerror = (event) => {
          addLog(`SSE connection failed: ${JSON.stringify(event)}`, 'error');
          addLog('SSE connection failed, falling back to polling...', 'warning');
          _eventSource.close();
          _eventSource = null;
          startPolling(linkId);
        };
        
        _eventSource.addEventListener('status', (event) => {
          addLog(`SSE status event received: ${event.data}`, 'info');
          try {
            const data = JSON.parse(event.data);
            addLog(`Parsed SSE status data: ${JSON.stringify(data)}`, 'info');
            updateLinkStatus(data);
            
            if ((data.status === 'linked' && data.applied) || data.status === 'expired') {
              stopLinkMonitoring();
              if (data.status === 'linked') {
                setButtonSuccess('linkBtn', 'Linked!');
                addLog('Cross-device linking completed successfully!', 'success');
              } else {
                setButtonError('linkBtn', 'Expired');
                addLog('Cross-device linking expired', 'warning');
              }
            }
          } catch (e) {
            addLog(`Failed to parse SSE status event: ${e.message}`, 'error');
          }
        });
        
        return; // SSE started successfully
      } catch (e) {
        addLog(`SSE setup failed: ${e.message}, falling back to polling...`, 'warning');
      }
    }
    
    // Fallback to polling
    startPolling(linkId);
  }
  
  async function startPolling(linkId) {
    addLog('Starting polling for link status...', 'info');
    _pollAbort.on = true;
    try {
      while (_pollAbort.on && _currentLinkId === linkId) {
        await new Promise(r => setTimeout(r, 2000));
        try {
          addLog(`Polling link status for: ${linkId}`, 'info');
          const j = await Stronghold.strongholdFetch(`/link/status/${encodeURIComponent(linkId)}`, { method: 'GET' });
          addLog(`Poll response: ${JSON.stringify(j)}`, 'info');
          updateLinkStatus(j);
          
          if ((j.status === 'linked' && j.applied) || j.status === 'expired') {
            stopLinkMonitoring();
            if (j.status === 'linked') {
              setButtonSuccess('linkBtn', 'Linked!');
              addLog('Cross-device linking completed successfully!', 'success');
            } else {
              setButtonError('linkBtn', 'Expired');
              addLog('Cross-device linking expired', 'warning');
            }
            return;
          }
        } catch (e) {
          addLog(`Link status check failed: ${e.message}`, 'error');
          addLog(`Error details: ${JSON.stringify(e)}`, 'error');
          stopLinkMonitoring();
        }
      }
    } finally {
      _pollAbort.on = false;
    }
  }
  
  function stopLinkMonitoring() {
    _pollAbort.on = false;
    
    if (_eventSource) {
      _eventSource.close();
      _eventSource = null;
    }
    
    if (_currentLinkId) {
      _currentLinkId = null;
    }
  }

  function updateLinkStatus(j) {
    addLog(`Updating link status: ${JSON.stringify(j)}`, 'info');
    const statusEl = document.getElementById('link-status');
    if (statusEl) {
      const newStatus = `${j.status}${j.applied ? ' (applied)' : ''}`;
      addLog(`Setting status element to: ${newStatus}`, 'info');
      statusEl.textContent = newStatus;
    } else {
      addLog('Status element not found in DOM', 'warning');
    }
  }

  // Initial status check
  const checkInitialStatus = async () => {
    try {
      // Stop any existing monitoring
      stopLinkMonitoring();
      
      // Clear any existing QR containers
      const qrContainer = document.querySelector('.qr-container');
      if (qrContainer) qrContainer.remove();
      
      // Check passkey support first
      await checkPasskeySupport();
      
      const bind = (await Stronghold.get('bind'))?.value || null;
      if (bind) {
        addLog('Existing session found - ready to continue', 'info');
        enableButton('bikBtn');
        enableButton('dpopBtn');
        enableButton('apiBtn');
        enableButton('linkBtn');
        
        // Only enable passkey buttons if supported
        if (passkeySupport.hasAPI && passkeySupport.uvp) {
          enableButton('regBtn');
          enableButton('authBtn');
        }
      } else {
        addLog('No existing session - start with initialization', 'info');
      }
    } catch (e) {
      addLog(`Status check failed: ${e.message}`, 'error');
    }
  };

  // Initialize
  checkInitialStatus();
  addLog('Demo page loaded successfully', 'success');
  console.log('[init] handlers bound');
})();

// Global error handling
window.addEventListener('error', e => console.error('[global-error]', e.message));
window.addEventListener('unhandledrejection', e => console.error('[unhandled]', e.reason?.message || e.reason));
