// src/services/LinkingService.js
// Cross-device linking service

import { ApiService } from './ApiService.js';

export class LinkingService extends ApiService {
  constructor(strongholdService = null) {
    super();
    this.strongholdService = strongholdService;
    this.currentLinkId = null;
    this.statusCallbacks = new Map();
    this.websocket = null;
    this.statusInterval = null;
  }

  /**
   * Start cross-device linking process
   * @returns {Promise<Object>} Linking data with QR code
   */
  async startLinking() {
    try {
      if (!this.strongholdService) {
        throw new Error('StrongholdService not provided');
      }
      const response = await this.strongholdService.secureRequest('/link/start', {
        method: 'POST'
      });
      this.currentLinkId = response.linkId;
      return response;
    } catch (error) {
      throw new Error(`Failed to start linking: ${error.message}`);
    }
  }

  /**
   * Complete mobile linking
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Completion result
   */
  async completeMobileLink(linkId) {
    try {
      if (!this.strongholdService) {
        throw new Error('StrongholdService not provided');
      }
      const response = await this.strongholdService.secureRequest('/link/mobile/complete', {
        method: 'POST',
        body: JSON.stringify({
          link_id: linkId
        })
      });
      return response;
    } catch (error) {
      throw new Error(`Failed to complete mobile link: ${error.message}`);
    }
  }

  /**
   * Get linking status
   * @param {string} linkId - Link ID
   * @returns {Promise<Object>} Status data
   */
  async getLinkStatus(linkId) {
    try {
      if (!this.strongholdService) {
        throw new Error('StrongholdService not provided');
      }
      const response = await this.strongholdService.secureRequest(`/link/status/${linkId}`, {
        method: 'GET'
      });
      return response;
    } catch (error) {
      throw new Error(`Failed to get link status: ${error.message}`);
    }
  }

  /**
   * Start WebSocket connection for real-time status updates
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   */
  startWebSocket(linkId, onStatusUpdate, onError) {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${protocol}//${window.location.host}/link/ws/${linkId}`;
      
      this.websocket = new WebSocket(wsUrl);
      
      this.websocket.onopen = () => {
        console.log('WebSocket connected for linking status');
      };
      
      this.websocket.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onStatusUpdate(data);
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };
      
      this.websocket.onerror = (error) => {
        console.error('WebSocket error:', error);
        onError(error);
      };
      
      this.websocket.onclose = () => {
        console.log('WebSocket disconnected');
      };
      
    } catch (error) {
      console.error('Failed to start WebSocket:', error);
      onError(error);
    }
  }

  /**
   * Start Server-Sent Events for status updates
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   */
  startSSE(linkId, onStatusUpdate, onError) {
    try {
      // Use fetch with streaming instead of EventSource to support credentials
      const controller = new AbortController();
      this.currentSSEController = controller;
      
      const startSSEStream = async () => {
        try {
          console.log('Starting SSE stream with fetch...');
          const response = await fetch(`/link/events/${linkId}`, {
            method: 'GET',
            credentials: 'include', // This is the key difference from EventSource
            headers: {
              'Accept': 'text/event-stream',
              'Cache-Control': 'no-cache'
            },
            signal: controller.signal
          });
          
          if (!response.ok) {
            throw new Error(`SSE request failed: ${response.status}`);
          }
          
          console.log('SSE connection opened successfully');
          
          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = '';
          
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            
            buffer += decoder.decode(value, { stream: true });
            const lines = buffer.split('\n');
            buffer = lines.pop() || ''; // Keep incomplete line in buffer
            
            for (const line of lines) {
              if (line.trim() === '') continue;
              
              if (line.startsWith('data: ')) {
                try {
                  const data = JSON.parse(line.slice(6));
                  onStatusUpdate(data);
                } catch (error) {
                  console.error('Failed to parse SSE data:', error);
                }
              } else if (line.startsWith('event: ')) {
                // Handle event type if needed
                const eventType = line.slice(7);
                console.log('SSE event type:', eventType);
              }
            }
          }
        } catch (error) {
          if (error.name === 'AbortError') {
            console.log('SSE stream aborted');
            return;
          }
          console.error('SSE stream error:', error);
          onError(error);
          
          // Trigger fallback to polling
          setTimeout(() => {
            this.startPolling(linkId, onStatusUpdate, onError);
          }, 1000);
        }
      };
      
      startSSEStream();
      
      return { close: () => controller.abort() };
      
    } catch (error) {
      console.error('Failed to start SSE:', error);
      onError(error);
      return null;
    }
  }

  /**
   * Start polling for status updates
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   * @param {number} interval - Polling interval in ms (default: 2000)
   */
  startPolling(linkId, onStatusUpdate, onError, interval = 2000) {
    const poll = async () => {
      try {
        const status = await this.getLinkStatus(linkId);
        onStatusUpdate(status);
        
        // Continue polling if not complete
        if (status.status !== 'completed' && status.status !== 'failed') {
          this.statusInterval = setTimeout(poll, interval);
        }
      } catch (error) {
        console.error('Polling error:', error);
        onError(error);
      }
    };
    
    poll();
  }

  /**
   * Stop all status monitoring
   */
  stopStatusMonitoring() {
    if (this.websocket) {
      this.websocket.close();
      this.websocket = null;
    }
    
    if (this.currentEventSource) {
      this.currentEventSource.close();
      this.currentEventSource = null;
    }
    
    if (this.currentSSEController) {
      this.currentSSEController.abort();
      this.currentSSEController = null;
    }
    
    if (this.statusInterval) {
      clearTimeout(this.statusInterval);
      this.statusInterval = null;
    }
  }

  /**
   * Monitor linking status with fallback methods
   * @param {string} linkId - Link ID
   * @param {Function} onStatusUpdate - Callback for status updates
   * @param {Function} onError - Callback for errors
   * @param {string} preferredMethod - Preferred method ('websocket', 'sse', 'polling')
   */
  monitorStatus(linkId, onStatusUpdate, onError, preferredMethod = 'websocket') {
    this.stopStatusMonitoring();
    
    const methods = {
      websocket: () => this.startWebSocket(linkId, onStatusUpdate, onError),
      sse: () => this.startSSE(linkId, onStatusUpdate, onError),
      polling: () => this.startPolling(linkId, onStatusUpdate, onError)
    };
    
    // Try preferred method first
    if (methods[preferredMethod]) {
      try {
        const result = methods[preferredMethod]();
        if (result) {
          console.log(`Using ${preferredMethod} for status monitoring`);
          return;
        }
      } catch (error) {
        console.warn(`${preferredMethod} failed:`, error);
      }
    }
    
    // Try fallback methods in order
    const fallbackOrder = ['websocket', 'sse', 'polling'].filter(method => method !== preferredMethod);
    
    for (const method of fallbackOrder) {
      try {
        const result = methods[method]();
        if (result) {
          console.log(`Using ${method} as fallback for status monitoring`);
          return;
        }
      } catch (error) {
        console.warn(`${method} fallback failed:`, error);
      }
    }
    
    // Final fallback to polling
    console.log('All methods failed, using polling as final fallback');
    this.startPolling(linkId, onStatusUpdate, onError);
  }

  /**
   * Get current link ID
   * @returns {string|null} Current link ID
   */
  getCurrentLinkId() {
    return this.currentLinkId;
  }

  /**
   * Clear current link
   */
  clearLink() {
    this.currentLinkId = null;
    this.stopStatusMonitoring();
  }

  /**
   * Check if currently linking
   * @returns {boolean} Whether currently linking
   */
  isLinking() {
    return !!this.currentLinkId;
  }
}
