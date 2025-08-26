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
      const eventSource = new EventSource(`/link/status/${linkId}/stream`);
      
      eventSource.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          onStatusUpdate(data);
        } catch (error) {
          console.error('Failed to parse SSE message:', error);
        }
      };
      
      eventSource.onerror = (error) => {
        console.error('SSE error:', error);
        onError(error);
        eventSource.close();
      };
      
      return eventSource;
      
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
        methods[preferredMethod]();
        return;
      } catch (error) {
        console.warn(`${preferredMethod} failed, trying fallback methods`);
      }
    }
    
    // Fallback to polling if other methods fail
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
