// src/services/ApiService.js
// Centralized API communication service

export class ApiService {
  constructor(baseURL = '') {
    this.baseURL = baseURL;
    this.defaultHeaders = {
      'Content-Type': 'application/json',
    };
  }

  /**
   * Make a fetch request with error handling
   * @param {string} url - Request URL
   * @param {Object} options - Fetch options
   * @returns {Promise<Object>} Response data
   */
  async request(url, options = {}) {
    const fullUrl = url.startsWith('http') ? url : `${this.baseURL}${url}`;
    
    const config = {
      headers: { ...this.defaultHeaders, ...options.headers },
      ...options
    };

    try {
      const response = await fetch(fullUrl, config);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return await response.json();
      }
      
      return await response.text();
    } catch (error) {
      console.error('API request failed:', error);
      throw new Error(`Request failed: ${error.message}`);
    }
  }

  /**
   * GET request
   * @param {string} url - Request URL
   * @param {Object} headers - Additional headers
   * @returns {Promise<Object>} Response data
   */
  async get(url, headers = {}) {
    return this.request(url, { method: 'GET', headers });
  }

  /**
   * POST request
   * @param {string} url - Request URL
   * @param {Object} data - Request body
   * @param {Object} headers - Additional headers
   * @returns {Promise<Object>} Response data
   */
  async post(url, data = {}, headers = {}) {
    return this.request(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(data)
    });
  }

  /**
   * PUT request
   * @param {string} url - Request URL
   * @param {Object} data - Request body
   * @param {Object} headers - Additional headers
   * @returns {Promise<Object>} Response data
   */
  async put(url, data = {}, headers = {}) {
    return this.request(url, {
      method: 'PUT',
      headers,
      body: JSON.stringify(data)
    });
  }

  /**
   * DELETE request
   * @param {string} url - Request URL
   * @param {Object} headers - Additional headers
   * @returns {Promise<Object>} Response data
   */
  async delete(url, headers = {}) {
    return this.request(url, { method: 'DELETE', headers });
  }

  /**
   * Set authorization header
   * @param {string} token - Authorization token
   */
  setAuthToken(token) {
    if (token) {
      this.defaultHeaders['Authorization'] = `Bearer ${token}`;
    } else {
      delete this.defaultHeaders['Authorization'];
    }
  }

  /**
   * Set custom header
   * @param {string} key - Header key
   * @param {string} value - Header value
   */
  setHeader(key, value) {
    this.defaultHeaders[key] = value;
  }

  /**
   * Remove custom header
   * @param {string} key - Header key
   */
  removeHeader(key) {
    delete this.defaultHeaders[key];
  }

  /**
   * Clear all custom headers
   */
  clearHeaders() {
    this.defaultHeaders = {
      'Content-Type': 'application/json',
    };
  }
}
