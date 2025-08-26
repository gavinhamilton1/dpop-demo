// src/components/Logger.js
// Logging component for consistent log management

export class Logger {
  constructor(containerId = 'logContainer') {
    this.container = document.getElementById(containerId);
    this.logLevels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    this.currentLevel = this.logLevels.info; // Default to info level
  }

  /**
   * Set the minimum log level to display
   * @param {string} level - Log level ('debug', 'info', 'warn', 'error')
   */
  setLevel(level) {
    if (this.logLevels.hasOwnProperty(level)) {
      this.currentLevel = this.logLevels[level];
    }
  }

  /**
   * Add a log entry
   * @param {string} message - Log message
   * @param {string} level - Log level ('info', 'success', 'warn', 'error')
   * @param {Object} data - Optional data to include
   */
  log(message, level = 'info', data = null) {
    if (!this.container) {
      console.log(`[${level.toUpperCase()}] ${message}`, data);
      return;
    }

    const timestamp = new Date().toLocaleTimeString();
    const levelClass = level || 'info';
    const levelIcon = this.getLevelIcon(level);
    
    const entry = document.createElement('div');
    entry.className = `log-entry ${levelClass}`;
    
    let logText = `<span class="log-timestamp">[${timestamp}]</span> ${levelIcon} ${message}`;
    
    if (data) {
      logText += ` <span class="log-data">${JSON.stringify(data, null, 2)}</span>`;
    }
    
    entry.innerHTML = logText;
    this.container.appendChild(entry);
    this.scrollToBottom();
    
    // Also log to console for debugging
    if (data !== null) {
      console.log(`[${level.toUpperCase()}] ${message}`, data);
    } else {
      console.log(`[${level.toUpperCase()}] ${message}`);
    }
  }

  /**
   * Log info message
   * @param {string} message - Log message
   * @param {Object} data - Optional data
   */
  info(message, data = null) {
    this.log(message, 'info', data);
  }

  /**
   * Log success message
   * @param {string} message - Log message
   * @param {Object} data - Optional data
   */
  success(message, data = null) {
    this.log(message, 'success', data);
  }

  /**
   * Log warning message
   * @param {string} message - Log message
   * @param {Object} data - Optional data
   */
  warn(message, data = null) {
    this.log(message, 'warn', data);
  }

  /**
   * Log error message
   * @param {string} message - Log message
   * @param {Object} data - Optional data
   */
  error(message, data = null) {
    this.log(message, 'error', data);
  }

  /**
   * Log debug message (only shown if debug level is enabled)
   * @param {string} message - Log message
   * @param {Object} data - Optional data
   */
  debug(message, data = null) {
    if (this.currentLevel <= this.logLevels.debug) {
      this.log(message, 'debug', data);
    }
  }

  /**
   * Get icon for log level
   * @param {string} level - Log level
   * @returns {string} Icon HTML
   */
  getLevelIcon(level) {
    const icons = {
      'info': 'ℹ️',
      'success': '✅',
      'warn': '⚠️',
      'error': '❌',
      'debug': '🔍'
    };
    return icons[level] || icons.info;
  }

  /**
   * Scroll log container to bottom
   */
  scrollToBottom() {
    if (this.container) {
      this.container.scrollTop = this.container.scrollHeight;
    }
  }

  /**
   * Clear all log entries
   */
  clear() {
    if (this.container) {
      this.container.innerHTML = '';
    }
  }

  /**
   * Get all log entries as array
   * @returns {Array} Array of log entries
   */
  getEntries() {
    if (!this.container) return [];
    
    const entries = [];
    const logElements = this.container.querySelectorAll('.log-entry');
    
    logElements.forEach(element => {
      entries.push({
        text: element.textContent,
        level: this.getElementLevel(element),
        timestamp: this.extractTimestamp(element.textContent)
      });
    });
    
    return entries;
  }

  /**
   * Extract log level from element
   * @param {Element} element - Log entry element
   * @returns {string} Log level
   */
  getElementLevel(element) {
    if (element.classList.contains('error')) return 'error';
    if (element.classList.contains('warn')) return 'warn';
    if (element.classList.contains('success')) return 'success';
    if (element.classList.contains('debug')) return 'debug';
    return 'info';
  }

  /**
   * Extract timestamp from log text
   * @param {string} text - Log text
   * @returns {string} Timestamp
   */
  extractTimestamp(text) {
    const match = text.match(/\[([^\]]+)\]/);
    return match ? match[1] : '';
  }

  /**
   * Export logs as text
   * @returns {string} Logs as text
   */
  exportAsText() {
    return this.getEntries()
      .map(entry => `[${entry.timestamp}] ${entry.text}`)
      .join('\n');
  }

  /**
   * Export logs as JSON
   * @returns {string} Logs as JSON
   */
  exportAsJSON() {
    return JSON.stringify(this.getEntries(), null, 2);
  }

  /**
   * Filter logs by level
   * @param {string} level - Log level to filter by
   * @returns {Array} Filtered log entries
   */
  filterByLevel(level) {
    return this.getEntries().filter(entry => entry.level === level);
  }

  /**
   * Search logs by text
   * @param {string} searchText - Text to search for
   * @returns {Array} Matching log entries
   */
  search(searchText) {
    const lowerSearch = searchText.toLowerCase();
    return this.getEntries().filter(entry => 
      entry.text.toLowerCase().includes(lowerSearch)
    );
  }
}
