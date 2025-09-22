// src/utils/logging.js
const LOG_LEVELS = {
  DEBUG: 0,
  INFO: 1,
  WARN: 2,
  ERROR: 3
};

const DEFAULT_LEVEL = LOG_LEVELS.INFO;

class Logger {
  constructor(prefix, level = DEFAULT_LEVEL) {
    this.prefix = prefix;
    this.level = level;
  }

  _getCaller() {
    const stack = new Error().stack;
    const lines = stack.split('\n');
    // Find the first line that's not from this logger class
    for (let i = 3; i < lines.length; i++) {
      const line = lines[i];
      if (line && !line.includes('logging.js') && !line.includes('Logger.')) {
        // Extract function name from stack trace
        const match = line.match(/at\s+(.+?)\s+\(/);
        if (match) {
          return match[1];
        }
        // Fallback to just the line content
        return line.trim().replace('at ', '');
      }
    }
    return 'unknown';
  }

  debug(...args) {
    if (this.level <= LOG_LEVELS.DEBUG) {
      const caller = this._getCaller();
      console.debug(`[${caller}]`, ...args);
    }
  }

  info(...args) {
    if (this.level <= LOG_LEVELS.INFO) {
      const caller = this._getCaller();
      console.info(`[${caller}]`, ...args);
    }
  }

  warn(...args) {
    if (this.level <= LOG_LEVELS.WARN) {
      const caller = this._getCaller();
      console.warn(`[${caller}]`, ...args);
    }
  }

  error(...args) {
    if (this.level <= LOG_LEVELS.ERROR) {
      const caller = this._getCaller();
      console.error(`[${caller}]`, ...args);
    }
  }

  setLevel(level) {
    this.level = level;
  }
}

export const createLogger = (prefix, level = DEFAULT_LEVEL) => new Logger(prefix, level);

export const logger = createLogger('dpop-fun');
