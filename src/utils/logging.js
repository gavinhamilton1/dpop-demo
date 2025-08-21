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

  debug(...args) {
    if (this.level <= LOG_LEVELS.DEBUG) {
      console.debug(`[${this.prefix}]`, ...args);
    }
  }

  info(...args) {
    if (this.level <= LOG_LEVELS.INFO) {
      console.info(`[${this.prefix}]`, ...args);
    }
  }

  warn(...args) {
    if (this.level <= LOG_LEVELS.WARN) {
      console.warn(`[${this.prefix}]`, ...args);
    }
  }

  error(...args) {
    if (this.level <= LOG_LEVELS.ERROR) {
      console.error(`[${this.prefix}]`, ...args);
    }
  }

  setLevel(level) {
    this.level = level;
  }
}

export const createLogger = (prefix, level = DEFAULT_LEVEL) => new Logger(prefix, level);

export const coreLogger = createLogger('stronghold/core');
export const swLogger = createLogger('stronghold/sw');
export const cryptoLogger = createLogger('stronghold/crypto');
export const storageLogger = createLogger('stronghold/storage');
export const networkLogger = createLogger('stronghold/network');
