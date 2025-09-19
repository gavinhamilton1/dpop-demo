// src/utils/errors.js
export class DPopFunError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'DPopFunError';
    this.code = code;
    this.details = details;
  }
}

export class AuthenticationError extends DPopFunError {
  constructor(message, details = {}) {
    super(message, 'AUTH_ERROR', details);
    this.name = 'AuthenticationError';
  }
}

export class NetworkError extends DPopFunError {
  constructor(message, status, details = {}) {
    super(message, 'NETWORK_ERROR', { status, ...details });
    this.name = 'NetworkError';
    this.status = status;
  }
}

export class CryptoError extends DPopFunError {
  constructor(message, details = {}) {
    super(message, 'CRYPTO_ERROR', details);
    this.name = 'CryptoError';
  }
}

export class StorageError extends DPopFunError {
  constructor(message, details = {}) {
    super(message, 'STORAGE_ERROR', details);
    this.name = 'StorageError';
  }
}
