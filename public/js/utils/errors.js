// src/utils/errors.js
export class StrongholdError extends Error {
  constructor(message, code, details = {}) {
    super(message);
    this.name = 'StrongholdError';
    this.code = code;
    this.details = details;
  }
}

export class AuthenticationError extends StrongholdError {
  constructor(message, details = {}) {
    super(message, 'AUTH_ERROR', details);
    this.name = 'AuthenticationError';
  }
}

export class NetworkError extends StrongholdError {
  constructor(message, status, details = {}) {
    super(message, 'NETWORK_ERROR', { status, ...details });
    this.name = 'NetworkError';
    this.status = status;
  }
}

export class CryptoError extends StrongholdError {
  constructor(message, details = {}) {
    super(message, 'CRYPTO_ERROR', details);
    this.name = 'CryptoError';
  }
}

export class StorageError extends StrongholdError {
  constructor(message, details = {}) {
    super(message, 'STORAGE_ERROR', details);
    this.name = 'StorageError';
  }
}
