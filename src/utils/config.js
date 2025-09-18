// src/utils/config.js
export const CONFIG = {
  TIMEOUTS: {
    BIK_ROTATE_SEC: 7 * 24 * 3600,  // 7 days
    DPOP_ROTATE_SEC: 1 * 24 * 3600, // 1 day
    SESSION_IDLE_TIMEOUT: 15 * 60 * 1000, // 15 minutes
  },
  ENDPOINTS: {
    SESSION_INIT: '/session/init',
    SESSION_RESUME_INIT: '/session/resume-init',
    SESSION_RESUME_CONFIRM: '/session/resume-confirm',
    BROWSER_REGISTER: '/browser/register',
    DPOP_BIND: '/dpop/bind',
    WEBAUTHN_REGISTRATION_OPTIONS: '/webauthn/registration/options',
    WEBAUTHN_REGISTRATION_VERIFY: '/webauthn/registration/verify',
    WEBAUTHN_AUTHENTICATION_OPTIONS: '/webauthn/authentication/options',
    WEBAUTHN_AUTHENTICATION_VERIFY: '/webauthn/authentication/verify',
  },
  // Allowed origins for multi-domain support
  ALLOWED_ORIGINS: [
    'http://localhost:8000',
    'https://dpop.fun',
    'https://stronghold.onrender.com'
  ],
  CRYPTO: {
    KEY_SIZE: 32,
    ALGORITHM: 'ES256',
    CURVE: 'P-256',
    JWT_TYPES: {
      DPOP: 'dpop+jwt',
      BIK_REG: 'bik-reg+jws',
      BIK_RESUME: 'bik-resume+jws',
      DPOP_BIND: 'dpop-bind+jws',
    }
  },
  STORAGE: {
    DB_NAME: 'dpop-fun',
    DB_VERSION: 1,
    STORES: { KEYS: 'keys', META: 'meta' },
    KEYS: {
      BIK_CURRENT: 'bik.current',
      DPOP_CURRENT: 'dpop.current',
      BIND: 'bind',
      DPOP_NONCE: 'dpop_nonce',
      BROWSER_UUID: 'browser_uuid',
      BIK_JKT: 'bik_jkt',
      CSRF: 'csrf',
      REG_NONCE: 'reg_nonce',
    }
  },
  HTTP: {
    METHODS: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'],
    STATUS_CODES: {
      OK: 200,
      UNAUTHORIZED: 401,
      PRECONDITION_REQUIRED: 428,
      INTERNAL_SERVER_ERROR: 500,
    }
  }
};
