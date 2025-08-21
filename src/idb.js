// src/idb.js
import { storageLogger } from './utils/logging.js';
import { StorageError } from './utils/errors.js';
import { CONFIG } from './utils/config.js';

export const DB_NAME = CONFIG.STORAGE.DB_NAME;
export const DB_VERSION = CONFIG.STORAGE.DB_VERSION;
export const STORES = CONFIG.STORAGE.STORES;

let _db = null;
let _opening = null;

export function idbReset() {
  try { 
    _db?.close(); 
  } catch (error) {
    storageLogger.warn('Error closing database during reset:', error);
  }
  _db = null;
  _opening = null;
  storageLogger.debug('IndexedDB reset completed');
}

export async function idbWipe() {
  try {
    storageLogger.debug('Wiping IndexedDB database');
    await new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => {
        storageLogger.debug('IndexedDB database deleted successfully');
        resolve();
      };
      req.onerror = () => {
        storageLogger.error('Failed to delete IndexedDB database:', req.error);
        reject(req.error);
      };
      req.onblocked = () => {
        const error = new Error('IndexedDB deletion blocked (another tab open?)');
        storageLogger.error('IndexedDB deletion blocked:', error);
        reject(error);
      };
    });
    idbReset(); // <<< critical: drop cached connection so next open recreates stores
  } catch (error) {
    storageLogger.error('Failed to wipe IndexedDB:', error);
    throw new StorageError('Failed to wipe IndexedDB database', { originalError: error.message });
  }
}

async function openDB() {
  if (_db) return _db;
  if (_opening) return _opening;

  storageLogger.debug('Opening IndexedDB connection');
  _opening = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    
    req.onupgradeneeded = () => {
      storageLogger.debug('IndexedDB upgrade needed, creating stores');
      const db = req.result;
      if (!db.objectStoreNames.contains(STORES.KEYS)) {
        db.createObjectStore(STORES.KEYS, { keyPath: 'id' });
        storageLogger.debug('Created keys store');
      }
      if (!db.objectStoreNames.contains(STORES.META)) {
        db.createObjectStore(STORES.META, { keyPath: 'id' });
        storageLogger.debug('Created meta store');
      }
    };
    
    req.onsuccess = () => {
      _db = req.result;
      _db.onversionchange = () => { 
        try { 
          _db.close(); 
        } catch (error) {
          storageLogger.warn('Error closing database on version change:', error);
        } 
        _db = null; 
      };
      _opening = null;
      storageLogger.debug('IndexedDB connection opened successfully');
      resolve(_db);
    };
    
    req.onerror = () => { 
      _opening = null; 
      storageLogger.error('Failed to open IndexedDB:', req.error);
      reject(req.error); 
    };
  });

  return _opening;
}

async function run(storeName, mode, fn, attempt = 0) {
  try {
    const db = await openDB();
    const tx = db.transaction(storeName, mode);
    const store = tx.objectStore(storeName);
    const result = await fn(store);
    await new Promise((resolve, reject) => {
      tx.oncomplete = () => resolve();
      tx.onabort = () => reject(tx.error || new Error('tx aborted'));
      tx.onerror = () => reject(tx.error);
    });
    return result;
  } catch (e) {
    // Auto-heal once if a stale handle/tx caused it
    if (attempt === 0 && (
      e?.name === 'InvalidStateError' ||
      e?.name === 'TransactionInactiveError' ||
      e?.name === 'NotFoundError'
    )) {
      storageLogger.warn('IndexedDB transaction failed, attempting auto-heal:', e);
      idbReset();
      return run(storeName, mode, fn, 1);
    }
    storageLogger.error('IndexedDB operation failed:', e);
    throw new StorageError('IndexedDB operation failed', { 
      originalError: e.message, 
      storeName, 
      mode, 
      attempt 
    });
  }
}

export async function idbPut(storeName, record) {
  try {
    storageLogger.debug('Putting record in store:', { storeName, recordId: record.id });
    const result = await run(storeName, 'readwrite', (store) => store.put(record));
    storageLogger.debug('Record put successfully');
    return result;
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new StorageError('Failed to put record in IndexedDB', { 
      originalError: error.message, 
      storeName, 
      recordId: record.id 
    });
  }
}

export async function idbGet(storeName, id) {
  try {
    storageLogger.debug('Getting record from store:', { storeName, id });
    const result = await run(storeName, 'readonly', (store) => new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    }));
    storageLogger.debug('Record retrieved:', { storeName, id, found: !!result });
    return result;
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new StorageError('Failed to get record from IndexedDB', { 
      originalError: error.message, 
      storeName, 
      id 
    });
  }
}
