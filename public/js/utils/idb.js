// src/idb.js
import { logger } from './logging.js';
import { CONFIG } from './config.js';

export const DB_NAME = CONFIG.STORAGE.DB_NAME;
export const DB_VERSION = CONFIG.STORAGE.DB_VERSION;
export const STORES = CONFIG.STORAGE.STORES;

let _db = null;
let _opening = null;

export function idbReset() {
  try { 
    _db?.close(); 
  } catch (error) {
    logger.warn('Error closing database during reset:', error);
  }
  _db = null;
  _opening = null;
  logger.info('IndexedDB reset completed');
}

export async function idbWipe() {
  try {
    logger.info('Wiping IndexedDB database');
    await new Promise((resolve, reject) => {
      const req = indexedDB.deleteDatabase(DB_NAME);
      req.onsuccess = () => {
        logger.info('IndexedDB database deleted successfully');
        resolve();
      };
      req.onerror = () => {
        logger.error('Failed to delete IndexedDB database:', req.error);
        reject(req.error);
      };
      req.onblocked = () => {
        const error = new Error('IndexedDB deletion blocked (another tab open?)');
        logger.error('IndexedDB deletion blocked:', error);
        reject(error);
      };
    });
    idbReset(); // <<< critical: drop cached connection so next open recreates stores
  } catch (error) {
    logger.error('Failed to wipe IndexedDB:', error);
    throw new Error('Failed to wipe IndexedDB database', { originalError: error.message });
  }
}

async function openDB() {
  if (_db) return _db;
  if (_opening) return _opening;

  logger.info('Opening IndexedDB connection');
  _opening = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    
    req.onupgradeneeded = () => {
      logger.info('IndexedDB upgrade needed, creating session store');
      const db = req.result;
      if (!db.objectStoreNames.contains(STORES.SESSION)) {
        db.createObjectStore(STORES.SESSION, { keyPath: 'id' });
        logger.info('Created session store');
      }
    };
    
    req.onsuccess = () => {
      _db = req.result;
      _db.onversionchange = () => { 
        try { 
          _db.close(); 
        } catch (error) {
          logger.warn('Error closing database on version change:', error);
        } 
        _db = null; 
      };
      _opening = null;
      logger.info('IndexedDB connection opened successfully');
      resolve(_db);
    };
    
    req.onerror = () => { 
      _opening = null; 
      logger.error('Failed to open IndexedDB:', req.error);
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
      logger.warn('IndexedDB transaction failed, attempting auto-heal by wiping database:', e);
      await idbWipe();
      return run(storeName, mode, fn, 1);
    }
    logger.error('IndexedDB operation failed:', e);
    throw new Error('IndexedDB operation failed', { 
      originalError: e.message, 
      storeName, 
      mode, 
      attempt 
    });
  }
}

export async function idbPut(storeName, record) {
  try {
    logger.info('Putting record in store:', { storeName, recordId: record.id, value: record.value });
    const result = await run(storeName, 'readwrite', (store) => store.put(record));
    logger.info('Record put successfully');
    return result;
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new Error('Failed to put record in IndexedDB', { 
      originalError: error.message, 
      storeName, 
      recordId: record.id 
    });
  }
}

export async function idbGet(storeName, id) {
  try {
    logger.info('Getting record from store:', { storeName, id });
    const result = await run(storeName, 'readonly', (store) => new Promise((resolve, reject) => {
      const req = store.get(id);
      req.onsuccess = () => resolve(req.result ?? null);
      req.onerror = () => reject(req.error);
    }));
    logger.info('Record retrieved:', { storeName, id, found: !!result });
    return result;
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new Error('Failed to get record from IndexedDB', { 
      originalError: error.message, 
      storeName, 
      id 
    });
  }
}

export async function idbDelete(storeName, id) {
  try {
    logger.info('Deleting record from store:', { storeName, id });
    await run(storeName, 'readwrite', (store) => new Promise((resolve, reject) => {
      const req = store.delete(id);
      req.onsuccess = () => resolve();
      req.onerror = () => reject(req.error);
    }));
    logger.info('Record deleted successfully:', { storeName, id });
  } catch (error) {
    if (error.name === 'StorageError') throw error;
    throw new Error('Failed to delete record from IndexedDB', { 
      originalError: error.message, 
      storeName, 
      id 
    });
  }
}
