// src/idb.js
export const DB_NAME = 'stronghold-demo';
export const DB_VERSION = 1;
export const STORES = { KEYS: 'keys', META: 'meta' };

let _db = null;
let _opening = null;

export function idbReset() {
  try { _db?.close(); } catch {}
  _db = null;
  _opening = null;
}

export async function idbWipe() {
  await new Promise((resolve, reject) => {
    const req = indexedDB.deleteDatabase(DB_NAME);
    req.onsuccess = () => resolve();
    req.onerror   = () => reject(req.error);
    req.onblocked = () => reject(new Error('IndexedDB deletion blocked (another tab open?)'));
  });
  idbReset(); // <<< critical: drop cached connection so next open recreates stores
}

async function openDB() {
  if (_db) return _db;
  if (_opening) return _opening;

  _opening = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORES.KEYS)) db.createObjectStore(STORES.KEYS, { keyPath: 'id' });
      if (!db.objectStoreNames.contains(STORES.META)) db.createObjectStore(STORES.META, { keyPath: 'id' });
    };
    req.onsuccess = () => {
      _db = req.result;
      _db.onversionchange = () => { try { _db.close(); } catch {} _db = null; };
      _opening = null;
      resolve(_db);
    };
    req.onerror = () => { _opening = null; reject(req.error); };
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
      idbReset();
      return run(storeName, mode, fn, 1);
    }
    throw e;
  }
}

export async function idbPut(storeName, record) {
  return run(storeName, 'readwrite', (store) => store.put(record));
}

export async function idbGet(storeName, id) {
  return run(storeName, 'readonly', (store) => new Promise((resolve, reject) => {
    const req = store.get(id);
    req.onsuccess = () => resolve(req.result ?? null);
    req.onerror = () => reject(req.error);
  }));
}
