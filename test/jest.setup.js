// test/jest.setup.js

// 1) IndexedDB polyfill (sync, no side effects beyond globals)
import 'fake-indexeddb/auto';

// 2) Stable WebCrypto + UUID from Node core (Node 18+)
import { webcrypto as nodeWebcrypto, randomUUID as nodeRandomUUID } from 'node:crypto';

// Some libs may have already defined a minimal `crypto` (e.g., only getRandomValues).
// Don't replace the object (could be non-writable); instead, fill in the pieces.
if (!global.crypto) global.crypto = {};
if (!global.crypto.subtle) global.crypto.subtle = nodeWebcrypto.subtle;
if (!global.crypto.getRandomValues) {
  // bind to the webcrypto object
  global.crypto.getRandomValues = nodeWebcrypto.getRandomValues.bind(nodeWebcrypto);
}
if (!global.crypto.randomUUID) {
  global.crypto.randomUUID = nodeRandomUUID;
}

// 3) TextEncoder/TextDecoder (Node 18+ provides these via node:util)
import { TextEncoder, TextDecoder } from 'node:util';
if (!global.TextEncoder) global.TextEncoder = TextEncoder;
if (!global.TextDecoder) global.TextDecoder = TextDecoder;

// 4) atob/btoa for base64 helpers
if (!global.atob) {
  global.atob = (b64) => Buffer.from(b64, 'base64').toString('binary');
}
if (!global.btoa) {
  global.btoa = (bin) => Buffer.from(bin, 'binary').toString('base64');
}

// 5) structuredClone fallback (good enough for tests)
if (!global.structuredClone) {
  global.structuredClone = (obj) => JSON.parse(JSON.stringify(obj));
}

// 6) location.origin used by canonicalUrl()
// Make sure both global and self share the same object, with explicit :8000 port
const testOrigin = 'http://localhost:8000';
if (!global.location) global.location = { origin: testOrigin };
if (!global.self) global.self = {};
if (!self.location) self.location = global.location;

// 7) Minimal Service Worker scaffolding for SW tests (no dynamic imports)
if (!self.__listeners) {
  self.__listeners = { install: [], activate: [], fetch: [], message: [] };
}
self.addEventListener = (type, fn) => {
  (self.__listeners[type] ||= []).push(fn);
};
self.skipWaiting = () => Promise.resolve();
self.clients = { claim: () => Promise.resolve() };

// 8) Fetch/Request/Response/Headers
// Node 18+ exposes these globally. If you run an older Node, upgrade to 18+.
