// test/idb.test.js
import { idbPut, idbGet, idbWipe, STORES } from '/src/idb.js';

describe('idb.js', () => {
  beforeEach(async () => {
    await idbWipe(); // exercise upgrade path too
  });

  test('put/get across both stores', async () => {
    await idbPut(STORES.KEYS, { id: 'k1', v: 123 });
    await idbPut(STORES.META, { id: 'm1', value: 'abc' });

    const k = await idbGet(STORES.KEYS, 'k1');
    const m = await idbGet(STORES.META, 'm1');
    expect(k?.v).toBe(123);
    expect(m?.value).toBe('abc');
  });

  test('wipe removes data and allows reopening DB', async () => {
    await idbPut(STORES.META, { id: 'temp', value: 42 });
    expect((await idbGet(STORES.META, 'temp'))?.value).toBe(42);

    await idbWipe();

    const after = await idbGet(STORES.META, 'temp');
    // implementation returns null (not undefined) when missing — accept either
    expect(after == null).toBe(true);

    // can write again after wipe
    await idbPut(STORES.META, { id: 'again', value: 'ok' });
    expect((await idbGet(STORES.META, 'again'))?.value).toBe('ok');
  });
});
