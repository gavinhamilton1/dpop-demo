// test/passkeys.test.js
import { jest } from '@jest/globals'; 

// ESM + Jest. Mock /src/dpop-fun.js BEFORE importing the SUT.
const dpopFunMock = { dpopFunFetch: jest.fn() };
await jest.unstable_mockModule('/src/dpop-fun.js', () => dpopFunMock);

const DpopFun = await import('/src/dpop-fun.js');
const {
  checkSupport,
  registerPasskey,
  getAuthOptions,
  authenticatePasskey,
} = await import('../src/passkeys.js');

// --- helpers ---
const abFrom = (arr) => Uint8Array.from(arr).buffer;
const abEq = (a, b) => {
  const A = new Uint8Array(a), B = new Uint8Array(b);
  if (A.length !== B.length) return false;
  for (let i = 0; i < A.length; i++) if (A[i] !== B[i]) return false;
  return true;
};
const b64u = (bufLike) =>
  Buffer
    .from(bufLike instanceof ArrayBuffer ? new Uint8Array(bufLike) : bufLike)
    .toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

beforeAll(() => {
  if (!global.window) global.window = global;
});

beforeEach(() => {
  jest.clearAllMocks();
  global.navigator = { credentials: { create: jest.fn(), get: jest.fn() } };
  delete window.PublicKeyCredential;
});

describe('checkSupport', () => {
  test('returns false when API missing', async () => {
    const res = await checkSupport();
    expect(res).toEqual({ hasAPI: false, uvp: false });
  });

  test('returns true/true when API present and uvp available', async () => {
    window.PublicKeyCredential = function(){};
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
      jest.fn().mockResolvedValue(true);

    const res = await checkSupport();
    expect(res).toEqual({ hasAPI: true, uvp: true });
    expect(window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable).toHaveBeenCalled();
  });

  test('uvp=false when probe rejects', async () => {
    window.PublicKeyCredential = function(){};
    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable =
      jest.fn().mockRejectedValue(new Error('nope'));

    const res = await checkSupport();
    expect(res).toEqual({ hasAPI: true, uvp: false });
  });
});

describe('registerPasskey', () => {
  test('happy path: shapes publicKey and verify payload', async () => {
    const userId = abFrom([0xde, 0xad, 0xbe, 0xef]);
    const challenge = abFrom([1, 2, 3, 4]);
    const opts = {
      rp: { id: 'localhost', name: 'Test RP' },
      user: { id: b64u(userId), name: 'acct:deadbeef', displayName: 'Acct deadbeef' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
      challenge: b64u(challenge),
      attestation: 'none',
      authenticatorSelection: { userVerification: 'preferred' },
    };
    DpopFun.dpopFunFetch
      .mockResolvedValueOnce(opts) // /registration/options
      .mockResolvedValueOnce({ ok: true, cred_id: 'cid123' }); // /registration/verify

    const rawId = abFrom([9, 8, 7, 6, 5]);
    const clientDataJSON = abFrom([11, 22, 33]);
    const attestationObject = abFrom([44, 55, 66]);

    navigator.credentials.create.mockImplementation(async (args) => {
      const pk = args.publicKey;
      expect(pk.rp).toEqual(opts.rp);
      expect(pk.user.name).toBe(opts.user.name);
      expect(pk.user.displayName).toBe(opts.user.displayName);
      expect(pk.user.id instanceof ArrayBuffer).toBe(true);
      expect(pk.pubKeyCredParams).toEqual(opts.pubKeyCredParams);
      expect(abEq(pk.challenge, challenge)).toBe(true);
      expect(pk.attestation).toBe('none');
      return {
        id: 'cred-123',
        rawId,
        type: 'public-key',
        response: {
          clientDataJSON,
          attestationObject,
          getTransports: () => ['internal'],
        },
      };
    });

    const res = await registerPasskey();
    expect(res).toEqual({ ok: true, cred_id: 'cid123' });

    const body = DpopFun.dpopFunFetch.mock.calls[1][1].body;
    expect(body).toEqual({
      id: 'cred-123',
      rawId: b64u(rawId),
      type: 'public-key',
      response: {
        clientDataJSON: b64u(clientDataJSON),
        attestationObject: b64u(attestationObject),
      },
      transports: ['internal'],
    });
  });

  test('throws on user cancellation', async () => {
    DpopFun.dpopFunFetch.mockResolvedValueOnce({
      rp: { id: 'localhost', name: 'RP' },
      user: { id: b64u(abFrom([1, 2, 3])) },
      pubKeyCredParams: [],
      challenge: b64u(abFrom([4, 5, 6])),
    });
    navigator.credentials.create.mockResolvedValue(null);
    await expect(registerPasskey()).rejects.toThrow('registration cancelled');
  });
});

describe('getAuthOptions', () => {
  test('POSTs to /webauthn/authentication/options and returns JSON', async () => {
    const opts = { rpId: 'localhost', challenge: b64u(abFrom([9])) };
    DpopFun.dpopFunFetch.mockResolvedValueOnce(opts);
    const out = await getAuthOptions();
    expect(out).toEqual(opts);
    expect(DpopFun.dpopFunFetch).toHaveBeenCalledWith(
      '/webauthn/authentication/options',
      expect.objectContaining({ method: 'POST' }),
    );
  });
});

describe('authenticatePasskey', () => {
  test('uses provided options and shapes allowCredentials + payload', async () => {
    const challenge = abFrom([1, 2, 3, 4, 5]);
    const preOpts = {
      rpId: 'localhost',
      challenge: b64u(challenge),
      userVerification: 'required',
      allowCredentials: [
        { type: 'public-key', id: b64u(abFrom([9, 9, 9])), transports: ['internal'] },
      ],
    };

    const rawId = abFrom([7, 7, 7]);
    const clientDataJSON = abFrom([10]);
    const authenticatorData = abFrom([20]);
    const signature = abFrom([30]);

    let captured;
    navigator.credentials.get.mockImplementation(async (args) => {
      captured = args;
      return {
        id: 'cred-abc',
        rawId,
        type: 'public-key',
        response: { clientDataJSON, authenticatorData, signature, userHandle: null },
      };
    });
    DpopFun.dpopFunFetch.mockResolvedValueOnce({ ok: true, principal: 'p1' });

    const out = await authenticatePasskey(preOpts);
    expect(out).toEqual({ ok: true, principal: 'p1' });

    const pk = captured.publicKey;
    expect(pk.rpId).toBe('localhost');
    expect(pk.userVerification).toBe('required');
    expect(abEq(pk.challenge, challenge)).toBe(true);
    expect(pk.allowCredentials).toHaveLength(1);
    expect(abEq(pk.allowCredentials[0].id, abFrom([9, 9, 9]))).toBe(true);

    expect(DpopFun.dpopFunFetch).toHaveBeenCalledWith(
      '/webauthn/authentication/verify',
      expect.objectContaining({
        method: 'POST',
        body: {
          id: 'cred-abc',
          rawId: b64u(rawId),
          type: 'public-key',
          response: {
            clientDataJSON: b64u(clientDataJSON),
            authenticatorData: b64u(authenticatorData),
            signature: b64u(signature),
            userHandle: undefined,
          },
        },
      }),
    );
  });

  test('fetches options when none passed', async () => {
    const opts = {
      rpId: 'localhost',
      challenge: b64u(abFrom([1])),
      userVerification: 'preferred',
      allowCredentials: [],
    };
    DpopFun.dpopFunFetch
      .mockResolvedValueOnce(opts)    // getAuthOptions
      .mockResolvedValueOnce({ ok: true }); // verify

    navigator.credentials.get.mockResolvedValue({
      id: 'x',
      rawId: abFrom([1, 2]),
      type: 'public-key',
      response: {
        clientDataJSON: abFrom([3]),
        authenticatorData: abFrom([4]),
        signature: abFrom([5]),
        userHandle: undefined,
      },
    });

    const res = await authenticatePasskey();
    expect(res).toEqual({ ok: true });
    expect(DpopFun.dpopFunFetch).toHaveBeenNthCalledWith(
      1,
      '/webauthn/authentication/options',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(DpopFun.dpopFunFetch).toHaveBeenNthCalledWith(
      2,
      '/webauthn/authentication/verify',
      expect.any(Object),
    );
  });

  test('throws on user cancellation', async () => {
    const opts = {
      rpId: 'localhost',
      challenge: b64u(abFrom([1])),
      allowCredentials: [],
    };
    DpopFun.dpopFunFetch.mockResolvedValueOnce(opts);
    navigator.credentials.get.mockResolvedValue(null);
    await expect(authenticatePasskey()).rejects.toThrow('authentication cancelled');
  });
});
