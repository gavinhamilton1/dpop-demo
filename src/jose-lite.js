export const b64u = (bytes) => {
  const bin = String.fromCharCode(...(bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)));
  return btoa(bin).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/g,'');
};
export const b64uJSON = (obj) => b64u(new TextEncoder().encode(JSON.stringify(obj)));

export function sigToJoseEcdsa(sig, size=32) {
  const u = new Uint8Array(sig);
  if (u.length === size*2) return u;
  if (u[0] !== 0x30) throw new Error('Unsupported ECDSA signature format');
  let i=2;
  if (u[i++]!==0x02) throw new Error('DER r');
  let rLen=u[i++]; let r=u.slice(i, i+rLen); i+=rLen;
  if (u[i++]!==0x02) throw new Error('DER s');
  let sLen=u[i++]; let s=u.slice(i, i+sLen);
  if (r[0]===0x00) r=r.slice(1);
  if (s[0]===0x00) s=s.slice(1);
  const R=new Uint8Array(size); R.set(r, size-r.length);
  const S=new Uint8Array(size); S.set(s, size-s.length);
  const out=new Uint8Array(size*2); out.set(R,0); out.set(S,size);
  return out;
}

export async function createJwsES256({ protectedHeader, payload, privateKey }) {
  const h = b64uJSON(protectedHeader);
  const p = b64uJSON(payload);
  const input = new TextEncoder().encode(`${h}.${p}`);
  const sig = await crypto.subtle.sign({ name:'ECDSA', hash:'SHA-256' }, privateKey, input);
  const sigJose = sigToJoseEcdsa(sig, 32);
  const s = b64u(sigJose);
  return `${h}.${p}.${s}`;
}

export async function createDpopProof({ url, method, nonce, privateKey, publicJwk, iat=Math.floor(Date.now()/1000), jti=crypto.randomUUID() }) {
  const protectedHeader = { alg:'ES256', typ:'dpop+jwt', jwk: publicJwk };
  const payload = { htu: url, htm: method.toUpperCase(), iat, jti, ...(nonce ? {nonce} : {}) };
  return createJwsES256({ protectedHeader, payload, privateKey });
}

export async function jwkThumbprint(jwk) {
  const ordered = { kty: jwk.kty, crv: jwk.crv, x: jwk.x, y: jwk.y };
  const data = new TextEncoder().encode(JSON.stringify(ordered));
  const hash = await crypto.subtle.digest('SHA-256', data);
  return b64u(hash);
}
