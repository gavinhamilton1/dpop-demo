# server/passkeys.py
from __future__ import annotations
import os, base64, hashlib, json, secrets, struct, threading, time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Set, Tuple, Callable
from urllib.parse import urlsplit

import cbor2
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding, ed25519
from cryptography.x509.oid import ObjectIdentifier

# ---------------- Policy (Android-friendly by default) ----------------
POLICY = os.getenv('PASSKEYS_POLICY', 'compat')  # 'compat' | 'strict'
ALLOW_NO_ATTESTATION = (POLICY == 'compat')
UV_MODE = 'preferred' if POLICY == 'compat' else 'required'
RESIDENT_MODE = 'preferred' if POLICY == 'compat' else 'required'
ATTESTATION_MODE = 'none' if POLICY == 'compat' else 'direct'

# NEW: Prefer platform authenticator & local device during auth by default
ATTACHMENT_PREF = os.getenv('PASSKEYS_ATTACHMENT', 'platform')  # 'platform' | 'cross-platform' | ''
PLATFORM_ONLY = os.getenv('PASSKEYS_PLATFORM_ONLY', '1') == '1' # if true, restrict allowCredentials transports to ['internal']
AUTH_HINTS = [h.strip() for h in os.getenv('PASSKEYS_AUTH_HINTS', 'client-device').split(',') if h.strip()]  # e.g. "client-device" or "client-device,security-key"

_DEF_RP_NAME = "Stronghold Demo"

# ---------------- utils ----------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def _b64u_dec(s: str) -> bytes:
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def _nonce_headers(ctx: Any) -> Dict[str, str]:
    try:
        n = ctx.get("next_nonce") if isinstance(ctx, dict) else None
        return {"DPoP-Nonce": n} if n else {}
    except Exception:
        return {}

def _now() -> int:
    return int(time.time())

# authData parser (RPID hash, flags, signCount; AT → aaguid, credId, rest)
def parse_authenticator_data(ad: bytes) -> Dict[str, Any]:
    if len(ad) < 37:
        raise HTTPException(status_code=400, detail="authData too short")
    rpIdHash = ad[0:32]
    flags = ad[32]
    signCount = struct.unpack(">I", ad[33:37])[0]
    off = 37
    res: Dict[str, Any] = {"rpIdHash": rpIdHash, "flags": flags, "signCount": signCount}
    AT = (flags & 0x40) != 0
    if AT:
        if len(ad) < off + 16 + 2:
            raise HTTPException(status_code=400, detail="attestedCredentialData truncated")
        aaguid = ad[off:off+16]; off += 16
        cred_len = struct.unpack(">H", ad[off:off+2])[0]; off += 2
        credId = ad[off:off+cred_len]; off += cred_len
        res.update({"aaguid": aaguid, "credId": credId})
        res["rest"] = ad[off:]
    return res

# COSE → JWK (EC P-256 / RSA / OKP Ed25519)
def cose_to_jwk(cbor_bytes: bytes) -> dict:
    m = cbor2.loads(cbor_bytes)
    kty = m.get(1)   # 1=OKP, 2=EC2, 3=RSA
    if kty == 2:  # EC2
        crv = m.get(-1); x = m.get(-2); y = m.get(-3)
        if crv != 1:
            raise HTTPException(status_code=400, detail="unsupported EC curve")
        return {"kty":"EC","crv":"P-256","x":_b64u(x),"y":_b64u(y),"alg":"ES256"}
    if kty == 3:  # RSA
        n = m.get(-1); e = m.get(-2)
        return {"kty":"RSA","n":_b64u(n),"e":_b64u(e),"alg":"RS256"}
    if kty == 1:  # OKP (Ed25519)
        crv = m.get(-1); x = m.get(-2)
        if crv == 6 and x:
            return {"kty":"OKP","crv":"Ed25519","x":_b64u(x),"alg":"EdDSA"}
        raise HTTPException(status_code=400, detail="unsupported OKP curve")
    raise HTTPException(status_code=400, detail="unsupported COSE key")

# JWK → public key
def jwk_to_pub(jwk: dict):
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(_b64u_dec(jwk["x"]), "big")
        y = int.from_bytes(_b64u_dec(jwk["y"]), "big")
        numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return numbers.public_key(), "ES256"
    if jwk.get("kty") == "RSA":
        n = int.from_bytes(_b64u_dec(jwk["n"]), "big")
        e = int.from_bytes(_b64u_dec(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub, "RS256"
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        pub = ed25519.Ed25519PublicKey.from_public_bytes(_b64u_dec(jwk["x"]))
        return pub, "EdDSA"
    raise HTTPException(status_code=400, detail="unsupported JWK")

# ---------------- Attestation (packed+x5c; allow-list optional) ----------------
class AttestationFailure(Exception): pass

@dataclass
class AAGUIDAllowlist:
    allowed: Set[str]
    @staticmethod
    def load(path: Optional[str] = None) -> 'AAGUIDAllowlist':
        if not path:
            return AAGUIDAllowlist(set())  # empty → allow any AAGUID after crypto checks
        with open(path, 'r') as f:
            j = json.load(f)
        return AAGUIDAllowlist(set([k.replace('-', '').lower() for k,v in j.items() if v]))

def _verify_chain_x5c(x5c: List[bytes], trusted_roots: List[x509.Certificate]) -> Tuple[bool, List[str]]:
    if not x5c: return False, []
    certs = [x509.load_der_x509_certificate(c) for c in x5c]
    for i in range(len(certs)-1):
        issuer_pk = certs[i+1].public_key(); cert = certs[i]
        try:
            if isinstance(issuer_pk, rsa.RSAPublicKey):
                issuer_pk.verify(cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm)
            else:
                issuer_pk.verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(cert.signature_hash_algorithm))
        except Exception:
            return False, []
    fps = [c.fingerprint(hashes.SHA256()).hex() for c in certs]
    if not trusted_roots:
        return True, fps
    anchor_fps = set(c.fingerprint(hashes.SHA256()) for c in trusted_roots)
    ok = any(c.fingerprint(hashes.SHA256()) in anchor_fps for c in certs)
    return ok, fps

def verify_packed_attestation_x5c(attStmt: dict, authData: bytes, client_hash: bytes, *, expected_rp_id: str, allowed_aaguids: Set[str]):
    if len(authData) < 37: raise AttestationFailure("authData too short")
    rpIdHash = authData[0:32]; flags = authData[32]
    signCount = int.from_bytes(authData[33:37], 'big')
    if (flags & 0x40) == 0: raise AttestationFailure("missing AT flag")
    off = 37
    aaguid = authData[off:off+16]; off += 16
    cred_len = int.from_bytes(authData[off:off+2], 'big'); off += 2
    credId = authData[off:off+cred_len]; off += cred_len
    cose = authData[off:]
    if rpIdHash != hashlib.sha256(expected_rp_id.encode()).digest():
        raise AttestationFailure("rpIdHash mismatch")

    x5c = attStmt.get('x5c'); 
    if not x5c: raise AttestationFailure("packed: missing x5c")
    x5c_bytes = [bytes(x) for x in x5c]
    leaf = x509.load_der_x509_certificate(x5c_bytes[0])
    alg = attStmt.get('alg', -7)
    sig = bytes(attStmt.get('sig'))
    signed = authData + client_hash
    if alg == -7:
        leaf.public_key().verify(sig, signed, ec.ECDSA(hashes.SHA256()))
    elif alg == -257:
        leaf.public_key().verify(sig, signed, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise AttestationFailure("unsupported packed alg")

    try:
        ext = leaf.extensions.get_extension_for_oid(ObjectIdentifier('1.3.6.1.4.1.45724.1.1.4')).value
        if ext and hasattr(ext, 'value') and ext.value != aaguid:
            raise AttestationFailure("certificate AAGUID != authData AAGUID")
    except Exception:
        pass

    fps: List[str] = []
    if allowed_aaguids:
        try:
            with open('server/mds_roots.json','r') as f:
                m = json.load(f)
            pem_list = m.get(aaguid.hex(), [])
            roots = []
            for pem in pem_list:
                try: roots.append(x509.load_pem_x509_certificate(pem.encode()))
                except Exception: pass
            ok, fps = _verify_chain_x5c(x5c_bytes, roots)
            if not ok:
                raise AttestationFailure("attestation chain not anchored to trusted root for AAGUID")
        except FileNotFoundError:
            raise AttestationFailure("no MDS roots available; provide server/mds_roots.json or disable allowlist")

    jwk = cose_to_jwk(cose)
    return {
        'aaguid': aaguid,
        'cred_id': _b64u(credId),
        'jwk': jwk,
        'sign_count': signCount,
        'trust_chain': fps,
    }

# ---------------- Passkey Repo (account-scoped persistence) ----------------
class PasskeyRepo:
    """
    Persistent store of passkey verifier material keyed by principal (account).
    Schema on disk:
      {
        "by_principal": {
          "<principal>": [ { cred_id, public_key_jwk, sign_count, aaguid, transports, created_at, ... }, ... ]
        }
      }
    """
    def __init__(self, file_path: Optional[str] = None):
        self._file = file_path
        self._lock = threading.RLock()
        self._by_principal: Dict[str, List[Dict[str, Any]]] = {}
        self._by_cred: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        self._load()

    def _load(self):
        if not self._file:
            self._by_principal = {}
            self._by_cred = {}
            return
        try:
            with open(self._file, 'r') as f:
                j = json.load(f)
            self._by_principal = j.get('by_principal', {}) or {}
            # rebuild cred index
            self._by_cred = {}
            for p, lst in self._by_principal.items():
                for rec in lst:
                    cid = rec.get("cred_id")
                    if cid:
                        self._by_cred[cid] = (p, rec)
        except FileNotFoundError:
            self._by_principal = {}; self._by_cred = {}
        except Exception:
            self._by_principal = {}; self._by_cred = {}

    def _flush(self):
        if not self._file:
            return
        os.makedirs(os.path.dirname(self._file) or ".", exist_ok=True)
        with open(self._file, 'w') as f:
            json.dump({'by_principal': self._by_principal}, f, indent=2)

    # ---- public API your routes depend on ----
    def get_for_principal(self, principal: str) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._by_principal.get(principal, []))

    def upsert(self, principal: str, rec: Dict[str, Any]) -> None:
        with self._lock:
            lst = self._by_principal.setdefault(principal, [])
            cid = rec.get("cred_id")
            idx = next((i for i, r in enumerate(lst) if r.get("cred_id") == cid), None)
            if idx is None:
                lst.append(rec)
            else:
                lst[idx] = rec
            if cid:
                self._by_cred[cid] = (principal, rec)
            self._flush()

    def find_by_cred_id(self, principal: str, cred_id: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            for r in self._by_principal.get(principal, []):
                if r.get("cred_id") == cred_id:
                    return r
            return None

    def get_by_cred_id(self, cred_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        with self._lock:
            return self._by_cred.get(cred_id)

    def update_sign_count(self, cred_id: str, new_count: int):
        with self._lock:
            ent = self._by_cred.get(cred_id)
            if ent:
                principal, rec = ent
                rec['sign_count'] = new_count
                # write back into the list
                lst = self._by_principal.get(principal, [])
                for i, r in enumerate(lst):
                    if r.get("cred_id") == cred_id:
                        lst[i] = rec
                        break
                self._by_principal[principal] = lst
                self._by_cred[cred_id] = (principal, rec)
                self._flush()

    def remove(self, principal: str, cred_id: str) -> bool:
        with self._lock:
            lst = self._by_principal.get(principal)
            if not lst:
                return False
            new = [r for r in lst if r.get("cred_id") != cred_id]
            changed = len(new) != len(lst)
            if changed:
                self._by_principal[principal] = new
                self._by_cred.pop(cred_id, None)
                self._flush()
            return changed

# ---------------- Router factory ----------------
def get_router(
    session_store: Any,
    require_dpop: Callable,                                 # FastAPI dep
    canonicalize_origin_and_url: Callable[[Request], Tuple[str, str]],
    now_fn: Callable[[], int],
    *,
    rp_name: str = _DEF_RP_NAME,
    passkey_repo: Optional[PasskeyRepo] = None,
    passkey_repo_file: Optional[str] = None,
) -> APIRouter:
    repo = passkey_repo or PasskeyRepo(file_path=passkey_repo_file)
    router = APIRouter()

    def _rp_id_from_origin(origin: str) -> str:
        host = urlsplit(origin).hostname or "localhost"
        return host

    def _principal_from_session(s: dict) -> str:
        # Prefer a stable account id; fallback keeps demo usable after BIK/DPoP.
        pid = s.get('sub') or s.get('acct') or s.get('bik_jkt') or s.get('dpop_jkt')
        if not pid:
            raise HTTPException(status_code=409, detail="no stable principal on session; complete BIK/DPoP first")
        return str(pid)

    # -------- Authentication options (supports discovery when no creds) --------
    @router.post("/webauthn/authentication/options")
    async def webauthn_auth_options(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await session_store.get_session(sid) if sid else None
        if not sid or not s: raise HTTPException(status_code=401, detail="no session")

        principal = _principal_from_session(s)
        origin, _ = canonicalize_origin_and_url(req)
        rp_id = _rp_id_from_origin(origin)

        challenge = secrets.token_bytes(32)

        # Known credentials for this principal
        creds = repo.get_for_principal(principal)
        allow = [
            {"type": "public-key", "id": c["cred_id"], "transports": c.get("transports") or ["internal"]}
            for c in creds
        ]
        allow_empty = (len(allow) == 0)

        # Remember whether we sent discovery (no allowCredentials)
        await session_store.update_session(sid, {
            "webauthn_auth": {
                "challenge": _b64u(challenge),
                "ts": now_fn(),
                "principal": principal,
                "allow_empty": allow_empty
            }
        })

        body = {
            "rpId": rp_id,
            "challenge": _b64u(challenge),
            "userVerification": UV_MODE,
        }
        if not allow_empty:
            body["allowCredentials"] = allow  # omit when none → resident/discoverable
        return JSONResponse(body, headers=_nonce_headers(ctx))



    # -------- Authentication verify (adopts principal when discovery used) --------
    @router.post("/webauthn/authentication/verify")
    async def webauthn_auth_verify(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await session_store.get_session(sid) if sid else None
        if not sid or not s: raise HTTPException(status_code=401, detail="no session")

        principal = _principal_from_session(s)  # as of flow start
        chal_info = (s.get("webauthn_auth") or {})
        expected_chal = chal_info.get("challenge")
        allow_empty = bool(chal_info.get("allow_empty"))
        if not expected_chal:
            raise HTTPException(status_code=400, detail="no auth in progress")

        origin, _ = canonicalize_origin_and_url(req)
        rp_id = _rp_id_from_origin(origin)

        data = await req.json()
        clientDataJSON = _b64u_dec(data["response"]["clientDataJSON"])
        client = json.loads(clientDataJSON)
        if client.get("type") != "webauthn.get":   raise HTTPException(status_code=400, detail="wrong clientData type")
        if client.get("origin") != origin:         raise HTTPException(status_code=400, detail="origin mismatch")
        if client.get("challenge") != expected_chal: raise HTTPException(status_code=400, detail="challenge mismatch")

        authData = _b64u_dec(data["response"]["authenticatorData"])
        info = parse_authenticator_data(authData)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        if info["rpIdHash"] != rp_hash:  raise HTTPException(status_code=400, detail="rpIdHash mismatch")
        if (info["flags"] & 0x01) == 0:  raise HTTPException(status_code=400, detail="user not present")
        if UV_MODE == 'required' and (info["flags"] & 0x04) == 0:
            raise HTTPException(status_code=400, detail="user verification required")

        cred_id = (data.get("id") or data.get("rawId") or "").strip()
        if not cred_id: raise HTTPException(status_code=400, detail="missing credential id")

        # 1) Try within current principal
        rec = repo.find_by_cred_id(principal, cred_id)

        # 2) If not found, try global and adopt principal if discovery mode was used
        if not rec:
            found = repo.get_by_cred_id(cred_id)
            if not found:
                raise HTTPException(status_code=404, detail="unknown credential id")
            found_principal, found_rec = found
            if found_principal != principal:
                if not allow_empty:
                    # We sent allowCredentials → do not switch accounts
                    raise HTTPException(status_code=403, detail="credential not associated with this principal")
                # Discovery: adopt credential owner
                principal = found_principal
                rec = found_rec

        # Verify signature
        sig = _b64u_dec(data["response"]["signature"])
        ct_hash = hashlib.sha256(clientDataJSON).digest()
        msg = authData + ct_hash

        pub, alg = jwk_to_pub(rec["public_key_jwk"])
        try:
            if alg == "ES256":
                pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            elif alg == "RS256":
                pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "EdDSA":
                pub.verify(sig, msg)
            else:
                raise HTTPException(status_code=400, detail="unsupported alg")
        except Exception:
            raise HTTPException(status_code=400, detail="signature verify failed")

        # Counters + bind session to (possibly adopted) principal
        if info["signCount"] < (rec.get("sign_count") or 0):
            pass
        repo.update_sign_count(cred_id, info["signCount"])
        await session_store.update_session(sid, {"passkey_auth": True, "passkey_principal": principal})

        return JSONResponse({"ok": True, "principal": principal}, headers=_nonce_headers(ctx))


    # -------- Authentication options --------
    @router.post("/webauthn/authentication/options")
    async def webauthn_auth_options(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await session_store.get_session(sid) if sid else None
        if not sid or not s: raise HTTPException(status_code=401, detail="no session")

        principal = _principal_from_session(s)
        origin, _ = canonicalize_origin_and_url(req)
        rp_id = _rp_id_from_origin(origin)

        challenge = secrets.token_bytes(32)
        await session_store.update_session(sid, {"webauthn_auth": {"challenge": _b64u(challenge), "ts": now_fn(), "principal": principal}})

        creds = repo.get_for_principal(principal)

        # Build allow list; optionally force platform-only by restricting transports to ['internal']
        def _tx(c: Dict[str, Any]) -> List[str]:
            if PLATFORM_ONLY:
                return ["internal"]
            return c.get("transports") or ["internal"]

        allow = [
            {"type": "public-key", "id": c["cred_id"], "transports": _tx(c)}
            for c in creds
        ]

        body: Dict[str, Any] = {
            "rpId": rp_id,
            "challenge": _b64u(challenge),
            "userVerification": UV_MODE,
        }
        if allow:
            body["allowCredentials"] = allow  # restrict to known creds; transports likely ['internal']
        # NEW: nudge UA toward on-device passkeys (ignored if unsupported)
        if AUTH_HINTS:
            body["hints"] = AUTH_HINTS

        return JSONResponse(body, headers=_nonce_headers(ctx))

    # -------- Authentication verify --------
    @router.post("/webauthn/authentication/verify")
    async def webauthn_auth_verify(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await session_store.get_session(sid) if sid else None
        if not sid or not s: raise HTTPException(status_code=401, detail="no session")

        principal = _principal_from_session(s)
        origin, _ = canonicalize_origin_and_url(req)
        rp_id = _rp_id_from_origin(origin)
        chal_info = (s.get("webauthn_auth") or {})
        expected_chal = chal_info.get("challenge")
        if not expected_chal:
            raise HTTPException(status_code=400, detail="no auth in progress")

        data = await req.json()
        clientDataJSON = _b64u_dec(data["response"]["clientDataJSON"])
        client = json.loads(clientDataJSON)
        if client.get("type") != "webauthn.get":   raise HTTPException(status_code=400, detail="wrong clientData type")
        if client.get("origin") != origin:         raise HTTPException(status_code=400, detail="origin mismatch")
        if client.get("challenge") != expected_chal: raise HTTPException(status_code=400, detail="challenge mismatch")

        authData = _b64u_dec(data["response"]["authenticatorData"])
        info = parse_authenticator_data(authData)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        if info["rpIdHash"] != rp_hash:  raise HTTPException(status_code=400, detail="rpIdHash mismatch")
        if (info["flags"] & 0x01) == 0:  raise HTTPException(status_code=400, detail="user not present")
        if UV_MODE == 'required' and (info["flags"] & 0x04) == 0:
            raise HTTPException(status_code=400, detail="user verification required")

        # Find stored public key by credId scoped to principal
        cred_id = (data.get("id") or data.get("rawId") or "").strip()
        if not cred_id: raise HTTPException(status_code=400, detail="missing credential id")
        rec = repo.find_by_cred_id(principal, cred_id)
        if not rec:
            # If you allowed resident creds without allowCredentials, fall back to global lookup then assert principal match.
            found = repo.get_by_cred_id(cred_id)
            if not found:
                raise HTTPException(status_code=404, detail="unknown credential id")
            found_principal, rec = found
            if found_principal != principal:
                raise HTTPException(status_code=403, detail="credential not associated with this principal")

        sig = _b64u_dec(data["response"]["signature"])
        ct_hash = hashlib.sha256(clientDataJSON).digest()
        msg = authData + ct_hash

        pub, alg = jwk_to_pub(rec["public_key_jwk"])
        try:
            if alg == "ES256":
                pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            elif alg == "RS256":
                pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "EdDSA":
                pub.verify(sig, msg)
            else:
                raise HTTPException(status_code=400, detail="unsupported alg")
        except Exception:
            raise HTTPException(status_code=400, detail="signature verify failed")

        # update counters + mark session associated with principal
        if info["signCount"] < (rec.get("sign_count") or 0):
            pass  # soft policy; tighten if you need to
        repo.update_sign_count(cred_id, info["signCount"])
        await session_store.update_session(sid, {"passkey_auth": True, "passkey_principal": principal})

        return JSONResponse({"ok": True, "principal": principal}, headers=_nonce_headers(ctx))

    return router
