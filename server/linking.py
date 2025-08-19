# server/linking.py
from __future__ import annotations
import os, json, secrets, hashlib, base64, threading
from typing import Any, Dict, Tuple, Optional, Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# -------------------------------------------------------------------
# Config / utils
# -------------------------------------------------------------------

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. "http://192.168.1.179:8000"
_LINK_TTL = int(os.getenv("LINK_TTL_SECONDS", "180"))  # seconds
_TTL_SECS = _LINK_TTL  # alias (compat with earlier code)

def external_base(req: Request) -> str:
    """
    Returns the public base URL to embed in the QR:
      - If PUBLIC_BASE_URL is set, use it (so mobiles see the LAN IP, not localhost)
      - Else, derive from Host header (scheme://host)
    """
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    scheme = req.url.scheme
    host = (req.headers.get("host") or req.url.netloc).split(",")[0].strip()
    return f"{scheme}://{host}"

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

# -------------------------------------------------------------------
# JWS (ES256) issuing & verification
#   - Server is both issuer and verifier (demo scenario)
#   - Uses P-256 private key from STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM if set
# -------------------------------------------------------------------

_SERVER_EC_KEY = None              # lazy-initialized P-256 key
_SERVER_KID: Optional[str] = None  # short kid (hash of pubkey)

def _ensure_server_signing_key():
    """Use STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM if provided, else ephemeral dev key."""
    global _SERVER_EC_KEY, _SERVER_KID
    if _SERVER_EC_KEY is not None:
        return
    pem = os.getenv("STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM")
    if pem:
        _SERVER_EC_KEY = serialization.load_pem_private_key(pem.encode(), password=None)
    else:
        print("WARNING stronghold link: STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM not set; generated ephemeral dev key.")
        _SERVER_EC_KEY = ec.generate_private_key(ec.SECP256R1())
    pub = _SERVER_EC_KEY.public_key().public_numbers()
    x = pub.x.to_bytes(32, "big"); y = pub.y.to_bytes(32, "big")
    _SERVER_KID = _b64u(hashlib.sha256(x + y).digest()[:8])

def _jws_es256_sign(payload: Dict[str, Any]) -> str:
    """
    Produces compact JWS with raw(64-byte) signature in base64url.
    header = {"alg":"ES256","typ":"link+jws","kid":<short>}
    """
    _ensure_server_signing_key()
    header = {"alg": "ES256", "typ": "link+jws", "kid": _SERVER_KID}
    h_b64 = _b64u(json.dumps(header, separators=(',', ':')).encode())
    p_b64 = _b64u(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    der = _SERVER_EC_KEY.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h_b64}.{p_b64}.{_b64u(sig)}"

def _jws_es256_verify(token: str) -> Dict[str, Any]:
    """
    Verifies compact JWS produced by _jws_es256_sign and returns JSON payload.
    """
    _ensure_server_signing_key()
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(_b64u_dec(h_b64))
        if header.get("alg") != "ES256":
            raise ValueError("alg mismatch")
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = _b64u_dec(s_b64)
        if len(sig) != 64:
            raise ValueError("bad sig length")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        _SERVER_EC_KEY.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        payload = json.loads(_b64u_dec(p_b64))
        return payload
    except Exception:
        raise HTTPException(status_code=400, detail="bad link token")

# -------------------------------------------------------------------
# In-memory link state
#   link_id (rid/lid) -> {
#     desktop_sid, status: pending|scanned|linked|expired, principal?, token, created_at, exp, applied?
#   }
# -------------------------------------------------------------------

_LINKS: Dict[str, Dict[str, Any]] = {}
_LINKS_LOCK = threading.RLock()

def _put_link(link_id: str, rec: Dict[str, Any]) -> None:
    with _LINKS_LOCK:
        _LINKS[link_id] = rec

# -------------------------------------------------------------------
# Router factory
# -------------------------------------------------------------------

def get_router(
    store: Any,
    require_dpop: Callable,                                 # FastAPI dep (enforces DPoP; provides next_nonce)
    canonicalize_origin_and_url: Callable[[Request], Tuple[str, str]],
    now_fn: Callable[[], int],
) -> APIRouter:
    """
    Routes:
      POST /link/start              (desktop; DPoP required)
      GET  /link/status/{link_id}   (desktop; DPoP required; applies auth when linked)
      POST /link/mobile/start       (mobile; no DPoP; validate JWS; mark scanned)
      POST /link/mobile/complete    (mobile; DPoP + passkey_auth required)
      GET  /link/qr/{link_id}.png   (optional; server-generated QR if qrcode installed)
    """
    router = APIRouter()

    # ---------------- Desktop: start link (issue JWS, return QR URL) ----------------
    @router.post("/link/start")
    async def link_start(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid")
        s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")
        # Optional: enforce DPoP-bound session:
        # if s.get("state") != "bound": raise HTTPException(status_code=403, detail="session must be DPoP-bound")

        rid = secrets.token_urlsafe(12)
        iat = now_fn()
        exp = iat + _TTL_SECS

        # JWS payload — note: use "lid" in token (what mobile routes expect)
        payload = {"iss": "stronghold", "aud": "link", "lid": rid, "sid": sid, "iat": iat, "exp": exp}
        token = _jws_es256_sign(payload)

        base = external_base(req)
        # IMPORTANT: include /public so mobile hits your static link page
        qr_url = f"{base}/public/link.html?token={token}"

        _put_link(rid, {
            "rid": rid,
            "desktop_sid": sid,
            "status": "pending",
            "token": token,
            "created_at": iat,
            "exp": exp,
        })
        return JSONResponse({"rid": rid, "token": token, "qr_url": qr_url}, headers=_nonce_headers(ctx))

    # ---------------- Desktop: poll link status (applies auth to desktop when ready) ----------------
    @router.get("/link/status/{link_id}")
    async def link_status(link_id: str, req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        need_apply = False
        principal: Optional[str] = None
        expires_in = 0

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if rec["desktop_sid"] != sid:
                raise HTTPException(status_code=403, detail="not your link")

            now = now_fn()
            if now > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"

            if rec["status"] == "linked" and not rec.get("applied") and rec.get("principal"):
                need_apply = True
                principal = rec["principal"]
            expires_in = max(0, rec["exp"] - now)

        # Apply to desktop session outside the lock
        if need_apply and principal:
            await store.update_session(sid, {
                "passkey_auth": True,
                "passkey_principal": principal,
            })
            with _LINKS_LOCK:
                if link_id in _LINKS:
                    _LINKS[link_id]["applied"] = True

        with _LINKS_LOCK:
            rec2 = _LINKS.get(link_id)
            out = {
                "status": rec2["status"],
                "principal": rec2.get("principal"),
                "applied": rec2.get("applied", False),
                "expires_in": expires_in,
            }
        return JSONResponse(out, headers=_nonce_headers(ctx))

    # ---------------- Mobile: tell server we scanned the QR ----------------
    @router.post("/link/mobile/start")
    async def link_mobile_start(body: Dict[str, Any]):
        """
        Mobile posts the QR token it scanned (no DPoP yet).
        We validate JWS, mark link as 'scanned' if valid & not expired.
        """
        token = body.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="missing token")
        claims = _jws_es256_verify(token)
        now = now_fn()
        if claims.get("aud") != "link":
            raise HTTPException(status_code=400, detail="bad aud")
        if now > int(claims.get("exp", 0)):
            raise HTTPException(status_code=400, detail="expired")
        lid = claims.get("lid")
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if now > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                raise HTTPException(status_code=400, detail="expired")
            if rec["status"] == "pending":
                rec["status"] = "scanned"
        return {"ok": True, "link_id": lid}

    # ---------------- Mobile: complete linking after mobile passkey auth ----------------
    @router.post("/link/mobile/complete")
    async def link_mobile_complete(body: Dict[str, Any], req: Request, ctx=Depends(require_dpop)):
        """
        Mobile calls this *after* BIK→DPoP→passkey auth on mobile.
        We bind the authenticated principal to the link; desktop poll will apply it.
        """
        lid = body.get("link_id")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link_id")
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")
        if not s.get("passkey_auth") or not s.get("passkey_principal"):
            raise HTTPException(status_code=403, detail="mobile not authenticated")

        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if now_fn() > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                raise HTTPException(status_code=400, detail="expired")
            rec["status"] = "linked"
            rec["principal"] = s["passkey_principal"]
            rec["mobile_sid"] = sid

        return JSONResponse({"ok": True}, headers=_nonce_headers(ctx))

    # ---------------- Optional: server-generated QR (if qrcode installed) ----------------
    @router.get("/link/qr/{link_id}.png")
    async def link_qr(link_id: str, req: Request):
        """
        Generates a QR PNG that encodes a fresh JWS (same expiry as the link record).
        Requires `qrcode[pil]` to be installed.
        """
        try:
            import qrcode
        except Exception:
            raise HTTPException(status_code=501, detail="qr lib not installed")

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            exp = rec["exp"]

        now = now_fn()
        payload = {"iss":"stronghold","aud":"link","iat":now,"exp":exp,"lid":link_id}
        token = _jws_es256_sign(payload)

        # Make sure the QR points to the PUBLIC page (mobile-friendly)
        base = external_base(req)
        uri = f"{base}/public/link.html?token={token}"

        img = qrcode.make(uri)
        import io
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png")

    return router
