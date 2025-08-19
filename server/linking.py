# server/linking.py
from __future__ import annotations
import os, json, secrets, hashlib, base64, threading, asyncio, time
from typing import Any, Dict, Tuple, Optional, Callable, List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# ---------------- utils ----------------

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. http://localhost:8000
_LINK_TTL = int(os.getenv("LINK_TTL_SECONDS", "180"))  # seconds

def external_base(req: Request) -> str:
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

def _now() -> int:
    return int(time.time())

# ---------------- JWS (ES256) key + helpers ----------------

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
    _ensure_server_signing_key()
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(_b64u_dec(h_b64))
        if header.get("alg") != "ES256":
            raise ValueError("alg")
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = _b64u_dec(s_b64)
        if len(sig) != 64:
            raise ValueError("sig")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        _SERVER_EC_KEY.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        payload = json.loads(_b64u_dec(p_b64))
        return payload
    except Exception:
        raise HTTPException(status_code=400, detail="bad link token")

# ---------------- in-memory link state + watchers ----------------

_LINKS: Dict[str, Dict[str, Any]] = {}
_LINKS_LOCK = threading.RLock()

# per-link async queues for SSE
_WATCHERS: Dict[str, List[asyncio.Queue]] = {}
_WATCHERS_LOCK = threading.RLock()

def _notify_watchers(link_id: str, event: Dict[str, Any]):
    with _WATCHERS_LOCK:
        qs = list(_WATCHERS.get(link_id, []))
    for q in qs:
        try:
            q.put_nowait(event)
        except Exception:
            pass

def _put_link(link_id: str, rec: Dict[str, Any]):
    with _LINKS_LOCK:
        _LINKS[link_id] = rec
    _notify_watchers(link_id, {"type": "status", **_public_view(rec)})

def _public_view(rec: Dict[str, Any]) -> Dict[str, Any]:
    now = _now()
    return {
        "id": rec["rid"],
        "status": rec.get("status"),
        "principal": rec.get("principal"),
        "applied": rec.get("applied", False),
        "expires_in": max(0, rec["exp"] - now),
    }

# ---------------- router factory ----------------

def get_router(
    store: Any,
    require_dpop: Callable,                                 # FastAPI dep
    canonicalize_origin_and_url: Callable[[Request], Tuple[str, str]],
    now_fn: Callable[[], int],
) -> APIRouter:
    """
    Routes:
      POST /link/start               (desktop; DPoP required)
      GET  /link/status/{id}         (desktop; DPoP required; applies auth when linked)
      GET  /link/events/{id}         (desktop; SSE; no DPoP; cookie session + same-origin)
      POST /link/mobile/start        (mobile; no DPoP; validate JWS; mark scanned)
      POST /link/mobile/complete     (mobile; DPoP + mobile passkey_auth required; patches desktop immediately)
      GET  /link/qr/{id}.png         (optional; serve QR PNG if 'qrcode' installed)
    """
    router = APIRouter()

    @router.post("/link/start")
    async def link_start(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid")
        s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        rid = secrets.token_urlsafe(12)
        iat = now_fn()
        exp = iat + _LINK_TTL
        payload = {"iss":"stronghold","aud":"link","iat":iat,"exp":exp,"lid":rid}
        token = _jws_es256_sign(payload)

        origin, _ = canonicalize_origin_and_url(req)
        base = external_base(req)
        qr_url = f"{base}/public/link.html?token={token}"

        _put_link(rid, {
            "rid": rid,
            "desktop_sid": sid,
            "status": "pending",
            "token": token,
            "created_at": iat,
            "exp": exp,
        })
        return JSONResponse({"linkId": rid, "exp": exp, "qr_url": qr_url}, headers=_nonce_headers(ctx))

    @router.get("/link/status/{link_id}")
    async def link_status(link_id: str, req: Request, ctx=Depends(require_dpop)):
        """Desktop polls; when 'linked', we patch desktop session if not already applied."""
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        need_apply = False
        principal: Optional[str] = None
        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if rec["desktop_sid"] != sid:
                raise HTTPException(status_code=403, detail="not your link")
            # expiry
            now = now_fn()
            if now > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
            if rec["status"] == "linked" and not rec.get("applied") and rec.get("principal"):
                need_apply = True
                principal = rec["principal"]

        if need_apply and principal:
            try:
                await store.update_session(sid, {
                    "passkey_auth": True,
                    "passkey_principal": principal,
                })
                with _LINKS_LOCK:
                    if link_id in _LINKS:
                        _LINKS[link_id]["applied"] = True
            finally:
                _notify_watchers(link_id, {"type":"status", **_public_view(_LINKS[link_id])})

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            out = _public_view(rec)
        return JSONResponse(out, headers=_nonce_headers(ctx))

    @router.get("/link/events/{link_id}")
    async def link_events(link_id: str, req: Request):
        """
        Server-Sent Events channel.
        - No DPoP (EventSource can't send headers).
        - Auth via same-origin cookie session and ownership of the link.
        """
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if rec["desktop_sid"] != sid:
                raise HTTPException(status_code=403, detail="not your link")
            initial = _public_view(rec)

        q: asyncio.Queue = asyncio.Queue()
        with _WATCHERS_LOCK:
            _WATCHERS.setdefault(link_id, []).append(q)

        async def event_gen():
            try:
                # Send initial snapshot
                yield f"event: status\ndata: {json.dumps(initial)}\n\n"
                # Heartbeat every 15s if no events
                while True:
                    try:
                        evt = await asyncio.wait_for(q.get(), timeout=15.0)
                        yield f"event: {evt.get('type','status')}\ndata: {json.dumps(evt)}\n\n"
                    except asyncio.TimeoutError:
                        # comment heartbeat
                        yield ": keep-alive\n\n"
            finally:
                # cleanup
                with _WATCHERS_LOCK:
                    lst = _WATCHERS.get(link_id, [])
                    if q in lst:
                        lst.remove(q)

        return StreamingResponse(event_gen(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })

    @router.post("/link/mobile/start")
    async def link_mobile_start(body: Dict[str, Any]):
        """Mobile posts the QR token it scanned. No DPoP yet."""
        token = body.get("token")
        if not token:
            raise HTTPException(status_code=400, detail="missing token")
        claims = _jws_es256_verify(token)
        now = _now()
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
                _notify_watchers(lid, {"type":"status", **_public_view(rec)})
                raise HTTPException(status_code=400, detail="expired")
            if rec["status"] == "pending":
                rec["status"] = "scanned"
        _notify_watchers(lid, {"type":"status", **_public_view(_LINKS[lid])})
        return {"ok": True, "link_id": lid}

    @router.post("/link/mobile/complete")
    async def link_mobile_complete(body: Dict[str, Any], req: Request, ctx=Depends(require_dpop)):
        """
        Mobile calls this *after* BIK→DPoP→passkey auth on mobile.
        We bind the authenticated principal to the link and PATCH THE DESKTOP SESSION IMMEDIATELY.
        """
        lid = body.get("link_id")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link_id")
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")
        if not s.get("passkey_auth") or not s.get("passkey_principal"):
            raise HTTPException(status_code=403, detail="mobile not authenticated")

        desktop_sid: Optional[str] = None
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if _now() > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                _notify_watchers(lid, {"type":"status", **_public_view(rec)})
                raise HTTPException(status_code=400, detail="expired")
            rec["status"] = "linked"
            rec["principal"] = s["passkey_principal"]
            rec["mobile_sid"] = sid
            rec["applied"] = False
            desktop_sid = rec.get("desktop_sid")

        # APPLY patch to desktop session right now (best-effort)
        applied = False
        if desktop_sid:
            try:
                ds = await store.get_session(desktop_sid)
                if ds is not None:
                    await store.update_session(desktop_sid, {
                        "passkey_auth": True,
                        "passkey_principal": s["passkey_principal"],
                    })
                    applied = True
            except Exception:
                applied = False

        with _LINKS_LOCK:
            if lid in _LINKS:
                _LINKS[lid]["applied"] = applied

        _notify_watchers(lid, {"type":"status", **_public_view(_LINKS[lid])})
        return JSONResponse({"ok": True, "applied": applied}, headers=_nonce_headers(ctx))

    # -------- Optional: serve QR PNG directly (requires 'qrcode[pil]') --------
    @router.get("/link/qr/{link_id}.png")
    async def link_qr(link_id: str, req: Request):
        try:
            import qrcode
        except Exception:
            raise HTTPException(status_code=501, detail="qr lib not installed")
        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
        # Re-issue token pointing at same link (keeps original exp)
        now = _now()
        payload = {"iss":"stronghold","aud":"link","iat":now,"exp":rec["exp"],"lid":link_id}
        token = _jws_es256_sign(payload)
        origin, _ = canonicalize_origin_and_url(req)
        uri = f"{origin}/public/link.html?token={token}"
        img = qrcode.make(uri)
        import io
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png")

    return router
