# server/linking.py
from __future__ import annotations
import os, json, secrets, hashlib, base64, asyncio, time
from typing import Any, Dict, Tuple, Optional, Callable

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL")  # e.g. http://localhost:8000
LINK_TTL = int(os.getenv("LINK_TTL_SECONDS", "180"))

def external_base(req: Request) -> str:
    if PUBLIC_BASE_URL:
        return PUBLIC_BASE_URL.rstrip("/")
    scheme = req.url.scheme
    host = (req.headers.get("host") or req.url.netloc).split(",")[0].strip()
    return f"{scheme}://{host}"

def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def _b64u_dec(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

def _nonce_headers(ctx: Any) -> Dict[str, str]:
    try:
        n = ctx.get("next_nonce") if isinstance(ctx, dict) else None
        return {"DPoP-Nonce": n} if n else {}
    except Exception:
        return {}

# --- ES256 JWS for QR tokens (server-signed) ---

_SERVER_EC_KEY = None
_SERVER_KID: Optional[str] = None

def _ensure_server_signing_key():
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
    h_b64 = _b64u(json.dumps(header, separators=(",", ":")).encode())
    p_b64 = _b64u(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    der = _SERVER_EC_KEY.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = _b64u(r.to_bytes(32, "big") + s.to_bytes(32, "big"))
    return f"{h_b64}.{p_b64}.{sig}"

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
        r = int.from_bytes(sig[:32], "big"); s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        _SERVER_EC_KEY.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        return json.loads(_b64u_dec(p_b64))
    except Exception:
        raise HTTPException(status_code=400, detail="bad link token")


def get_router(
    store: Any,
    require_dpop: Callable,
    canonicalize_origin_and_url: Callable[[Request], Tuple[str, str]],
    now_fn: Callable[[], int],
) -> APIRouter:
    router = APIRouter()

    @router.post("/link/start")
    async def link_start(req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid")
        s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        link_id = secrets.token_urlsafe(12)
        iat = now_fn()
        exp = iat + LINK_TTL
        payload = {"iss": "stronghold", "aud": "link", "lid": link_id, "sid": sid, "iat": iat, "exp": exp}
        token = _jws_es256_sign(payload)

        origin, _ = canonicalize_origin_and_url(req)
        base = external_base(req) or origin
        qr_url = f"{base}/public/link.html?token={token}"

        await store.link_create({
            "link_id": link_id,
            "desktop_sid": sid,
            "status": "pending",
            "token": token,
            "created_at": iat,
            "exp": exp,
            "applied": False,
        })
        return JSONResponse({"link_id": link_id, "token": token, "qr_url": qr_url, "exp": exp}, headers=_nonce_headers(ctx))

    @router.get("/link/status/{link_id}")
    async def link_status(link_id: str, req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        rec = await store.link_get(link_id)
        if not rec:
            raise HTTPException(status_code=404, detail="no such link")
        if rec["desktop_sid"] != sid:
            raise HTTPException(status_code=403, detail="not your link")

        now = now_fn()
        if now > rec["exp"] and rec["status"] != "linked":
            await store.link_patch(link_id, {"status": "expired"})
            rec["status"] = "expired"

        # Apply on first read after linked
        if rec["status"] == "linked" and not rec.get("applied") and rec.get("principal"):
            await store.update_session(sid, {
                "passkey_auth": True,
                "passkey_principal": rec["principal"],
            })
            await store.link_patch(link_id, {"applied": 1})

        rec = await store.link_get(link_id) or rec
        out = {
            "status": rec["status"],
            "principal": rec.get("principal"),
            "applied": bool(rec.get("applied")),
            "expires_in": max(0, rec["exp"] - now),
        }
        return JSONResponse(out, headers=_nonce_headers(ctx))

    @router.post("/link/mobile/start")
    async def link_mobile_start(body: Dict[str, Any]):
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
        rec = await store.link_get(lid)
        if not rec:
            raise HTTPException(status_code=404, detail="no such link")
        if now > rec["exp"] and rec["status"] != "linked":
            await store.link_patch(lid, {"status": "expired"})
            raise HTTPException(status_code=400, detail="expired")
        if rec["status"] == "pending":
            await store.link_patch(lid, {"status": "scanned"})
        return {"ok": True, "link_id": lid}

    @router.post("/link/mobile/complete")
    async def link_mobile_complete(body: Dict[str, Any], req: Request, ctx=Depends(require_dpop)):
        lid = body.get("link_id")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link_id")
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")
        if not s.get("passkey_auth") or not s.get("passkey_principal"):
            raise HTTPException(status_code=403, detail="mobile not authenticated")

        rec = await store.link_get(lid)
        if not rec:
            raise HTTPException(status_code=404, detail="no such link")
        if now_fn() > rec["exp"] and rec["status"] != "linked":
            await store.link_patch(lid, {"status": "expired"})
            raise HTTPException(status_code=400, detail="expired")

        await store.link_patch(lid, {
            "status": "linked",
            "principal": s["passkey_principal"],
            "mobile_sid": sid
        })
        return JSONResponse({"ok": True}, headers=_nonce_headers(ctx))

    # -------- SSE (desktop) --------
    @router.get("/link/events/{link_id}")
    async def link_events(link_id: str, req: Request, ctx=Depends(require_dpop)):
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")

        async def _gen():
            # lightweight server-push loop
            while True:
                rec = await store.link_get(link_id)
                if not rec:
                    yield f"data: {json.dumps({'status':'gone'})}\n\n"
                    return
                if rec["desktop_sid"] != sid:
                    yield f"data: {json.dumps({'status':'forbidden'})}\n\n"
                    return
                now = now_fn()
                if now > rec["exp"] and rec["status"] != "linked":
                    await store.link_patch(link_id, {"status": "expired"})
                    rec["status"] = "expired"

                payload = {
                    "status": rec["status"],
                    "applied": bool(rec.get("applied")),
                    "principal": rec.get("principal"),
                    "expires_in": max(0, rec["exp"] - now)
                }
                yield f"data: {json.dumps(payload)}\n\n"

                # stop on terminal states
                if rec["status"] in ("expired", "linked") and rec.get("applied"):
                    return
                await asyncio.sleep(2)

        return StreamingResponse(_gen(), media_type="text/event-stream")

    # Optional: serve QR PNG if python-qrcode present
    @router.get("/link/qr/{link_id}.png")
    async def link_qr(link_id: str, req: Request):
        try:
            import qrcode
        except Exception:
            raise HTTPException(status_code=501, detail="qr lib not installed")
        rec = await store.link_get(link_id)
        if not rec:
            raise HTTPException(status_code=404, detail="no such link")
        payload = {"iss": "stronghold", "aud": "link", "iat": now_fn(), "exp": rec["exp"], "lid": link_id}
        token = _jws_es256_sign(payload)
        base = external_base(req)
        uri = f"{base}/public/link.html?token={token}"
        img = qrcode.make(uri)
        import io
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png")

    return router
