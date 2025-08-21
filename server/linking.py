# server/linking.py
from __future__ import annotations
import json, secrets, threading, asyncio, logging
from typing import Any, Dict, Tuple, Optional, Callable, List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse

from server.config import load_settings
from server.utils import b64u, b64u_dec, jws_es256_sign, jws_es256_verify, now

log = logging.getLogger("stronghold")
SETTINGS = load_settings()

# ---------------- utils ----------------

_LINK_TTL = SETTINGS.link_ttl_seconds  # seconds

def _nonce_headers(ctx: Any) -> Dict[str, str]:
    try:
        n = ctx.get("next_nonce") if isinstance(ctx, dict) else None
        return {"DPoP-Nonce": n} if n else {}
    except Exception:
        return {}



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
    now_ts = now()
    return {
        "id": rec["rid"],
        "status": rec.get("status"),
        "principal": rec.get("principal"),
        "applied": rec.get("applied", False),
        "expires_in": max(0, rec["exp"] - now_ts),
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
        token = jws_es256_sign(payload)

        origin, _ = canonicalize_origin_and_url(req)
        qr_url = f"{origin}/public/link.html?token={token}"

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
            now_ts = now_fn()
            if now_ts > rec["exp"] and rec["status"] != "linked":
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
        claims = jws_es256_verify(token)
        now_ts = now()
        if claims.get("aud") != "link":
            raise HTTPException(status_code=400, detail="bad aud")
        if now_ts > int(claims.get("exp", 0)):
            raise HTTPException(status_code=400, detail="expired")
        lid = claims.get("lid")
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            if now_ts > rec["exp"] and rec["status"] != "linked":
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
            if now() > rec["exp"] and rec["status"] != "linked":
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
        now_ts = now()
        payload = {"iss":"stronghold","aud":"link","iat":now_ts,"exp":rec["exp"],"lid":link_id}
        token = jws_es256_sign(payload)
        origin, _ = canonicalize_origin_and_url(req)
        uri = f"{origin}/public/link.html?token={token}"
        img = qrcode.make(uri)
        import io
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png")

    return router
