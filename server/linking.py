# server/linking.py
from __future__ import annotations
import json, secrets, threading, asyncio, logging, random, uuid, string
from typing import Any, Dict, Tuple, Optional, Callable, List

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse, Response, StreamingResponse
from starlette.websockets import WebSocket, WebSocketDisconnect

from server.config import load_settings
from server.utils import b64u, b64u_dec, jws_es256_sign, jws_es256_verify, now

log = logging.getLogger("dpop-fun")
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

# -------- WebSocket connections --------
_WEBSOCKET_CONNECTIONS: Dict[str, List[WebSocket]] = {}
_WEBSOCKET_LOCK = threading.RLock()

def _notify_watchers(link_id: str, event: Dict[str, Any]):
    with _WATCHERS_LOCK:
        qs = list(_WATCHERS.get(link_id, []))
    log.info("Notifying %d watchers for link %s with event: %s", len(qs), link_id, event)
    for q in qs:
        try:
            q.put_nowait(event)
        except Exception as e:
            log.warning("Failed to notify watcher: %s", e)

def _get_link_by_desktop_sid(desktop_sid: str) -> Optional[Dict[str, Any]]:
    """Find a link by desktop session ID"""
    with _LINKS_LOCK:
        for link_id, link_data in _LINKS.items():
            if link_data.get("desktop_sid") == desktop_sid:
                return link_data
    return None

def _get_link_by_mobile_sid(mobile_sid: str) -> Optional[Dict[str, Any]]:
    """Find a link by mobile session ID"""
    with _LINKS_LOCK:
        for link_id, link_data in _LINKS.items():
            if link_data.get("mobile_sid") == mobile_sid:
                return link_data
    return None

def _notify_websockets(link_id: str, event: Dict[str, Any]):
    """Notify WebSocket connections for a specific link."""
    with _WEBSOCKET_LOCK:
        connections = list(_WEBSOCKET_CONNECTIONS.get(link_id, []))
    
    log.info("Notifying %d WebSocket connections for link %s with event: %s", len(connections), link_id, event)
    
    # Send to all connected WebSockets
    for ws in connections:
        try:
            asyncio.create_task(ws.send_text(json.dumps(event)))
        except Exception as e:
            log.warning("Failed to send WebSocket message: %s", e)
            # Remove failed connection
            with _WEBSOCKET_LOCK:
                if link_id in _WEBSOCKET_CONNECTIONS:
                    try:
                        _WEBSOCKET_CONNECTIONS[link_id].remove(ws)
                    except ValueError:
                        pass

def _put_link(link_id: str, rec: Dict[str, Any]):
    with _LINKS_LOCK:
        _LINKS[link_id] = rec
    event = {"type": "status", **_public_view(rec)}
    _notify_watchers(link_id, event)
    _notify_websockets(link_id, event)

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
        payload = {"iss":"dpop-fun","aud":"link","iat":iat,"exp":exp,"lid":rid}
        token = jws_es256_sign(payload)

        origin, _ = canonicalize_origin_and_url(req)
        
        # Use the current request's origin for QR generation to maintain session consistency
        # This ensures the mobile device accesses the same domain as the desktop
        qr_origin = origin
        
        # Log the QR generation for debugging
        log.info("QR generation - desktop_origin=%s qr_origin=%s", origin, qr_origin)
            
        qr_url = f"{qr_origin}/public/link.html?lid={rid}"

        # Get desktop session device type for logging
        desktop_device_type = s.get("device_type", "unknown")
        
        _put_link(rid, {
            "rid": rid,
            "desktop_sid": sid,
            "status": "pending",
            "token": token,
            "created_at": iat,
            "exp": exp,
        })
        log.info("Link created - rid=%s desktop_sid=%s desktop_device_type=%s status=pending exp=%s", 
                rid, sid, desktop_device_type, exp)
        return JSONResponse({"linkId": rid, "exp": exp, "qr_url": qr_url}, headers=_nonce_headers(ctx))

    @router.get("/link/status/{link_id}")
    async def link_status(link_id: str, req: Request):
        """Desktop polls; when 'linked', we patch desktop session if not already applied."""
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            log.warning("Link status - no session found for sid=%s", sid)
            raise HTTPException(status_code=401, detail="no session")

        log.info("Link status check - link_id=%s sid=%s", link_id, sid)

        need_apply = False
        principal: Optional[str] = None
        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                log.error("Link status - link not found: %s", link_id)
                raise HTTPException(status_code=404, detail="no such link")
            if rec["desktop_sid"] != sid:
                log.warning("Link status - wrong session: expected %s, got %s", rec["desktop_sid"], sid)
                raise HTTPException(status_code=403, detail="not your link")
            # expiry
            now_ts = now_fn()
            if now_ts > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                log.info("Link status - link expired: %s", link_id)
            if rec["status"] == "linked" and not rec.get("applied") and rec.get("principal"):
                need_apply = True
                principal = rec["principal"]
                log.info("Link status - need to apply principal: %s", principal)

        if need_apply and principal:
            try:
                await store.update_session(sid, {
                    "passkey_auth": True,
                    "passkey_principal": principal,
                })
                with _LINKS_LOCK:
                    if link_id in _LINKS:
                        _LINKS[link_id]["applied"] = True
                log.info("Link status - desktop session updated successfully")
            except Exception as e:
                log.error("Link status - failed to update desktop session: %s", e)
            finally:
                _notify_watchers(link_id, {"type":"status", **_public_view(_LINKS[link_id])})

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            out = _public_view(rec)
        
        log.info("Link status response - status=%s applied=%s", out.get("status"), out.get("applied"))
        return JSONResponse(out)

    @router.get("/link/events/{link_id}")
    async def link_events(link_id: str, req: Request):
        """
        Server-Sent Events channel.
        - No DPoP (EventSource can't send headers).
        - Auth via same-origin cookie session and ownership of the link.
        """
        sid = req.session.get("sid"); s = await store.get_session(sid) if sid else None
        if not sid or not s:
            log.warning("Link events - no session found for sid=%s", sid)
            raise HTTPException(status_code=401, detail="no session")

        log.info("Link events - starting SSE for link_id=%s sid=%s", link_id, sid)

        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                log.error("Link events - link not found: %s", link_id)
                raise HTTPException(status_code=404, detail="no such link")
            
            # Allow both desktop and mobile sessions to listen to the same link
            desktop_sid = rec.get("desktop_sid")
            mobile_sid = rec.get("mobile_sid")
            if sid != desktop_sid and sid != mobile_sid:
                log.warning("Link events - wrong session: expected desktop=%s or mobile=%s, got %s", 
                           desktop_sid, mobile_sid, sid)
                raise HTTPException(status_code=403, detail="not your link")
            
            initial = _public_view(rec)

        log.info("Link events - initial data: %s", initial)

        q: asyncio.Queue = asyncio.Queue()
        with _WATCHERS_LOCK:
            _WATCHERS.setdefault(link_id, []).append(q)

        async def event_gen():
            try:
                # Send initial snapshot
                yield f"event: status\ndata: {json.dumps(initial)}\n\n"
                log.info("Link events - sent initial snapshot")
                # Heartbeat every 15s if no events
                while True:
                    try:
                        evt = await asyncio.wait_for(q.get(), timeout=15.0)
                        log.info("Link events - sending event: %s", evt)
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
                log.info("Link events - SSE connection closed for link_id=%s", link_id)

        return StreamingResponse(event_gen(), media_type="text/event-stream", headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        })

    @router.websocket("/link/ws/{link_id}")
    async def link_websocket(websocket: WebSocket, link_id: str):
        """
        WebSocket endpoint for link status updates.
        Alternative to SSE for environments where SSE is blocked.
        """
        await websocket.accept()
        
        # Get session from query params or headers
        session_id = None
        try:
            # Try to get session from query params
            session_id = websocket.query_params.get("sid")
            if not session_id:
                # Try to get from headers
                session_id = websocket.headers.get("x-session-id")
        except Exception:
            pass
            
        log.info("WebSocket connection - link_id=%s session_id=%s", link_id, session_id)
        
        # Validate link exists and session owns it
        with _LINKS_LOCK:
            rec = _LINKS.get(link_id)
            if not rec:
                await websocket.close(code=4004, reason="Link not found")
                return
            if session_id and rec.get("desktop_sid") != session_id:
                await websocket.close(code=4003, reason="Not your link")
                return
            initial = _public_view(rec)
        
        # Send initial status
        try:
            initial_event = {"type": "status", **initial}
            await websocket.send_text(json.dumps(initial_event))
            log.info("WebSocket - sent initial data: %s", initial_event)
        except Exception as e:
            log.error("WebSocket - failed to send initial data: %s", e)
            await websocket.close()
            return
        
        # Add to connections
        with _WEBSOCKET_LOCK:
            if link_id not in _WEBSOCKET_CONNECTIONS:
                _WEBSOCKET_CONNECTIONS[link_id] = []
            _WEBSOCKET_CONNECTIONS[link_id].append(websocket)
            log.info("WebSocket - added to connections. Total connections for %s: %d", link_id, len(_WEBSOCKET_CONNECTIONS[link_id]))
        
        try:
            # Keep connection alive and handle incoming messages
            while True:
                try:
                    # Wait for any message (ping/pong, signature, or close)
                    data = await websocket.receive_text()
                    log.info("WebSocket - received message: %s", data)
                    
                    # Handle ping/pong
                    if data == "ping":
                        await websocket.send_text("pong")
                        continue
                    
                    # Handle JSON messages
                    try:
                        message = json.loads(data)
                        
                        # Handle signature sharing
                        if message.get("type") == "signature":
                            signature_data = message.get("data", {})
                            log.info("WebSocket - signature data: %s", signature_data)
                            
                            # Broadcast signature data to all connected WebSockets for this link
                            signature_message = {
                                "type": "signature",
                                "data": signature_data
                            }
                            
                            with _WEBSOCKET_LOCK:
                                connections = list(_WEBSOCKET_CONNECTIONS.get(link_id, []))
                            
                            for conn in connections:
                                if conn != websocket:  # Don't send back to sender
                                    try:
                                        await conn.send_text(json.dumps(signature_message))
                                    except Exception as e:
                                        log.warning("Failed to send signature to WebSocket: %s", e)
                                        # Remove failed connection
                                        with _WEBSOCKET_LOCK:
                                            if link_id in _WEBSOCKET_CONNECTIONS:
                                                try:
                                                    _WEBSOCKET_CONNECTIONS[link_id].remove(conn)
                                                except ValueError:
                                                    pass
                            
                            continue
                            
                    except json.JSONDecodeError:
                        # Not JSON, might be ping/pong or other text
                        pass
                    
                except WebSocketDisconnect:
                    log.info("WebSocket - client disconnected")
                    break
                except Exception as e:
                    log.error("WebSocket - error: %s", e)
                    break
                    
        finally:
            # Cleanup
            with _WEBSOCKET_LOCK:
                if link_id in _WEBSOCKET_CONNECTIONS:
                    try:
                        _WEBSOCKET_CONNECTIONS[link_id].remove(websocket)
                    except ValueError:
                        pass
            log.info("WebSocket - connection closed for link_id=%s", link_id)

    @router.post("/link/mobile/start")
    async def link_mobile_start(body: Dict[str, Any], req: Request):
        """Mobile posts the link ID it scanned. No DPoP yet."""
        lid = body.get("lid")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link id")
        
        # Log request details for debugging
        origin = req.headers.get("origin", "unknown")
        host = req.headers.get("host", "unknown")
        user_agent = req.headers.get("user-agent", "unknown")
        sid = req.session.get("sid")
        
        log.info("Mobile link start - lid=%s origin=%s host=%s sid=%s", 
                lid, origin, host, sid)
        
        # Verify the link ID exists and is still valid
        with _LINKS_LOCK:
            link_data = _LINKS.get(lid)
            if not link_data:
                raise HTTPException(status_code=400, detail="invalid or expired link id")
            
            # Check if link has expired
            now_ts = now()
            if now_ts > link_data.get("exp", 0):
                log.warning("Link expired - lid=%s exp=%s now=%s", lid, link_data.get("exp"), now_ts)
                _LINKS.pop(lid, None)  # Clean up expired link
                raise HTTPException(status_code=400, detail="link expired")
        
        log.info("Link ID verified - lid=%s exp=%s", lid, link_data.get("exp"))
        
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                log.error("Link not found - lid=%s", lid)
                raise HTTPException(status_code=404, detail="no such link")
            if now_ts > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                _notify_watchers(lid, {"type":"status", **_public_view(rec)})
                log.warning("Link expired - lid=%s", lid)
                raise HTTPException(status_code=400, detail="expired")
            if rec["status"] == "pending":
                rec["status"] = "scanned"
                log.info("Link status updated to scanned - lid=%s desktop_sid=%s", lid, rec.get("desktop_sid"))
        
        _notify_watchers(lid, {"type":"status", **_public_view(_LINKS[lid])})
        _notify_websockets(lid, {"type":"status", **_public_view(_LINKS[lid])})
        log.info("Mobile link start - notified watchers and websockets for lid=%s", lid)
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

        # Log request details for debugging
        origin = req.headers.get("origin", "unknown")
        host = req.headers.get("host", "unknown")
        
        log.info("Mobile link complete - lid=%s sid=%s principal=%s origin=%s host=%s", 
                lid, sid, s.get("passkey_principal"), origin, host)

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

        # Get device types for logging
        desktop_session = await store.get_session(desktop_sid) if desktop_sid else None
        mobile_session = await store.get_session(sid) if sid else None
        desktop_device_type = desktop_session.get("device_type", "unknown") if desktop_session else "unknown"
        mobile_device_type = mobile_session.get("device_type", "unknown") if mobile_session else "unknown"
        
        log.info("Link status updated - desktop_sid=%s mobile_sid=%s", desktop_sid, sid)
        log.info("Link data after mobile complete - rid=%s desktop_sid=%s desktop_device_type=%s mobile_sid=%s mobile_device_type=%s status=%s", 
                lid, desktop_sid, desktop_device_type, sid, mobile_device_type, rec.get("status"))

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
                    log.info("Desktop session updated successfully - desktop_sid=%s principal=%s", desktop_sid, s["passkey_principal"])
                    log.info("Desktop session data after update - desktop_sid=%s has_fingerprint=%s", 
                            desktop_sid, "fingerprint" in ds)
                else:
                    log.warning("Desktop session not found - desktop_sid=%s", desktop_sid)
            except Exception as e:
                log.error("Failed to update desktop session: %s", e)
                applied = False

        with _LINKS_LOCK:
            if lid in _LINKS:
                _LINKS[lid]["applied"] = applied

        _notify_watchers(lid, {"type":"status", **_public_view(_LINKS[lid])})
        _notify_websockets(lid, {"type":"status", **_public_view(_LINKS[lid])})
        log.info("Mobile link complete - applied=%s", applied)
        return JSONResponse({"ok": True, "applied": applied}, headers=_nonce_headers(ctx))

    @router.post("/link/mobile/issue-bc")
    async def link_mobile_issue_bc(body: Dict[str, Any], req: Request, ctx=Depends(require_dpop)):
        """Mobile issues a BC (verification code) for desktop to enter."""
        lid = body.get("lid")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link id")
        
        # Log request details for debugging
        origin = req.headers.get("origin", "unknown")
        host = req.headers.get("host", "unknown")
        sid = req.session.get("sid")
        
        log.info("Mobile issue-bc - lid=%s origin=%s host=%s sid=%s", 
                lid, origin, host, sid)
        
        s = await store.get_session(sid) if sid else None
        if not sid or not s:
            log.error("No session found - sid=%s", sid)
            raise HTTPException(status_code=401, detail="no session")
        if not s.get("passkey_auth") or not s.get("passkey_principal"):
            log.error("Mobile not authenticated - passkey_auth=%s principal=%s", 
                     s.get("passkey_auth"), s.get("passkey_principal"))
            raise HTTPException(status_code=403, detail="mobile not authenticated")
        
        # Generate a random BC code
        # Generate BC code using only characters that won't be filtered by formatBC
        # Avoid: 0,1,I,L,O,U (these get replaced/filtered)
        allowed_chars = 'ABCDEFGHJKMNPQRSTVWXYZ23456789'
        bc_raw = ''.join(random.choices(allowed_chars, k=8))
        
        # Store BC with link ID for validation
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            log.info("Link lookup - lid=%s found=%s status=%s exp=%s now=%s", 
                    lid, rec is not None, rec.get("status") if rec else None, 
                    rec.get("exp") if rec else None, now())
            if not rec:
                log.error("Link not found in storage - lid=%s available_links=%s", 
                         lid, list(_LINKS.keys()))
                raise HTTPException(status_code=404, detail="no such link")
            if now() > rec["exp"] and rec["status"] != "linked":
                rec["status"] = "expired"
                log.warning("Link expired - lid=%s", lid)
                raise HTTPException(status_code=400, detail="expired")
            
            # Store BC in link record
            rec["bc"] = bc_raw
            rec["bc_exp"] = now() + 60  # 60 second TTL
        
        log.info("BC issued - lid=%s bc=%s", lid, bc_raw)
        return JSONResponse({"bc": bc_raw, "expires_in": 60}, headers=_nonce_headers(ctx))
    
    @router.post("/link/mobile/cancel")
    async def link_mobile_cancel(body: Dict[str, Any], req: Request, ctx=Depends(require_dpop)):
        """Mobile cancels the linking process."""
        lid = body.get("lid")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link id")
        
        sid = req.session.get("sid")
        s = await store.get_session(sid) if sid else None
        if not sid or not s:
            raise HTTPException(status_code=401, detail="no session")
        
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if rec:
                rec["status"] = "cancelled"
                _notify_watchers(lid, {"type":"status", **_public_view(rec)})
                _notify_websockets(lid, {"type":"status", **_public_view(rec)})
        
        log.info("Link cancelled - lid=%s", lid)
        return JSONResponse({"ok": True}, headers=_nonce_headers(ctx))
    
    @router.get("/link/state")
    async def link_state(req: Request):
        """Get the current state of a link (for polling)."""
        lid = req.query_params.get("lid")
        if not lid:
            raise HTTPException(status_code=400, detail="missing link id")
        
        with _LINKS_LOCK:
            rec = _LINKS.get(lid)
            if not rec:
                raise HTTPException(status_code=404, detail="no such link")
            
            # Check if BC was entered (simplified check)
            status = rec["status"]
            if (status == "scanned" or status == "linked") and rec.get("bc"):
                # Check if BC was consumed (simplified - in real implementation, 
                # this would check if desktop entered the BC)
                if now() > rec.get("bc_exp", 0):
                    status = "confirmed"  # BC expired, assume confirmed for demo
                elif rec.get("bc_consumed"):
                    status = "confirmed"
        
        return {"status": status}

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
        payload = {"iss":"dpop-fun","aud":"link","iat":now_ts,"exp":rec["exp"],"lid":link_id}
        token = jws_es256_sign(payload)
        origin, _ = canonicalize_origin_and_url(req)
        uri = f"{origin}/public/link.html?lid={link_id}"
        img = qrcode.make(uri)
        import io
        buf = io.BytesIO(); img.save(buf, format="PNG")
        return Response(buf.getvalue(), media_type="image/png")



    @router.post("/get-apriltags")
    async def get_apriltags(request: Request):
        """Simple endpoint to get AprilTag numbers for QR generation."""
        try:
            log.info("Generating AprilTag numbers for QR code")
            
            # Generate 5 random AprilTag numbers between 1 and 586
            apriltag_numbers = []
            for _ in range(5):
                random_num = random.randint(1, 586)
                apriltag_numbers.append(random_num)

            # Return just the AprilTag numbers
            response_json = {
                "apriltag_numbers": apriltag_numbers
            }
            
            log.info(f"AprilTag numbers generated: {apriltag_numbers}")
            log.info(f"Full response: {response_json}")
            return JSONResponse(content=response_json)

        except Exception as e:
            log.error(f"AprilTag generation failed: {str(e)}")
            import traceback
            log.error(f"Traceback: {traceback.format_exc()}")
            return JSONResponse({
                "result": False,
                "error": f"AprilTag generation failed: {str(e)}"
            })


    return router
