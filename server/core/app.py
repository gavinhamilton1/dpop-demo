# server/main.py
import os, json, secrets, logging, asyncio, base64, hashlib, time
from typing import Dict, Any, Tuple, List, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware import Middleware
from starlette.responses import FileResponse
from starlette.middleware.base import BaseHTTPMiddleware
from pydantic import BaseModel

from jose import jws as jose_jws
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from server.core.config import load_settings
from server.db.session import SessionDB  # singlet
from server.utils.geolocation import GeolocationService
from server.utils.helpers import (ec_p256_thumbprint, now, b64u, canonicalize_origin_and_url, b64u_dec,
                                   cose_to_jwk, jwk_to_public_key, parse_authenticator_data)
from typing import Tuple, Optional, Dict
from server.services.session_service import SessionService
from server.services.passkeys import PasskeyService

# ---------------- Config ----------------
SETTINGS = load_settings()

logging.basicConfig(level=SETTINGS.log_level, format="%(asctime)s %(levelname)s [%(name)s.%(funcName)s] %(message)s")
log = logging.getLogger(__name__)
log.info("Loaded config from: %s", SETTINGS.cfg_file_used or "<defaults>")
log.info("Allowed origins: %s", SETTINGS.allowed_origins)

# ---------------- Security / request-id middleware ----------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    # Default site-wide CSP (tight)
    CSP_DEFAULT = (
        "default-src 'none'; "
        "script-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "base-uri 'none'; "
        "form-action 'self'"
    )

    # Face capture page CSP (local-only WASM, MediaRecorder, blobs, workers)
    CSP_FACE_CAPTURE = (
        "default-src 'none'; "
        "script-src 'self' 'wasm-unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "media-src 'self' blob:; "
        "worker-src 'self' blob:; "
        "base-uri 'none'; "
        "form-action 'self'"
    )

    # Docs page CSP (allows Swagger UI external resources)
    CSP_DOCS = (
        "default-src 'none'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "img-src 'self' data: https:; "
        "connect-src 'self'; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "base-uri 'none'; "
        "form-action 'self'"
    )

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)

        path = request.url.path or "/"

        # If a route already set CSP, do not overwrite
        if "Content-Security-Policy" in resp.headers:
            # still set the other security headers
            resp.headers.setdefault("Referrer-Policy", "no-referrer")
            resp.headers.setdefault("X-Content-Type-Options", "nosniff")
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
            
            # Set permissions policy based on path
            if path == "/onboarding" or path == "/face-verify" or path == "/" or path.startswith("/public/vendor/tasks-vision"):
                resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(self), camera=(self)")
            else:
                resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=(self)")
            return resp

        # Path-based CSP: face capture pages (onboarding, verification, and main page with inline face capture)
        if path == "/onboarding" or path == "/face-verify" or path == "/" or path.startswith("/public/vendor/tasks-vision") or path == "/pad-test.html":
            csp = self.CSP_FACE_CAPTURE
            permissions_policy = "geolocation=(), microphone=(self), camera=(self)"
        elif path == "/docs" or path == "/redoc" or path == "/openapi.json":
            csp = self.CSP_DOCS
            permissions_policy = "geolocation=(), microphone=(), camera=()"
        else:
            csp = self.CSP_DEFAULT
            permissions_policy = "geolocation=(), microphone=(), camera=(self)"

        resp.headers.setdefault("Content-Security-Policy", csp)
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Permissions-Policy", permissions_policy)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
        return resp

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or base64.urlsafe_b64encode(secrets.token_bytes(9)).rstrip(b"=").decode()
        request.state.request_id = rid
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp

class FetchMetadataMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    async def dispatch(self, request: Request, call_next):
        site = (request.headers.get("sec-fetch-site") or "").lower()
        origin = request.headers.get("Origin", "")

        # Allow localhost to bypass for dev
        if origin.startswith('http://localhost') or origin.startswith('https://localhost'):
            return await call_next(request)

        if site in ("", "same-origin", "same-site", "none"):
            return await call_next(request)
        if request.method.upper() in self.SAFE_METHODS:
            return await call_next(request)

        log.warning("FetchMetadata: blocking site=%s method=%s origin=%s", site, request.method, origin)
        return JSONResponse({"detail": "blocked by fetch-metadata"}, status_code=403)

class CORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get('Origin', '')

        # Preflight
        if request.method == "OPTIONS":
            allowed_origin = (
                origin if (
                    origin.startswith('http://localhost') or origin.startswith('https://localhost') or
                    origin.endswith('.dpop.fun') or origin == 'https://dpop.fun' or
                    origin in ('https://dpop-fun.onrender.com', 'https://dpop-fun-test.onrender.com')
                ) else 'https://dpop.fun'
            )
            return JSONResponse(
                content={"ok": True},
                headers={
                    'Access-Control-Allow-Origin': allowed_origin,
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
                    'Access-Control-Allow-Credentials': 'true',
                    'Access-Control-Max-Age': '86400',
                }
            )

        response = await call_next(request)
        allowed_origin = (
            origin if (
                origin.startswith('http://localhost') or origin.startswith('https://localhost') or
                origin in ('https://dpop-fun.onrender.com', 'https://dpop-fun-test.onrender.com') or
                origin.endswith('.dpop.fun') or origin == 'https://dpop.fun'
            ) else 'https://dpop.fun'
        )
        response.headers['Access-Control-Allow-Origin'] = allowed_origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        return response

# ---------------- Server signing key (ES256) ----------------
SERVER_EC_PRIVATE_KEY_PEM: str
if SETTINGS.server_ec_private_key_pem:
    SERVER_EC_PRIVATE_KEY_PEM = SETTINGS.server_ec_private_key_pem
    log.info("Loaded ES256 private key from config.")
else:
    _priv = ec.generate_private_key(ec.SECP256R1())
    SERVER_EC_PRIVATE_KEY_PEM = _priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    log.warning("No server EC private key configured; generated ephemeral dev key.")

def _pem_to_public_jwk_and_kid(pem_priv: str):
    priv = serialization.load_pem_private_key(pem_priv.encode(), password=None)
    pub = priv.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big"); y = nums.y.to_bytes(32, "big")
    jwk = {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y), "alg": "ES256"}
    ordered = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    h = hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).digest()
    kid = b64u(h); jwk["kid"] = kid
    return {"jwk": jwk, "kid": kid}

SERVER_JWK_INFO = _pem_to_public_jwk_and_kid(SERVER_EC_PRIVATE_KEY_PEM)
SERVER_PUBLIC_JWK = SERVER_JWK_INFO["jwk"]; SERVER_KID = SERVER_JWK_INFO["kid"]

# ---------------- FastAPI app ----------------
app = FastAPI(
    title="DPoP-Fun API",
    description="""Browser Identity & DPoP Security API documentation""",
    version="1.0.0",
    middleware=[
        Middleware(RequestIDMiddleware),
        Middleware(FetchMetadataMiddleware),
        Middleware(SecurityHeadersMiddleware),
        Middleware(CORSMiddleware),
        Middleware(SessionMiddleware,
                   secret_key=(SETTINGS.session_secret_key or base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()),
                   session_cookie=SETTINGS.session_cookie_name,
                   https_only=SETTINGS.https_only,
                   same_site=SETTINGS.session_samesite),
    ]
)

BASE_DIR = os.path.dirname(os.path.dirname(__file__))  # Go up one level from core/

# Static file mounting
app.mount("/public", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public")), name="public")
app.mount("/vendor", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public", "vendor")), name="public")

def _new_nonce() -> str: return b64u(secrets.token_bytes(18))

# ---------------- Binding token helpers (moved to SessionService) ----------------

# ---- DB startup ----
@app.on_event("startup")
async def _init_db():
    try:
        await SessionDB.init(SETTINGS.db_path)  # type: ignore[arg-type]
        log.info("DB initialized at %s", SETTINGS.db_path)
    except TypeError:
        log.warning("SessionDB.init(db_path) not supported; calling SessionDB.init() without args. Ensure SessionDB uses %s.", SETTINGS.db_path)
        await SessionDB.init()

# ---------------- Basic routes ----------------
@app.get("/", 
         response_class=HTMLResponse,
         tags=["demo"],
         summary="Main Application Page",
         description="Serves the main journeys page with the complete DPoP demo interface")
async def index():
    with open(os.path.join(BASE_DIR, "..", "public", "journeys.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/face-verify", 
         response_class=HTMLResponse,
         tags=["demo"],
         summary="Face Verification Page",
         description="Serves the face verification page for biometric authentication")
async def face_verify():
    # Serve the onboarding page with verify mode
    with open(os.path.join(BASE_DIR, "..", "public", "onboarding.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/favicon.ico",
         tags=["demo"],
         summary="Favicon",
         description="Returns the application favicon")
async def favicon():
    return FileResponse("public/favicon.ico")

@app.get("/mobile",
         response_class=HTMLResponse,
         tags=["demo"],
         summary="Mobile Device Page",
         description="Serves the mobile device page for linking and authentication")
async def mobile():
    """Serve the mobile device page"""
    with open(os.path.join(BASE_DIR, "..", "public", "mobile.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/manifest.json",
         tags=["demo"],
         summary="PWA Manifest",
         description="Returns the Progressive Web App manifest file")
async def manifest():
    return FileResponse("app/static/manifest.json")

@app.get("/.well-known/dpop-fun-jwks.json",
         tags=["dpop"],
         summary="JWKS Endpoint",
         description="Returns the JSON Web Key Set (JWKS) for server public key verification")
async def jwks(): return {"keys": [SERVER_PUBLIC_JWK]}


@app.post("/session/init",
          tags=["session"],
          summary="Initialize Session",
          description="Endpoint that handles session initialization, BIK registration, and DPoP binding in a single call. Supports incremental setup or complete setup in one request.")
async def session_init(req: Request, response: Response):
    """Route handler for session initialization"""
    result = await SessionService.session_init(req, response)
    return result


@app.post("/session/logout",
          tags=["session"],
          summary="Logout Session",
          description="Logout the current user and set session state to TERMINATED")
async def session_logout(req: Request, response: Response):
    """Route handler for session logout"""
    try:
        # Get session data (requires response parameter)
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        
        if not session_id:
            raise HTTPException(status_code=400, detail="No session ID found")
        
        # Logout the session
        await SessionService.logout_session(session_id)
        
        return {"ok": True, "message": "Logged out successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Session logout failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/session/kill",
          tags=["session"],
          summary="Kill Another Session",
          description="Terminate another active session (not the current one)")
async def session_kill(req: Request, response: Response):
    """Kill/terminate another user's session"""
    try:
        # Get current session ID from cookie
        current_session_id = req.session.get("session_id")
        if not current_session_id:
            raise HTTPException(status_code=401, detail="No session found")
        
        # Get current session from database
        current_session = await SessionDB.get_session(current_session_id)
        if not current_session:
            raise HTTPException(status_code=401, detail="Session not found")
        
        # Check if user is authenticated
        current_username = current_session.get("auth_username")
        if not current_username or current_session.get("auth_status") != "authenticated":
            raise HTTPException(status_code=401, detail="User not authenticated")
        
        # Get target session ID from request
        body = await req.json()
        target_session_id = body.get("payload", {}).get("session_id")
        
        if not target_session_id:
            raise HTTPException(status_code=400, detail="No target session ID provided")
        
        # Prevent killing own session
        if target_session_id == current_session_id:
            raise HTTPException(status_code=400, detail="Cannot kill current session. Use logout instead.")
        
        # Get target session to verify ownership
        target_session = await SessionDB.get_session(target_session_id)
        if not target_session:
            raise HTTPException(status_code=404, detail="Target session not found")
        
        # Verify the target session belongs to the same user
        if target_session.get("auth_username") != current_username:
            raise HTTPException(status_code=403, detail="Cannot kill another user's session")
        
        # Kill the target session
        await SessionService.logout_session(target_session_id)
        
        log.info(f"User {current_username} killed session {target_session_id}")
        
        return {"ok": True, "message": "Session terminated successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Session kill failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/session/history",
         tags=["session"],
         summary="Get Session History",
         description="Get session history for authenticated user (last 10 days)")
async def get_session_history(req: Request, response: Response):
    """Get session history for authenticated user"""
    try:
        # For GET requests, we need to get session data without parsing a body
        session_id = req.session.get("session_id")
        if not session_id:
            raise HTTPException(status_code=401, detail="No session found")
        
        # Get session from database
        session_data = await SessionDB.get_session(session_id)
        if not session_data:
            raise HTTPException(status_code=401, detail="Session not found")
        
        # Check if user is authenticated
        username = session_data.get("auth_username")
        if not username or session_data.get("auth_status") != "authenticated":
            raise HTTPException(status_code=401, detail="User not authenticated")
        
        # Get session history for the user (last 10 days)
        history = await SessionService.get_session_history(username, days=10)
        
        # Transform _session_id to session_id for client compatibility
        for session in history:
            if '_session_id' in session and 'session_id' not in session:
                session['session_id'] = session['_session_id']
        
        log.info(f"Session history retrieved for user {username}: {len(history)} sessions")
        
        return {
            "ok": True,
            "history": history,
            "username": username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Get session history failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ---- Mobile Linking Endpoints ----

# In-memory link storage (temporary solution)
_LINK_STORAGE = {}

@app.post("/link/start",
          tags=["mobile-linking"],
          summary="Start Mobile Linking",
          description="Start cross-device linking process (desktop side)")
async def link_start(req: Request, response: Response):
    """Start mobile device linking"""
    try:
        # Get session data
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        
        if not session_id:
            raise HTTPException(status_code=401, detail="No session ID found")
        
        # Get flow type and username from request body
        body = await req.json()
        flow_type = body.get("flow_type", "registration")
        username = body.get("username")  # Username from desktop
        
        # Generate link ID
        import secrets
        link_id = secrets.token_urlsafe(12)
        created_at = now()
        expires_at = created_at + 300  # 5 minutes
        
        # Generate QR URL
        origin = f"{req.url.scheme}://{req.url.netloc}"
        qr_url = f"{origin}/mobile?lid={link_id}&flow={flow_type}"
        
        # Store link data in memory with username
        _LINK_STORAGE[link_id] = {
            "link_id": link_id,
            "desktop_session_id": session_id,
            "username": username,  # Store username in link properties
            "flow_type": flow_type,
            "created_at": created_at,
            "expires_at": expires_at,
            "status": "pending"
        }
        
        log.info(f"Link created: {link_id}, flow: {flow_type}, username: {username}, qr_url: {qr_url}")
        
        return {
            "linkId": link_id,
            "qr_url": qr_url,
            "flow_type": flow_type,
            "expires_at": expires_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Link start failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/link/events/{link_id}",
         tags=["mobile-linking"],
         summary="Link Status Events",
         description="Server-sent events for mobile linking status updates")
async def link_events(link_id: str, req: Request):
    """SSE endpoint for link status updates"""
    import asyncio
    
    async def event_generator():
        # Send status updates based on link storage
        try:
            while True:
                link_data = _LINK_STORAGE.get(link_id)
                if link_data:
                    status = link_data.get("status", "pending")
                    yield f"data: {json.dumps({'status': status, 'link_id': link_id})}\n\n"
                    
                    # Stop sending if link is completed or failed
                    if status in ["linked", "completed", "failed", "expired"]:
                        break
                else:
                    yield f"data: {json.dumps({'status': 'expired', 'link_id': link_id})}\n\n"
                    break
                
                await asyncio.sleep(2)  # Check every 2 seconds
        except asyncio.CancelledError:
            pass
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
        }
    )


@app.post("/get-apriltags",
          tags=["mobile-linking"],
          summary="Get AprilTag Numbers",
          description="Generate AprilTag numbers for QR code overlay")
async def get_apriltags(req: Request):
    """Generate AprilTag numbers for QR overlay"""
    try:
        body = await req.json()
        link_id = body.get("linkId", "")
        
        # Generate deterministic AprilTag IDs from link ID
        import hashlib
        hash_obj = hashlib.sha256(link_id.encode())
        hash_bytes = hash_obj.digest()
        
        # Generate 4 tag IDs from hash (use first 16 bytes, 4 bytes each)
        tag_ids = []
        for i in range(4):
            offset = i * 4
            tag_id = int.from_bytes(hash_bytes[offset:offset+4], byteorder='big') % 587  # 36h11 family has 587 tags
            tag_ids.append(tag_id)
        
        log.info(f"Generated AprilTag IDs for link {link_id}: {tag_ids}")
        
        return {"tags": tag_ids}
        
    except Exception as e:
        log.error(f"AprilTag generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/link/mobile/start",
          tags=["mobile-linking"],
          summary="Mobile Start Linking",
          description="Mobile device scans QR and starts linking process")
async def link_mobile_start(req: Request):
    """Mobile device starts linking"""
    try:
        body = await req.json()
        link_id = body.get("lid")
        
        if not link_id:
            raise HTTPException(status_code=400, detail="Link ID is required")
        
        # Get link data from storage
        link_data = _LINK_STORAGE.get(link_id)
        
        if not link_data:
            raise HTTPException(status_code=404, detail="Link ID not found or expired")
        
        # Check if link has expired
        if now() > link_data.get("expires_at", 0):
            # Clean up expired link
            _LINK_STORAGE.pop(link_id, None)
            raise HTTPException(status_code=400, detail="Link has expired")
        
        # Update link status to scanned
        link_data["status"] = "scanned"
        
        # Get username from link data
        desktop_username = link_data.get("username")
        
        log.info(f"Mobile device started linking - link_id: {link_id}, username: {desktop_username}")
        
        return {
            "ok": True,
            "link_id": link_id,
            "desktop_username": desktop_username
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Mobile link start failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/link/mobile/complete",
          tags=["mobile-linking"],
          summary="Complete Mobile Linking",
          description="Complete the mobile device linking process")
async def link_mobile_complete(req: Request, response: Response):
    """Complete mobile device linking"""
    try:
        # Get session data
        session_data = await SessionService.get_session_data(req, response)
        mobile_session_id = req.session.get("session_id")
        
        body = await req.json()
        link_id = body.get("link_id")
        
        if not link_id:
            raise HTTPException(status_code=400, detail="Link ID is required")
        
        # Get link data from storage
        link_data = _LINK_STORAGE.get(link_id)
        
        if not link_data:
            raise HTTPException(status_code=404, detail="Link ID not found")
        
        # Check if mobile session is authenticated
        mobile_username = session_data.get("auth_username")
        mobile_auth_status = session_data.get("auth_status")
        
        if not mobile_username or mobile_auth_status != "authenticated":
            raise HTTPException(status_code=403, detail="Mobile session not authenticated")
        
        # Update link status to completed
        link_data["status"] = "linked"
        link_data["mobile_session_id"] = mobile_session_id
        link_data["mobile_username"] = mobile_username
        
        # Link sessions together (desktop <-> mobile)
        desktop_session_id = link_data.get("desktop_session_id")
        if desktop_session_id:
            # Create bidirectional link between desktop and mobile sessions
            await SessionDB.link_sessions(desktop_session_id, mobile_session_id)
            log.info(f"Linked sessions: desktop {desktop_session_id} <-> mobile {mobile_session_id}")
            
            # For login flow, also authenticate the desktop session
            flow_type = link_data.get("flow_type", "registration")
            if flow_type == "login":
                # Get desktop session
                desktop_session = await SessionDB.get_session(desktop_session_id)
                if desktop_session:
                    # Update desktop session to be authenticated
                    await SessionDB.update_session_auth_status(
                        desktop_session_id,
                        "Mobile Passkey",  # auth_method
                        "authenticated",   # auth_status
                        mobile_username    # username
                    )
                    
                    log.info(f"Desktop session {desktop_session_id} authenticated via mobile linking with username {mobile_username}")
                else:
                    log.warning(f"Desktop session {desktop_session_id} not found")
        else:
            log.warning(f"No desktop session ID in link data for {link_id}")
        
        log.info(f"Mobile linking completed: {link_id}, flow: {flow_type}, mobile_user: {mobile_username}")
        
        return {
            "ok": True,
            "message": "Mobile linking completed successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Mobile link complete failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/link/mobile/issue-bc",
          tags=["mobile-linking"],
          summary="Issue Bootstrap Code",
          description="Issue bootstrap code for desktop verification")
async def link_mobile_issue_bc(req: Request, response: Response):
    """Issue bootstrap code for desktop verification"""
    try:
        # Get session data
        session_data = await SessionService.get_session_data(req, response)
        
        body = await req.json()
        link_id = body.get("lid")
        
        if not link_id:
            raise HTTPException(status_code=400, detail="Link ID is required")
        
        # Get link data from storage
        link_data = _LINK_STORAGE.get(link_id)
        
        if not link_data:
            raise HTTPException(status_code=404, detail="Link ID not found")
        
        # Generate bootstrap code (8 alphanumeric characters only)
        import secrets
        import string
        alphanumeric = string.ascii_uppercase + string.digits
        bc = ''.join(secrets.choice(alphanumeric) for _ in range(8))
        expires_at = now() + 60  # 60 seconds
        
        # Store BC in link data for validation
        link_data["bc"] = bc
        link_data["bc_expires_at"] = expires_at
        link_data["bc_consumed"] = False
        
        log.info(f"Bootstrap code issued for link {link_id}: {bc}")
        
        return {
            "ok": True,
            "bc": bc,
            "expires_at": expires_at
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Issue BC failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/link/status/{link_id}",
         tags=["mobile-linking"],
         summary="Get Link Status",
         description="Get current status of a link (for mobile polling)")
async def get_link_status(link_id: str):
    """Get link status for mobile polling (fallback)"""
    try:
        link_data = _LINK_STORAGE.get(link_id)
        
        if not link_data:
            raise HTTPException(status_code=404, detail="Link not found")
        
        # Check if link has expired
        if now() > link_data.get("expires_at", 0):
            status = "expired"
        else:
            status = link_data.get("status", "pending")
        
        return {
            "link_id": link_id,
            "status": status
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Get link status failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/link/status/{link_id}/stream",
         tags=["mobile-linking"],
         summary="Stream Link Status (SSE)",
         description="Stream link status updates via Server-Sent Events")
async def stream_link_status(link_id: str):
    """Stream link status updates to mobile device via SSE"""
    async def event_generator():
        try:
            link_data = _LINK_STORAGE.get(link_id)
            
            if not link_data:
                yield f"data: {json.dumps({'error': 'Link not found'})}\n\n"
                return
            
            # Send initial status
            initial_status = link_data.get("status", "pending")
            yield f"data: {json.dumps({'link_id': link_id, 'status': initial_status})}\n\n"
            
            # Poll for status changes (server-side, much more efficient)
            last_status = initial_status
            max_duration = 300  # 5 minutes max
            start_time = now()
            
            while (now() - start_time) < max_duration:
                await asyncio.sleep(1)  # Check every second
                
                link_data = _LINK_STORAGE.get(link_id)
                if not link_data:
                    yield f"data: {json.dumps({'status': 'expired'})}\n\n"
                    break
                
                current_status = link_data.get("status", "pending")
                
                # Check if status changed
                if current_status != last_status:
                    yield f"data: {json.dumps({'link_id': link_id, 'status': current_status})}\n\n"
                    last_status = current_status
                    
                    # If completed or confirmed, close the connection
                    if current_status in ['completed', 'confirmed', 'verified']:
                        break
                
                # Check if link expired
                if now() > link_data.get("expires_at", 0):
                    yield f"data: {json.dumps({'status': 'expired'})}\n\n"
                    break
            
            # Send final keepalive
            yield f"data: {json.dumps({'status': 'timeout'})}\n\n"
            
        except asyncio.CancelledError:
            log.info(f"SSE connection cancelled for link: {link_id}")
        except Exception as e:
            log.error(f"SSE stream error for link {link_id}: {e}")
            yield f"data: {json.dumps({'error': str(e)})}\n\n"
    
    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )


@app.post("/device/redeem",
          tags=["mobile-linking"],
          summary="Redeem Bootstrap Code",
          description="Desktop redeems bootstrap code to verify mobile device")
async def device_redeem(req: Request, response: Response):
    """Redeem bootstrap code from mobile device"""
    try:
        # Get session data
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        
        if not session_id:
            raise HTTPException(status_code=401, detail="No session ID found")
        
        body = await req.json()
        bc = body.get("bc", "").upper().strip()
        
        if len(bc) != 8:
            raise HTTPException(status_code=400, detail="Invalid bootstrap code format")
        
        # Find and validate BC in link storage
        link_id = None
        for lid, link_data in _LINK_STORAGE.items():
            if link_data.get("bc") == bc:
                # Check if BC is still valid
                if now() <= link_data.get("bc_expires_at", 0):
                    if not link_data.get("bc_consumed"):
                        link_id = lid
                        link_data["bc_consumed"] = True
                        link_data["status"] = "confirmed"
                        log.info(f"BC consumed - link_id: {lid}, bc: {bc}")
                        break
                else:
                    log.warning(f"BC expired - link_id: {lid}, bc: {bc}")
        
        if not link_id:
            raise HTTPException(status_code=400, detail="Invalid or expired bootstrap code")
        
        log.info(f"Bootstrap code redeemed successfully for link: {link_id}")
        
        return {
            "ok": True,
            "link_id": link_id,
            "message": "Bootstrap code verified successfully"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Device redeem failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))























# ---- Example protected endpoint with DPoP validation ----
@app.get("/api/protected",
         tags=["api"],
         summary="Protected API Endpoint",
         description="Example protected endpoint that requires DPoP proof")
async def protected_endpoint(req: Request):
    """Example of a protected endpoint using DPoP validation"""
    
    # Require DPoP proof for this protected endpoint
    try:
        auth_data = await SessionService.require_dpop_proof(req)
        dpop_payload = auth_data["dpop_payload"]
        session_data = auth_data["session_data"]
        session_id = auth_data["session_id"]
        
        log.info("Protected endpoint accessed - Session ID: %s, Device ID: %s", 
                session_id, session_data.get("device_id"))
        
        return JSONResponse({
            "message": "Access granted to protected resource",
            "session_id": session_id,
            "device_id": session_data.get("device_id"),
            "dpop_jti": dpop_payload.get("jti"),
            "timestamp": now()
        })
        
    except HTTPException as e:
        log.warning("Protected endpoint access denied: %s", e.detail)
        raise e


# ---- Passkey Endpoints ----
@app.post("/webauthn/registration/options",
          tags=["passkeys"],
          summary="Get Passkey Registration Options",
          description="Get challenge and options for registering a new passkey")
async def webauthn_registration_options(req: Request, response: Response):
    """Get passkey registration challenge"""
    try:
        # Get session data (requires response parameter)
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        log.info("Passkey registration options - Session Data: %s", session_data)

        # Parse request body to get username
        request_body = await req.json()
        
        # Pass session_id, session_data, request, and body
        body = await PasskeyService.get_registration_options(session_id, session_data, req, request_body)
        return body
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Passkey registration options failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webauthn/registration/verify",
          tags=["passkeys"],
          summary="Verify Passkey Registration",
          description="Verify attestation and complete passkey registration")
async def webauthn_registration_verify(req: Request, response: Response):
    """Verify passkey registration"""
    try:
        # Get session data (requires response parameter)
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")

        # Parse request body
        attestation_data = await req.json()
        
        result = await PasskeyService.verify_registration(
            session_id, req, attestation_data
        )
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Passkey registration verify failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webauthn/authentication/options",
          tags=["passkeys"],
          summary="Get Passkey Authentication Options",
          description="Get challenge and options for authenticating with a passkey")
async def webauthn_authentication_options(req: Request, response: Response):
    """Get passkey authentication challenge"""
    try:
        # Get session data (requires response parameter)
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        log.info('HERE')
        
        # Parse request body to get username (optional)
        request_body = await req.json()

        body = await PasskeyService.get_authentication_options(session_id, session_data, req, request_body)
        return body
        
    except Exception as e:
        log.error(f"Passkey auth options failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/webauthn/authentication/verify",
          tags=["passkeys"],
          summary="Verify Passkey Authentication",
          description="Verify assertion and complete passkey authentication")
async def webauthn_authentication_verify(req: Request, response: Response):
    """Verify passkey authentication"""
    try:
        # Get session data (requires response parameter)
        session_data = await SessionService.get_session_data(req, response)
        session_id = req.session.get("session_id")
        
        # Parse request body
        assertion_data = await req.json()
        
        # Get username from assertion data (client should include it)
        username = assertion_data.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Username is required for passkey authentication")
        
        result = await PasskeyService.verify_authentication(
            session_id, session_data, req, assertion_data, username
        )
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        log.error(f"Passkey auth verify failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


log.info("Passkey endpoints registered")

