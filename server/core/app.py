# server/main.py
import os, json, secrets, logging, asyncio, base64, hashlib, time
from typing import Dict, Any, Tuple, List, Optional
from urllib.parse import urlsplit, urlunsplit

from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse, Response
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
from server.db.database import DB
from server.utils.geolocation import GeolocationService
from server.services.passkeys import get_router as get_passkeys_router
from server.services.linking import get_router as get_linking_router
from server.utils.helpers import ec_p256_thumbprint, now, b64u
from server.utils.url_utils import canonicalize_origin_and_url
from server.services.signal_service import signal_service
from typing import Tuple, Optional, Dict
from server.services.face_service import face_service
from server.services.session_service import SessionService

# ---------------- Config ----------------
SETTINGS = load_settings()


logging.basicConfig(level=SETTINGS.log_level, format="%(asctime)s %(levelname)s dpop-fun %(message)s")
log = logging.getLogger("dpop-fun")
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
    contact={
        "name": "DPoP-Fun Demo",
        "url": "https://dpop.fun",
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT",
    },
    tags_metadata=[
        {
            "name": "session",
            "description": "Session management and initialization endpoints",
        },
        {
            "name": "authentication",
            "description": "Authentication and user binding endpoints",
        },
        {
            "name": "browser-identity",
            "description": "Browser Identity Key (BIK) registration and management",
        },
        {
            "name": "dpop",
            "description": "DPoP (Demonstration of Proof-of-Possession) binding and validation",
        },
        {
            "name": "face-auth",
            "description": "Face authentication and biometric verification",
        },
        {
            "name": "passkeys",
            "description": "WebAuthn/FIDO2 passkey authentication",
        },
        {
            "name": "device-linking",
            "description": "Device-to-device linking and QR code authentication",
        },
        {
            "name": "fingerprinting",
            "description": "Device fingerprinting and signal collection",
        },
        {
            "name": "admin",
            "description": "Administrative endpoints for debugging and maintenance",
        },
        {
            "name": "demo",
            "description": "Demo and testing endpoints",
        },
    ],
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
app.mount("/models", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public", "models")), name="public")

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

@app.get("/mobile-login",
         tags=["demo"],
         summary="Mobile Login Page",
         description="Serves the mobile login page for device linking")
async def mobile_login():
    """Serve the mobile login page"""
    with open(os.path.join(BASE_DIR, "..", "public", "mobile-login.html"), "r", encoding="utf-8") as f:
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
    body = await req.json()
    result = await SessionService.session_init(req, body, response)
    
    # loop round the headers and body
    for header, value in result["headers"].items():
        log.info("Setting header: %s: %s", header, value)
        response.headers[header] = value
    return result["body"] 






# ---------------- Resume (BIK) ----------------
@app.post("/session/resume-init")
async def resume_init(req: Request):
    sid = req.session.get("sid")
    s = await SessionDB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    # Use session nonce for resume operations
    session_nonce = s.get("session_nonce") or _new_nonce()
    await SessionDB.update_session(sid, {"session_nonce": session_nonce})
    next_nonce = _new_nonce(); await DB.add_nonce(sid, next_nonce, SETTINGS.nonce_ttl)
    return JSONResponse({"session_nonce": session_nonce}, headers={"DPoP-Nonce": next_nonce})

@app.post("/session/resume-confirm")
async def resume_confirm(req: Request):
    sid = req.session.get("sid")
    s = await SessionDB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    jws_compact = (await req.body()).decode()
    
    # Use the generic JWS validation helper
    try:
        resume_data = validate_jws_token(jws_compact, "bik-resume+jws", ["session_nonce"])
        payload = resume_data["payload"]
        header = resume_data["header"]
    except ValueError as e:
        raise HTTPException(401, f"JWS validation failed: {e}")
    
    if payload.get("session_nonce") != s.get("session_nonce"):
        raise HTTPException(401, "bad session_nonce")
    if ec_p256_thumbprint(header["jwk"]) != s.get("bik_jkt"):
        raise HTTPException(401, "bik mismatch")

    origin, _ = canonicalize_origin_and_url(req, SETTINGS.external_origin)
    dpop_jkt = s.get("dpop_jkt")
    bind = SessionService.issue_binding_token(sid=sid, bik_jkt=s["bik_jkt"], dpop_jkt=dpop_jkt, aud=origin)
    n = _new_nonce(); await SessionDB.add_nonce(sid, n, SETTINGS.nonce_ttl)
    # Rotate session nonce after successful resume
    new_session_nonce = _new_nonce()
    await SessionDB.update_session(sid, {"session_nonce": new_session_nonce})
    return JSONResponse({"bind": bind}, headers={"DPoP-Nonce": n})

@app.post("/session/kill")
async def kill_session(req: Request):
    """Route handler for killing session"""
    return await SessionService.kill_session(req)

@app.post("/session/fingerprint",
          tags=["fingerprinting"],
          summary="Collect Device Fingerprint",
          description="Collect device fingerprinting and geolocation data for security analysis and signal comparison")
async def collect_fingerprint(req: Request):
    """Collect device fingerprinting and geolocation data"""
    log.info("POST /session/fingerprint endpoint called")
    log.info("POST /session/fingerprint - request headers: %s", dict(req.headers))
    log.info("POST /session/fingerprint - request cookies: %s", dict(req.cookies))
    
    sid = req.session.get("sid")
    log.info("POST /session/fingerprint - session data: %s", dict(req.session))
    if not sid:
        log.error("POST /session/fingerprint - no session ID found")
        raise HTTPException(401, "no session")
    
    log.info("POST /session/fingerprint called with sid=%s", sid)
    log.info("POST /session/fingerprint - storing fingerprint data for session_id=%s", sid)
    log.info("POST /session/fingerprint - session cookie: %s", req.cookies.get("dpop-fun_session"))
    
    try:
        # Verify session exists before updating
        existing_session = await SessionDB.get_session(sid)
        if not existing_session:
            log.error("Session not found for fingerprint collection sid=%s", sid)
            raise HTTPException(404, "session not found")
        
        log.info("Existing session found sid=%s keys=%s", sid, list(existing_session.keys()))
        
        # Get fingerprint data from request body
        fingerprint_data = await req.json()
        log.info("Received fingerprint data sid=%s device_type=%s data=%s", 
                sid, fingerprint_data.get("deviceType", "unknown"), fingerprint_data)
        
        # Get client IP for geolocation
        client_ip = req.client.host
        if req.headers.get("x-forwarded-for"):
            client_ip = req.headers.get("x-forwarded-for").split(",")[0].strip()
        elif req.headers.get("x-real-ip"):
            client_ip = req.headers.get("x-real-ip")
        
        # Add IP to fingerprint data
        fingerprint_data["ip_address"] = client_ip
        
        # Perform geolocation lookup
        log.info("Performing geolocation lookup for IP: %s", client_ip)
        geolocation_data = GeolocationService.get_ip_geolocation(client_ip)
        
        # Try fallback service if primary fails
        if not geolocation_data:
            log.info("Primary geolocation failed, trying fallback for IP: %s", client_ip)
            geolocation_data = GeolocationService.get_ip_geolocation_fallback(client_ip)
        
        # Add geolocation data to fingerprint if available
        if geolocation_data:
            fingerprint_data["geolocation"] = geolocation_data
            log.info("Geolocation data added to fingerprint: %s, %s, %s", 
                    geolocation_data.get('city', 'Unknown'), 
                    geolocation_data.get('region', 'Unknown'), 
                    geolocation_data.get('country', 'Unknown'))
        else:
            log.warning("No geolocation data available for IP: %s", client_ip)
            fingerprint_data["geolocation"] = None
        
        # Store fingerprint data and device type in session
        device_type = fingerprint_data.get("deviceType", "unknown")
        await SessionDB.update_session(sid, {
            "fingerprint": fingerprint_data,
            "device_type": device_type
        })
        
        # Verify the data was stored
        stored_session = await SessionDB.get_session(sid)
        stored_fingerprint = stored_session.get("fingerprint", {}) if stored_session else {}
        stored_device_type = stored_session.get("device_type", "unknown") if stored_session else "unknown"
        log.info("Fingerprint stored verification sid=%s device_type=%s stored_keys=%s", 
                sid, stored_device_type, list(stored_fingerprint.keys()))
        
        # Final verification - check if fingerprint data is actually in the stored session
        if not stored_fingerprint or len(stored_fingerprint) == 0:
            log.error("Fingerprint data not found in stored session sid=%s", sid)
            raise HTTPException(500, "Fingerprint data was not stored properly")
        
        log.info("Fingerprint data successfully stored sid=%s device_type=%s fingerprint_keys=%s", 
                sid, stored_device_type, list(stored_fingerprint.keys()))
        
        # Store signal data linked to BIK if available
        bik_jkt = stored_session.get("bik_jkt")
        if bik_jkt:
            # Check if signal data has already been stored for this session
            signal_data_stored = stored_session.get("signal_data_stored", False)
            
            if not signal_data_stored:
                # Only store signal data if it hasn't been stored for this session yet
                signal_stored = await SessionDB.store_signal_data(
                    bik_jkt=bik_jkt,
                    session_id=sid,
                    device_type=device_type,
                    fingerprint_data=fingerprint_data,
                    ip_address=client_ip,
                    geolocation_data=geolocation_data
                )
                
                if signal_stored:
                    # Mark that signal data has been stored for this session
                    await SessionDB.update_session(sid, {"signal_data_stored": True})
                    log.info("Signal data stored for BIK %s session %s", bik_jkt[:8], sid[:8])
                else:
                    log.warning("Failed to store signal data for BIK %s", bik_jkt[:8])
            else:
                log.info("Signal data already stored for session %s, skipping duplicate storage", sid[:8])
        else:
            log.info("No BIK available yet for signal storage - will be stored after BIK registration")
        
        log.info("Fingerprint collected sid=%s device_type=%s ip=%s", 
                sid, fingerprint_data.get("deviceType", "unknown"), client_ip)
        return JSONResponse({"ok": True, "message": "Fingerprint collected successfully"})
    except Exception as e:
        log.exception("Failed to collect fingerprint sid=%s", sid)
        raise HTTPException(500, f"Failed to collect fingerprint: {e}")

@app.get("/session/signal-data")
async def get_signal_data(req: Request):
    """Get historical signal data for the current session's BIK"""
    sid = req.session.get("sid")
    if not sid:
        raise HTTPException(401, "no session")
    
    try:
        session_data = await SessionDB.get_session(sid)
        if not session_data:
            raise HTTPException(404, "session not found")
        
        bik_jkt = session_data.get("bik_jkt")
        if not bik_jkt:
            return JSONResponse({"historical_signal": None})
        
        # Get historical signal data for this BIK
        historical_signal = await SessionDB.get_latest_signal_data_by_bik(bik_jkt)
        
        log.info("Signal data request - BIK JKT: %s, Historical signal found: %s", 
                bik_jkt[:8] if bik_jkt else "None", 
                "Yes" if historical_signal else "No")
        
        return JSONResponse({"historical_signal": historical_signal})
        
    except Exception as e:
        log.exception("Failed to get signal data sid=%s", sid)
        raise HTTPException(500, f"Failed to get signal data: {e}")

@app.get("/session/bik-authentication-status")
async def get_bik_authentication_status(req: Request):
    """Get BIK authentication status and history"""
    sid = req.session.get("sid")
    if not sid:
        raise HTTPException(401, "no session")
    
    try:
        session_data = await DB.get_session(sid)
        if not session_data:
            raise HTTPException(404, "session not found")
        
        bik_jkt = session_data.get("bik_jkt")
        if not bik_jkt:
            return JSONResponse({
                "bik_jkt": None,
                "is_authenticated": False,
                "authentication_history": []
            })
        
        # Check if BIK has ever been authenticated
        is_authenticated = await DB.is_bik_authenticated(bik_jkt)
        
        # Get authentication history
        auth_history = await DB.get_bik_authentication_history(bik_jkt)
        
        log.info("BIK authentication status - BIK: %s, Authenticated: %s, History entries: %d", 
                bik_jkt[:8] if bik_jkt else "None", 
                is_authenticated, 
                len(auth_history))
        
        return JSONResponse({
            "bik_jkt": bik_jkt,
            "is_authenticated": is_authenticated,
            "authentication_history": auth_history
        })
        
    except Exception as e:
        log.exception("Failed to get BIK authentication status sid=%s", sid)
        raise HTTPException(500, f"Failed to get BIK authentication status: {e}")

@app.post("/session/compare-signals")
async def compare_signals(req: Request):
    """Compare current fingerprint with historical data"""
    sid = req.session.get("sid")
    if not sid:
        raise HTTPException(401, "no session")
    
    try:
        body = await req.json()
        current_fingerprint = body.get("current_fingerprint", {})
        historical_fingerprint = body.get("historical_fingerprint", {})
        
        if not current_fingerprint or not historical_fingerprint:
            raise HTTPException(400, "Missing fingerprint data")
        
        # Use signal service to compare
        comparison = signal_service.compare_signals(current_fingerprint, historical_fingerprint)
        
        log.info(f"Signal comparison result: is_similar={comparison.is_similar}, similarity_score={comparison.similarity_score}, risk_level={comparison.risk_level}")
        log.info(f"Differences: {comparison.differences}")
        log.info(f"Warnings: {comparison.warnings}")
        
        return JSONResponse({
            "is_similar": comparison.is_similar,
            "similarity_score": comparison.similarity_score,
            "risk_level": comparison.risk_level,
            "differences": comparison.differences,
            "warnings": comparison.warnings
        })
        
    except Exception as e:
        log.exception("Failed to compare signals sid=%s", sid)
        raise HTTPException(500, f"Failed to compare signals: {e}")






































@app.post("/onboarding/username",
          tags=["authentication"],
          summary="Submit Username",
          description="Submit username during user binding - validates uniqueness and stores in session",
)
async def submit_username(req: Request):
    """Submit username during user binding - validates uniqueness and stores in session"""
    body = await req.json()
    username = body.get("username", "").strip()
    
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    
    if len(username) < 3:
        raise HTTPException(status_code=400, detail="Username must be at least 3 characters")
    
    if len(username) > 50:
        raise HTTPException(status_code=400, detail="Username must be less than 50 characters")
    
    # Check for valid characters (alphanumeric, underscore, hyphen)
    if not username.replace("_", "").replace("-", "").isalnum():
        raise HTTPException(status_code=400, detail="Username can only contain letters, numbers, underscores, and hyphens")
    
    # Check if username already exists in users table
    existing_user = await DB.get_user_by_username(username)
    if existing_user:
        raise HTTPException(status_code=409, detail="Username already taken")
    
    # Get or create session
    sid = req.session.get("sid")
    if not sid:
        # Create new session if none exists
        sid = secrets.token_urlsafe(18)
        csrf = secrets.token_urlsafe(18)
        session_nonce = _new_nonce()
        req.session.update({"sid": sid})
        await DB.set_session(sid, {
            "state": "user-binding", 
            "csrf": csrf, 
            "session_nonce": session_nonce
        })
    else:
        # Verify existing session
        session_data = await DB.get_session(sid)
        if not session_data:
            raise HTTPException(status_code=401, detail="Invalid session")
    
    # Create user record in users table
    log.info(f"Creating user with username: {username}, session_id: {sid}")
    user_created = await DB.create_user(username, sid)
    if not user_created:
        raise HTTPException(status_code=500, detail="Failed to create user record")
    
    # Update session state to include username
    log.info(f"Session state before username update: {session_data.get('state')}")
    await DB.update_session(sid, {"username": username})
    log.info(f"User created and session updated successfully for username: {username}, session_id: {sid}")
    
    # Check session state after update
    updated_session = await DB.get_session(sid)
    log.info(f"Session state after username update: {updated_session.get('state')}")
    
    log.info("Username submitted - sid=%s username=%s rid=%s", sid, username, req.state.request_id)
    return JSONResponse({"username": username, "status": "success"})

@app.post("/onboarding/signin",
          tags=["authentication"],
          summary="Sign In User",
          description="Sign in with existing username and link to current session")
async def signin_user(req: Request):
    """Sign in with existing username"""
    body = await req.json()
    username = body.get("username", "").strip()
    
    if not username:
        raise HTTPException(status_code=400, detail="Username is required")
    
    # Check if username exists
    existing_user = await DB.get_user_by_username(username)
    if not existing_user:
        raise HTTPException(status_code=404, detail="Username not found")
    
    # Get or create session
    sid = req.session.get("sid")
    if not sid:
        # Create new session if none exists
        sid = secrets.token_urlsafe(18)
        csrf = secrets.token_urlsafe(18)
        session_nonce = _new_nonce()
        req.session.update({"sid": sid})
        await DB.set_session(sid, {
            "state": "user-binding", 
            "csrf": csrf, 
            "session_nonce": session_nonce
        })
    else:
        # Verify existing session
        session_data = await DB.get_session(sid)
        if not session_data:
            raise HTTPException(status_code=401, detail="Invalid session")
    
    # Check if user is already linked to current session
    if existing_user.get("session_id") == sid:
        log.info("User already linked to current session - sid=%s username=%s rid=%s", sid, username, req.state.request_id)
        return JSONResponse({"username": username, "status": "already_linked"})
    
    # Update user's session_id to link to current session
    await DB.exec(
        "UPDATE users SET session_id = ? WHERE username = ?",
        (sid, username)
    )
    
    # Update session state to include username
    await DB.update_session(sid, {"username": username})
    
    log.info("User signed in - sid=%s username=%s rid=%s", sid, username, req.state.request_id)
    return JSONResponse({"username": username, "status": "success"})

@app.get("/onboarding/current-user",
         tags=["authentication"],
         summary="Get Current User",
         description="Get current user's username and details from session")
async def get_current_user(req: Request):
    """Get current user's username from session"""
    # Require valid session with username and DPoP binding
    username, session_data = await SessionService.require_valid_session(req)
    
    # Get user data from database
    user = await DB.get_user_by_session(req.session.get("sid"))
    
    return JSONResponse({
        "username": user["username"],
        "user_id": user["id"],
        "created_at": user["created_at"]
    })



# ---------------- Post-Authentication Tracking ----------------
# Moved to server/auth_tracking.py to avoid circular imports

# ---------------- DPoP gate for protected APIs (existing) ----------------
def _nonce_fail_response(sid: str, detail: str) -> None:
    n = _new_nonce()
    asyncio.create_task(DB.add_nonce(sid, n, SETTINGS.nonce_ttl))
    raise HTTPException(status_code=401, detail=detail, headers={"DPoP-Nonce": n})

async def require_dpop(req: Request) -> Dict[str, Any]:
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s:
        raise HTTPException(status_code=401, detail="no session")
    
    # Check if session was killed by user
    session_state = s.get("state")
    if session_state == "USER_KILLED":
        log.warning("Session access denied - session was killed by user sid=%s", sid)
        raise HTTPException(status_code=401, detail="session killed by user - please relogin")

    dpop_hdr = req.headers.get("DPoP"); bind_hdr = req.headers.get("DPoP-Bind")
    if not dpop_hdr or not bind_hdr:
        n = _new_nonce(); await DB.add_nonce(sid, n, SETTINGS.nonce_ttl)
        raise HTTPException(status_code=428, detail="dpop required", headers={"DPoP-Nonce": n})

    try:
        bind_payload = SessionService.verify_binding_token(bind_hdr)
    except HTTPException:
        _nonce_fail_response(sid, "bind verify failed")

    if bind_payload.get("sid") != sid:
        _nonce_fail_response(sid, "bind token sid mismatch")

    origin, full_url = canonicalize_origin_and_url(req, SETTINGS.external_origin)
    aud = bind_payload.get("aud")
    if not aud:
        _nonce_fail_response(sid, "missing aud")
    if aud not in SETTINGS.allowed_origins:
        _nonce_fail_response(sid, f"bind token aud not allowed: {aud}")

    try:
        # Use the generic JWS validation helper
        dpop_data = validate_jws_token(dpop_hdr, "dpop+jwt", ["htm", "htu", "iat", "nonce"])
        payload = dpop_data["payload"]
        header = dpop_data["header"]
        jwk = header.get("jwk", {})
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
            _nonce_fail_response(sid, "bad jwk")

        htu = payload.get("htu"); 
        if not htu: _nonce_fail_response(sid, "missing htu")
        canonical_htu = _canonicalize_url_for_validation(htu, SETTINGS.allowed_origins)
        if not canonical_htu:
            _nonce_fail_response(sid, f"htu origin not allowed: {htu}")

        expected_parts = urlsplit(full_url); htu_parts = urlsplit(canonical_htu)
        if expected_parts.path != htu_parts.path:
            _nonce_fail_response(sid, "htu path mismatch")
        if expected_parts.query != htu_parts.query:
            _nonce_fail_response(sid, "htu query mismatch")
        if payload.get("htm","").upper() != req.method.upper():
            _nonce_fail_response(sid, "htm mismatch")
        if abs(now() - int(payload.get("iat",0))) > SETTINGS.skew_sec:
            _nonce_fail_response(sid, "bad iat")

        n = payload.get("nonce")
        if not n or not (await DB.nonce_valid(sid, n)):
            _nonce_fail_response(sid, "bad nonce")

        jti = payload.get("jti")
        if not jti or not (await DB.add_jti(sid, jti, SETTINGS.jti_ttl)):
            _nonce_fail_response(sid, "jti replay")

        def jkt_of(jwk_: Dict[str, Any]) -> str:
            return ec_p256_thumbprint(jwk_)
        
        current_jkt = jkt_of(jwk)
        stored_jkt = (bind_payload.get("cnf") or {}).get("dpop_jkt")
        
        if current_jkt != stored_jkt:
            # Allow DPoP key updates for certain endpoints (key rotation)
            # Update the session with the new DPoP key
            await DB.update_session(sid, {"dpop_jkt": current_jkt})
            log.info("DPoP key updated in session - sid=%s old_jkt=%s new_jkt=%s", 
                    sid, stored_jkt[:8] if stored_jkt else "none", current_jkt[:8])

    except HTTPException:
        raise
    except Exception as e:
        log.exception("dpop verify failed sid=%s rid=%s", sid, req.state.request_id)
        _nonce_fail_response(sid, f"dpop verify failed: {e}")

    next_nonce = _new_nonce()
    await DB.add_nonce(sid, next_nonce, SETTINGS.nonce_ttl)
    req.state.next_nonce = next_nonce
    return {"sid": sid, "next_nonce": next_nonce}

# ---- Passkey repo adapter / routers (existing) ----
class _PasskeyRepoAdapter:
    def __init__(self, db): self.db = db
    async def get_for_principal(self, principal: str):
        return await self.db.pk_get_for_principal(principal)
    async def upsert(self, principal: str, rec: Dict[str, Any]):
        return await self.db.pk_upsert(principal, rec)
    async def find_by_cred_id(self, principal: str, cred_id: str):
        return await self.db.pk_find_by_cred_id(principal, cred_id)
    async def get_by_cred_id(self, cred_id: str):
        return await self.db.pk_get_by_cred_id(cred_id)
    async def update_sign_count(self, cred_id: str, new_count: int):
        return await self.db.pk_update_sign_count(cred_id, new_count)
    async def remove(self, principal: str, cred_id: str):
        return await self.db.pk_remove(principal, cred_id)

PASSKEY_REPO = _PasskeyRepoAdapter(DB)

app.include_router(get_passkeys_router(
    DB,
    require_dpop,
    canonicalize_origin_and_url,
    now,
    passkey_repo=PASSKEY_REPO,
))

app.include_router(get_linking_router(
    DB, require_dpop, canonicalize_origin_and_url, now,
))



@app.get("/debug/test-mobile-fingerprint")
async def test_mobile_fingerprint():
    """Test endpoint to verify mobile fingerprint collection"""
    try:
        # Create a test session
        test_sid = secrets.token_urlsafe(18)
        test_fingerprint = {
            "userAgent": "Test Mobile Agent",
            "deviceType": "mobile",
            "screenResolution": "375x667",
            "timestamp": "2024-01-01T00:00:00Z"
        }
        
        await DB.set_session(test_sid, {
            "state": "test",
            "fingerprint": test_fingerprint,
            "device_type": "mobile"
        })
        
        # Verify it was stored
        stored = await DB.get_session(test_sid)
        if stored and stored.get("device_type") == "mobile":
            return JSONResponse({
                "success": True,
                "message": "Mobile fingerprint test successful",
                "test_sid": test_sid,
                "stored_data": stored
            })
        else:
            return JSONResponse({
                "success": False,
                "message": "Mobile fingerprint test failed",
                "stored_data": stored
            })
    except Exception as e:
        log.exception("Mobile fingerprint test failed")
        return JSONResponse({
            "success": False,
            "message": f"Test failed: {e}"
        })

@app.get("/debug/sessions")
async def debug_sessions():
    """Debug endpoint to see all sessions in database"""
    try:
        # Get all sessions from database
        sessions = []
        async with DB._conn.execute("SELECT sid, data, updated_at FROM sessions ORDER BY updated_at DESC LIMIT 10") as cursor:
            async for row in cursor:
                try:
                    data = json.loads(row["data"])
                    sessions.append({
                        "sid": row["sid"],
                        "device_type": data.get("device_type", "unknown"),
                        "has_fingerprint": "fingerprint" in data,
                        "fingerprint_keys": list(data.get("fingerprint", {}).keys()) if "fingerprint" in data else [],
                        "updated_at": row["updated_at"]
                    })
                except Exception as e:
                    sessions.append({
                        "sid": row["sid"],
                        "error": f"Failed to parse data: {e}",
                        "updated_at": row["updated_at"]
                    })
        
        return JSONResponse({"sessions": sessions})
    except Exception as e:
        log.exception("Failed to get debug sessions")
        raise HTTPException(500, f"Failed to get debug sessions: {e}")

@app.get("/debug/usernames")
async def debug_usernames():
    """Debug endpoint to list all usernames from users table"""
    try:
        # Get all users from users table
        rows = await DB.fetchall("SELECT id, username, session_id, created_at FROM users ORDER BY created_at DESC")
        
        usernames = []
        for row in rows:
            # Get session data for additional context
            session_data = await DB.get_session(row["session_id"])
            state = session_data.get("state", "Unknown") if session_data else "Session not found"
            
            usernames.append({
                "id": row["id"],
                "username": row["username"],
                "session_id": row["session_id"],
                "state": state,
                "created_at": row["created_at"]
            })
        
        return JSONResponse({
            "total_usernames": len(usernames),
            "usernames": usernames
        })
    except Exception as e:
        log.exception("Failed to get debug usernames")
        raise HTTPException(500, f"Failed to get debug usernames: {e}")

@app.get("/session/fingerprint")
async def get_fingerprint(req: Request):
    """Get stored fingerprint data for current session"""
    sid = req.session.get("sid")
    if not sid:
        raise HTTPException(404, "No session found")
    
    log.info("GET /session/fingerprint called with sid=%s", sid)
    
    try:
        session_data = await DB.get_session(sid)
        if not session_data:
            raise HTTPException(404, "Session not found")
            
        log.info("Full session data sid=%s keys=%s", sid, list(session_data.keys()))
        fingerprint_data = session_data.get("fingerprint", {})
        device_type = session_data.get("device_type", "unknown")
        log.info("Retrieved fingerprint data sid=%s device_type=%s", sid, device_type)
        return JSONResponse({
            "fingerprint": fingerprint_data,
            "device_type": device_type
        })
    except HTTPException:
        raise
    except Exception as e:
        log.exception("Failed to get fingerprint sid=%s", sid)
        raise HTTPException(500, f"Failed to get fingerprint: {e}")

@app.get("/session/fingerprint-data")
async def get_fingerprint_data(req: Request):
    """Get both desktop and mobile fingerprint data for the current session"""
    sid = req.session.get("sid")
    if not sid:
        raise HTTPException(401, "No session found")
    
    log.info("GET /session/fingerprint-data called with sid=%s", sid)
    
    try:
        # Get current session data
        current_session = await DB.get_session(sid)
        if not current_session:
            raise HTTPException(404, "Session not found")
        
        log.info("Current session found sid=%s keys=%s", sid, list(current_session.keys()))
        current_fingerprint = current_session.get("fingerprint", {})
        current_device_type = current_session.get("device_type", "unknown")
        
        log.info("Current session device_type=%s", current_device_type)
        
        # Import linking module to access link store
        from server.linking import _get_link_by_desktop_sid, _get_link_by_mobile_sid
        
        # Determine if current session is desktop or mobile and find the linked session
        linked_sid = None
        linked_fingerprint = {}
        linked_device_type = "unknown"
        
        if current_device_type == "desktop":
            # Current session is desktop, look for linked mobile session
            log.info("Current session is desktop, looking for linked mobile session")
            link_data = _get_link_by_desktop_sid(req.session.get("sid"))
            if link_data and link_data.get("mobile_sid"):
                linked_sid = link_data["mobile_sid"]
                log.info("Found linked mobile session mobile_sid=%s for desktop_sid=%s", linked_sid, req.session.get("sid"))
                
                # Get mobile session data
                linked_session = await DB.get_session(linked_sid)
                if linked_session:
                    log.info("Linked mobile session found mobile_sid=%s keys=%s", linked_sid, list(linked_session.keys()))
                    linked_fingerprint = linked_session.get("fingerprint", {})
                    linked_device_type = linked_session.get("device_type", "unknown")
                    log.info("Retrieved linked mobile fingerprint data mobile_sid=%s device_type=%s fingerprint_keys=%s", 
                            linked_sid, linked_device_type, list(linked_fingerprint.keys()))
                else:
                    log.warning("Linked mobile session not found mobile_sid=%s", linked_sid)
            else:
                log.info("No linked mobile session found for desktop_sid=%s", req.session.get("sid"))
                
        elif current_device_type == "mobile":
            # Current session is mobile, look for linked desktop session
            log.info("Current session is mobile, looking for linked desktop session")
            link_data = _get_link_by_mobile_sid(req.session.get("sid"))
            if link_data and link_data.get("desktop_sid"):
                linked_sid = link_data["desktop_sid"]
                log.info("Found linked desktop session desktop_sid=%s for mobile_sid=%s", linked_sid, req.session.get("sid"))
                
                # Get desktop session data
                linked_session = await DB.get_session(linked_sid)
                if linked_session:
                    log.info("Linked desktop session found desktop_sid=%s keys=%s", linked_sid, list(linked_session.keys()))
                    linked_fingerprint = linked_session.get("fingerprint", {})
                    linked_device_type = linked_session.get("device_type", "unknown")
                    log.info("Retrieved linked desktop fingerprint data desktop_sid=%s device_type=%s fingerprint_keys=%s", 
                            linked_sid, linked_device_type, list(linked_fingerprint.keys()))
                else:
                    log.warning("Linked desktop session not found desktop_sid=%s", linked_sid)
            else:
                log.info("No linked desktop session found for mobile_sid=%s", req.session.get("sid"))
        else:
            log.warning("Unknown device type for session sid=%s: %s", req.session.get("sid"), current_device_type)
        
        # Return data with appropriate labels based on current session type
        if current_device_type == "desktop":
            response_data = {
                "desktop": {
                    "fingerprint": current_fingerprint,
                    "device_type": current_device_type
                },
                "mobile": {
                    "fingerprint": linked_fingerprint,
                    "device_type": linked_device_type,
                    "linked": linked_sid is not None
                }
            }
            log.info("Returning desktop session data - desktop fingerprint keys: %s, mobile fingerprint keys: %s", 
                    list(current_fingerprint.keys()), list(linked_fingerprint.keys()))
        else:  # mobile or unknown
            response_data = {
                "desktop": {
                    "fingerprint": linked_fingerprint,
                    "device_type": linked_device_type,
                    "linked": linked_sid is not None
                },
                "mobile": {
                    "fingerprint": current_fingerprint,
                    "device_type": current_device_type
                }
            }
            log.info("Returning mobile session data - mobile fingerprint keys: %s, desktop fingerprint keys: %s", 
                    list(current_fingerprint.keys()), list(linked_fingerprint.keys()))
        
        log.info("Final response data structure: %s", response_data)
        return JSONResponse(response_data)
        
    except Exception as e:
        log.exception("Failed to get fingerprint data sid=%s username=%s", req.session.get("sid"), username)
        raise HTTPException(500, f"Failed to get fingerprint data: {e}")

# ---------------- Demo API ----------------
@app.post("/api/echo",
          tags=["demo"],
          summary="Echo API Test",
          description="Test endpoint that requires valid DPoP authentication - echoes back the request body",
)
async def api_echo(req: Request, ctx=Depends(require_dpop)):
    # Test endpoint - requires valid session and DPoP binding, but not username
    username, session_data = await SessionService.require_valid_session(req, require_username=False)
    
    body = await req.json()
    headers = {"DPoP-Nonce": ctx["next_nonce"]}
    log.info("api_echo ok sid=%s username=%s rid=%s", ctx["sid"], username, req.state.request_id)
    return JSONResponse({"ok": True, "echo": body, "ts": now()}, headers=headers)

# ---------------- Testing (kept) ----------------
_test_link_storage = {}

@app.get("/reg-link/{link_id}")
async def reg_link(link_id: str):
    try:
        _test_link_storage[link_id] = str(time.time())
        html = f"""<!doctype html><html><body><h1>Registered</h1><p>{link_id}</p></body></html>"""
        return HTMLResponse(html)
    except Exception as e:
        raise HTTPException(500, f"reg-link failed: {e}")

@app.get("/link-verify/{link_id}")
async def link_verify(link_id: str):
    try:
        found = link_id in _test_link_storage
        return {"ok": True, "link_id": link_id, "found": found}
    except Exception as e:
        raise HTTPException(500, f"link-verify failed: {e}")

@app.post("/_admin/clear-test-links")
async def clear_test_links():
    try:
        count = len(_test_link_storage); _test_link_storage.clear()
        return {"ok": True, "cleared_count": count}
    except Exception as e:
        raise HTTPException(500, f"clear-test-links failed: {e}")

@app.post("/_admin/flush",
          tags=["admin"],
          summary="Admin Flush User Data",
          description="Administrative endpoint to completely flush all user data including face embeddings, passkeys, and session data")
async def admin_flush(req: Request):
    # Get current session ID
    sid = req.session.get("sid")
    log.info(f"admin_flush: request session sid={sid}")
    
    if not sid:
        raise HTTPException(401, "No active session to flush")
    
    # Get session data to identify user
    session_data = await DB.get_session(sid)
    log.info(f"admin_flush: session_data found={bool(session_data)}, keys={list(session_data.keys()) if session_data else 'None'}")
    
    if not session_data:
        raise HTTPException(404, "Session not found")
    
    username = None
    bik_jkt = session_data.get("bik_jkt")
    
    # Try to get username from session or users table
    try:
        user_row = await DB.fetchone("SELECT username FROM users WHERE session_id = ?", (sid,))
        log.info(f"admin_flush: user_row query result={user_row}")
        if user_row:
            username = user_row["username"]
    except Exception as e:
        log.error(f"admin_flush: error getting username: {e}")
    
    log.info(f"admin_flush: clearing data for sid={sid}, username={username}, bik_jkt={bik_jkt[:8] if bik_jkt else 'None'}")
    
    # Clear user record FIRST (before session) to respect foreign key constraints
    if username:
        log.info(f"admin_flush: deleting user record for username={username}")
        result = await DB.exec("DELETE FROM users WHERE username = ?", (username,))
        log.info(f"admin_flush: user deletion result={result}")
        
        # Clear face embeddings for this user
        log.info(f"admin_flush: deleting face embeddings for username={username}")
        face_result = await DB.delete_face_embeddings_for_user(username)
        log.info(f"admin_flush: face embeddings deletion result={face_result}")
        
        log.info(f"admin_flush: cleared user data for username={username}")
    else:
        log.warning(f"admin_flush: no username found for sid={sid}, skipping user deletion")
    
    # Clear nonces and JTIs for this session
    await DB.exec("DELETE FROM nonces WHERE sid = ?", (sid,))
    await DB.exec("DELETE FROM jtis WHERE sid = ?", (sid,))
    
    # Clear current session data LAST (after user record is deleted)
    await DB.delete_session(sid)
    
    # Clear passkeys for this BIK if exists
    if bik_jkt:
        await DB.exec("DELETE FROM passkeys WHERE principal = ?", (bik_jkt,))
        log.info(f"admin_flush: cleared passkeys for bik_jkt={bik_jkt[:8]}")
    
    # Clear links owned by this session
    await DB.exec("DELETE FROM links WHERE owner_sid = ?", (sid,))
    
    # Clear in-memory link storage for this session
    from server.linking import _LINKS, _LINKS_LOCK, _WATCHERS
    with _LINKS_LOCK:
        # Remove links owned by this session
        links_to_remove = [link_id for link_id, link_data in _LINKS.items() if link_data.get("owner_sid") == sid]
        for link_id in links_to_remove:
            _LINKS.pop(link_id, None)
            _WATCHERS.pop(link_id, None)
        log.info(f"admin_flush: cleared {len(links_to_remove)} in-memory links")
    
    # Clear test link storage for this session
    global _test_link_storage
    test_links_to_remove = [link_id for link_id, link_data in _test_link_storage.items() if link_data.get("owner_sid") == sid]
    for link_id in test_links_to_remove:
        _test_link_storage.pop(link_id, None)
    log.info(f"admin_flush: cleared {len(test_links_to_remove)} test links")
    
    log.warning(f"admin_flush: cleared data for current user (sid={sid}, username={username})")
    
    # Return response that tells client to clear session cookie
    response = JSONResponse({"ok": True, "message": f"User data cleared for {username or 'current session'}. Please reload page for new session."})
    
    # Clear the session cookie on the server side
    response.delete_cookie(SETTINGS.session_cookie_name, path="/")
    
    return response

@app.post("/logout")
async def logout_user(req: Request):
    """Logout user - clear session cookie but preserve all user data"""
    try:
        sid = req.session.get("sid")
        if not sid:
            return JSONResponse({"ok": True, "message": "No active session to logout"})
        
        # Mark session as logged out but preserve all data
        await DB.update_session(sid, {"state": "logged_out", "logout_time": now()})
        
        # Clear session-related temporary data (nonces, jtis) but keep session record
        await DB.exec("DELETE FROM nonces WHERE sid = ?", (sid,))
        await DB.exec("DELETE FROM jtis WHERE sid = ?", (sid,))
        
        log.info(f"User logged out - session marked as logged_out for sid={sid} (all user data preserved)")
        
        # Return response that tells client to clear session cookie
        response = JSONResponse({"ok": True, "message": "Logged out successfully"})
        
        # Clear the session cookie on the server side
        response.delete_cookie(SETTINGS.session_cookie_name, path="/")
        
        return response
        
    except Exception as e:
        log.exception("Logout failed")
        raise HTTPException(500, f"Logout failed: {e}")

@app.post("/session/clear")
async def clear_session_only(req: Request):
    """Route handler for clearing session"""
    return await SessionService.clear_session_only(req)

@app.post("/session/update")
async def update_session(req: Request):
    """Route handler for updating session"""
    return await SessionService.update_session(req)

@app.post("/session/mark-authenticated")
async def mark_user_authenticated(req: Request):
    """Route handler for marking user as authenticated"""
    return await SessionService.mark_user_authenticated(req)

@app.post("/session/update-auth")
async def update_session_auth(req: Request):
    """Route handler for updating session authentication data"""
    return await SessionService.update_session_auth(req)

# ======================================================================
# =============== NEW: verify subdomain desktop endpoints ===============
# ======================================================================

def _require_host(request: Request, host: str):
    h = (request.headers.get("x-forwarded-host") or request.url.hostname or "").lower()
    if h != host:
        raise HTTPException(status_code=400, detail=f"wrong host: expected {host}")

def _require_top_level_post(request: Request):
    site = (request.headers.get("sec-fetch-site") or "").lower()
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    if site not in ("same-origin", "none"):
        raise HTTPException(403, "cross-site blocked")
    if dest not in ("document", "empty"):
        raise HTTPException(400, "bad destination")

def _parse_b64u(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)

def _parse_compact_jwt(compact: str) -> Tuple[Dict[str, Any], Dict[str, Any], bytes]:
    try:
        h_b64, p_b64, s_b64 = compact.split(".")
        header = json.loads(_parse_b64u(h_b64))
        payload = json.loads(_parse_b64u(p_b64))
        sig = _parse_b64u(s_b64)
        return header, payload, sig
    except Exception:
        raise HTTPException(400, "bad_dpop_format")


# ---- POST /device/redeem (accept BC -> issue short-lived DPoP nonce) ----
@app.post("/device/redeem",
          tags=["device-linking"],
          summary="Redeem Device Code",
          description="Redeem a device linking code (BC) to establish connection between devices")
async def verify_device_redeem(req: Request):
    _require_top_level_post(req)

    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s:
        raise HTTPException(401, "no session")

    try:
        body = await req.json()
        bc = (body.get("bc") or "").upper().replace("-", "").strip()
        if not (6 <= len(bc) <= 16):
            raise HTTPException(400, "invalid_or_expired_code")
        
        # Validate BC against link storage
        from server.linking import _LINKS, _LINKS_LOCK
        bc_valid = False
        link_id = None
        
        with _LINKS_LOCK:
            for lid, rec in _LINKS.items():
                if rec.get("bc") == bc:
                    # Check if BC is still valid (not expired)
                    if now() <= rec.get("bc_exp", 0):
                        bc_valid = True
                        link_id = lid
                        # Mark BC as consumed
                        rec["bc_consumed"] = True
                        log.info("BC consumed - lid=%s bc=%s", lid, bc)
                        
                        # Notify SSE watchers that BC was consumed
                        from server.linking import _notify_watchers, _public_view
                        # Compute the status the same way /link/state does
                        computed_status = "confirmed" if rec.get("bc_consumed") else rec["status"]
                        notification_data = _public_view(rec)
                        notification_data["status"] = computed_status
                        _notify_watchers(lid, {"type": "status", **notification_data})
                        break
                    else:
                        log.warning("BC expired - lid=%s bc=%s", lid, bc)
        
        if not bc_valid:
            raise HTTPException(400, "invalid_or_expired_code")

        # Mark link consumed if you have server-side state; then mint nonce
        next_nonce = _new_nonce()
        await DB.add_nonce(sid, next_nonce, SETTINGS.nonce_ttl)
        log.info("device_redeem ok sid=%s rid=%s link_id=%s", sid, req.state.request_id, link_id)
        return JSONResponse({"dpop_nonce": next_nonce, "exp": now() + SETTINGS.nonce_ttl, "link_id": link_id})
    except HTTPException:
        raise
    except Exception as e:
        log.exception("device_redeem failed sid=%s rid=%s", sid, req.state.request_id)
        raise HTTPException(400, f"redeem failed: {e}")

# ---- POST /link/finalize (verify raw DPoP; bind session to jkt) ----
@app.post("/link/finalize",
          tags=["device-linking"],
          summary="Finalize Device Link",
          description="Finalize device linking by verifying DPoP proof and binding the session")
async def verify_link_finalize(req: Request, resp: Response):

    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s:
        raise HTTPException(401, "no session")

    dpop = req.headers.get("DPoP")
    if not dpop:
        # return nonce challenge if missing
        n = _new_nonce(); await DB.add_nonce(sid, n, SETTINGS.nonce_ttl)
        raise HTTPException(428, "dpop required", headers={"DPoP-Nonce": n})

    try:
        # Use the generic JWS validation helper - allow both types
        try:
            dpop_data = validate_jws_token(dpop, "dpop+jwt", ["htm", "htu", "iat"])
        except ValueError:
            # Try alternative type
            dpop_data = validate_jws_token(dpop, "DPoP", ["htm", "htu", "iat"])
        
        header = dpop_data["header"]
        payload = dpop_data["payload"]
        jwk = header.get("jwk", {})

        # Validate claims
        origin, full_url = canonicalize_origin_and_url(req, SETTINGS.external_origin)
        expected_url = full_url.split("?")[0]
        if payload.get("htu") != expected_url:
            raise HTTPException(400, "htu mismatch")
        if payload.get("htm","").upper() != req.method.upper():
            raise HTTPException(400, "htm mismatch")
        if abs(now() - int(payload.get("iat",0))) > SETTINGS.skew_sec:
            raise HTTPException(400, "iat skew")
        n = payload.get("nonce")
        if not n or not (await DB.nonce_valid(sid, n)):
            raise HTTPException(401, "nonce missing/expired")
        jti = payload.get("jti")
        if not jti or not (await DB.add_jti(sid, jti, SETTINGS.jti_ttl)):
            raise HTTPException(401, "jti replay")

        # Compute jkt and bind to session
        dpop_jkt = ec_p256_thumbprint(jwk)
        
        # Always allow new DPoP key binding for /link/finalize endpoint
        # This allows verify page to bind its own DPoP key
        await DB.update_session(sid, {"dpop_jkt": dpop_jkt, "state": "active"})
        if s.get("dpop_jkt") and s.get("dpop_jkt") != dpop_jkt:
            log.info("DPoP key updated - sid=%s old_jkt=%s new_jkt=%s", 
                    sid, s.get("dpop_jkt", "")[:8], dpop_jkt[:8])

        # Next nonce for caller
        next_nonce = _new_nonce()
        await DB.add_nonce(sid, next_nonce, SETTINGS.nonce_ttl)
        resp.headers["DPoP-Nonce"] = next_nonce
        log.info("link_finalize ok sid=%s jkt=%s rid=%s", sid, dpop_jkt[:8], req.state.request_id)
        return JSONResponse({"ok": True, "session_state": "active", "jkt": dpop_jkt})
    except HTTPException:
        raise
    except Exception as e:
        log.exception("link_finalize failed sid=%s rid=%s", sid, req.state.request_id)
        raise HTTPException(400, f"finalize failed: {e}")


# Face processing endpoints
@app.post("/face/register",
          tags=["face-auth"],
          summary="Register Face",
          description="Register a face by uploading a video and extracting facial embeddings for biometric authentication",
)
async def register_face(req: Request):
    """Register a face by uploading a video and extracting embeddings"""
    try:
        # Require valid session with username and DPoP binding
        username, session_data = await SessionService.require_valid_session(req)
        
        # Get uploaded file
        form = await req.form()
        video_file = form.get("video")
        if not video_file:
            raise HTTPException(400, "No video file provided")
        
        # Save video temporarily
        import tempfile
        import os
        with tempfile.NamedTemporaryFile(delete=False, suffix=".webm") as tmp_file:
            content = await video_file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        try:
            # Process video and extract embeddings with PAD analysis
            log.info(f"Processing video file: {tmp_path}, size: {len(content)} bytes")
            
            # Extract frames first
            frames = face_service.extract_frames_from_video(tmp_path)
            log.info(f"Extracted {len(frames)} frames from video")
            
            if not frames:
                raise HTTPException(400, "No frames extracted from video")
            
            # Extract embeddings without PAD analysis (registration only)
            embeddings = face_service.extract_face_embeddings(frames)
            
            log.info(f"Extracted {len(embeddings)} embeddings for registration")
            
            if not embeddings:
                raise HTTPException(400, "No faces detected in video")
            
            # Store embeddings in database
            embedding_ids = []
            for i, embedding in enumerate(embeddings):
                embedding_bytes = embedding.tobytes()
                metadata = {
                    "embedding_index": i,
                    "video_size": len(content),
                    "embedding_shape": embedding.shape
                }
                embedding_id = await DB.store_face_embedding(
                    user_id=username,
                    embedding=embedding_bytes,
                    video_path=tmp_path,
                    frame_count=len(embeddings),
                    metadata=metadata
                )
                embedding_ids.append(embedding_id)
            
            log.info(f"Registered {len(embeddings)} face embeddings for user {username}")
            return JSONResponse({
                "success": True,
                "embeddings_count": len(embeddings),
                "embedding_ids": embedding_ids
            })
            
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    except HTTPException as he:
        log.error(f"HTTP Exception in face registration: {he.detail}")
        raise
    except Exception as e:
        log.exception("face registration failed")
        log.error(f"Exception type: {type(e).__name__}")
        log.error(f"Exception message: {str(e)}")
        raise HTTPException(500, f"Face registration failed: {e}")


@app.post("/face/verify",
          tags=["face-auth"],
          summary="Verify Face",
          description="Verify a face against stored embeddings with anti-spoofing protection using Presentation Attack Detection (PAD)",
)
async def verify_face(req: Request):
    """Verify a face against stored embeddings"""
    try:
        # Require valid session with username and DPoP binding
        username, session_data = await SessionService.require_valid_session(req)
        
        # Get uploaded file
        form = await req.form()
        video_file = form.get("video")
        if not video_file:
            raise HTTPException(400, "No video file provided")
        
        # Save video temporarily
        import tempfile
        import os
        import numpy as np
        
        with tempfile.NamedTemporaryFile(delete=False, suffix=".webm") as tmp_file:
            content = await video_file.read()
            tmp_file.write(content)
            tmp_path = tmp_file.name
        
        try:
            # Process video and extract embeddings with PAD analysis
            frames = face_service.extract_frames_from_video(tmp_path)
            log.info(f"Extracted {len(frames)} frames from verification video")
            
            if not frames:
                raise HTTPException(400, "No frames extracted from video")
            
            # Process with PAD analysis (conservative settings)
            result = await face_service.extract_face_embeddings_with_pad(frames)
            query_embeddings = result["embeddings"]
            pad_results = result["pad_results"]
            
            log.info(f"Extracted {len(query_embeddings)} embeddings for verification")
            log.info(f"PAD analysis: attack_detected={pad_results['attack_detected']}, confidence={pad_results['confidence']:.3f}")
            
            if not query_embeddings:
                raise HTTPException(400, "No faces detected in video")
            
            # Check PAD results using advanced techniques
            if not pad_results.get("live_final", True):
                log.warning(f"PAD attack detected during verification for user {username}: {pad_results}")
                return JSONResponse({
                    "verified": False,
                    "message": "Security check failed: Potential spoof attack detected. Please ensure you are using a live face, not a photo or video.",
                    "pad_results": {
                        "rppg_hr_bpm": pad_results.get("rppg_hr_bpm"),
                        "rppg_snr_db": pad_results.get("rppg_snr_db"),
                        "rppg_live_prob": pad_results.get("rppg_live_prob"),
                        "display_flicker_score": pad_results.get("display_flicker_score"),
                        "planarity_score": pad_results.get("planarity_score"),
                        "live_final": pad_results.get("live_final")
                    }
                })
            
            # Get stored embeddings for this user
            stored_embeddings = await DB.get_face_embeddings_for_user(username)
            
            if not stored_embeddings:
                return JSONResponse({
                    "verified": False,
                    "message": "No registered faces found"
                })
            
            # Convert stored embeddings back to numpy arrays
            stored_np_embeddings = []
            for stored in stored_embeddings:
                embedding_array = np.frombuffer(stored["embedding"], dtype=np.float32)
                stored_np_embeddings.append(embedding_array)
            
            # Find best match
            best_match = None
            best_similarity = 0.0
            threshold = 0.5  # Reduced threshold to reduce false negatives on real attempts
            
            log.info(f"Comparing {len(query_embeddings)} query embeddings against {len(stored_np_embeddings)} stored embeddings")
            
            for i, query_embedding in enumerate(query_embeddings):
                match_idx, similarity = face_service.find_best_match(
                    query_embedding, stored_np_embeddings, threshold
                )
                log.info(f"Query embedding {i}: match_idx={match_idx}, similarity={similarity:.3f}")
                log.info(f"Debug: similarity={similarity:.3f}, best_similarity={best_similarity:.3f}, condition={similarity > best_similarity}")
                if similarity > best_similarity:
                    best_similarity = similarity
                    best_match = stored_embeddings[match_idx] if match_idx is not None else None
                    log.info(f"Debug: Updated best_match={best_match is not None}, best_similarity={best_similarity:.3f}")
            
            verified = best_match is not None and best_similarity >= threshold
            
            log.info(f"Face verification for user {username}: verified={verified}, similarity={best_similarity:.3f}, threshold={threshold}")
            log.info(f"Debug: best_match={best_match is not None}, best_similarity={best_similarity:.3f}, threshold={threshold}")
            
            # Mark user as authenticated if verification successful
            if verified:
                sid = req.session.get("sid")
                from server.auth_tracking import mark_user_authenticated
                await mark_user_authenticated(sid, username, "face verify")
            
            return JSONResponse({
                "verified": bool(verified),
                "similarity": float(best_similarity),
                "threshold": float(threshold),
                "matched_user": best_match["user_id"] if best_match else None,
                "message": "Face verified successfully" if verified else "Face verification failed",
                "pad_results": {
                    "rppg_hr_bpm": pad_results.get("rppg_hr_bpm"),
                    "rppg_snr_db": pad_results.get("rppg_snr_db"),
                    "rppg_live_prob": pad_results.get("rppg_live_prob"),
                    "display_flicker_score": pad_results.get("display_flicker_score"),
                    "planarity_score": pad_results.get("planarity_score"),
                    "live_final": pad_results.get("live_final")
                }
            })
            
        finally:
            # Clean up temporary file
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
                
    except HTTPException:
        raise
    except Exception as e:
        log.exception("face verification failed")
        raise HTTPException(500, f"Face verification failed: {e}")


@app.get("/face/health")
async def face_health_check():
    """Health check for face processing service"""
    try:
        # Try to initialize the face service
        face_service._ensure_initialized()
        return JSONResponse({
            "status": "healthy",
            "initialized": face_service._initialized,
            "message": "Face processing service is ready"
        })
    except Exception as e:
        return JSONResponse({
            "status": "unhealthy",
            "initialized": face_service._initialized,
            "error": str(e),
            "message": "Face processing service is not ready"
        }, status_code=503)

@app.get("/face/status")
async def get_face_status(req: Request):
    """Get face registration status for current user"""
    try:
        sid = req.session.get("sid")
        if not sid:
            raise HTTPException(401, "No active session")
        
        embeddings = await DB.get_face_embeddings_for_user(sid)
        
        return JSONResponse({
            "registered": len(embeddings) > 0,
            "embeddings_count": len(embeddings),
            "embeddings": [
                {
                    "id": emb["id"],
                    "created_at": emb["created_at"],
                    "frame_count": emb["frame_count"],
                    "metadata": emb["metadata"]
                }
                for emb in embeddings
            ]
        })
        
    except HTTPException:
        raise
    except Exception as e:
        log.exception("face status check failed")
        raise HTTPException(500, f"Face status check failed: {e}")


@app.delete("/face/delete")
async def delete_face_data(req: Request):
    """Delete all face data for current user"""
    try:
        sid = req.session.get("sid")
        if not sid:
            raise HTTPException(401, "No active session")
        
        await DB.delete_face_embeddings_for_user(sid)
        
        log.info(f"Deleted all face data for user {sid}")
        return JSONResponse({"success": True, "message": "Face data deleted successfully"})
        
    except HTTPException:
        raise
    except Exception as e:
        log.exception("face deletion failed")
        raise HTTPException(500, f"Face deletion failed: {e}")
