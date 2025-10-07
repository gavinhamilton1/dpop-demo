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
from server.utils.geolocation import GeolocationService
from server.services.passkeys import get_router as get_passkeys_router
from server.services.linking import get_router as get_linking_router
from server.utils.helpers import ec_p256_thumbprint, now, b64u, canonicalize_origin_and_url
from typing import Tuple, Optional, Dict
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


def _require_top_level_post(request: Request):
    site = (request.headers.get("sec-fetch-site") or "").lower()
    dest = (request.headers.get("sec-fetch-dest") or "").lower()
    if site not in ("same-origin", "none"):
        raise HTTPException(403, "cross-site blocked")
    if dest not in ("document", "empty"):
        raise HTTPException(400, "bad destination")


# ---- POST /device/redeem (accept BC -> issue short-lived DPoP nonce) ----
@app.post("/device/redeem",
          tags=["device-linking"],
          summary="Redeem Device Code",
          description="Redeem a device linking code (BC) to establish connection between devices")
async def verify_device_redeem(req: Request):
    _require_top_level_post(req)

    # Require DPoP proof for this protected endpoint
    try:
        auth_data = await SessionService.require_dpop_proof(req)
        dpop_payload = auth_data["dpop_payload"]
        session_data = auth_data["session_data"]
        session_id = auth_data["session_id"]
        log.info("DPoP validation successful for device redeem - Session ID: %s", session_id)
    except HTTPException as e:
        log.warning("DPoP validation failed for device redeem: %s", e.detail)
        raise e

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

    # Require DPoP proof for this protected endpoint
    try:
        auth_data = await SessionService.require_dpop_proof(req)
        dpop_payload = auth_data["dpop_payload"]
        session_data = auth_data["session_data"]
        session_id = auth_data["session_id"]
        log.info("DPoP validation successful for link finalize - Session ID: %s", session_id)
    except HTTPException as e:
        log.warning("DPoP validation failed for link finalize: %s", e.detail)
        # For this endpoint, we might want to return a nonce challenge instead of failing
        if e.status_code == 401 and "Missing DPoP header" in e.detail:
            sid = req.session.get("sid")
            if sid:
                n = _new_nonce(); await DB.add_nonce(sid, n, SETTINGS.nonce_ttl)
                raise HTTPException(428, "dpop required", headers={"DPoP-Nonce": n})
        raise e

    try:
        # DPoP validation is now handled by require_dpop_proof above
        # Extract the DPoP data from the validated payload
        n = dpop_payload.get("nonce")
        if not n or not (await DB.nonce_valid(session_id, n)):
            raise HTTPException(401, "nonce missing/expired")
        jti = dpop_payload.get("jti")
        if not jti or not (await DB.add_jti(session_id, jti, SETTINGS.jti_ttl)):
            raise HTTPException(401, "jti replay")

        # Get the JWK from the DPoP header (we need to extract it from the original header)
        dpop_header = req.headers.get("dpop")
        dpop_data = validate_jws_token(dpop_header, "dpop+jwt", ["htm", "htu", "iat", "jti", "nonce"])
        jwk = dpop_data["header"].get("jwk", {})

        # Compute jkt and bind to session
        dpop_jkt = ec_p256_thumbprint(jwk)
        
        # Always allow new DPoP key binding for /link/finalize endpoint
        # This allows verify page to bind its own DPoP key
        await DB.update_session(session_id, {"dpop_jkt": dpop_jkt, "state": "active"})
        if session_data.get("dpop_jkt") and session_data.get("dpop_jkt") != dpop_jkt:
            log.info("DPoP key updated - sid=%s old_jkt=%s new_jkt=%s", 
                    session_id, session_data.get("dpop_jkt", "")[:8], dpop_jkt[:8])

        # Next nonce for caller
        next_nonce = _new_nonce()
        await DB.add_nonce(session_id, next_nonce, SETTINGS.nonce_ttl)
        resp.headers["DPoP-Nonce"] = next_nonce
        log.info("link_finalize ok sid=%s jkt=%s rid=%s", session_id, dpop_jkt[:8], req.state.request_id)
        return JSONResponse({"ok": True, "session_state": "active", "jkt": dpop_jkt})
    except HTTPException:
        raise
    except Exception as e:
        log.exception("link_finalize failed sid=%s rid=%s", session_id, req.state.request_id)
        raise HTTPException(400, f"finalize failed: {e}")


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


