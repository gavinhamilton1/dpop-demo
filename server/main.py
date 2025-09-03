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

from jose import jws as jose_jws
from jose.utils import base64url_decode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec

from server.config import load_settings
from server.db import DB  # singleton DB instance
from server.passkeys import get_router as get_passkeys_router
from server.linking import get_router as get_linking_router
from server.utils import ec_p256_thumbprint, now, b64u

# ---------------- Config ----------------
SETTINGS = load_settings()

LOG_LEVEL = SETTINGS.log_level
SESSION_SAMESITE = SETTINGS.session_samesite
SESSION_COOKIE_NAME = SETTINGS.session_cookie_name
HTTPS_ONLY = SETTINGS.https_only
SKEW_SEC = SETTINGS.skew_sec
NONCE_TTL = SETTINGS.nonce_ttl
JTI_TTL = SETTINGS.jti_ttl
BIND_TTL = SETTINGS.bind_ttl
EXTERNAL_ORIGIN = SETTINGS.external_origin

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s stronghold %(message)s")
log = logging.getLogger("stronghold")
log.info("Loaded config from: %s", SETTINGS.cfg_file_used or "<defaults>")
log.info("Allowed origins: %s", SETTINGS.allowed_origins)

# ---------------- Security / request-id middleware ----------------
class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        csp = (
            "default-src 'none'; "
            "script-src 'self'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "connect-src 'self'; "
            "base-uri 'none'; "
            "form-action 'self'"
        )
        resp = await call_next(request)
        resp.headers["Content-Security-Policy"] = csp
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=(self)"
        resp.headers["X-Content-Type-Options"] = "nosniff"
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
        
        # Allow localhost requests to bypass fetch-metadata checks
        if origin.startswith('http://localhost') or origin.startswith('https://localhost'):
            log.info("FetchMetadata: allowing localhost request from %s", origin)
            return await call_next(request)
        
        if site in ("", "same-origin", "same-site", "none"):
            return await call_next(request)
        if request.method.upper() in self.SAFE_METHODS:
            return await call_next(request)
        
        log.warning("FetchMetadata: blocking request from site=%s, method=%s, origin=%s", site, request.method, origin)
        return JSONResponse({"detail": "blocked by fetch-metadata"}, status_code=403)

class CORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        origin = request.headers.get('Origin', '')
        log.info("CORS middleware: method=%s, origin=%s, path=%s", request.method, origin, request.url.path)
        
        # Handle CORS preflight OPTIONS requests
        if request.method == "OPTIONS":
            # Determine allowed origin
            if origin.endswith('.jpmchase.net') or origin == 'https://jpmchase.net':
                allowed_origin = origin
            elif origin.startswith('http://localhost') or origin.startswith('https://localhost'):
                allowed_origin = origin
            elif origin.endswith('.dpop.fun') or origin == 'https://dpop.fun':
                allowed_origin = origin
            else:
                allowed_origin = 'https://dpop.fun'
            
            log.info("CORS preflight: returning allowed_origin=%s", allowed_origin)
            
            # Return preflight response
            return JSONResponse(
                content={"ok": True},
                headers={
                    'Access-Control-Allow-Origin': allowed_origin,
                    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
                    'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
                    'Access-Control-Max-Age': '86400',  # Cache preflight for 24 hours
                }
            )
        
        # Handle regular requests
        response = await call_next(request)
        
        # Determine allowed origin for response headers
        if origin.endswith('.jpmchase.net') or origin == 'https://jpmchase.net':
            allowed_origin = origin
        elif origin.startswith('http://localhost') or origin.startswith('https://localhost'):
            allowed_origin = origin
        elif origin.endswith('.dpop.fun') or origin == 'https://dpop.fun':
            allowed_origin = origin
        else:
            allowed_origin = 'https://dpop.fun'
        
        # Set CORS headers
        response.headers['Access-Control-Allow-Origin'] = allowed_origin
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        
        log.info("CORS response: set headers for origin=%s, allowed_origin=%s", origin, allowed_origin)
        
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

# ---------------- Canonical origin + URL (IPv6-safe) ----------------
def _bracket_host(host: str) -> str:
    if host and ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host

def _is_allowed_origin(url: str, allowed_origins: List[str]) -> bool:
    """Check if a URL's origin is in the allowed origins list."""
    try:
        parsed_url = urlsplit(url)
        url_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        return url_origin in allowed_origins
    except Exception:
        return False

def _canonicalize_url_for_validation(url: str, allowed_origins: List[str]) -> Optional[str]:
    """Canonicalize URL and validate against allowed origins."""
    try:
        parsed_url = urlsplit(url)
        scheme = parsed_url.scheme.lower()
        host = parsed_url.hostname.lower() if parsed_url.hostname else ""
        port = parsed_url.port
        
        # Handle default ports
        if ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            port = None
            
        # Reconstruct netloc
        if port:
            netloc = f"{host}:{port}"
        else:
            netloc = host
            
        # Reconstruct URL
        canonical = urlunsplit((scheme, netloc, parsed_url.path or "/", parsed_url.query, ""))
        
        # Check if origin is allowed
        if _is_allowed_origin(canonical, allowed_origins):
            return canonical
        return None
    except Exception:
        return None

def canonicalize_origin_and_url(request: Request) -> Tuple[str, str]:
    if EXTERNAL_ORIGIN:
        origin = EXTERNAL_ORIGIN.rstrip("/")
    else:
        scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
        host = request.headers.get("x-forwarded-host")
        port = request.headers.get("x-forwarded-port")
        if host:
            if host.startswith("["):
                if "]:" in host:
                    h, p = host.split("]:", 1)
                    host = h.strip("[]")
                    port = port or p
                else:
                    host = host.strip("[]")
            else:
                if ":" in host and host.count(":") == 1:
                    h, p = host.split(":", 1)
                    host, port = h, (port or p)
        else:
            host = request.url.hostname or ""
            if request.url.port:
                port = str(request.url.port)

        host = host.lower()
        if port and ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
            netloc = _bracket_host(host)
        elif port:
            netloc = f"{_bracket_host(host)}:{port}"
        else:
            netloc = _bracket_host(host)
        origin = f"{scheme}://{netloc}"

    parts = urlsplit(str(request.url))
    o_parts = urlsplit(origin)
    path = parts.path or "/"
    query = parts.query
    full = urlunsplit((o_parts.scheme, o_parts.netloc, path, query, ""))
    return origin, full

# ---------------- FastAPI app ----------------
app = FastAPI(middleware=[
    Middleware(RequestIDMiddleware),
    Middleware(FetchMetadataMiddleware),
    Middleware(SecurityHeadersMiddleware),
    Middleware(CORSMiddleware),
    Middleware(SessionMiddleware,
               secret_key=(SETTINGS.session_secret_key or base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()),
               session_cookie=SESSION_COOKIE_NAME,
               https_only=HTTPS_ONLY,
               same_site=SESSION_SAMESITE),
])

BASE_DIR = os.path.dirname(__file__)



# Static file mounting
app.mount("/public", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public")), name="public")
app.mount("/src", StaticFiles(directory=os.path.join(BASE_DIR, "..", "src")), name="src")
app.mount("/css", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public/css")), name="css")

def _new_nonce() -> str: return b64u(secrets.token_bytes(18))



def issue_binding_token(*, sid: str, bik_jkt: str, dpop_jkt: str, aud: str, ttl: int = BIND_TTL) -> str:
    now_ts = now()
    payload = {"sid": sid, "aud": aud, "nbf": now_ts - 60, "exp": now_ts + ttl, "cnf": {"bik_jkt": bik_jkt, "dpop_jkt": dpop_jkt}}
    protected = {"alg": "ES256", "typ": "bik-bind+jws", "kid": SERVER_KID}
    tok = jose_jws.sign(payload, SERVER_EC_PRIVATE_KEY_PEM, algorithm="ES256", headers=protected)
    log.info("issued bind token sid=%s aud=%s exp=%s", sid, aud, payload["exp"])
    return tok

def verify_binding_token(token: str) -> Dict[str, Any]:
    payload = jose_jws.verify(token, SERVER_PUBLIC_JWK, algorithms=["ES256"])
    data = payload if isinstance(payload, dict) else json.loads(payload)
    if data.get("exp", 0) < now():
        raise HTTPException(status_code=401, detail="bind token expired")
    return data

# ---- DB startup ----
@app.on_event("startup")
async def _init_db():
    # Prefer path from config; fall back if DB.init() has no parameter
    try:
        await DB.init(SETTINGS.db_path)  # type: ignore[arg-type]
        log.info("DB initialized at %s", SETTINGS.db_path)
    except TypeError:
        log.warning("DB.init(db_path) not supported; calling DB.init() without args. Ensure DB uses %s.", SETTINGS.db_path)
        await DB.init()

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(BASE_DIR, "..", "public", "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())



@app.get("/.well-known/stronghold-jwks.json")
async def jwks(): return {"keys": [SERVER_PUBLIC_JWK]}

# ---------------- Session + Bind endpoints ----------------
@app.post("/session/init")
async def session_init(req: Request):
    body = await req.json()
    sid = secrets.token_urlsafe(18)
    csrf = secrets.token_urlsafe(18)
    reg_nonce = _new_nonce()
    req.session.update({"sid": sid})
    await DB.set_session(sid, {"state":"pending-bind","csrf":csrf,"reg_nonce":reg_nonce,"browser_uuid":body.get("browser_uuid")})
    log.info("session_init sid=%s rid=%s", sid, req.state.request_id)
    return JSONResponse({"csrf": csrf, "reg_nonce": reg_nonce, "state": "pending-bind"})

@app.post("/browser/register")
async def browser_register(req: Request):
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(status_code=401, detail="no session")
    if req.headers.get("X-CSRF-Token") != s.get("csrf"): raise HTTPException(status_code=403, detail="bad csrf")
    jws_compact = (await req.body()).decode()
    try:
        h_b64, p_b64, _ = jws_compact.split(".")
        header = json.loads(base64url_decode(h_b64.encode())); payload = json.loads(base64url_decode(p_b64.encode()))
        if header.get("typ") != "bik-reg+jws": raise HTTPException(status_code=400, detail="wrong typ")
        if header.get("alg") != "ES256": raise HTTPException(status_code=400, detail="bad alg")
        jose_jws.verify(jws_compact, header["jwk"], algorithms=["ES256"])
        if payload.get("nonce") != s.get("reg_nonce"): raise HTTPException(status_code=401, detail="bad nonce")
        if abs(now() - int(payload.get("iat",0))) > SKEW_SEC: raise HTTPException(status_code=401, detail="bad iat")
        jwk = header.get("jwk") or {}
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
            raise HTTPException(status_code=400, detail="bad jwk")
        bik_jkt = ec_p256_thumbprint(jwk)
        await DB.update_session(sid, {"bik_jkt": bik_jkt, "state": "bound-bik", "reg_nonce": None})
        log.info("bik_register sid=%s jkt=%s rid=%s", sid, bik_jkt[:8], req.state.request_id)
        return {"bik_jkt": bik_jkt, "state": "bound-bik"}
    except HTTPException: raise
    except Exception as e:
        log.exception("bik_register failed sid=%s rid=%s", sid, req.state.request_id); raise HTTPException(status_code=400, detail=f"register verify failed: {e}")

@app.post("/dpop/bind")
async def dpop_bind(req: Request):
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(status_code=401, detail="no session")
    if req.headers.get("X-CSRF-Token") != s.get("csrf"): raise HTTPException(status_code=403, detail="bad csrf")
    if s.get("state") != "bound-bik": raise HTTPException(status_code=403, detail="bik not bound")
    jws_compact = (await req.body()).decode()
    try:
        h_b64, p_b64, _ = jws_compact.split(".")
        header = json.loads(base64url_decode(h_b64.encode())); payload = json.loads(base64url_decode(p_b64.encode()))
        if header.get("typ") != "dpop-bind+jws": raise HTTPException(status_code=400, detail="wrong typ")
        if header.get("alg") != "ES256": raise HTTPException(status_code=400, detail="bad alg")
        jose_jws.verify(jws_compact, header["jwk"], algorithms=["ES256"])
        if abs(now() - int(payload.get("iat",0))) > SKEW_SEC: raise HTTPException(status_code=401, detail="bad iat")
        dpop_pub_jwk = payload.get("dpop_jwk") or {}
        if dpop_pub_jwk.get("kty") != "EC" or dpop_pub_jwk.get("crv") != "P-256" or not dpop_pub_jwk.get("x") or not dpop_pub_jwk.get("y"):
            raise HTTPException(status_code=400, detail="bad dpop jwk")
        dpop_jkt = ec_p256_thumbprint(dpop_pub_jwk)
        origin, _ = canonicalize_origin_and_url(req)
        bind = issue_binding_token(sid=sid, bik_jkt=s["bik_jkt"], dpop_jkt=dpop_jkt, aud=origin, ttl=BIND_TTL)
        next_nonce = _new_nonce()
        await DB.add_nonce(sid, next_nonce, NONCE_TTL)
        await DB.update_session(sid, {"dpop_jkt": dpop_jkt, "state": "bound"})
        log.info("dpop_bind sid=%s dpop_jkt=%s rid=%s", sid, dpop_jkt[:8], req.state.request_id)
        return JSONResponse({"bind": bind, "cnf": {"dpop_jkt": dpop_jkt}, "expires_at": now() + BIND_TTL}, headers={"DPoP-Nonce": next_nonce})
    except HTTPException: raise
    except Exception as e:
        log.exception("dpop bind failed sid=%s rid=%s", sid, req.state.request_id); raise HTTPException(status_code=400, detail=f"dpop bind failed: {e}")

@app.get("/session/status")
async def session_status(req: Request):
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s:
        return {"valid": False, "state": None, "bik_registered": False, "dpop_bound": False}
    
    state = s.get("state")
    bik_registered = bool(s.get("bik_jkt"))
    dpop_bound = bool(s.get("dpop_jkt"))
    
    return {
        "valid": True,
        "state": state,
        "bik_registered": bik_registered,
        "dpop_bound": dpop_bound
    }

# ---------------- DPoP gate ----------------
def _nonce_fail_response(sid: str, detail: str) -> None:
    n = _new_nonce()
    asyncio.create_task(DB.add_nonce(sid, n, NONCE_TTL))
    raise HTTPException(status_code=401, detail=detail, headers={"DPoP-Nonce": n})

async def require_dpop(req: Request) -> Dict[str, Any]:
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s:
        raise HTTPException(status_code=401, detail="no session")

    dpop_hdr = req.headers.get("DPoP"); bind_hdr = req.headers.get("DPoP-Bind")
    if not dpop_hdr or not bind_hdr:
        n = _new_nonce(); await DB.add_nonce(sid, n, NONCE_TTL)
        raise HTTPException(status_code=428, detail="dpop required", headers={"DPoP-Nonce": n})

    try:
        bind_payload = verify_binding_token(bind_hdr)
    except HTTPException:
        _nonce_fail_response(sid, "bind verify failed")

    if bind_payload.get("sid") != sid:
        _nonce_fail_response(sid, "bind token sid mismatch")

    origin, full_url = canonicalize_origin_and_url(req)
    # Validate aud against allowed origins (multi-domain support)
    aud = bind_payload.get("aud")
    if not aud:
        _nonce_fail_response(sid, "missing aud")
    
    if aud not in SETTINGS.allowed_origins:
        _nonce_fail_response(sid, f"bind token aud not allowed: {aud}")

    try:
        h_b64, p_b64, _ = dpop_hdr.split(".")
        header = json.loads(base64url_decode(h_b64.encode())); payload = json.loads(base64url_decode(p_b64.encode()))

        if header.get("typ") != "dpop+jwt":
            _nonce_fail_response(sid, "wrong typ")
        if header.get("alg") != "ES256":
            _nonce_fail_response(sid, "bad alg")

        jwk = header.get("jwk") or {}
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
            _nonce_fail_response(sid, "bad jwk")

        jose_jws.verify(dpop_hdr, jwk, algorithms=["ES256"])

        # Validate htu against allowed origins (multi-domain support)
        htu = payload.get("htu")
        if not htu:
            _nonce_fail_response(sid, "missing htu")
        
        log.debug("DPoP validation - htu: %s, full_url: %s, allowed_origins: %s", htu, full_url, SETTINGS.allowed_origins)
        
        # Try to canonicalize and validate the htu against allowed origins
        canonical_htu = _canonicalize_url_for_validation(htu, SETTINGS.allowed_origins)
        if not canonical_htu:
            log.warning("DPoP validation failed - htu origin not allowed: %s (allowed: %s)", htu, SETTINGS.allowed_origins)
            _nonce_fail_response(sid, f"htu origin not allowed: {htu}")
        
        log.debug("DPoP validation - canonical_htu: %s", canonical_htu)
        
        # For path and query validation, we can use the canonicalized htu
        # but we need to ensure the path and query match what we expect
        expected_parts = urlsplit(full_url)
        htu_parts = urlsplit(canonical_htu)
        
        if expected_parts.path != htu_parts.path:
            log.warning("DPoP validation failed - path mismatch: expected %s, got %s", expected_parts.path, htu_parts.path)
            _nonce_fail_response(sid, f"htu path mismatch: expected {expected_parts.path}, got {htu_parts.path}")
        if expected_parts.query != htu_parts.query:
            log.warning("DPoP validation failed - query mismatch: expected %s, got %s", expected_parts.query, htu_parts.query)
            _nonce_fail_response(sid, f"htu query mismatch: expected {expected_parts.query}, got {htu_parts.query}")
        if payload.get("htm","").upper() != req.method.upper():
            _nonce_fail_response(sid, "htm mismatch")
        if abs(now() - int(payload.get("iat",0))) > SKEW_SEC:
            _nonce_fail_response(sid, "bad iat")

        n = payload.get("nonce")
        if not n or not (await DB.nonce_valid(sid, n)):
            _nonce_fail_response(sid, "bad nonce")

        jti = payload.get("jti")
        if not jti or not (await DB.add_jti(sid, jti, JTI_TTL)):
            _nonce_fail_response(sid, "jti replay")

        def jkt_of(jwk_: Dict[str, Any]) -> str:
            return ec_p256_thumbprint(jwk_)
        if jkt_of(jwk) != (bind_payload.get("cnf") or {}).get("dpop_jkt"):
            _nonce_fail_response(sid, "dpop_jkt mismatch")

    except HTTPException:
        raise
    except Exception as e:
        log.exception("dpop verify failed sid=%s rid=%s", sid, req.state.request_id)
        _nonce_fail_response(sid, f"dpop verify failed: {e}")

    next_nonce = _new_nonce()
    await DB.add_nonce(sid, next_nonce, NONCE_TTL)
    req.state.next_nonce = next_nonce
    return {"sid": sid, "next_nonce": next_nonce}

# ---- Passkey repo adapter (maps passkeys.py expectations to DB.pk_* methods) ----
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

# ---------------- Routers ----------------
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

# ---------------- Resume (BIK) ----------------
@app.post("/session/resume-init")
async def resume_init(req: Request):
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    n = _new_nonce()
    await DB.update_session(sid, {"resume_nonce": n})
    next_nonce = _new_nonce(); await DB.add_nonce(sid, next_nonce, NONCE_TTL)
    return JSONResponse({"resume_nonce": n}, headers={"DPoP-Nonce": next_nonce})

@app.post("/session/resume-confirm")
async def resume_confirm(req: Request):
    sid = req.session.get("sid")
    s = await DB.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    jws_compact = (await req.body()).decode()
    h_b64, p_b64, _ = jws_compact.split(".")
    header = json.loads(base64url_decode(h_b64.encode()))
    payload = json.loads(base64url_decode(p_b64.encode()))
    jose_jws.verify(jws_compact, header["jwk"], algorithms=["ES256"])
    if abs(now() - int(payload.get("iat",0))) > SKEW_SEC:
        raise HTTPException(401, "bad iat")
    if payload.get("resume_nonce") != s.get("resume_nonce"):
        raise HTTPException(401, "bad resume_nonce")
    if ec_p256_thumbprint(header["jwk"]) != s.get("bik_jkt"):
        raise HTTPException(401, "bik mismatch")

    origin, _ = canonicalize_origin_and_url(req)
    dpop_jkt = s.get("dpop_jkt")
    bind = issue_binding_token(sid=sid, bik_jkt=s["bik_jkt"], dpop_jkt=dpop_jkt, aud=origin)
    n = _new_nonce(); await DB.add_nonce(sid, n, NONCE_TTL)
    await DB.update_session(sid, {"resume_nonce": None})
    return JSONResponse({"bind": bind}, headers={"DPoP-Nonce": n})

# ---------------- Demo API ----------------
@app.post("/api/echo")
async def api_echo(req: Request, ctx=Depends(require_dpop)):
    body = await req.json()
    headers = {"DPoP-Nonce": ctx["next_nonce"]}
    log.info("api_echo ok sid=%s rid=%s", ctx["sid"], req.state.request_id)
    return JSONResponse({"ok": True, "echo": body, "ts": now()}, headers=headers)



# ---------------- Testing Endpoints ----------------
# Simple in-memory storage for testing (independent of app sessions)
_test_link_storage = {}

@app.get("/reg-link/{link_id}")
async def reg_link(link_id: str):
    """
    Store a link ID in memory for testing purposes.
    Completely independent of the main app.
    Access via GET request - simply visit the URL to register the link ID.
    """
    try:
        log.info("reg-link endpoint called: link_id=%s", link_id)
        
        # Store the link ID in simple in-memory storage
        _test_link_storage[link_id] = str(time.time())
        log.info("reg-link: stored link_id=%s", link_id)
        
        # Return HTML success page
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Link Registration Success</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    text-align: center;
                    padding: 0;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    min-height: 100vh;
                    margin: 0;
                    display: flex;
                    align-items: flex-start;
                    justify-content: center;
                    padding-top: 80px;
                }}
                .success-card {{
                    background: rgba(255, 255, 255, 0.1);
                    backdrop-filter: blur(10px);
                    border-radius: 20px;
                    padding: 40px;
                    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
                    border: 1px solid rgba(255, 255, 255, 0.2);
                    max-width: 500px;
                }}
                .success-icon {{
                    font-size: 64px;
                    margin-bottom: 20px;
                }}
                h1 {{
                    margin: 0 0 20px 0;
                    font-size: 2.5em;
                    text-shadow: 2px 2px 4px rgba(0, 0, 0, 0.3);
                }}
                .link-id {{
                    background: rgba(255, 255, 255, 0.2);
                    padding: 15px;
                    border-radius: 10px;
                    font-family: monospace;
                    font-size: 1.1em;
                    margin: 20px 0;
                    word-break: break-all;
                }}
                .timestamp {{
                    font-size: 0.9em;
                    opacity: 0.8;
                    margin-top: 20px;
                }}
                .back-link {{
                    margin-top: 30px;
                }}
                .back-link a {{
                    color: white;
                    text-decoration: none;
                    padding: 10px 20px;
                    border: 2px solid white;
                    border-radius: 25px;
                    transition: all 0.3s ease;
                }}
                .back-link a:hover {{
                    background: white;
                    color: #667eea;
                }}
            </style>
        </head>
        <body>
            <div class="success-card">
                <div class="success-icon">✅</div>
                <h1>Link Registration Success!</h1>
                <p>The link ID has been successfully stored in memory.</p>
                
                <div class="link-id">
                    <strong>Link ID:</strong><br>
                    {link_id}
                </div>
                
                <p>This link ID is now available for verification.</p>
                
                <div class="timestamp">
                    Registered at: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}
                </div>
                
                <div class="back-link">
                    <a href="javascript:history.back()">← Go Back</a>
                </div>
            </div>
        </body>
        </html>
        """
        
        log.info("reg-link: returning HTML success page")
        return HTMLResponse(html_content)
        
    except Exception as e:
        log.exception("reg-link failed for link_id=%s", link_id)
        raise HTTPException(500, f"reg-link failed: {e}")

@app.get("/link-verify/{link_id}")
async def link_verify(link_id: str):
    """
    Check if a link ID exists in memory for testing purposes.
    Completely independent of the main app.
    """
    try:
        # Check if the link ID exists in storage
        found = link_id in _test_link_storage
        
        log.info("link-verify: link_id=%s found=%s", link_id, found)
        
        return {"ok": True, "link_id": link_id, "found": found}
        
    except Exception as e:
        log.exception("link-verify failed for link_id=%s", link_id)
        raise HTTPException(500, f"link-verify failed: {e}")

@app.post("/_admin/clear-test-links")
async def clear_test_links():
    """
    Clear all test link storage (for testing cleanup).
    """
    try:
        count = len(_test_link_storage)
        _test_link_storage.clear()
        log.info("clear-test-links: cleared %d test links", count)
        
        return {"ok": True, "cleared_count": count}
        
    except Exception as e:
        log.exception("clear-test-links failed")
        raise HTTPException(500, f"clear-test-links failed: {e}")

# ---------------- Admin ----------------
@app.post("/_admin/flush")
async def admin_flush():
    await DB.flush()
    log.warning("admin_flush: cleared demo stores")
    return {"ok": True}
