import os, json, time, base64, secrets, logging, asyncio
from typing import Dict, Any, Optional, Tuple
from fastapi import FastAPI, Request, HTTPException, Depends
from fastapi.responses import JSONResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware import Middleware
from starlette.responses import FileResponse
from jose import jws as jose_jws
from jose.utils import base64url_decode
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec
from urllib.parse import urlsplit, urlunsplit
from pathlib import Path

from passkeys import get_router, PasskeyRepo

PASSKEY_DB_PATH = Path(__file__).resolve().parent / "passkeys_db.json"
PASSKEY_DB = PasskeyRepo(file_path=str(PASSKEY_DB_PATH))

LOG_LEVEL = os.getenv("STRONGHOLD_LOG_LEVEL", "INFO").upper()
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "stronghold_session")
HTTPS_ONLY = os.getenv("DEV_ALLOW_INSECURE_COOKIE", "") != "1"
SKEW_SEC = int(os.getenv("STRONGHOLD_SKEW_SEC", "120"))
NONCE_WINDOW = int(os.getenv("STRONGHOLD_NONCE_WINDOW", "5"))
NONCE_TTL = int(os.getenv("STRONGHOLD_NONCE_TTL", "60"))
JTI_TTL = int(os.getenv("STRONGHOLD_JTI_TTL", "60"))
BIND_TTL = int(os.getenv("STRONGHOLD_BIND_TTL", "3600"))
EXTERNAL_ORIGIN = os.getenv("STRONGHOLD_EXTERNAL_ORIGIN")
REDIS_URL = os.getenv("REDIS_URL")

logging.basicConfig(level=LOG_LEVEL, format="%(asctime)s %(levelname)s stronghold %(message)s")
log = logging.getLogger("stronghold")


# ---------------- Security / request-id middleware ----------------

from starlette.middleware.base import BaseHTTPMiddleware

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
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        resp.headers["X-Content-Type-Options"] = "nosniff"
        return resp

class RequestIDMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        rid = request.headers.get("X-Request-ID") or base64.urlsafe_b64encode(secrets.token_bytes(9)).rstrip(b"=").decode()
        request.state.request_id = rid
        resp = await call_next(request)
        resp.headers["X-Request-ID"] = rid
        return resp

# **NEW**: Cheap and effective cross-site request defense per Fetch Metadata
class FetchMetadataMiddleware(BaseHTTPMiddleware):
    SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
    async def dispatch(self, request: Request, call_next):
        site = (request.headers.get("sec-fetch-site") or "").lower()
        mode = (request.headers.get("sec-fetch-mode") or "").lower()
        dest = (request.headers.get("sec-fetch-dest") or "").lower()
        # Allow same-origin / same-site, or simple navigations
        if site in ("", "same-origin", "same-site", "none"):
            return await call_next(request)
        # Cross-site: only allow safe methods or simple navigations (e.g., to fetch static)
        if request.method.upper() in self.SAFE_METHODS:
            return await call_next(request)
        return JSONResponse({"detail": "blocked by fetch-metadata"}, status_code=403)

# ---------------- Server signing key (ES256) ----------------

SERVER_EC_PRIVATE_KEY_PEM = os.getenv("STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM")
if not SERVER_EC_PRIVATE_KEY_PEM:
    _priv = ec.generate_private_key(ec.SECP256R1())
    SERVER_EC_PRIVATE_KEY_PEM = _priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    log.warning("STRONGHOLD_SERVER_EC_PRIVATE_KEY_PEM not set; generated ephemeral dev key.")

def _pem_to_public_jwk_and_kid(pem_priv: str):
    priv = serialization.load_pem_private_key(pem_priv.encode(), password=None)
    pub = priv.public_key()
    nums = pub.public_numbers()
    x = nums.x.to_bytes(32, "big"); y = nums.y.to_bytes(32, "big")
    b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode()
    jwk = {"kty": "EC", "crv": "P-256", "x": b64(x), "y": b64(y), "alg": "ES256"}
    ordered = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    h = hashes.Hash(hashes.SHA256()); h.update(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode())
    kid = b64(h.finalize()); jwk["kid"] = kid
    return {"jwk": jwk, "kid": kid}

SERVER_JWK_INFO = _pem_to_public_jwk_and_kid(SERVER_EC_PRIVATE_KEY_PEM)
SERVER_PUBLIC_JWK = SERVER_JWK_INFO["jwk"]; SERVER_KID = SERVER_JWK_INFO["kid"]

# ---------------- Store (memory or Redis) ----------------

class Store:
    def __init__(self):
        self.redis = None
        if REDIS_URL:
            try:
                import redis.asyncio as redis
                self.redis = redis.from_url(REDIS_URL, decode_responses=True)
                log.info("Using Redis at %s", REDIS_URL)
            except Exception as e:
                log.error("Redis unavailable (%s); falling back to memory", e)
        self.sess = {}
    async def set_session(self, sid: str, data: Dict[str, Any]):
        if self.redis:
            await self.redis.set(f"session:{sid}", json.dumps(data), ex=BIND_TTL*4)
        else:
            self.sess[sid] = data
    async def get_session(self, sid: str) -> Optional[Dict[str, Any]]:
        if self.redis:
            v = await self.redis.get(f"session:{sid}")
            return json.loads(v) if v else None
        return self.sess.get(sid)
    async def update_session(self, sid: str, patch: Dict[str, Any]):
        s = await self.get_session(sid) or {}
        s.update(patch); await self.set_session(sid, s)
    async def add_nonce(self, sid: str, nonce: str, ttl: int):
        if self.redis:
            await self.redis.set(f"nonce:{sid}:{nonce}", "1", ex=ttl)
        else:
            s = self.sess.setdefault(sid, {})
            lst = s.setdefault("nonces", [])
            lst.append({"nonce": nonce, "exp": int(time.time()) + ttl})
            while len(lst) > NONCE_WINDOW:
                lst.pop(0)
    async def nonce_valid(self, sid: str, nonce: str) -> bool:
        if self.redis:
            return await self.redis.exists(f"nonce:{sid}:{nonce}") == 1
        s = self.sess.get(sid) or {}
        now = int(time.time())
        lst = s.get("nonces", [])
        s["nonces"] = [n for n in lst if n["exp"] >= now]
        return any(n["nonce"] == nonce for n in s["nonces"])
    async def add_jti(self, sid: str, jti: str, ttl: int) -> bool:
        if self.redis:
            ok = await self.redis.set(f"jti:{sid}:{jti}", "1", ex=ttl, nx=True)
            return bool(ok)
        s = self.sess.setdefault(sid, {})
        now = int(time.time())
        lst = s.setdefault("jtis", [])
        s["jtis"] = [j for j in lst if j["exp"] >= now]
        if any(j["jti"] == jti for j in s["jtis"]):
            return False
        s["jtis"].append({"jti": jti, "exp": now + ttl})
        return True
    async def flush(self):
        if self.redis:
            keys = []
            keys += await self.redis.keys("session:*")
            keys += await self.redis.keys("nonce:*")
            keys += await self.redis.keys("jti:*")
            if keys:
                await self.redis.delete(*keys)
        self.sess.clear()

STORE = Store()

# ---------------- Canonical origin + URL (IPv6-safe) ----------------

def _bracket_host(host: str) -> str:
    # Wrap IPv6 literal in [] if not already
    if host and ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host

def canonicalize_origin_and_url(request: Request) -> Tuple[str, str]:
    # Origin
    if EXTERNAL_ORIGIN:
        origin = EXTERNAL_ORIGIN.rstrip("/")
    else:
        scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
        host = request.headers.get("x-forwarded-host")
        port = request.headers.get("x-forwarded-port")
        if host:
            # If header includes port, split it carefully (IPv6 may already be bracketed)
            if host.startswith("["):
                # bracketed IPv6 netloc like "[::1]:8443" or "[::1]"
                if "]:" in host:
                    h, p = host.split("]:", 1)
                    host = h.strip("[]")
                    port = port or p
                else:
                    host = host.strip("[]")
            else:
                # v4/hostname maybe with ":port"
                if ":" in host and host.count(":") == 1:
                    h, p = host.split(":", 1)
                    host, port = h, (port or p)
        else:
            host = request.url.hostname or ""
            if request.url.port:
                port = str(request.url.port)

        host = host.lower()
        # Strip default ports
        if port and ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
            netloc = _bracket_host(host)
        elif port:
            netloc = f"{_bracket_host(host)}:{port}"
        else:
            netloc = _bracket_host(host)
        origin = f"{scheme}://{netloc}"

    # Full canonical URL (origin + path + query; no fragment)
    parts = urlsplit(str(request.url))
    o_parts = urlsplit(origin)
    path = parts.path or "/"
    query = parts.query
    full = urlunsplit((o_parts.scheme, o_parts.netloc, path, query, ""))
    return origin, full

# ---------------- FastAPI app ----------------

app = FastAPI(middleware=[
    Middleware(RequestIDMiddleware),
    Middleware(FetchMetadataMiddleware),      # <— NEW (before sessions)
    Middleware(SecurityHeadersMiddleware),
    Middleware(SessionMiddleware,
               secret_key=os.getenv("SESSION_SECRET_KEY", base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()),
               session_cookie=SESSION_COOKIE_NAME,
               https_only=HTTPS_ONLY,
               same_site="strict"),
])



BASE_DIR = os.path.dirname(__file__)
app.mount("/public", StaticFiles(directory=os.path.join(BASE_DIR, "..", "public")), name="public")
app.mount("/src", StaticFiles(directory=os.path.join(BASE_DIR, "..", "src")), name="src")

def _now() -> int: return int(time.time())
def _new_nonce() -> str: return base64.urlsafe_b64encode(secrets.token_bytes(18)).rstrip(b"=").decode()

def _ec_p256_thumbprint(jwk: Dict[str, Any]) -> str:
    ordered = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    import hashlib
    return base64.urlsafe_b64encode(hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).digest()).rstrip(b"=").decode()

def issue_binding_token(*, sid: str, bik_jkt: str, dpop_jkt: str, aud: str, ttl: int = BIND_TTL) -> str:
    now = _now()
    payload = {"sid": sid, "aud": aud, "nbf": now - 60, "exp": now + ttl, "cnf": {"bik_jkt": bik_jkt, "dpop_jkt": dpop_jkt}}
    protected = {"alg": "ES256", "typ": "bik-bind+jws", "kid": SERVER_KID}
    tok = jose_jws.sign(payload, SERVER_EC_PRIVATE_KEY_PEM, algorithm="ES256", headers=protected)
    log.info("issued bind token sid=%s aud=%s exp=%s", sid, aud, payload["exp"])
    return tok

def verify_binding_token(token: str) -> Dict[str, Any]:
    payload = jose_jws.verify(token, SERVER_PUBLIC_JWK, algorithms=["ES256"])
    data = payload if isinstance(payload, dict) else json.loads(payload)
    if data.get("exp", 0) < _now():
        raise HTTPException(status_code=401, detail="bind token expired")
    return data

@app.get("/", response_class=HTMLResponse)
async def index():
    with open(os.path.join(BASE_DIR, "..", "public", "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/stronghold-sw.js")
async def stronghold_sw():
    sw_path = os.path.join(BASE_DIR, "..", "src", "stronghold-sw.js")
    return FileResponse(sw_path, media_type="application/javascript")

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
    await STORE.set_session(sid, {"state":"pending-bind","csrf":csrf,"reg_nonce":reg_nonce,"browser_uuid":body.get("browser_uuid")})
    log.info("session_init sid=%s rid=%s", sid, req.state.request_id)
    return JSONResponse({"csrf": csrf, "reg_nonce": reg_nonce, "state": "pending-bind"})

@app.post("/browser/register")
async def browser_register(req: Request):
    sid = req.session.get("sid")
    s = await STORE.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(status_code=401, detail="no session")
    if req.headers.get("X-CSRF-Token") != s.get("csrf"): raise HTTPException(status_code=403, detail="bad csrf")
    jws_compact = (await req.body()).decode()
    try:
        h_b64, p_b64, _ = jws_compact.split(".")
        header = json.loads(base64url_decode(h_b64.encode())); payload = json.loads(base64url_decode(p_b64.encode()))
        if header.get("typ") != "bik-reg+jws": raise HTTPException(status_code=400, detail="wrong typ")
        # enforce ES256
        if header.get("alg") != "ES256": raise HTTPException(status_code=400, detail="bad alg")
        # verify JWS using embedded pubkey
        jose_jws.verify(jws_compact, header["jwk"], algorithms=["ES256"])
        if payload.get("nonce") != s.get("reg_nonce"): raise HTTPException(status_code=401, detail="bad nonce")
        if abs(_now() - int(payload.get("iat",0))) > SKEW_SEC: raise HTTPException(status_code=401, detail="bad iat")
        # compute BIK thumbprint
        jwk = header.get("jwk") or {}
        if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
            raise HTTPException(status_code=400, detail="bad jwk")
        bik_jkt = _ec_p256_thumbprint(jwk)
        await STORE.update_session(sid, {"bik_jkt": bik_jkt, "state": "bound-bik", "reg_nonce": None})
        log.info("bik_register sid=%s jkt=%s rid=%s", sid, bik_jkt[:8], req.state.request_id)
        return {"bik_jkt": bik_jkt, "state": "bound-bik"}
    except HTTPException: raise
    except Exception as e:
        log.exception("bik_register failed sid=%s rid=%s", sid, req.state.request_id); raise HTTPException(status_code=400, detail=f"register verify failed: {e}")

@app.post("/dpop/bind")
async def dpop_bind(req: Request):
    sid = req.session.get("sid")
    s = await STORE.get_session(sid) if sid else None
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
        if abs(_now() - int(payload.get("iat",0))) > SKEW_SEC: raise HTTPException(status_code=401, detail="bad iat")
        dpop_pub_jwk = payload.get("dpop_jwk") or {}
        # enforce EC P-256 key
        if dpop_pub_jwk.get("kty") != "EC" or dpop_pub_jwk.get("crv") != "P-256" or not dpop_pub_jwk.get("x") or not dpop_pub_jwk.get("y"):
            raise HTTPException(status_code=400, detail="bad dpop jwk")
        dpop_jkt = _ec_p256_thumbprint(dpop_pub_jwk)
        origin, _ = canonicalize_origin_and_url(req)
        bind = issue_binding_token(sid=sid, bik_jkt=s["bik_jkt"], dpop_jkt=dpop_jkt, aud=origin, ttl=BIND_TTL)
        next_nonce = _new_nonce()
        await STORE.add_nonce(sid, next_nonce, NONCE_TTL)
        await STORE.update_session(sid, {"dpop_jkt": dpop_jkt, "state": "bound"})
        log.info("dpop_bind sid=%s dpop_jkt=%s rid=%s", sid, dpop_jkt[:8], req.state.request_id)
        return JSONResponse({"bind": bind, "cnf": {"dpop_jkt": dpop_jkt}, "expires_at": _now() + BIND_TTL}, headers={"DPoP-Nonce": next_nonce})
    except HTTPException: raise
    except Exception as e:
        log.exception("dpop_bind failed sid=%s rid=%s", sid, req.state.request_id); raise HTTPException(status_code=400, detail=f"dpop bind failed: {e}")

# ---------------- DPoP gate ----------------

def _nonce_fail_response(sid: str, detail: str) -> None:
    n = _new_nonce()
    asyncio.create_task(STORE.add_nonce(sid, n, NONCE_TTL))
    raise HTTPException(status_code=401, detail=detail, headers={"DPoP-Nonce": n})

async def require_dpop(req: Request) -> Dict[str, Any]:
    sid = req.session.get("sid")
    s = await STORE.get_session(sid) if sid else None
    if not sid or not s:
        raise HTTPException(status_code=401, detail="no session")

    dpop_hdr = req.headers.get("DPoP"); bind_hdr = req.headers.get("DPoP-Bind")
    if not dpop_hdr or not bind_hdr:
        n = _new_nonce(); await STORE.add_nonce(sid, n, NONCE_TTL)
        raise HTTPException(status_code=428, detail="dpop required", headers={"DPoP-Nonce": n})

    # Verify bind token first
    try:
        bind_payload = verify_binding_token(bind_hdr)
    except HTTPException:
        # Bind invalid — do not leak info; ask client to re-prove with fresh nonce
        _nonce_fail_response(sid, "bind verify failed")

    if bind_payload.get("sid") != sid:
        _nonce_fail_response(sid, "bind token sid mismatch")

    origin, full_url = canonicalize_origin_and_url(req)
    if bind_payload.get("aud") != origin:
        _nonce_fail_response(sid, "bind token aud mismatch")

    # Verify DPoP proof (tight checks)
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

        if payload.get("htu") != full_url:
            _nonce_fail_response(sid, "htu mismatch")
        if payload.get("htm","").upper() != req.method.upper():
            _nonce_fail_response(sid, "htm mismatch")
        if abs(_now() - int(payload.get("iat",0))) > SKEW_SEC:
            _nonce_fail_response(sid, "bad iat")

        n = payload.get("nonce")
        if not n or not (await STORE.nonce_valid(sid, n)):
            _nonce_fail_response(sid, "bad nonce")

        jti = payload.get("jti")
        if not jti or not (await STORE.add_jti(sid, jti, JTI_TTL)):
            _nonce_fail_response(sid, "jti replay")

        # Tie live DPoP key to bound key
        def jkt_of(jwk_: Dict[str, Any]) -> str:
            ordered = {"kty": "EC", "crv": "P-256", "x": jwk_["x"], "y": jwk_["y"]}
            import hashlib
            return base64.urlsafe_b64encode(hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).digest()).rstrip(b"=").decode()
        if jkt_of(jwk) != (bind_payload.get("cnf") or {}).get("dpop_jkt"):
            _nonce_fail_response(sid, "dpop_jkt mismatch")

    except HTTPException:
        raise
    except Exception as e:
        log.exception("dpop verify failed sid=%s rid=%s", sid, req.state.request_id)
        _nonce_fail_response(sid, f"dpop verify failed: {e}")

    # Success: rotate nonce for next request
    next_nonce = _new_nonce()
    await STORE.add_nonce(sid, next_nonce, NONCE_TTL)
    req.state.next_nonce = next_nonce
    return {"sid": sid, "next_nonce": next_nonce}

# ---------------- Resume (BIK) ----------------

app.include_router(get_router(
    STORE,
    require_dpop,
    canonicalize_origin_and_url,
    _now,
    passkey_repo=PASSKEY_DB,           # <-- pass the instance, not a string
))

@app.post("/session/resume-init")
async def resume_init(req: Request):
    sid = req.session.get("sid")
    s = await STORE.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    n = _new_nonce()
    await STORE.update_session(sid, {"resume_nonce": n})
    next_nonce = _new_nonce(); await STORE.add_nonce(sid, next_nonce, NONCE_TTL)
    return JSONResponse({"resume_nonce": n}, headers={"DPoP-Nonce": next_nonce})

@app.post("/session/resume-confirm")
async def resume_confirm(req: Request):
    sid = req.session.get("sid")
    s = await STORE.get_session(sid) if sid else None
    if not sid or not s: raise HTTPException(401, "no session")
    jws_compact = (await req.body()).decode()
    h_b64, p_b64, _ = jws_compact.split(".")
    header = json.loads(base64url_decode(h_b64.encode()))
    payload = json.loads(base64url_decode(p_b64.encode()))
    jose_jws.verify(jws_compact, header["jwk"], algorithms=["ES256"])
    if abs(_now() - int(payload.get("iat",0))) > SKEW_SEC:
        raise HTTPException(401, "bad iat")
    if payload.get("resume_nonce") != s.get("resume_nonce"):
        raise HTTPException(401, "bad resume_nonce")
    if _ec_p256_thumbprint(header["jwk"]) != s.get("bik_jkt"):
        raise HTTPException(401, "bik mismatch")

    origin, _ = canonicalize_origin_and_url(req)
    dpop_jkt = s.get("dpop_jkt")
    bind = issue_binding_token(sid=sid, bik_jkt=s["bik_jkt"], dpop_jkt=dpop_jkt, aud=origin)
    n = _new_nonce(); await STORE.add_nonce(sid, n, NONCE_TTL)
    await STORE.update_session(sid, {"resume_nonce": None})
    return JSONResponse({"bind": bind}, headers={"DPoP-Nonce": n})

# ---------------- Demo API ----------------

@app.post("/api/echo")
async def api_echo(req: Request, ctx=Depends(require_dpop)):
    body = await req.json()
    headers = {"DPoP-Nonce": ctx["next_nonce"]}
    log.info("api_echo ok sid=%s rid=%s", ctx["sid"], req.state.request_id)
    return JSONResponse({"ok": True, "echo": body, "ts": _now()}, headers=headers)

# ---------------- Admin ----------------

@app.post("/_admin/flush")
async def admin_flush():
    await STORE.flush()
    log.warning("admin_flush: cleared demo stores")
    return {"ok": True}
