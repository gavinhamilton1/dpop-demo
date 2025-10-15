# server/utils.py
import base64
import hashlib
import json
import logging
import secrets
import time
from typing import Dict, Any, Optional
import jose.jws as jose_jws
import jose.utils as jose_utils
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit
from fastapi import Request

log = logging.getLogger(__name__)


from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature

# -------- Base64 utilities --------
def b64u(data: bytes) -> str:
    """Base64url encode bytes to string."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

def b64u_dec(s: str) -> bytes:
    """Base64url decode string to bytes."""
    pad = '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode((s + pad).encode())

# -------- JWS utilities --------
def _ensure_server_signing_key():
    """Lazy-initialize server EC signing key."""
    global _SERVER_EC_KEY, _SERVER_KID
    if _SERVER_EC_KEY is not None:
        return
    
    from server.config import load_settings
    SETTINGS = load_settings()
    
    pem = SETTINGS.server_ec_private_key_pem
    if pem:
        _SERVER_EC_KEY = serialization.load_pem_private_key(pem.encode(), password=None)
    else:
        _SERVER_EC_KEY = ec.generate_private_key(ec.SECP256R1())
    
    pub = _SERVER_EC_KEY.public_key().public_numbers()
    x = pub.x.to_bytes(32, "big")
    y = pub.y.to_bytes(32, "big")
    _SERVER_KID = b64u(hashlib.sha256(x + y).digest()[:8])

_SERVER_EC_KEY = None
_SERVER_KID: Optional[str] = None

def jws_es256_sign(payload: Dict[str, Any], private_key: Optional[ec.EllipticCurvePrivateKey] = None, header: Optional[Dict[str, Any]] = None) -> str:
    """Sign a payload with ES256 JWS using the provided private key or server key."""
    if private_key is None:
        _ensure_server_signing_key()
        private_key = _SERVER_EC_KEY
        if header is None:
            header = {"alg": "ES256", "typ": "link+jws", "kid": _SERVER_KID}
    
    if header is None:
        header = {"alg": "ES256"}
    
    h_b64 = b64u(json.dumps(header, separators=(',', ':')).encode())
    p_b64 = b64u(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    der = private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h_b64}.{p_b64}.{b64u(sig)}"

def jwk_to_ec_public_key(jwk: Dict[str, Any]) -> ec.EllipticCurvePublicKey:
    """Convert a JWK to an EC public key object."""
    if jwk.get("kty") != "EC":
        raise ValueError("JWK must be EC type")
    if jwk.get("crv") != "P-256":
        raise ValueError("JWK must use P-256 curve")
    
    x = int.from_bytes(b64u_dec(jwk["x"]), "big")
    y = int.from_bytes(b64u_dec(jwk["y"]), "big")
    
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    return public_numbers.public_key()


def validate_key_jws(jws_token: str, expected_typ: str, expected_payload_fields: list, key_type: str) -> tuple[str, dict, dict]:
    """
    Generic validation function for BIK and DPoP JWS tokens
    
    Args:
        jws_token: The JWS token to validate
        expected_typ: Expected JWT type (e.g., "bik-reg+jws", "dpop-bind+jws")
        expected_payload_fields: List of required payload field names (e.g., ["device_id"] or ["htm", "htu", "iat", "jti", "nonce"])
        key_type: Type of key for error messages (e.g., "BIK", "DPoP")
        
    Returns:
        tuple[str, dict, dict]: (jkt, public_jwk, payload)
        - jkt: The validated JKT
        - public_jwk: The JWK from the header
        - payload: The complete payload from the JWS token
        
    Raises:
        ValueError: If validation fails
    """
    try:
        # Validate the JWS token with the specified payload fields (validates field presence)
        key_data = validate_jws_token(jws_token, expected_typ, expected_payload_fields)
        public_jwk = key_data["header"].get("jwk", {})
        
        # Validate JWK structure
        if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256" or not public_jwk.get("x") or not public_jwk.get("y"):
            raise ValueError(f"bad {key_type.lower()} jwk")
        
        # Generate JKT from JWK
        jkt = ec_p256_thumbprint(public_jwk)
        
        log.info("Validated %s JKT: %s", key_type, jkt)
        
        # Additional validation for DPoP-specific claims
        if "htm" in expected_payload_fields:
            payload = key_data["payload"]
            if payload.get("htm") != "POST":
                raise ValueError("Invalid HTTP method")
            
        return jkt, public_jwk, key_data["payload"]
        
    except ValueError as e:
        raise ValueError(f"{key_type} JWS validation failed: {str(e)}")


def validate_jws_token(jws_token: str, expected_typ: str, required_payload_fields: list = None) -> Dict[str, Any]:
    """Generic JWS validation function that verifies signature and validates structure using Jose library."""
    if jws_token is None:
        raise ValueError("JWS token cannot be None")
    
    try:

        
        # Parse JWS token using Jose's safe parsing
        h_b64, p_b64, _ = jws_token.split(".")
        header = json.loads(jose_utils.base64url_decode(h_b64.encode()))
        payload = json.loads(jose_utils.base64url_decode(p_b64.encode()))
        
        # Validate header structure first
        if header.get("typ") != expected_typ:
            raise ValueError(f"Invalid JWS type: expected '{expected_typ}', got '{header.get('typ')}'")
        if header.get("alg") != "ES256":
            raise ValueError("Invalid algorithm: expected 'ES256'")
        
        # Get JWK from header
        jwk = header.get("jwk")
        if not jwk:
            raise ValueError("Missing JWK in header")
        
        # Verify signature using Jose library (this is the critical security step)
        jose_jws.verify(jws_token, jwk, algorithms=["ES256"])
        
        # Validate required payload fields
        if required_payload_fields:
            for field in required_payload_fields:
                if field not in payload:
                    raise ValueError(f"Missing required field '{field}' in payload")
        
        return {
            "header": header,
            "payload": payload
        }
        
    except Exception as e:
        raise ValueError(f"JWS validation failed: {str(e)}")

# -------- EC P-256 thumbprint utility --------
def ec_p256_thumbprint(jwk: Dict[str, Any]) -> str:
    """Generate EC P-256 JWK thumbprint."""
    ordered = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    return b64u(hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).digest())

# -------- Time utility --------
def now() -> int:
    """Get current timestamp."""
    return int(time.time())

# -------- Nonce utility --------
def _new_nonce() -> str:
    """Generate a new nonce for session security."""
    return base64.urlsafe_b64encode(secrets.token_bytes(18)).rstrip(b"=").decode()


"""
URL canonicalization and validation utilities
"""

def _bracket_host(host: str) -> str:
    """Wrap IPv6 addresses in brackets if needed"""
    if ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def canonicalize_origin_and_url(request: Request, external_origin: Optional[str] = None) -> Tuple[str, str]:
    """Canonicalize origin and URL from a request, handling IPv6 and proxy headers"""
    if external_origin:
        origin = external_origin.rstrip("/")
    else:
        scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
        host = request.headers.get("x-forwarded-host")
        port = request.headers.get("x-forwarded-port")
        if host:
            if host.startswith("["):
                if "]:" in host:
                    h, p = host.split("]:", 1)
                    host = h.strip("[]"); port = port or p
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


# -------- Passkey / WebAuthn utilities --------
import struct
import cbor2
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ed25519
from fastapi import HTTPException

def cose_to_jwk(cbor_bytes: bytes) -> dict:
    """Convert COSE key to JWK format"""
    m = cbor2.loads(cbor_bytes)
    kty = m.get(1)  # 1=OKP, 2=EC2, 3=RSA
    if kty == 2:  # EC2
        crv = m.get(-1); x = m.get(-2); y = m.get(-3)
        if crv != 1:
            raise HTTPException(status_code=400, detail="unsupported EC curve")
        return {"kty": "EC", "crv": "P-256", "x": b64u(x), "y": b64u(y), "alg": "ES256"}
    if kty == 3:  # RSA
        n = m.get(-1); e = m.get(-2)
        return {"kty": "RSA", "n": b64u(n), "e": b64u(e), "alg": "RS256"}
    if kty == 1:  # OKP (Ed25519)
        crv = m.get(-1); x = m.get(-2)
        if crv == 6 and x:
            return {"kty": "OKP", "crv": "Ed25519", "x": b64u(x), "alg": "EdDSA"}
        raise HTTPException(status_code=400, detail="unsupported OKP curve")
    raise HTTPException(status_code=400, detail="unsupported COSE key")

def jwk_to_public_key(jwk: dict):
    """Convert JWK to cryptography public key object
    
    Returns:
        Tuple of (public_key, algorithm_name)
    """
    if jwk.get("kty") == "EC" and jwk.get("crv") == "P-256":
        x = int.from_bytes(b64u_dec(jwk["x"]), "big")
        y = int.from_bytes(b64u_dec(jwk["y"]), "big")
        numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        return numbers.public_key(), "ES256"
    if jwk.get("kty") == "RSA":
        n = int.from_bytes(b64u_dec(jwk["n"]), "big")
        e = int.from_bytes(b64u_dec(jwk["e"]), "big")
        pub = rsa.RSAPublicNumbers(e, n).public_key()
        return pub, "RS256"
    if jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
        pub = ed25519.Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
        return pub, "EdDSA"
    raise HTTPException(status_code=400, detail="unsupported JWK")

def parse_authenticator_data(ad: bytes) -> Dict[str, Any]:
    """Parse WebAuthn authenticator data
    
    Returns dict with:
        - rpIdHash: bytes
        - flags: int
        - signCount: int
        - aaguid: bytes (if AT flag set)
        - credId: bytes (if AT flag set)
        - rest: bytes (remaining data after credId, typically COSE key)
    """
    if len(ad) < 37:
        raise HTTPException(status_code=400, detail="authData too short")
    rpIdHash = ad[0:32]
    flags = ad[32]
    signCount = struct.unpack(">I", ad[33:37])[0]
    off = 37
    res: Dict[str, Any] = {"rpIdHash": rpIdHash, "flags": flags, "signCount": signCount}
    AT = (flags & 0x40) != 0
    if AT:
        if len(ad) < off + 16 + 2:
            raise HTTPException(status_code=400, detail="attestedCredentialData truncated")
        aaguid = ad[off:off+16]; off += 16
        cred_len = struct.unpack(">H", ad[off:off+2])[0]; off += 2
        credId = ad[off:off+cred_len]; off += cred_len
        res.update({"aaguid": aaguid, "credId": credId})
        res["rest"] = ad[off:]
    return res
