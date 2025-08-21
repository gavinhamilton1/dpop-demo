# server/utils.py
import base64
import hashlib
import json
import time
from typing import Dict, Any, Optional

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

def jws_es256_sign(payload: Dict[str, Any]) -> str:
    """Sign a payload with ES256 JWS."""
    _ensure_server_signing_key()
    header = {"alg": "ES256", "typ": "link+jws", "kid": _SERVER_KID}
    h_b64 = b64u(json.dumps(header, separators=(',', ':')).encode())
    p_b64 = b64u(json.dumps(payload, separators=(',', ':')).encode())
    signing_input = f"{h_b64}.{p_b64}".encode()
    der = _SERVER_EC_KEY.sign(signing_input, ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return f"{h_b64}.{p_b64}.{b64u(sig)}"

def jws_es256_verify(token: str) -> Dict[str, Any]:
    """Verify and decode an ES256 JWS token."""
    _ensure_server_signing_key()
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        header = json.loads(b64u_dec(h_b64))
        if header.get("alg") != "ES256":
            raise ValueError("alg")
        signing_input = f"{h_b64}.{p_b64}".encode()
        sig = b64u_dec(s_b64)
        if len(sig) != 64:
            raise ValueError("sig")
        r = int.from_bytes(sig[:32], "big")
        s = int.from_bytes(sig[32:], "big")
        der = encode_dss_signature(r, s)
        _SERVER_EC_KEY.public_key().verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
        payload = json.loads(b64u_dec(p_b64))
        return payload
    except Exception:
        raise ValueError("bad link token")

# -------- EC P-256 thumbprint utility --------
def ec_p256_thumbprint(jwk: Dict[str, Any]) -> str:
    """Generate EC P-256 JWK thumbprint."""
    ordered = {"kty": jwk["kty"], "crv": jwk["crv"], "x": jwk["x"], "y": jwk["y"]}
    return b64u(hashlib.sha256(json.dumps(ordered, separators=(",", ":"), ensure_ascii=False).encode()).digest())

# -------- Time utility --------
def now() -> int:
    """Get current timestamp."""
    return int(time.time())
