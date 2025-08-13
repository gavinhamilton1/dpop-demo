from fastapi import FastAPI, HTTPException, Request, Response, Header
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import uvicorn
import secrets
import base64
import json
import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import uuid
import logging
import ecdsa
from ecdsa.curves import NIST256p
from ecdsa.keys import VerifyingKey
import hashlib

# Set up logging with more detailed output
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
app = FastAPI(title="Stronghold Device Registration Demo", description="Secure session creation with ECDHE handshake")

# Mount static files directory
app.mount("/static", StaticFiles(directory="."), name="static")

# Security headers middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'"
    return response

# In-memory storage (in production, use secure database)
sessions: Dict[str, Dict[str, Any]] = {}
handshake_nonces: Dict[str, Dict[str, Any]] = {}
dpop_nonces: Dict[str, Dict[str, Any]] = {}  # Store DPoP nonces per session
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Pydantic models
class HandshakeRequest(BaseModel):
    client_ecdhe_public_key: str

class RegistrationRequest(BaseModel):
    handshake_nonce: str
    browser_identity_public_key: str
    dpop_public_key: str
    browser_uuid: str
    browser_fingerprint_hash: str
    encrypted_payload: str

class DPoPRequest(BaseModel):
    encrypted_payload: Optional[str] = None
    browser_fingerprint_hash: Optional[str] = None
    dpop_nonce: Optional[str] = None

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the index.html page"""
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/handshake")
async def initiate_handshake(request: HandshakeRequest):
    """Initiate ECDHE handshake and return server nonce"""
    try:
        # Generate handshake nonce
        nonce = secrets.token_urlsafe(32)
        session_id = str(uuid.uuid4())
        
        # Import client's ECDHE public key
        logging.debug(f"Client ECDHE public key: {request.client_ecdhe_public_key}")
        client_public_key_bytes = base64.b64decode(request.client_ecdhe_public_key)
        client_public_key = serialization.load_der_public_key(client_public_key_bytes)
        
        # Generate server's ECDHE key pair
        server_ecdhe_private_key = ec.generate_private_key(ec.SECP256R1())
        server_ecdhe_public_key = server_ecdhe_private_key.public_key()
        
        # Derive shared secret
        shared_secret = server_ecdhe_private_key.exchange(
            ec.ECDH(), client_public_key
        )
        logging.debug(f"Shared secret: {base64.b64encode(shared_secret).decode()}")    
        
        # Derive Session Encryption Key (SEK) using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b"stronghold-handshake",
            info=b"session-encryption-key",
        )
        session_encryption_key = hkdf.derive(shared_secret)
        
        # Store handshake data
        handshake_nonces[nonce] = {
            "session_id": session_id,
            "client_ecdhe_public_key": request.client_ecdhe_public_key,
            "server_ecdhe_private_key": server_ecdhe_private_key,
            "session_encryption_key": session_encryption_key,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(minutes=5)
        }
        
        # Return server's ECDHE public key and nonce
        server_public_key_der = server_ecdhe_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return {
            "success": True,
            "handshake_nonce": nonce,
            "server_ecdhe_public_key": base64.b64encode(server_public_key_der).decode(),
            "session_id": session_id
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Handshake failed: {str(e)}")

@app.post("/register-session")
async def register_session(request: RegistrationRequest):
    """Register browser identity and DPoP keys over E2EE channel"""
    try:
        # Verify handshake nonce exists and is valid
        if request.handshake_nonce not in handshake_nonces:
            raise HTTPException(status_code=400, detail="Invalid or expired handshake nonce")
        
        handshake_data = handshake_nonces[request.handshake_nonce]
        
        # Check if handshake has expired
        if datetime.now() > handshake_data["expires_at"]:
            del handshake_nonces[request.handshake_nonce]
            raise HTTPException(status_code=400, detail="Handshake expired")
        
        # Decrypt the payload using SEK
        session_encryption_key = handshake_data["session_encryption_key"]
        aesgcm = AESGCM(session_encryption_key)
        
        # Extract nonce and ciphertext from encrypted payload
        encrypted_data = base64.b64decode(request.encrypted_payload)
        nonce = encrypted_data[:12]  # AES-GCM nonce is 12 bytes
        ciphertext = encrypted_data[12:]
        
        # Decrypt
        decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
        payload = json.loads(decrypted_payload.decode())
        
        # Verify the decrypted nonce matches
        if payload.get("handshake_nonce") != request.handshake_nonce:
            raise HTTPException(status_code=400, detail="Nonce mismatch")
        
        # Create session
        session_id = handshake_data["session_id"]
        logging.debug(f"Creating session at: {datetime.utcnow().timestamp()} UTC")
        session_token = create_session_token(session_id=session_id)
        
        # Store session data
        current_server_time = datetime.utcnow()
        sessions[session_id] = {
            "browser_identity_public_key": request.browser_identity_public_key,
            "browser_uuid": request.browser_uuid,
            "browser_fingerprint_hash": request.browser_fingerprint_hash,
            "session_encryption_key": session_encryption_key,
            "created_at": datetime.now(),
            "last_activity": datetime.now(),
            "session_created_time": current_server_time.timestamp()
        }
        
        logging.debug(f"Stored DPoP public key for session {session_id}: {request.dpop_public_key}")
        
        logging.debug(f"Session stored with ID: {session_id}")
        logging.debug(f"Total sessions: {len(sessions)}")
        logging.debug(f"Session keys: {list(sessions.keys())}")
        
        # Clean up handshake data
        del handshake_nonces[request.handshake_nonce]
        
        # Encrypt session token with SEK
        token_nonce = secrets.token_bytes(12)
        token_ciphertext = aesgcm.encrypt(token_nonce, session_token.encode(), None)
        encrypted_token = base64.b64encode(token_nonce + token_ciphertext).decode()
        
        return {
            "success": True,
            "session_id": session_id,
            "encrypted_session_token": encrypted_token
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")

@app.post("/verify-dpop")
async def verify_dpop(request: DPoPRequest, authorization: str = Header(None), dpop: str = Header(None)):
    """Verify DPoP proof and handle authenticated requests"""
    try:
        # Extract session token from Authorization header
        if not authorization or not authorization.startswith("DPoP "):
            raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
        
        session_token = authorization[5:]  # Remove "DPoP " prefix
        
        # Extract DPoP proof from DPoP header
        if not dpop:
            raise HTTPException(status_code=401, detail="Missing DPoP header")
        
        dpop_proof = dpop
        
        # Decode and verify session token
        session_data = verify_session_token(session_token)
        session_id = session_data["session_id"]
        
        logging.debug(f"Session token decoded, session_id: {session_id}")
        logging.debug(f"Available sessions: {list(sessions.keys())}")
        logging.debug(f"Session data: {session_data}")
        logging.debug(f"Current server time: {datetime.utcnow().timestamp()}")
        logging.debug(f"JWT token iat: {session_data.get('iat')}")
        
        if session_id not in sessions:
            logging.error(f"Session {session_id} not found in sessions")
            raise HTTPException(status_code=401, detail="Invalid session")
        
        session = sessions[session_id]
        logging.debug(f"Retrieved DPoP public key for session {session_id}: {session.get('dpop_public_key')}")
        logging.debug(f"Server session created time: {session.get('session_created_time')}")
        logging.debug(f"Time since JWT creation: {datetime.utcnow().timestamp() - session_data.get('iat')} seconds")
        logging.debug(f"Time since server session creation: {datetime.utcnow().timestamp() - session.get('session_created_time')} seconds")
        
        # Verify DPoP proof with full validation
        # For the first request, we don't require a nonce
        require_nonce = session_id in dpop_nonces
        
        if not verify_dpop_proof(
            dpop_proof, 
            method="POST",
            url="/verify-dpop",
            access_token=session_token,
            nonce=request.dpop_nonce if hasattr(request, 'dpop_nonce') and require_nonce else None,
            session_id=session_id
        ):
            raise HTTPException(status_code=401, detail="Invalid DPoP proof")
        
        # Verify browser fingerprint (if provided in request)
        if hasattr(request, 'browser_fingerprint_hash') and request.browser_fingerprint_hash:
            if request.browser_fingerprint_hash != session.get("browser_fingerprint_hash"):
                logging.warning(f"Fingerprint mismatch for session {session_id}")
                raise HTTPException(status_code=401, detail="Browser fingerprint mismatch")
        
        # Add browser identity data to response for client reference
        response_data = {
            "browser_uuid": session.get("browser_uuid"),
            "browser_identity_public_key": session.get("browser_identity_public_key")
        }
        
        # Update last activity
        session["last_activity"] = datetime.now()
        
        # Generate new DPoP nonce for next request
        new_nonce = generate_dpop_nonce(session_id)
        
        # Handle encrypted payload if provided
        decrypted_payload = None
        if request.encrypted_payload:
            session_encryption_key = session["session_encryption_key"]
            aesgcm = AESGCM(session_encryption_key)
            
            encrypted_data = base64.b64decode(request.encrypted_payload)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
        
        return {
            "success": True,
            "session_id": session_id,
            "browser_uuid": session["browser_uuid"],
            "browser_identity_public_key": session["browser_identity_public_key"],
            "decrypted_payload": decrypted_payload.decode() if decrypted_payload else None,
            "dpop_nonce": new_nonce
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DPoP verification failed: {str(e)}")

def create_session_token(session_id: str) -> str:
    """Create a signed session token with minimal sensitive data"""
    current_time = datetime.utcnow()
    logging.debug(f"Creating session token with time: {current_time.timestamp()} UTC")
    
    payload = {
        "session_id": session_id,
        "iat": current_time,
        "exp": current_time + timedelta(hours=24)
    }
    
    # In production, use a proper JWT library with the server's private key
    # Note: Session token is signed but not encrypted. For additional security,
    # consider encrypting with the Session Encryption Key (SEK) if the client
    # can handle decryption.
    return jwt.encode(payload, "server-secret-key", algorithm="HS256")

def verify_session_token(token: str) -> Dict[str, Any]:
    """Verify and decode session token"""
    try:
        payload = jwt.decode(token, "server-secret-key", algorithms=["HS256"])
        return payload
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid session token")

def generate_dpop_nonce(session_id: str) -> str:
    """Generate a fresh DPoP nonce for a session"""
    nonce = secrets.token_urlsafe(32)
    dpop_nonces[session_id] = {
        "nonce": nonce,
        "created_at": datetime.utcnow(),
        "used": False
    }
    return nonce

def validate_dpop_nonce(session_id: str, nonce: str) -> bool:
    """Validate that a DPoP nonce is fresh and unused"""
    if session_id not in dpop_nonces:
        return False
    
    nonce_data = dpop_nonces[session_id]
    
    # Check if nonce matches
    if nonce_data["nonce"] != nonce:
        return False
    
    # Check if nonce is already used
    if nonce_data["used"]:
        return False
    
    # Check if nonce is not too old (5 minutes)
    if datetime.utcnow() - nonce_data["created_at"] > timedelta(minutes=5):
        return False
    
    # Mark nonce as used
    nonce_data["used"] = True
    return True

def verify_dpop_proof(dpop_proof: str, method: str = None, url: str = None, access_token: str = None, nonce: str = None, session_id: str = None) -> bool:
    """Verify DPoP proof signature and claims"""
    try:
        logging.debug(f"Verifying DPoP proof: method={method}, url={url}, nonce={nonce}")
        
        # Parse the DPoP proof JWT
        parts = dpop_proof.split('.')
        if len(parts) != 3:
            logging.error("Invalid DPoP proof format: not a valid JWT")
            return False
        
        # Decode header and payload
        import base64
        import json
        
        # Decode header
        header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)  # Add padding
        header_json = base64.b64decode(header_b64).decode('utf-8')
        header = json.loads(header_json)
        
        # Decode payload
        payload_b64 = parts[1] + '=' * (4 - len(parts[1]) % 4)  # Add padding
        payload_json = base64.b64decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        
        # Verify JWT header
        logging.debug(f"DPoP header: {header}")
        if header.get('typ') != 'dpop+jwt':
            logging.error("Invalid DPoP proof: wrong typ")
            return False
        
        if header.get('alg') != 'ES256':
            logging.error("Invalid DPoP proof: wrong algorithm")
            return False
        
        # Verify JWT payload claims
        current_time = datetime.utcnow().timestamp()
        
        # Check expiration
        if 'exp' in payload and payload['exp'] < current_time:
            logging.error("DPoP proof expired")
            return False
        
        # Check issued at (not too old, not in future)
        if 'iat' in payload:
            logging.debug(f"DPoP proof iat: {payload['iat']}, current_time: {current_time}, difference: {current_time - payload['iat']} seconds")
            logging.debug(f"Server datetime.utcnow(): {datetime.utcnow()}")
            logging.debug(f"Server datetime.now(): {datetime.now()}")
            if payload['iat'] > current_time + 60:  # Allow 1 minute clock skew
                logging.error("DPoP proof issued in future")
                return False
            if payload['iat'] < current_time - 86400:  # Allow up to 24 hours for session-based requests
                logging.error("DPoP proof too old")
                return False
        
        # Verify HTTP method if provided
        logging.debug(f"DPoP payload: {payload}")
        if method and payload.get('htm') != method:
            logging.error(f"DPoP proof method mismatch: expected {method}, got {payload.get('htm')}")
            return False
        
        # Verify HTTP URL if provided
        if url and payload.get('htu') != url:
            logging.error(f"DPoP proof URL mismatch: expected {url}, got {payload.get('htu')}")
            return False
        
        # Verify access token hash if provided
        if access_token:
            import hashlib
            token_hash = base64.b64encode(hashlib.sha256(access_token.encode()).digest()).decode().rstrip('=')
            logging.debug(f"Access token: {access_token}")
            logging.debug(f"Expected token hash: {token_hash}")
            logging.debug(f"Received token hash: {payload.get('ath')}")
            if payload.get('ath') != token_hash:
                logging.error("DPoP proof access token hash mismatch")
                return False
        
        # Verify nonce if provided
        if nonce and session_id:
            if payload.get('nonce') != nonce:
                logging.error("DPoP proof nonce mismatch")
                return False
            
            if not validate_dpop_nonce(session_id, nonce):
                logging.error("DPoP proof nonce validation failed")
                return False
        
        # Verify JWT signature
        try:
            # Extract public key from DPoP proof header
            if 'jwk' not in header:
                logging.error("DPoP proof missing jwk in header")
                return False
            
            jwk = header['jwk']
            if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
                logging.error("DPoP proof jwk has wrong key type or curve")
                return False
            
            # Convert JWK to DER format for cryptography library
            x_bytes = base64.b64decode(jwk['x'] + '=' * (4 - len(jwk['x']) % 4))
            y_bytes = base64.b64decode(jwk['y'] + '=' * (4 - len(jwk['y']) % 4))
            
            # Create DER public key
            from cryptography.hazmat.primitives.asymmetric import ec
            public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, 'big'),
                int.from_bytes(y_bytes, 'big'),
                ec.SECP256R1()
            )
            dpop_public_key_obj = public_numbers.public_key()
            
            # Create the signature input
            signature_input = f"{parts[0]}.{parts[1]}"
            signature_input_bytes = signature_input.encode('utf-8')
            
            # Decode the signature (Web Crypto API returns raw ECDSA signature)
            signature_b64 = parts[2] + '=' * (4 - len(parts[2]) % 4)  # Add padding
            signature_bytes = base64.b64decode(signature_b64)
            
            # Web Crypto API returns raw ECDSA signature (r||s, each 32 bytes for P-256)
            # Verify the signature directly
            logging.debug(f"Verifying signature with input: {signature_input}")
            logging.debug(f"Signature length: {len(signature_bytes)} bytes")
            logging.debug(f"Signature bytes (hex): {signature_bytes.hex()}")
            logging.debug(f"Public key extracted from DPoP proof header")
            logging.debug(f"Public key type: {type(dpop_public_key_obj)}")
            
            
            # Extract r and s from raw signature (first 32 bytes = r, last 32 bytes = s)
            r = int.from_bytes(signature_bytes[:32], 'big')
            s = int.from_bytes(signature_bytes[32:], 'big')
            
            # Convert cryptography public key to ecdsa format
            public_numbers = dpop_public_key_obj.public_numbers()
            verifying_key = VerifyingKey.from_public_point(
                ecdsa.ellipticcurve.Point(NIST256p.curve, public_numbers.x, public_numbers.y),
                curve=NIST256p
            )
            
            # Verify signature using raw bytes
            verifying_key.verify(signature_bytes, signature_input_bytes, hashfunc=hashlib.sha256)
            
            logging.debug("DPoP proof signature verified successfully")
            return True
            
        except Exception as e:
            logging.error(f"DPoP proof signature verification failed: {str(e)}")
            logging.error(f"Exception type: {type(e).__name__}")
            import traceback
            logging.error(f"Full traceback: {traceback.format_exc()}")
            return False
        
    except Exception as e:
        logging.error(f"DPoP proof verification error: {str(e)}")
        return False



if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=True) 