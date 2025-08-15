from fastapi import FastAPI, HTTPException, Request, Response, Header, Cookie
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
browser_sessions: Dict[str, str] = {}  # Map browser_uuid to session_id
invalidated_sessions: set = set()  # Track invalidated sessions
rate_limit_attempts: Dict[str, Dict[str, Any]] = {}  # Rate limiting per IP
challenges: Dict[str, Dict[str, Any]] = {}  # Store challenges for session restoration

# Generate cryptographically secure secret for JWT signing
import os
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_urlsafe(64))
server_private_key = ec.generate_private_key(ec.SECP256R1())
server_public_key = server_private_key.public_key()

# Pydantic models
class HandshakeRequest(BaseModel):
    client_ecdhe_public_key: str

class RegistrationRequest(BaseModel):
    handshake_nonce: str
    browser_identity_public_key: str
    browser_uuid: str
    encrypted_payload: str

class DPoPRequest(BaseModel):
    encrypted_payload: Optional[str] = None

class ChallengeRequest(BaseModel):
    browser_uuid: str

class ChallengeResponse(BaseModel):
    challenge: str
    session_id: str

class ChallengeVerificationRequest(BaseModel):
    session_id: str
    challenge: str
    signature: str

class SessionKeyUpdateRequest(BaseModel):
    session_id: str
    handshake_nonce: str







@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the index.html page"""
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.get("/check-session/{browser_uuid}")
async def check_session(browser_uuid: str):
    """Check if a browser UUID has an existing session"""
    try:
        if browser_uuid in browser_sessions:
            session_id = browser_sessions[browser_uuid]
            if session_id in sessions:
                session = sessions[session_id]
                return {
                    "has_session": True,
                    "session_id": session_id,
                    "browser_uuid": browser_uuid,
                    "created_at": session["created_at"].isoformat(),
                    "last_activity": session["last_activity"].isoformat()
                }
        
        return {
            "has_session": False,
            "browser_uuid": browser_uuid
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Session check failed: {str(e)}")

@app.post("/request-challenge")
async def request_challenge(request: ChallengeRequest):
    """Request a challenge for session restoration"""
    try:
        browser_uuid = request.browser_uuid
        
        # Check if browser UUID has an existing session
        if browser_uuid not in browser_sessions:
            raise HTTPException(status_code=404, detail="No session found for browser UUID")
        
        session_id = browser_sessions[browser_uuid]
        if session_id not in sessions:
            raise HTTPException(status_code=404, detail="Session not found")
        
        session = sessions[session_id]
        
        # Generate a random challenge
        challenge = secrets.token_urlsafe(32)
        
        # Store challenge with expiration (5 minutes)
        challenges[session_id] = {
            "challenge": challenge,
            "browser_uuid": browser_uuid,
            "browser_identity_public_key": session.get("browser_identity_public_key"),
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(minutes=5)
        }
        
        logging.info(f"Generated challenge for session {session_id}: {challenge}")
        logging.info(f"Stored browser identity public key: {session.get('browser_identity_public_key')}")
        
        return ChallengeResponse(
            challenge=challenge,
            session_id=session_id
        )
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Challenge request failed: {str(e)}")

@app.post("/verify-challenge")
async def verify_challenge(request: ChallengeVerificationRequest):
    """Verify challenge signature and restore session"""
    try:
        session_id = request.session_id
        challenge = request.challenge
        signature = request.signature
        
        # Check if challenge exists and is valid
        if session_id not in challenges:
            raise HTTPException(status_code=400, detail="Invalid or expired challenge")
        
        challenge_data = challenges[session_id]
        
        # Check if challenge matches
        if challenge_data["challenge"] != challenge:
            raise HTTPException(status_code=400, detail="Challenge mismatch")
        
        # Check if challenge has expired
        if datetime.utcnow() > challenge_data["expires_at"]:
            del challenges[session_id]
            raise HTTPException(status_code=400, detail="Challenge expired")
        
        # Verify signature using stored browser identity public key
        browser_identity_public_key = challenge_data["browser_identity_public_key"]
        if not browser_identity_public_key:
            raise HTTPException(status_code=400, detail="No browser identity public key found")
        
        # Import the public key
        public_key_bytes = base64.b64decode(browser_identity_public_key)
        public_key_obj = serialization.load_der_public_key(public_key_bytes)
        
        # Verify the signature
        try:
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Create signature input (challenge string)
            challenge_bytes = challenge.encode('utf-8')
            
            # Web Crypto API returns raw ECDSA signature (r||s, each 32 bytes for P-256)
            # Convert to DER format for Python cryptography library
            if len(signature_bytes) == 64:  # Raw signature (32 + 32 bytes)
                r = int.from_bytes(signature_bytes[:32], 'big')
                s = int.from_bytes(signature_bytes[32:], 'big')
                
                # Create DER signature
                from cryptography.hazmat.primitives.asymmetric import utils
                der_signature = utils.encode_dss_signature(r, s)
            else:
                # Assume it's already DER encoded
                der_signature = signature_bytes
            
            # Verify signature using cryptography library
            public_key_obj.verify(
                der_signature,
                challenge_bytes,
                ec.ECDSA(hashes.SHA256())
            )
            
            logging.info(f"Challenge signature verified for session {session_id}")
            
            # Clean up challenge
            del challenges[session_id]
            
            # Return success response with session restoration data
            return {
                "success": True,
                "session_id": session_id,
                "browser_uuid": challenge_data["browser_uuid"],
                "message": "Challenge verified successfully"
            }
            
        except Exception as e:
            logging.error(f"Challenge signature verification failed: {str(e)}")
            raise HTTPException(status_code=401, detail="Invalid signature")
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Challenge verification failed: {str(e)}")

@app.post("/update-session-key")
async def update_session_key(request: SessionKeyUpdateRequest, session_id: str = Cookie(None)):
    """Update session encryption key using handshake nonce after ECDHE handshake"""
    try:
        # Verify session exists
        if session_id not in sessions:
            raise HTTPException(status_code=401, detail="Invalid session")
        
        # Verify handshake nonce exists and is valid
        if request.handshake_nonce not in handshake_nonces:
            raise HTTPException(status_code=400, detail="Invalid or expired handshake nonce")
        
        handshake_data = handshake_nonces[request.handshake_nonce]
        
        # Check if handshake has expired
        if datetime.now() > handshake_data["expires_at"]:
            del handshake_nonces[request.handshake_nonce]
            raise HTTPException(status_code=400, detail="Handshake expired")
        
        # Update session with new encryption key from handshake
        session = sessions[session_id]
        session["session_encryption_key"] = handshake_data["session_encryption_key"]
        session["last_activity"] = datetime.now()
        
        logging.info(f"Updated session encryption key for session {session_id} using handshake nonce {request.handshake_nonce}")
        
        # Clean up handshake data
        del handshake_nonces[request.handshake_nonce]
        
        return {
            "success": True,
            "message": "Session encryption key updated successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Session key update failed: {str(e)}")

@app.post("/debug/clear-rate-limits")
async def clear_rate_limits():
    """Clear all rate limiting data for testing"""
    try:
        global rate_limit_attempts
        cleared_count = len(rate_limit_attempts)
        rate_limit_attempts.clear()
        logging.info(f"Cleared rate limiting data for {cleared_count} IPs")
        return {
            "success": True,
            "message": f"Cleared rate limiting data for {cleared_count} IPs",
            "cleared_count": cleared_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to clear rate limits: {str(e)}")

@app.get("/debug/rate-limits")
async def get_rate_limit_debug(request: Request):
    """Debug endpoint to show current rate limiting state"""
    try:
        # Extract client IP for rate limiting
        client_ip = request.client.host if request.client else None
        logging.debug(f"Rate limit debug - Client IP: {client_ip}")
        
        # Apply rate limiting to this endpoint too
        if client_ip:
            current_time = datetime.utcnow()
            if client_ip not in rate_limit_attempts:
                rate_limit_attempts[client_ip] = {"count": 0, "window_start": current_time}
            
            # Reset window if more than 1 minute has passed
            if current_time - rate_limit_attempts[client_ip]["window_start"] > timedelta(minutes=1):
                rate_limit_attempts[client_ip] = {"count": 0, "window_start": current_time}
            
            # Increment attempt count
            rate_limit_attempts[client_ip]["count"] += 1
            logging.debug(f"Rate limit debug - attempts: {rate_limit_attempts[client_ip]}")
            
            # Block if more than 3 attempts per minute
            logging.debug(f"Rate limit debug - check: {rate_limit_attempts[client_ip]['count']} attempts for IP {client_ip}")
            if rate_limit_attempts[client_ip]["count"] > 3:
                logging.warning(f"Rate limit exceeded for IP {client_ip}: {rate_limit_attempts[client_ip]['count']} attempts")
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        return {
            "rate_limit_attempts": rate_limit_attempts,
            "total_ips": len(rate_limit_attempts),
            "current_time": datetime.utcnow().isoformat(),
            "client_ip": client_ip
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rate limit debug failed: {str(e)}")

@app.get("/debug/data")
async def get_debug_data():
    """Debug endpoint to return all internal data structures for testing"""
    try:
        # Convert datetime objects to strings for JSON serialization
        def serialize_datetime(obj):
            if isinstance(obj, datetime):
                return obj.isoformat()
            return obj
        
        # Safe serialization function
        def safe_serialize(obj):
            try:
                if isinstance(obj, bytes):
                    return f"[Binary Data - {len(obj)} bytes]"
                elif isinstance(obj, datetime):
                    return obj.isoformat()
                elif hasattr(obj, '__dict__'):
                    # Handle objects with attributes
                    return f"[Object: {type(obj).__name__}]"
                else:
                    return obj
            except Exception:
                return f"[Unserializable: {type(obj).__name__}]"
        
        # Process sessions data
        serialized_sessions = {}
        for session_id, session_data in sessions.items():
            serialized_session = {}
            for key, value in session_data.items():
                if key in ['session_encryption_key', 'server_ecdhe_private_key']:
                    # Hide sensitive cryptographic data
                    serialized_session[key] = "[REDACTED - Cryptographic Key]"
                else:
                    serialized_session[key] = safe_serialize(value)
            serialized_sessions[session_id] = serialized_session
        
        # Process handshake nonces data
        serialized_handshake_nonces = {}
        for nonce, nonce_data in handshake_nonces.items():
            serialized_nonce_data = {}
            for key, value in nonce_data.items():
                if key in ['session_encryption_key', 'server_ecdhe_private_key']:
                    serialized_nonce_data[key] = "[REDACTED - Cryptographic Key]"
                else:
                    serialized_nonce_data[key] = safe_serialize(value)
            serialized_handshake_nonces[nonce] = serialized_nonce_data
        
        # Process DPoP nonces data
        serialized_dpop_nonces = {}
        for session_id, nonce_data in dpop_nonces.items():
            serialized_nonce_data = {}
            for key, value in nonce_data.items():
                serialized_nonce_data[key] = safe_serialize(value)
            serialized_dpop_nonces[session_id] = serialized_nonce_data
        
        # Process challenges data
        serialized_challenges = {}
        for session_id, challenge_data in challenges.items():
            serialized_challenge_data = {}
            for key, value in challenge_data.items():
                serialized_challenge_data[key] = safe_serialize(value)
            serialized_challenges[session_id] = serialized_challenge_data
        
        # Process rate limiting data
        serialized_rate_limits = {}
        for ip, rate_data in rate_limit_attempts.items():
            serialized_rate_data = {}
            for key, value in rate_data.items():
                serialized_rate_data[key] = safe_serialize(value)
            serialized_rate_limits[ip] = serialized_rate_data
        
        debug_data = {
            "timestamp": datetime.utcnow().isoformat(),
            "server_info": {
                "jwt_secret_length": len(JWT_SECRET),
                "server_public_key_available": server_public_key is not None
            },
            "sessions": {
                "count": len(sessions),
                "session_ids": list(sessions.keys()),
                "data": serialized_sessions
            },
            "browser_sessions": {
                "count": len(browser_sessions),
                "mappings": browser_sessions
            },
            "handshake_nonces": {
                "count": len(handshake_nonces),
                "nonces": list(handshake_nonces.keys()),
                "data": serialized_handshake_nonces
            },
            "dpop_nonces": {
                "count": len(dpop_nonces),
                "session_ids": list(dpop_nonces.keys()),
                "data": serialized_dpop_nonces
            },
            "challenges": {
                "count": len(challenges),
                "session_ids": list(challenges.keys()),
                "data": serialized_challenges
            },
            "invalidated_sessions": {
                "count": len(invalidated_sessions),
                "session_ids": list(invalidated_sessions)
            },
            "rate_limiting": {
                "count": len(rate_limit_attempts),
                "ips": list(rate_limit_attempts.keys()),
                "data": serialized_rate_limits
            }
        }
        
        return debug_data
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Debug data retrieval failed: {str(e)}")


@app.post("/invalidate-session")
async def invalidate_session(session_id: str = Cookie(None)):
    """Invalidate the current session (for security purposes)"""
    try:
        if not session_id:
            raise HTTPException(status_code=401, detail="Missing session cookie")
        
        if session_id in sessions:
            # Remove session data
            del sessions[session_id]
            
            # Remove from browser sessions mapping
            browser_uuid = sessions.get(session_id, {}).get("browser_uuid")
            if browser_uuid and browser_uuid in browser_sessions:
                del browser_sessions[browser_uuid]
            
            # Clean up DPoP nonces
            if session_id in dpop_nonces:
                del dpop_nonces[session_id]
            
            logging.info(f"Session {session_id} invalidated successfully")
            
            # Return response that clears the cookie
            from fastapi.responses import JSONResponse
            response = JSONResponse(content={"success": True, "message": "Session invalidated"})
            response.delete_cookie("session_id")
            return response
        else:
            raise HTTPException(status_code=404, detail="Session not found")
            
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Session invalidation failed: {str(e)}")

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
async def register_session(request: RegistrationRequest, dpop: str = Header(None)):
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
        
        # Extract DPoP public key from DPoP proof header
        if not dpop:
            raise HTTPException(status_code=400, detail="Missing DPoP header for registration")
        
        # Parse DPoP proof to extract public key
        try:
            parts = dpop.split('.')
            if len(parts) != 3:
                raise HTTPException(status_code=400, detail="Invalid DPoP proof format")
            
            # Decode header to get JWK
            header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)  # Add padding
            header_json = base64.b64decode(header_b64).decode('utf-8')
            header = json.loads(header_json)
            
            if 'jwk' not in header:
                raise HTTPException(status_code=400, detail="DPoP proof missing jwk header")
            
            # Convert JWK to DER format for storage
            jwk = header['jwk']
            if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
                raise HTTPException(status_code=400, detail="DPoP proof jwk has wrong key type or curve")
            
            x_bytes = base64.b64decode(jwk['x'] + '=' * (4 - len(jwk['x']) % 4))
            y_bytes = base64.b64decode(jwk['y'] + '=' * (4 - len(jwk['y']) % 4))
            
            # Create DER public key from JWK
            from cryptography.hazmat.primitives.asymmetric import ec
            jwk_public_numbers = ec.EllipticCurvePublicNumbers(
                int.from_bytes(x_bytes, 'big'),
                int.from_bytes(y_bytes, 'big'),
                ec.SECP256R1()
            )
            jwk_public_key_obj = jwk_public_numbers.public_key()
            
            # Convert to DER format for storage
            dpop_public_key_der = jwk_public_key_obj.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            dpop_public_key = base64.b64encode(dpop_public_key_der).decode()
            
        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Failed to extract DPoP public key: {str(e)}")
        
        # Check if a session already exists for this browser UUID
        existing_session_id = None
        if request.browser_uuid in browser_sessions:
            existing_session_id = browser_sessions[request.browser_uuid]
            if existing_session_id in sessions:
                logging.debug(f"Reusing existing session {existing_session_id} for browser UUID {request.browser_uuid}")
                session_id = existing_session_id
            else:
                # Session exists in mapping but not in sessions (expired/cleared)
                logging.debug(f"Session {existing_session_id} not found in sessions, creating new one")
                existing_session_id = None
        
        if not existing_session_id:
            # Create new session
            session_id = handshake_data["session_id"]
            logging.debug(f"Creating new session at: {datetime.utcnow().timestamp()} UTC")
            
            # Store session data
            current_server_time = datetime.utcnow()
            sessions[session_id] = {
                "browser_identity_public_key": request.browser_identity_public_key,
                "dpop_public_key": dpop_public_key,  # Store DPoP public key from proof
                "browser_uuid": request.browser_uuid,
                "session_encryption_key": session_encryption_key,
                "created_at": datetime.now(),
                "last_activity": datetime.now(),
                "session_created_time": current_server_time.timestamp()
            }
            
            # Map browser UUID to session ID for session recovery
            browser_sessions[request.browser_uuid] = session_id
        else:
            # Update existing session with new keys
            logging.debug(f"Updating existing session {session_id} with new keys")
            sessions[session_id].update({
                "browser_identity_public_key": request.browser_identity_public_key,
                "dpop_public_key": dpop_public_key,  # Use extracted DPoP public key
                "session_encryption_key": session_encryption_key,
                "last_activity": datetime.now()
            })
        
        # Generate initial DPoP nonce for the session
        initial_nonce = generate_dpop_nonce(session_id)
        
        logging.debug(f"Stored DPoP public key for session {session_id}: {dpop_public_key}")
        logging.debug(f"Mapped browser UUID {request.browser_uuid} to session {session_id}")
        logging.debug(f"Generated initial nonce for session {session_id}: {initial_nonce}")
        
        logging.debug(f"Session stored with ID: {session_id}")
        logging.debug(f"Total sessions: {len(sessions)}")
        logging.debug(f"Session keys: {list(sessions.keys())}")
        logging.debug(f"Browser sessions: {browser_sessions}")
        
        # Clean up handshake data
        del handshake_nonces[request.handshake_nonce]
        
        # Create response with HTTP-only cookie for session persistence
        response_data = {
            "success": True,
            "session_id": session_id,
            "browser_uuid": request.browser_uuid,
            "initial_dpop_nonce": initial_nonce
        }
        
        # Set HTTP-only cookie for session persistence
        from fastapi.responses import JSONResponse
        response = JSONResponse(content=response_data)
        response.set_cookie(
            "session_id",
            session_id,
            httponly=True,
            secure=True,
            samesite="strict",
            max_age=86400  # 24 hours
        )
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")

@app.post("/verify-dpop")
async def verify_dpop(request: DPoPRequest, http_request: Request, dpop: str = Header(None), dpop_nonce: str = Header(None), session_id: str = Cookie(None)):
    """Verify DPoP proof and handle authenticated requests"""
    try:
        # Extract client IP for rate limiting
        client_ip = http_request.client.host if http_request.client else None
        logging.debug(f"Client IP: {client_ip}")
        
        # Basic rate limiting (in production, use Redis or similar)
        if client_ip:
            current_time = datetime.utcnow()
            if client_ip not in rate_limit_attempts:
                rate_limit_attempts[client_ip] = {"count": 0, "window_start": current_time}
            
            # Reset window if more than 1 minute has passed
            if current_time - rate_limit_attempts[client_ip]["window_start"] > timedelta(minutes=1):
                rate_limit_attempts[client_ip] = {"count": 0, "window_start": current_time}
            
            # Increment attempt count
            rate_limit_attempts[client_ip]["count"] += 1
            logging.debug(f"Rate limit attempts: {rate_limit_attempts[client_ip]}")
            
            # Block if more than 3 attempts per minute (temporarily lowered for testing)
            logging.debug(f"Rate limit check: {rate_limit_attempts[client_ip]['count']} attempts for IP {client_ip}")
            if rate_limit_attempts[client_ip]["count"] > 3:
                logging.warning(f"Rate limit exceeded for IP {client_ip}: {rate_limit_attempts[client_ip]['count']} attempts")
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
        
        # Extract session ID from HTTP-only cookie
        if not session_id:
            raise HTTPException(status_code=401, detail="Missing session cookie")
        
        # Extract DPoP proof from DPoP header
        if not dpop:
            raise HTTPException(status_code=401, detail="Missing DPoP header")
        
        dpop_proof = dpop
        
        # Verify session exists
        if session_id not in sessions:
            raise HTTPException(status_code=401, detail="Invalid session")
        
        logging.debug(f"Session ID from cookie: {session_id}")
        logging.debug(f"Available sessions: {list(sessions.keys())}")
        logging.debug(f"Current server time: {datetime.utcnow().timestamp()}")
        
        if session_id not in sessions:
            logging.error(f"Session {session_id} not found in sessions")
            raise HTTPException(status_code=401, detail="Invalid session")
        
        session = sessions[session_id]
        
        # Session bindings are validated through DPoP proof verification
        # Browser UUID is bound to the DPoP key pair
        
        logging.debug(f"Retrieved DPoP public key for session {session_id}: {session.get('dpop_public_key')}")
        logging.debug(f"Server session created time: {session.get('session_created_time')}")
        logging.debug(f"Time since server session creation: {datetime.utcnow().timestamp() - session.get('session_created_time')} seconds")
        
        # Log the DPoP proof header for debugging
        logging.debug(f"DPoP proof header: {dpop[:100]}...")
        
        # Verify DPoP proof with full validation
        # For the first request, we don't require a nonce
        require_nonce = session_id in dpop_nonces
        
        stored_dpop_key = session.get("dpop_public_key")
        logging.debug(f"About to verify DPoP proof with stored key: {stored_dpop_key[:50] if stored_dpop_key else 'None'}...")
        
        # Log the DPoP proof to extract the public key for comparison
        try:
            parts = dpop_proof.split('.')
            if len(parts) == 3:
                header_b64 = parts[0] + '=' * (4 - len(parts[0]) % 4)
                header_json = base64.b64decode(header_b64).decode('utf-8')
                header = json.loads(header_json)
                
                if 'jwk' in header:
                    jwk = header['jwk']
                    logging.debug(f"DPoP proof contains JWK with x: {jwk.get('x', '')[:20]}...")
                    logging.debug(f"DPoP proof contains JWK with y: {jwk.get('y', '')[:20]}...")
        except Exception as e:
            logging.debug(f"Could not extract JWK from DPoP proof: {e}")
        
        verification_result = verify_dpop_proof(
            dpop_proof, 
            method="POST",
            url="/verify-dpop",
            nonce=dpop_nonce if require_nonce else None,
            session_id=session_id,
            stored_dpop_public_key=stored_dpop_key
        )
        
        if not verification_result:
            logging.error(f"DPoP verification failed for session {session_id}")
            raise HTTPException(status_code=401, detail="Invalid DPoP proof")
        
        # Browser UUID is already validated through session binding
        # No need to validate it again from request body
        
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
        encrypted_payload_received = None
        if request.encrypted_payload:
            encrypted_payload_received = request.encrypted_payload
            session_encryption_key = session["session_encryption_key"]
            aesgcm = AESGCM(session_encryption_key)
            
            encrypted_data = base64.b64decode(request.encrypted_payload)
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            
            decrypted_payload = aesgcm.decrypt(nonce, ciphertext, None)
            
            # Log the decrypted message for verification
            try:
                decrypted_json = json.loads(decrypted_payload.decode())
                if 'message' in decrypted_json:
                    logging.info(f"🔓 DECRYPTED MESSAGE from session {session_id}: '{decrypted_json['message']}'")
                    print(f"🔓 DECRYPTED MESSAGE from session {session_id}: '{decrypted_json['message']}'")
            except Exception as e:
                logging.warning(f"Could not parse decrypted payload as JSON: {e}")
        
        # Create server response message
        server_message = {
            "message": "Hello from Stronghold server!"
        }
        
        # Encrypt server response with session encryption key
        server_nonce = secrets.token_bytes(12)
        server_ciphertext = aesgcm.encrypt(server_nonce, json.dumps(server_message).encode(), None)
        encrypted_server_response = base64.b64encode(server_nonce + server_ciphertext).decode()
        
        # Log the server message for verification
        logging.info(f"🔒 ENCRYPTED SERVER MESSAGE for session {session_id}: '{server_message['message']}'")
        print(f"🔒 ENCRYPTED SERVER MESSAGE for session {session_id}: '{server_message['message']}'")
        
        # Create response with encrypted server payload
        response_data = {
            "success": True,
            "encrypted_payload": encrypted_server_response
        }
        
        # Return Response object with proper DPoP-Nonce header as per RFC 9449
        from fastapi.responses import JSONResponse
        response = JSONResponse(content=response_data)
        response.headers["DPoP-Nonce"] = new_nonce
        
        return response
        
    except Exception as e:
        logging.error(f"Exception in /verify-dpop endpoint: {str(e)}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        raise HTTPException(status_code=400, detail=f"DPoP verification failed: {str(e)}")

# Session token functions removed - using HTTP-only cookies instead

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

def verify_dpop_proof(dpop_proof: str, method: str = None, url: str = None, nonce: str = None, session_id: str = None, stored_dpop_public_key: str = None) -> bool:
    """Verify DPoP proof signature and claims"""
    try:
        logging.debug(f"Verifying DPoP proof: method={method}, url={url}, nonce={nonce}")
        logging.debug(f"DPoP proof length: {len(dpop_proof)}")
        logging.debug(f"Stored DPoP public key length: {len(stored_dpop_public_key) if stored_dpop_public_key else 'None'}")
        
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
                logging.error(f"DPoP proof too old: iat={payload['iat']}, current={current_time}, diff={current_time - payload['iat']} seconds")
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
        
        # No access token validation needed - we're using session-based authentication
        
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
            # Use stored DPoP public key for verification
            if not stored_dpop_public_key:
                logging.error("No stored DPoP public key found for session")
                return False
            
            # Import the stored DPoP public key
            stored_public_key_bytes = base64.b64decode(stored_dpop_public_key)
            dpop_public_key_obj = serialization.load_der_public_key(stored_public_key_bytes)
            
            # Verify that the JWT header contains the same public key (security check)
            if 'jwk' in header:
                jwk = header['jwk']
                if jwk.get('kty') != 'EC' or jwk.get('crv') != 'P-256':
                    logging.error("DPoP proof jwk has wrong key type or curve")
                    return False
                
                # Convert JWK to DER format for comparison
                x_bytes = base64.b64decode(jwk['x'] + '=' * (4 - len(jwk['x']) % 4))
                y_bytes = base64.b64decode(jwk['y'] + '=' * (4 - len(jwk['y']) % 4))
                
                # Create DER public key from JWK
                from cryptography.hazmat.primitives.asymmetric import ec
                jwk_public_numbers = ec.EllipticCurvePublicNumbers(
                    int.from_bytes(x_bytes, 'big'),
                    int.from_bytes(y_bytes, 'big'),
                    ec.SECP256R1()
                )
                jwk_public_key_obj = jwk_public_numbers.public_key()
                
                # Compare the public keys
                if dpop_public_key_obj.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ) != jwk_public_key_obj.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                ):
                    logging.error("DPoP proof public key mismatch with stored key")
                    return False
            
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
            logging.debug("DPoP proof verification completed successfully - returning True")
            return True
            
        except Exception as e:
            logging.error(f"DPoP proof signature verification failed: {str(e)}")
            logging.error(f"Exception type: {type(e).__name__}")
            import traceback
            logging.error(f"Full traceback: {traceback.format_exc()}")
            return False
        
    except Exception as e:
        logging.error(f"DPoP proof verification error: {str(e)}")
        import traceback
        logging.error(f"Full traceback: {traceback.format_exc()}")
        return False



if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8001, reload=True) 