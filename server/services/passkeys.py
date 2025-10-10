# server/services/passkeys.py
import logging
import json
import secrets
from typing import Dict, Any
from urllib.parse import urlsplit

import cbor2
from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse

from server.core.config import load_settings
from server.db.session import SessionDB
from server.utils.helpers import (
    b64u, b64u_dec, now, cose_to_jwk, 
    jwk_to_public_key, parse_authenticator_data,
    canonicalize_origin_and_url
)
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

SETTINGS = load_settings()
logging.basicConfig(level=SETTINGS.log_level, format="%(asctime)s %(levelname)s [%(name)s.%(funcName)s] %(message)s")
log = logging.getLogger(__name__)



class PasskeyService:
    """Service for WebAuthn/Passkey operations"""
    
    @staticmethod
    def _rp_id_from_origin(origin: str) -> str:
        """Extract RP ID (domain) from origin URL"""
        host = urlsplit(origin).hostname or "localhost"
        return host
    
    @staticmethod
    async def get_registration_options(session_id: str, session_data: Dict[str, Any], request: Request, body: Dict[str, Any]) -> Dict[str, Any]:
        # Get username from request body
        username = body.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Username is required for passkey registration")
        
        origin, _ = canonicalize_origin_and_url(request)
        rp_id = PasskeyService._rp_id_from_origin(origin)
        
        # Generate challenge
        challenge = secrets.token_bytes(32)
        
        # Store challenge for validation (5 minutes TTL)
        expires_at = now() + 300  # 5 minutes
        if not session_id:
            raise HTTPException(status_code=401, detail="No session ID in session data")
        await SessionDB.store_webauthn_challenge(session_id, "registration", b64u(challenge), expires_at)
        
        # Get existing credentials for this username to exclude
        existing_credentials = await SessionDB.pk_get_for_principal(username)
        exclude_credentials = [
            {
                "id": cred["cred_id"],
                "type": "public-key",
                "transports": cred.get("transports", [])
            }
            for cred in existing_credentials
        ]
        
        return {
            "rp": {"id": rp_id, "name": "DPoP-Fun Demo"},
            "user": {
                "id": b64u(username.encode()),
                "name": username,
                "displayName": username
            },
            "challenge": b64u(challenge),
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},    # ES256
                {"type": "public-key", "alg": -257},  # RS256
                {"type": "public-key", "alg": -8},    # EdDSA
            ],
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "residentKey": "preferred",
                "userVerification": "required",
                "requireResidentKey": True
            },
            "attestation": "none",
            "excludeCredentials": exclude_credentials,
        }
    
    @staticmethod
    async def verify_registration(session_id: str, request: Request, attestation_data: Dict[str, Any]) -> Dict[str, Any]:
        # Get username from attestation_data (passed from client)
        username = attestation_data.get("username")
        if not username:
            raise HTTPException(status_code=400, detail="Username is required for passkey registration")
        
        origin, _ = canonicalize_origin_and_url(request)
        rp_id = PasskeyService._rp_id_from_origin(origin)
        
        # Parse client data
        try:
            clientDataJSON = b64u_dec(attestation_data["response"]["clientDataJSON"])
            client = json.loads(clientDataJSON)
        except Exception:
            raise HTTPException(status_code=400, detail="bad clientDataJSON")
        
        # Validate client data
        if client.get("type") != "webauthn.create":
            raise HTTPException(status_code=400, detail="wrong clientData type")
        if client.get("origin") != origin:
            raise HTTPException(status_code=400, detail="origin mismatch")
        
        # Validate challenge
        challenge = client.get("challenge")
        if not challenge:
            raise HTTPException(status_code=400, detail="missing challenge")
        
        is_valid = await SessionDB.validate_webauthn_challenge(session_id, "registration", challenge)
        if not is_valid:
            raise HTTPException(status_code=400, detail="invalid or expired challenge")
        
        # Parse attestation object
        attObj = b64u_dec(attestation_data["response"]["attestationObject"])
        att = cbor2.loads(attObj)
        authData = att.get("authData")
        fmt = att.get("fmt")
        
        # Parse authenticator data
        import hashlib
        info = parse_authenticator_data(authData)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        if info["rpIdHash"] != rp_hash:
            raise HTTPException(status_code=400, detail="rpIdHash mismatch")
        
        # Extract credential
        jwk = cose_to_jwk(info.get("rest") or b"")
        aaguid_hex = (info.get("aaguid") or b"").hex() or None
        sign_count = info["signCount"]
        cred_id = b64u(info["credId"])
        
        # Get device type from session to track where passkey was created
        session = await SessionDB.get_session(session_id)
        device_type = session.get("device_type") if session else None
        
        # Store passkey in dedicated passkey table (keyed by username, not device_id)
        await SessionDB.pk_upsert(username, {
            "cred_id": cred_id,
            "public_key_jwk": jwk,
            "sign_count": sign_count,
            "aaguid": aaguid_hex,
            "transports": attestation_data.get("transports", ["internal"]),
            "device_type": device_type,
            "created_at": now()
        })
        
        # Update session auth method, status, and username
        await SessionDB.update_session_auth_status(session_id, "Passkey", "authenticated", username)
        
        log.info(f"Passkey registered for username: {username}, session: {session_id}, cred_id: {cred_id[:16]}")
        
        return {"ok": True, "cred_id": cred_id, "aaguid": aaguid_hex, "username": username}
    
    @staticmethod
    async def get_authentication_options(session_id: str, session_data: Dict[str, Any], request: Request, body: Dict[str, Any] = None) -> Dict[str, Any]:
        # Get username from request body (optional - if not provided, allow any credential)
        username = body.get("username") if body else None

        origin, _ = canonicalize_origin_and_url(request)
        rp_id = PasskeyService._rp_id_from_origin(origin)
        
        # Generate challenge
        challenge = secrets.token_bytes(32)
        
        # Store challenge for validation (5 minutes TTL)
        expires_at = now() + 300  # 5 minutes
        if not session_id:
            raise HTTPException(status_code=401, detail="No session ID in session data")
        await SessionDB.store_webauthn_challenge(session_id, "authentication", b64u(challenge), expires_at)
        
        # Get stored credentials from passkey table
        # Filter by device type to only show passkeys created on the same device type
        current_device_type = session_data.get("device_type")
        
        if username:
            all_credentials = await SessionDB.pk_get_for_principal(username)
            # Filter credentials by device type
            existing_credentials = [
                cred for cred in all_credentials 
                if cred.get("device_type") == current_device_type
            ]
            log.info(f"Filtered passkeys for {username}: {len(existing_credentials)} of {len(all_credentials)} match device type '{current_device_type}'")
            
            # Count passkeys by device type for UI display
            mobile_count = sum(1 for cred in all_credentials if cred.get("device_type") == "mobile")
            desktop_count = sum(1 for cred in all_credentials if cred.get("device_type") == "desktop")
        else:
            # For usernameless flow, return empty to allow platform authenticator discovery
            existing_credentials = []
            all_credentials = []
            mobile_count = 0
            desktop_count = 0
        
        # For usernameless discovery on mobile, send empty allowCredentials
        # This allows the platform to surface on-device passkeys
        allow = [] if not username else [
            {
                "type": "public-key",
                "id": cred["cred_id"],
                "transports": cred.get("transports", ["internal"])
            }
            for cred in existing_credentials
        ]
        
        return {
            "rpId": rp_id,
            "challenge": b64u(challenge),
            "userVerification": "required",
            "allowCredentials": allow,
            "_meta": {
                "hasCredentials": bool(allow),
                "registeredCount": len(allow),
                "usernameless": not username,
                "totalCredentials": len(all_credentials) if username else 0,
                "mobileCredentials": mobile_count,
                "desktopCredentials": desktop_count,
            },
        }
    
    @staticmethod
    async def verify_authentication(session_id: str, session_data: Dict[str, Any], request: Request, assertion_data: Dict[str, Any], username: str) -> Dict[str, Any]:
        
        origin, _ = canonicalize_origin_and_url(request)
        rp_id = PasskeyService._rp_id_from_origin(origin)
        
        # Parse client data first to get challenge
        clientDataJSON = b64u_dec(assertion_data["response"]["clientDataJSON"])
        client = json.loads(clientDataJSON)
        
        # Validate challenge
        challenge = client.get("challenge")
        if not challenge:
            raise HTTPException(status_code=400, detail="missing challenge")
        
        is_valid = await SessionDB.validate_webauthn_challenge(session_id, "authentication", challenge)
        if not is_valid:
            raise HTTPException(status_code=400, detail="invalid or expired challenge")
        
        # Get stored credential from passkey table
        cred_id = assertion_data.get("id") or assertion_data.get("rawId")
        if not cred_id:
            raise HTTPException(status_code=400, detail="missing credential ID")
        
        stored_cred = await SessionDB.pk_find_by_cred_id(username, cred_id)
        if not stored_cred:
            raise HTTPException(status_code=404, detail="credential not found")
        
        stored_jwk = stored_cred["public_key_jwk"]
        
        # Validate client data
        if client.get("type") != "webauthn.get":
            raise HTTPException(status_code=400, detail="wrong clientData type")
        if client.get("origin") != origin:
            raise HTTPException(status_code=400, detail="origin mismatch")
        
        # Parse authenticator data
        import hashlib
        authData = b64u_dec(assertion_data["response"]["authenticatorData"])
        info = parse_authenticator_data(authData)
        rp_hash = hashlib.sha256(rp_id.encode()).digest()
        if info["rpIdHash"] != rp_hash:
            raise HTTPException(status_code=400, detail="rpIdHash mismatch")
        if (info["flags"] & 0x01) == 0:
            raise HTTPException(status_code=400, detail="user not present")
        
        # Verify credential ID matches (already validated above)
        
        # Verify signature
        sig = b64u_dec(assertion_data["response"]["signature"])
        ct_hash = hashlib.sha256(clientDataJSON).digest()
        msg = authData + ct_hash
        
        pub, alg = jwk_to_public_key(stored_jwk)
        try:
            if alg == "ES256":
                from cryptography.hazmat.primitives.asymmetric import ec
                pub.verify(sig, msg, ec.ECDSA(hashes.SHA256()))
            elif alg == "RS256":
                pub.verify(sig, msg, padding.PKCS1v15(), hashes.SHA256())
            elif alg == "EdDSA":
                pub.verify(sig, msg)
            else:
                raise HTTPException(status_code=400, detail="unsupported alg")
        except Exception:
            raise HTTPException(status_code=400, detail="signature verify failed")
        
        # Update sign count in passkey table (preserve device_type)
        await SessionDB.pk_upsert(username, {
            "cred_id": cred_id,
            "public_key_jwk": stored_jwk,
            "sign_count": info["signCount"],
            "aaguid": stored_cred.get("aaguid"),
            "transports": stored_cred.get("transports", ["internal"]),
            "device_type": stored_cred.get("device_type"),
            "created_at": stored_cred.get("created_at", now())
        })
        
        # Update session auth status
        await SessionDB.update_session_auth_status(session_id, "Passkey", "authenticated", username)
        
        log.info(f"Passkey authentication successful for username: {username}")
        
        return {"ok": True, "username": username}