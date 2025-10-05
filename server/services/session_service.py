"""
Session Service - Handles all session-related business logic
"""

import base64
import json
import logging
import secrets
import time
from enum import Enum
from typing import Dict, Any, Optional, Tuple
from fastapi import Request, HTTPException, Response
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from server.core.config import load_settings
from server.db.database import DB
from server.utils.helpers import ec_p256_thumbprint, now, _new_nonce, validate_jws_token
from server.utils.url_utils import canonicalize_origin_and_url
from server.services.signal_service import signal_service
# Removed schemas for development simplicity

# Import constants from main
BIND_TTL = 3600  # 1 hour
NONCE_TTL = 300  # 5 minutes

log = logging.getLogger("dpop-fun")

SETTINGS = load_settings()

SESSION = {
    "session_id": None,
    "device_id": None,
    "bik_jws": None,
    "dpop_jws": None,
    "dpop_nonce": None,
    "auth_method": None,
    "auth_status": None,
    "auth_username": None,
    "signal_data": None,
    "csrf": None,
    "state": None,
    "bik_jkt": None,
    "dpop_jkt": None,
    "bind_token": None,
    "bind_expires_at": None,
    "created_at": None,
    "updated_at": None,
}

#enum for session states
SessionState = Enum("SessionState", ["pending_dpop_bind", "bound_bik", "bound_dpop", "authenticated", "user_terminated", "system_terminated", "expired"])


class SessionService:
    """Service class for handling session-related operations"""
    
    @staticmethod
    async def session_init(req: Request, body: dict, response: Response = None) -> dict:
        """
        Unified session initialization orchestrator that coordinates the 4 parts:
        1. Session creation/restoration
        2. BIK registration (if needed)
        3. DPoP binding (if needed) 
        4. Signal data registration (if needed)
        """

        #check origin details from the https request against allow list
        log.info("Session initialization - Origin: %s", req.headers.get("origin"))
        if not req.headers.get("origin") in SETTINGS.allowed_origins:
            log.error("Session initialization - Origin not allowed: %s", req.headers.get("origin"), SETTINGS.allowed_origins)
            raise HTTPException(status_code=400, detail="Origin not allowed")
        
        payload = body.get("payload")
        #make sure we have a uuid, bik, dpop and signal data
        if not payload.get("device_id") or not payload.get("bik_jws") or not payload.get("dpop_jws") or not payload.get("signal_data"):
            raise HTTPException(status_code=400, detail="Missing required fields")
                
        # Validate the BIK and DPoP JWS tokens
        bik_jkt = SessionService._validate_key_jws(
            payload.get("bik_jws"), 
            "bik-reg+jws", 
            ["device_id"], 
            payload.get("device_id"), 
            "BIK"
        )
        dpop_jkt = SessionService._validate_key_jws(
            payload.get("dpop_jws"), 
            "dpop-bind+jws", 
            ["htm", "htu", "iat", "jti", "nonce"], 
            payload.get("device_id"), 
            "DPoP"
        )
        
        #is there a session cookie and is it valid
        session_id = req.session.get("session_id")
        #session_id = None
        log.info("Session initialization - Session ID: %s", session_id)
        if not session_id:
            #create a new session
            log.info("Session initialization - No session found, creating new session")
            session_id = secrets.token_urlsafe(18)
            csrf = secrets.token_urlsafe(18)
            bind_token = SessionService.issue_binding_token(sid=session_id, bik_jkt=bik_jkt, dpop_jkt=dpop_jkt, aud=req.headers.get("origin"), ttl=BIND_TTL)
            
            log.info("Session initialization - Session ID: %s, CSRF: %s, Bind Token: %s", session_id, csrf, bind_token)
            SESSION["session_id"] = session_id
            SESSION["csrf"] = csrf
            SESSION["device_id"] = payload.get("device_id")
            SESSION["bik_jkt"] = bik_jkt
            SESSION["dpop_jkt"] = dpop_jkt
            SESSION["dpop_nonce"] = _new_nonce()
            SESSION["bind_token"] = bind_token
            SESSION["bind_expires_at"] = now() + BIND_TTL
            SESSION["signal_data"] = payload.get("signal_data")
            SESSION["state"] = SessionState.pending_dpop_bind
            SESSION["created_at"] = now()
            SESSION["updated_at"] = now()
            log.info("Session initialization - Session ID: %s created, CSRF: %s", session_id, csrf)
            req.session.update({
                "session_id": session_id,
                "expires_at": now(),
                "gavin": "was here"
            })
            
        else:
            # check if the session cookie has not expired
            if session.get("expires_at") < now():
                log.info("Session initialization - Session ID: %s has expired", session_id)
                raise HTTPException(status_code=400, detail="Session expired")

            if session.get("device_id") != payload.get("device_id"):
                log.info("Session initialization - Session ID: %s, Device ID: %s, Device ID mismatch", session_id, payload.get("device_id"))
                raise HTTPException(status_code=400, detail="Device ID mismatch")
            
            if session.get("bik_jkt") != payload.get("bik_jkt"):
                log.info("Session initialization - Session ID: %s, BIK JKT: %s, BIK JKT mismatch", session_id, payload.get("bik_jkt"))
                raise HTTPException(status_code=400, detail="BIK JKT mismatch")
            
            if session.get("dpop_jkt") != payload.get("dpop_jkt"):
                log.info("Session initialization - Session ID: %s, DPoP JKT: %s, DPoP JKT mismatch", session_id, payload.get("dpop_jkt"))
                raise HTTPException(status_code=400, detail="DPoP JKT mismatch")

            if session.get("bind_token") != payload.get("bind_token"):
                log.info("Session initialization - Session ID: %s, Bind Token: %s, Bind Token mismatch", session_id, payload.get("bind_token"))
                raise HTTPException(status_code=400, detail="Bind Token mismatch")
            
            if session.get("dpop_nonce") != payload.get("dpop_nonce"):
                log.info("Session initialization - Session ID: %s, DPoP Nonce: %s, DPoP Nonce mismatch", session_id, payload.get("dpop_nonce"))
                raise HTTPException(status_code=400, detail="DPoP Nonce mismatch")
            
            if session.get("state") != payload.get("state"):
                log.info("Session initialization - Session ID: %s, State: %s, State mismatch", session_id, payload.get("state"))
                raise HTTPException(status_code=400, detail="State mismatch")

                
        #add HTTPS headers
        response_data = {
            "headers": {
                "X-CSRF-Token": SESSION["csrf"],
                "DPoP-Nonce": SESSION["dpop_nonce"],
                "DPoP-Bind-Token": SESSION["bind_token"]
            },
            "body": SESSION
        }
        return response_data



                    

        
    
    @staticmethod
    def _validate_key_jws(jws_token: str, expected_typ: str, expected_payload_fields: list, expected_device_id: str, key_type: str) -> str:
        """
        Generic validation function for BIK and DPoP JWS tokens
        
        Args:
            jws_token: The JWS token to validate
            expected_typ: Expected JWT type (e.g., "bik-reg+jws", "dpop-bind+jws")
            expected_payload_fields: List of required payload field names (e.g., ["device_id"] or ["htm", "htu", "iat", "jti", "nonce"])
            expected_device_id: Expected device ID for validation
            key_type: Type of key for error messages (e.g., "BIK", "DPoP")
            
        Returns:
            The validated JKT
            
        Raises:
            HTTPException: If validation fails
        """
        try:
            # Validate the JWS token with the specified payload fields
            key_data = validate_jws_token(jws_token, expected_typ, expected_payload_fields)
            public_jwk = key_data["header"].get("jwk", {})
            
            # Validate JWK structure
            if public_jwk.get("kty") != "EC" or public_jwk.get("crv") != "P-256" or not public_jwk.get("x") or not public_jwk.get("y"):
                raise HTTPException(status_code=400, detail=f"bad {key_type.lower()} jwk")
            
            # Generate JKT from JWK (since JKT is not in payload anymore)
            jkt = ec_p256_thumbprint(public_jwk)
            
            # Validate device ID if it's in the expected fields
            if "device_id" in expected_payload_fields:
                device_id = key_data["payload"].get("device_id")
                log.info("Got %s JKT: %s, Device ID: %s", key_type, jkt, device_id)
                if device_id != expected_device_id:
                    raise HTTPException(status_code=400, detail="Device ID mismatch")
            else:
                log.info("Got %s JKT: %s", key_type, jkt)
            
            # Additional validation for DPoP-specific claims
            if "htm" in expected_payload_fields:
                payload = key_data["payload"]
                if payload.get("htm") != "POST":
                    raise HTTPException(status_code=400, detail="Invalid HTTP method")
                
            return jkt
            
        except ValueError as e:
            raise HTTPException(status_code=400, detail=f"{key_type} JWS validation failed: {str(e)}")


    @staticmethod
    def issue_binding_token(*, sid: str, bik_jkt: str, dpop_jkt: str, aud: str, ttl: int = BIND_TTL) -> str:
        """Issue a binding token for session authentication"""
        from jose import jws as jose_jws

        now_ts = now()
        payload = {"sid": sid, "aud": aud, "nbf": now_ts - 60, "exp": now_ts + ttl, "cnf": {"bik_jkt": bik_jkt, "dpop_jkt": dpop_jkt}}
        protected = {"alg": "ES256", "typ": "bik-bind+jws", "kid": "server-kid"}
     
        # Get server private key
        server_key = SETTINGS.server_ec_private_key_pem
        if not server_key:
            raise HTTPException(status_code=500, detail="Server key not configured")
        
        tok = jose_jws.sign(payload, server_key, algorithm="ES256", headers=protected)
        log.info("issued bind token sid=%s aud=%s exp=%s", sid, aud, payload["exp"])
        return tok
    
    @staticmethod
    def verify_binding_token(token: str) -> Dict[str, Any]:
        """Verify a binding token and return its payload"""
        from jose import jws as jose_jws
        from server.core.config import load_settings
        
        SETTINGS = load_settings()
        try:
            # Get server public key for verification
            server_key = SETTINGS.server_ec_private_key_pem
            if not server_key:
                raise HTTPException(status_code=500, detail="Server key not configured")
            
            payload = jose_jws.verify(token, server_key, algorithms=["ES256"])
            data = payload if isinstance(payload, dict) else json.loads(payload)
            if data.get("exp", 0) < now():
                raise HTTPException(status_code=401, detail="bind token expired")
            return data
        except Exception as e:
            log.warning(f"Binding token verification failed: {e}")
            raise HTTPException(status_code=401, detail="bind token invalid - please refresh session")
        
        
        
        
        
        
    
    
    
    



    @staticmethod
    async def _create_or_restore_device_and_session(req: Request, device_id: str, signal_data: dict) -> Tuple[str, str, bool]:
        """Create or restore device and session in the new device-centric model"""
        import json
        
        # Check if device exists
        device = await DB.get_device(device_id)
        if not device:
            # Create new device
            await DB.create_device(device_id, "browser", json.dumps(signal_data))
            log.info("Created new device - Device ID: %s", device_id)
        else:
            # Update device last_seen and signal data
            await DB.update_device(device_id, 
                                 last_seen=int(time.time()),
                                 signal_data=json.dumps(signal_data))
            log.info("Updated existing device - Device ID: %s", device_id)
        
        # Check for existing session
        session_id = req.session.get("session_id")
        is_existing_session = False
        
        if not session_id:
            # Create new session
            session_id = secrets.token_urlsafe(18)
            csrf = secrets.token_urlsafe(18)
            req.session.update({"session_id": session_id})
            await DB.create_session(session_id, device_id, csrf)
            log.info("Created new session - Session ID: %s, Device ID: %s", session_id, device_id)
        else:
            # Check if session exists and is valid
            session = await DB.get_session(session_id)
            if not session or session.get("device_id") != device_id:
                # Invalid session, create new one
                session_id = secrets.token_urlsafe(18)
                csrf = secrets.token_urlsafe(18)
                req.session.update({"sid": session_id})
                await DB.create_session(session_id, device_id, csrf)
                log.info("Created new session (invalid old session) - Session ID: %s, Device ID: %s", session_id, device_id)
            else:
            # Use existing session
                csrf = session.get("csrf_token")
                is_existing_session = True
                log.info("Using existing session - Session ID: %s, Device ID: %s", session_id, device_id)
        
        return session_id, csrf, is_existing_session






    
    
    @staticmethod
    async def _handle_bik_registration(req: Request, session_id: str, device_id: str, body: dict) -> Optional[str]:
        """
        Part 2: Handle BIK registration if bik_jws is provided
        
        Returns:
            bik_jkt if registration successful, None if skipped
        """
        if not body.get("bik_jws"):
            return None
            
        try:
            # Use the generic JWS validation helper
            bik_data = validate_jws_token(body.get("bik_jws"), "bik-reg+jws", ["bik_jkt"])
            
            # Validate nonce if present (for dpop_nonce integration)
            nonce = bik_data["payload"].get("nonce")
            if nonce:
                # Validate that the nonce is valid for this session
                if not await DB.nonce_valid(session_id, nonce):
                    raise HTTPException(status_code=401, detail="Invalid nonce")
            
            # Extract JWK from header
            jwk = bik_data["header"].get("jwk", {})
            if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256" or not jwk.get("x") or not jwk.get("y"):
                raise HTTPException(status_code=400, detail="bad jwk")
            
            bik_jkt = ec_p256_thumbprint(jwk)
            # Store BIK in device table
            await DB.update_device(device_id, 
                                 bik_jkt=bik_jkt,
                                 bik_public_jwk=json.dumps(jwk))
            # Rotate session nonce after successful BIK registration
            await DB.update_session(session_id, {"state": "bound-bik"})
            
            log.info("BIK registered - Session ID: %s, Device ID: %s, BIK JKT: %s", session_id, device_id, bik_jkt[:8])
            return bik_jkt
            
        except HTTPException: 
            raise
        except Exception as e:
            log.exception("BIK registration failed - Session ID: %s, Device ID: %s", session_id, device_id)
            raise HTTPException(status_code=400, detail=f"BIK registration failed: {e}")
    
    
    @staticmethod
    async def _register_signal_data(req: Request, session_id: str, device_id: str, bik_jkt: str) -> bool:
        """
        Part 4: Register signal data for the BIK if fingerprint data exists
        
        Returns:
            True if signal data was stored, False if skipped
        """
        if not bik_jkt:
            return False
            
        session = await DB.get_session(sid)
        if not session or not session.get("fingerprint"):
            return False
            
        try:
            fingerprint_data = session.get("fingerprint", {})
            device_type = session.get("device_type", "unknown")
            
            # Get client IP for geolocation
            client_ip = req.client.host
            if req.headers.get("x-forwarded-for"):
                client_ip = req.headers.get("x-forwarded-for").split(",")[0].strip()
            elif req.headers.get("x-real-ip"):
                client_ip = req.headers.get("x-real-ip")
            
            # Get geolocation data
            geolocation_data = fingerprint_data.get("geolocation")
            
            # Store signal data linked to BIK
            signal_stored = await DB.store_signal_data(
                bik_jkt=bik_jkt,
                session_id=sid,
                device_type=device_type,
                fingerprint_data=fingerprint_data,
                ip_address=client_ip,
                geolocation_data=geolocation_data
            )
            
            if signal_stored:
                # Mark that signal data has been stored for this session
                await DB.update_session(sid, {"signal_data_stored": True})
                log.info("Signal data registered - SID: %s, BIK JKT: %s", sid, bik_jkt[:8])
                return True
            else:
                log.warning("Failed to store signal data - SID: %s, BIK JKT: %s", sid, bik_jkt[:8])
                return False
                
        except Exception as e:
            log.exception("Signal data registration failed - SID: %s, BIK JKT: %s", sid, bik_jkt[:8])
            return False
    
    

    

    
 
    
    @staticmethod
    async def kill_session(req: Request) -> Dict[str, Any]:
        """Kill the current session completely - mark as USER_KILLED for auditing"""
        sid = req.session.get("sid")
        if not sid:
            raise HTTPException(status_code=401, detail="No session to kill")
        
        try:
            # Get session data for auditing
            session_data = await DB.get_session(sid)
            username = session_data.get("username") if session_data else None
            
            # Mark session as USER_KILLED for auditing purposes
            await DB.update_session(sid, {
                "state": "USER_KILLED",
                "kill_time": now(),
                "kill_reason": "user_requested"
            })
            
            # Invalidate all links owned by this session (mark as killed, don't delete)
            await DB.exec("UPDATE links SET status = 'killed' WHERE owner_sid = ?", (sid,))
            
            # Clear in-memory link storage for this session
            from server.linking import _LINKS, _LINKS_LOCK, _WATCHERS, _notify_watchers
            with _LINKS_LOCK:
                # Mark links as killed in memory
                for link_id, link_data in _LINKS.items():
                    if link_data.get("owner_sid") == sid:
                        link_data["status"] = "killed"
                        # Notify watchers that link was killed
                        _notify_watchers(link_id, {"type": "status", "status": "killed", "reason": "session_killed"})
            
            # Clear the session cookie
            req.session.clear()
            
            log.warning("Session killed by user - sid=%s username=%s (all clients will need to relogin)", sid, username)
            return {"ok": True, "message": "Session killed successfully - all clients invalidated"}
        except Exception as e:
            log.exception("Failed to kill session %s: %s", sid, e)
            raise HTTPException(status_code=500, detail="Failed to kill session")
    
    @staticmethod
    async def clear_session_only(req: Request) -> Dict[str, Any]:
        """Clear session data only - preserve all user data"""
        try:
            sid = req.session.get("sid")
            if not sid:
                return {"ok": True, "message": "No active session to clear"}
            
            # Mark session as cleared but preserve all data
            await DB.update_session(sid, {"state": "cleared", "clear_time": now()})
            
            # Clear session-related temporary data (nonces, jtis) but keep session record
            await DB.exec("DELETE FROM nonces WHERE sid = ?", (sid,))
            await DB.exec("DELETE FROM jtis WHERE sid = ?", (sid,))
            
            log.info(f"Session cleared for sid={sid} (all user data preserved)")
            
            return {"ok": True, "message": "Session cleared successfully"}
            
        except Exception as e:
            log.exception("Session clear failed")
            raise HTTPException(status_code=500, detail="Session clear failed")
    
    @staticmethod
    async def update_session(req: Request) -> Dict[str, Any]:
        """Update session with provided data"""
        try:
            sid = req.session.get("sid")
            if not sid:
                raise HTTPException(status_code=401, detail="No active session")
            
            # Get session data
            session_data = await DB.get_session(sid)
            if not session_data:
                raise HTTPException(status_code=401, detail="Session not found")
            
            # Get request body
            body = await req.json()
            
            # Update session with provided data
            await DB.update_session(sid, body)
            
            log.info(f"Session {sid} updated with data: {body}")
            
            return {
                "ok": True, 
                "message": "Session updated successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            log.exception("Session update failed")
            raise HTTPException(status_code=500, detail="Session update failed")
    
    @staticmethod
    async def update_session_auth(req: Request) -> Dict[str, Any]:
        """Update session with authentication data for mobile registration flow"""
        try:
            sid = req.session.get("sid")
            if not sid:
                raise HTTPException(status_code=401, detail="No active session")
            
            # Get session data
            session_data = await DB.get_session(sid)
            if not session_data:
                raise HTTPException(status_code=401, detail="Session not found")
            
            # Get request body
            body = await req.json()
            passkey_auth = body.get("passkey_auth", False)
            passkey_principal = body.get("passkey_principal")
            mobile_auth = body.get("mobile_auth", False)
            
            # Update session with authentication data
            update_data = {}
            if passkey_auth:
                update_data["passkey_auth"] = True
            if passkey_principal:
                update_data["passkey_principal"] = passkey_principal
            if mobile_auth:
                update_data["mobile_auth"] = True
            
            await DB.update_session(sid, update_data)
            
            log.info(f"Session {sid} updated with auth data: {update_data}")
            
            return {
                "ok": True, 
                "message": "Session authentication data updated successfully"
            }
            
        except HTTPException:
            raise
        except Exception as e:
            log.exception("Update session auth failed")
            raise HTTPException(status_code=500, detail="Update session auth failed")
    
    @staticmethod
    async def mark_user_authenticated(req: Request) -> Dict[str, Any]:
        """Mark user as authenticated in the session"""
        try:
            sid = req.session.get("sid")
            if not sid:
                raise HTTPException(status_code=401, detail="No active session")
            
            # Get session data
            session_data = await DB.get_session(sid)
            if not session_data:
                raise HTTPException(status_code=401, detail="Session not found")
            
            # Get request body
            body = await req.json()
            username = body.get("username")
            if not username:
                raise HTTPException(status_code=400, detail="Username is required")
            
            # Verify user exists
            user = await DB.get_user_by_username(username)
            if not user:
                raise HTTPException(status_code=404, detail="User not found")
            
            # Get additional authentication parameters
            passkey_auth = body.get("passkey_auth", False)
            passkey_principal = body.get("passkey_principal")
            mobile_auth = body.get("mobile_auth", False)
            
            # Mark user as authenticated in session
            update_data = {
                "username": username,
                "authenticated": True,
                "auth_timestamp": now()
            }
            
            # Add passkey authentication data if provided
            if passkey_auth:
                update_data["passkey_auth"] = True
            if passkey_principal:
                update_data["passkey_principal"] = passkey_principal
            if mobile_auth:
                update_data["mobile_auth"] = True
            
            await DB.update_session(sid, update_data)
            
            log.info(f"User {username} marked as authenticated in session {sid}")
            
            return {
                "ok": True, 
                "message": "User authenticated successfully",
                "username": username
            }
            
        except HTTPException:
            raise
        except Exception as e:
            log.exception("Mark user authenticated failed")
            raise HTTPException(status_code=500, detail="Mark user authenticated failed")
    
