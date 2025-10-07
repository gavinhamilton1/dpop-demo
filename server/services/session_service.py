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
from jose import jws as jose_jws
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
            
from server.core.config import load_settings
from server.db.session import SessionDB
from server.utils.helpers import ec_p256_thumbprint, now, _new_nonce, validate_jws_token, validate_key_jws, canonicalize_origin_and_url
from server.utils.geolocation import GeolocationService
# Removed schemas for development simplicity

# Import constants from main
BIND_TTL = 120  # 2 minutes
NONCE_TTL = 60  # 1 minute
SESSION_TTL = 120  # 2 minutes

log = logging.getLogger("dpop-fun")

SETTINGS = load_settings()

#naming convention: _x_<name> is for headrs, x_<name> is internal, anything else is for client use

#enum for session states
SessionState = Enum("SessionState", ["PENDING_BIND", "BOUND_DPOP", "AUTHENTICATED", "USER_TERMINATED", "SYSTEM_TERMINATED", "EXPIRED"])
SessionStatus = Enum("SessionStatus", ["NEW", "ACTIVE", "EXPIRED", "TERMINATED"])
NonceStatus = Enum("NonceStatus", ["PENDING", "REDEEMED", "EXPIRED"])
SessionFlag = Enum("SessionFlag", ["RED", "AMBER", "GREEN"])


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
        
        # Create fresh SESSION object for this request
        SESSION = {
            "_x_x-csrf-token": None,
            "_x_dpop-nonce": None,
            "_x_dpop-bind": None,
            "dpop_bind_expires_at": None,
            "_session_id": None,
            "_session_status": SessionStatus.ACTIVE.name,
            "_access_token": None,
            "_refresh_token": None,
            "_id_token": None,
            "_signal_data": None,
            "_signal_hash": None,
            "_bik_jkt": None,
            "_dpop_jkt": None,
            "session_flag": None,
            "session_flag_comment": None,
            "device_id": None,
            "bik_jwk": None,
            "dpop_jwk": None,
            "auth_method": None,
            "auth_status": None,
            "auth_username": None,
            "client_ip": None,
            "state": SessionState.PENDING_BIND.name,
            "created_at": None,
            "updated_at": None,
            "expires_at": None,
            "geolocation": None,
            "active_user_sessions": 0
        }

        #check origin details from the https request against allow list
        log.info("Session initialization - Origin: %s", req.headers.get("origin"))
        if not req.headers.get("origin") in SETTINGS.allowed_origins:
            log.error("Session initialization - Origin not allowed: %s", req.headers.get("origin"), SETTINGS.allowed_origins)
            raise HTTPException(status_code=400, detail="Origin not allowed")
        
        payload = body.get("payload")
        headers = req.headers
        #make sure we have a uuid, bik, and signal data
        # dpop_jws is now optional since we can extract DPoP key from DPoP header
        if not payload.get("device_id") or not payload.get("bik_jws") or not payload.get("signal_data"):
            raise HTTPException(status_code=400, detail="Missing required fields")
                
        # Validate BIK JWS token (always required)
        try:
            bik_jkt, bik_jwk, bik_payload = validate_key_jws(payload.get("bik_jws"), "bik-reg+jws", ["device_id"], payload.get("device_id"), "BIK")   
        except HTTPException as e:
            raise HTTPException(status_code=400, detail=f"BIK JWS validation failed: {e}")
        
        # Extract DPoP key from either DPoP header (preferred) or dpop_jws in body
        dpop_jkt = None
        dpop_jwk = None
        dpop_payload = None
        
        dpop_header = headers.get("dpop")
        if dpop_header:
            # Prefer DPoP header for key extraction (more secure, includes proper DPoP claims)
            try:
                dpop_payload = SessionService._validate_dpop_header(dpop_header, req.method, str(req.url), payload.get("device_id"))
                # Extract JWK from the DPoP header
                dpop_data = validate_jws_token(dpop_header, "dpop+jwt", ["htm", "htu", "iat", "jti", "nonce", "device_id"])
                dpop_jwk = dpop_data["header"].get("jwk", {})
                dpop_jkt = ec_p256_thumbprint(dpop_jwk)
                log.info("Session initialization - DPoP key extracted from DPoP header")
            except Exception as e:
                log.warning("Session initialization - DPoP header validation failed: %s", e)
                raise HTTPException(status_code=401, detail=f"DPoP header validation failed: {e}")
        elif payload.get("dpop_jws"):
            # Fall back to dpop_jws in body for initial session setup
            try:
                dpop_jkt, dpop_jwk, dpop_payload = validate_key_jws(payload.get("dpop_jws"), "dpop-bind+jws", ["htm", "htu", "iat", "jti", "nonce", "device_id"], payload.get("device_id"), "DPoP")
                log.info("Session initialization - DPoP key extracted from dpop_jws in body")
            except HTTPException as e:
                raise HTTPException(status_code=400, detail=f"DPoP JWS validation failed: {e}")
        else:
            raise HTTPException(status_code=400, detail="Either DPoP header or dpop_jws in body is required")
        
        #is there a session and is it valid
        session_id = req.session.get("session_id")
        
        session_db = await SessionDB.get_session(session_id)
        session_status = session_db.get("_session_status") if session_db else None
        log.info("Session initialization - Session ID: %s, Session Status: %s", session_id, session_status)
        
        if not session_id or not session_db or session_db.get("_session_status") != SessionStatus.ACTIVE.name:
            #create a new session
            log.info("Session initialization - No session found, creating new session")
            session_id = secrets.token_urlsafe(18)
            csrf = secrets.token_urlsafe(18)
            bind_token = SessionService.issue_binding_token(sid=session_id, bik_jkt=bik_jkt, dpop_jkt=dpop_jkt, aud=req.headers.get("origin"), ttl=BIND_TTL)
            nonce_valid, new_nonce = await SessionService._do_nonce_sense(session_id, None)
            log.info("Session initialization - Session ID: %s, CSRF: %s, Bind Token: %s", session_id, csrf, bind_token)
            SESSION["_session_id"] = session_id
            SESSION["_session_status"] = SessionStatus.ACTIVE.name
            SESSION["session_flag"] = SessionFlag.GREEN.name
            SESSION["session_flag_comment"] = None
            SESSION["_access_token"] = None
            SESSION["_refresh_token"] = None
            SESSION["_id_token"] = None
            SESSION["_x_x-csrf-token"] = csrf
            SESSION["device_id"] = payload.get("device_id")
            SESSION["bik_jkt"] = bik_jkt
            SESSION["dpop_jkt"] = dpop_jkt
            SESSION["bik_jwk"] = json.dumps(bik_jwk) if bik_jwk else None
            SESSION["dpop_jwk"] = json.dumps(dpop_jwk) if dpop_jwk else None
            SESSION["_x_dpop-nonce"] = new_nonce
            SESSION["_x_dpop-bind"] = bind_token
            SESSION["dpop_bind_expires_at"] = now() + BIND_TTL
            SESSION["signal_data"] = json.dumps(payload.get("signal_data")) if payload.get("signal_data") else None
            SESSION["signal_hash"] = None
            SESSION["client_ip"] = req.client.host
            if req.headers.get("x-forwarded-for"):
                SESSION["client_ip"] = req.headers.get("x-forwarded-for").split(",")[0].strip()
            elif req.headers.get("x-real-ip"):
                SESSION["client_ip"] = req.headers.get("x-real-ip")
            SESSION["state"] = SessionState.BOUND_DPOP.name
            SESSION["created_at"] = now()
            SESSION["updated_at"] = now()
            SESSION["expires_at"] = now() + SESSION_TTL
            SESSION["geolocation"] = None
            SESSION["active_user_sessions"] = 0
            log.info("Session initialization - Session ID: %s created, CSRF: %s", session_id, csrf)
            req.session.update({
                "session_id": session_id,
                "expires_at": now(),
                "gavin": "was here"
            })
            
            
            try:
                geolocation = GeolocationService.get_ip_geolocation(SESSION["client_ip"])
                SESSION["geolocation"] = json.dumps(geolocation) if geolocation else None
                log.info("Session initialization - Geolocation City: %s, Country: %s", geolocation.get("city"), geolocation.get("country"))
            except Exception as e:
                log.error("Session initialization - Error getting geolocation: %s", e)
            
            try:
                device = await SessionDB.get_device(payload.get("device_id"))
                if not device:
                    await SessionDB.set_device(payload.get("device_id"), SESSION)
                else:
                    log.info("Session initialization - Device already exists: %s", payload.get("device_id"))

                await SessionDB.set_session(session_id, SESSION)
            except Exception as e:
                log.error("Session initialization - Error setting device or session: %s", e)
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="Error setting device or session")
            

            # Generate browser fingerprint hash for session
            try:
                if SESSION.get("signal_data"):
                    fingerprint_result = SessionService._generate_browser_fingerprint(SESSION["signal_data"])
                    SESSION["signal_hash"] = fingerprint_result["hash"]
                    
                    # Check for automation flags
                    signal_data = json.loads(SESSION["signal_data"])
                    if signal_data.get("automation", {}).get("headlessUA") or signal_data.get("automation", {}).get("webdriver"):
                        log.info("Session initialization - Headless UA or Webdriver detected")
                        SESSION["session_flag"] = SessionFlag.RED.name
                        SESSION["session_flag_comment"] = "Headless UA or Webdriver detected"
                    
                    log.info("Session initialization - Browser fingerprint: %s", fingerprint_result)
            except Exception as e:
                log.error("Session initialization - Error generating browser fingerprint: %s", e)
            
        else:
            log.info("Session initialization - FOUND a session of some sort")
            
            # Calculate signal hash for comparison
            try:
                if payload.get("signal_data"):
                    signal_data_json = json.dumps(payload.get("signal_data"))
                    fingerprint_result = SessionService._generate_browser_fingerprint(signal_data_json)
                    SESSION["signal_hash"] = fingerprint_result["hash"]
                    
                    # Compare with stored fingerprint if available
                    stored_signal_hash = session_db.get("signal_hash")
                    if stored_signal_hash and stored_signal_hash != fingerprint_result["hash"]:
                        log.warning("Session initialization - Browser fingerprint mismatch detected")
                        log.warning("Stored hash: %s", stored_signal_hash)
                        log.warning("Current hash: %s", fingerprint_result["hash"])
                        SESSION["session_flag"] = SessionFlag.AMBER.name
                        SESSION["session_flag_comment"] = "Browser fingerprint mismatch"
                    else:
                        log.info("Session initialization - Browser fingerprint matches stored fingerprint")
                    
                    log.info("Session initialization - Browser fingerprint: %s", fingerprint_result)
            except Exception as e:
                log.error("Session initialization - Error comparing browser fingerprint: %s", e)
            
            # Validate CSRF token for existing session
            if headers.get("x-csrf-token") != session_db.get("_x_x_csrf_token"):
                log.info("Session initialization - Session ID: %s, CSRF Token: %s, stored CSRF Token: %s, CSRF Token mismatch", session_id, headers.get("x-csrf-token"), session_db.get("_x_x_csrf_token"))
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="CSRF Token mismatch")
            
            # Validate DPoP bind token for existing session
            if headers.get("x-dpop-bind") != session_db.get("_x_dpop-bind"):
                log.info("Session initialization - Session ID: %s, DPoP Bind Token: %s, DPoP Bind Token mismatch", session_id, headers.get("x-dpop-bind"))
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="DPoP Bind Token mismatch")

            log.info("Session initialization - Session ID: %s, SESSION: %s", session_id, SESSION)
            
            # Validate nonce for existing session
            nonce_valid, new_nonce = await SessionService._do_nonce_sense(session_id, payload.get("nonce"))
            if not nonce_valid:
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="Nonce is invalid")
            
            try:
                geolocation = GeolocationService.get_ip_geolocation(req.client.host)
                geolocation_db = session_db.get("geolocation")

                if geolocation and geolocation_db:
                    SESSION["geolocation"] = json.dumps(geolocation)
                    log.info("Session initialization - GeolocationIP City: %s, Country: %s", geolocation.get("city"), geolocation.get("country"))
                    geolocation_db_parsed = json.loads(geolocation_db)
                    log.info("Session initialization - GeolocationDB City: %s, Country: %s", geolocation_db_parsed.get("city"), geolocation_db_parsed.get("country"))
                else:
                    log.warning("Session initialization - No geolocation data returned")
            except Exception as e:
                log.error("Session initialization - Error getting geolocation: %s", e)

            # For existing sessions, we primarily validate the DPoP header
            # BIK validation is still needed for consistency, but DPoP key comes from header
            try:
                bik_jkt, bik_jwk, bik_payload = validate_key_jws(payload.get("bik_jws"), "bik-reg+jws", ["device_id"], payload.get("device_id"), "BIK")   
                
            except HTTPException as e:
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail=f"BIK or Bind Token JWS validation failed: {e}")
            
            # For existing sessions, DPoP key should come from the DPoP header
            dpop_header = headers.get("dpop")
            if not dpop_header:
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=401, detail="DPoP header required for existing sessions")
            
            try:
                dpop_payload = SessionService._validate_dpop_header(dpop_header, req.method, str(req.url), payload.get("device_id"))
                # Extract JWK from the DPoP header
                dpop_data = validate_jws_token(dpop_header, "dpop+jwt", ["htm", "htu", "iat", "jti", "nonce", "device_id"])
                dpop_jwk = dpop_data["header"].get("jwk", {})
                dpop_jkt = ec_p256_thumbprint(dpop_jwk)
                log.info("Session initialization - DPoP key extracted from DPoP header for existing session")
            except Exception as e:
                log.warning("Session initialization - DPoP header validation failed for existing session: %s", e)
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=401, detail=f"DPoP header validation failed: {e}")
            
            #check bik and dpop jkt match - only for existing sessions that already have keys
            if session_db and session_db.get("bik_jkt") and session_db.get("bik_jkt") != bik_jkt:
                log.info("Session initialization - Session ID: %s, BIK JKT: %s, BIK JKT mismatch", session_id, bik_jkt)
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="BIK JKT mismatch")
            
            if session_db and session_db.get("dpop_jkt") and session_db.get("dpop_jkt") != dpop_jkt:
                log.info("Session initialization - Session ID: %s, DPoP JKT: %s, DPoP JKT mismatch", session_id, dpop_jkt)
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="DPoP JKT mismatch")
            
            #check device id matches session and BIK JWS device id and DPoP JWS device id
            if session_db.get("device_id") != payload.get("device_id") or bik_payload.get("device_id") != payload.get("device_id") or dpop_payload.get("device_id") != payload.get("device_id"):
                log.info("Session initialization - Session ID: %s, Device ID: %s, Device ID mismatch", session_id, payload.get("device_id"))
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="Device ID mismatch")


            # Validate bind token (server-signed, not client JWS) - optional on first request
            bind_token = headers.get("Dpop-Bind")
            log.info("Got Bind Token: %s", bind_token)
            bind_payload = None
            if bind_token:
                try:
                    bind_payload = SessionService.verify_binding_token(bind_token, bik_jkt, dpop_jkt)
                except Exception as e:
                    log.warning(f"Bind token validation failed: {e}")


            #hydrate SESSION with session from db and add headers
            #if key starts with _x_, then replace all _ after position 3 with - // this gets around the db naming constraints
            SESSION.update(session_db)
            
            #check for other sessions for the authenticated user
            if SESSION.get("auth_username"):
                active_user_sessions = await SessionDB.get_active_user_sessions(SESSION.get("auth_username"))
                SESSION["active_user_sessions"] = len(active_user_sessions)
            else:
                SESSION["active_user_sessions"] = 0
            
            
            for key, value in session_db.items():
                if key.startswith("_x_"):
                    #remove original key
                    del SESSION[key]
                    #add in with new name    
                    key = key[:3] + key[3:].replace("_", "-")
                    SESSION[key] = value
                    log.info("Session initialization - Session ID: %s, Added key: %s, Value: %s", session_id, key, value)
                else:
                    SESSION[key] = value
            log.info("Session initialization - Session ID: %s, CSRF Token: %s", session_id, SESSION['_x_x-csrf-token'])
            SESSION["_x_dpop-nonce"] = new_nonce

                
        #add HTTPS headers
        body = SessionService._sendable_session_data(SESSION)
        headers = SessionService._session_headers(SESSION)
        response_data = {
            "headers": headers,
            "body": body
        }
        return response_data


    
    @staticmethod
    async def _terminate_session(session_id: str) -> bool:
        """Check if session is active and return True if it is, False if it is not"""
        log.info("Terminating session: %s", session_id)
        return await SessionDB.terminate_session(session_id)

    
    @staticmethod
    def _generate_browser_fingerprint(signal_data_json: str) -> dict:
        """
        Generate browser fingerprint hash from signal data for device identification.
        
        Args:
            signal_data_json: JSON string containing browser signal data
        
        Returns:
            dict: {
                "hash": str - SHA256 hash of browser fingerprint
                "fingerprint": dict - Raw fingerprint data
                "context": dict - Additional browser context for logging
            }
        """
        try:
            signal_data = json.loads(signal_data_json)
            ua_ch = signal_data.get("ua_ch", {})
            
            # Extract browser name from User Agent string
            user_agent = signal_data.get("userAgent", "")
            browser_name = "Unknown"
            browser_version = "Unknown"
            
            # Parse browser from User Agent (simple regex approach)
            import re
            if "Chrome/" in user_agent and "Safari/" in user_agent:
                # Chrome/Chromium-based browsers
                chrome_match = re.search(r'Chrome/([0-9.]+)', user_agent)
                if chrome_match:
                    browser_version = chrome_match.group(1)
                    if "Edg/" in user_agent:
                        browser_name = "Microsoft Edge"
                    elif "OPR/" in user_agent:
                        browser_name = "Opera"
                    else:
                        browser_name = "Google Chrome"
            elif "Firefox/" in user_agent:
                firefox_match = re.search(r'Firefox/([0-9.]+)', user_agent)
                if firefox_match:
                    browser_name = "Firefox"
                    browser_version = firefox_match.group(1)
            elif "Safari/" in user_agent and "Chrome/" not in user_agent:
                safari_match = re.search(r'Version/([0-9.]+)', user_agent)
                if safari_match:
                    browser_name = "Safari"
                    browser_version = safari_match.group(1)
            
            # Browser-specific identifiers for BIK validation
            browser_fingerprint = {
                "browser_name": browser_name,
                "platform": signal_data.get("platform"),
                "cpu_architecture": ua_ch.get("architecture"),
                "hardware_concurrency": signal_data.get("hardwareConcurrency"),
                "device_memory": signal_data.get("deviceMemory"),
                "webgl_renderer": signal_data.get("webglRenderer")
            }
            
            # Additional context for logging
            browser_context = {
                "browser_version": browser_version,
                "os_name": ua_ch.get("platform"),
                "os_version": ua_ch.get("platformVersion"),
                "timezone": signal_data.get("timezone"),
                "language": signal_data.get("language"),
                "user_agent": user_agent
            }
            
            # Create browser fingerprint hash for comparison
            import hashlib
            fingerprint_data = json.dumps(browser_fingerprint, sort_keys=True)
            browser_fingerprint_hash = hashlib.sha256(fingerprint_data.encode()).hexdigest()
            
            return {
                "hash": browser_fingerprint_hash,
                "fingerprint": browser_fingerprint,
                "context": browser_context
            }
                
        except Exception as e:
            log.error("Error generating browser fingerprint: %s", e)
            return {
                "hash": "unknown",
                "fingerprint": {},
                "context": {}
            }
    
    @staticmethod
    async def _do_nonce_sense(session_id: str, nonce: str) -> tuple[bool, str]:

        new_nonce = _new_nonce()

        if not nonce:
            # No nonce provided - this is a first-time request
            await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
            return True, new_nonce
        else:
            # Validate existing nonce
            nonce_record = await SessionDB.get_nonce(session_id, nonce)
            if not nonce_record:
                log.warning("Nonce validation failed - nonce not found: %s", nonce)
                await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                return False, new_nonce
                
            if nonce_record.get("nonce_status") == NonceStatus.EXPIRED.name:
                log.warning("Nonce validation failed - nonce expired: %s", nonce)
                await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                return False, new_nonce
                
            if nonce_record.get("nonce_status") == NonceStatus.REDEEMED.name:
                log.warning("Nonce validation failed - nonce already redeemed: %s", nonce)
                await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                return False, new_nonce
            
            # Valid nonce - mark as redeemed and issue new one
            if nonce_record.get("nonce_status") == NonceStatus.PENDING.name:
                await SessionDB.set_nonce(session_id, nonce, NonceStatus.REDEEMED.name, NONCE_TTL)
            
            await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
            return True, new_nonce
    
    
    @staticmethod
    def _session_headers(session_data: dict) -> dict:
        """Return a dictionary of session headers that can be sent to the client.  anything that starts with _x_"""
        return {key[3:]: value for key, value in session_data.items() if key.startswith("_x_") and value is not None}


    @staticmethod
    def _sendable_session_data(session_data: dict) -> dict:
        """Return a dictionary of session data that can be sent to the client.  anything that doesn't start with an underscore"""
        return {key: value for key, value in session_data.items() if not key.startswith("_")}


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
            raise ValueError("Server key not configured")
        
        tok = jose_jws.sign(payload, server_key, algorithm="ES256", headers=protected)
        log.info("issued bind token sid=%s aud=%s exp=%s", sid, aud, payload["exp"])
        return tok
    
    @staticmethod
    def verify_binding_token(token: str, bik_jkt: str, dpop_jkt: str) -> Dict[str, Any]:
        """Verify a binding token and return its payload"""
        
        log.info("Verifying binding token: %s", token)
        try:
            # Get server private key and derive public key for verification
            server_private_key = SETTINGS.server_ec_private_key_pem
            if not server_private_key:
                raise ValueError("Server key not configured")
            
            # Load the private key and get the public key
            private_key = serialization.load_pem_private_key(server_private_key.encode(), password=None)
            public_key = private_key.public_key()
            
            payload = jose_jws.verify(token, public_key, algorithms=["ES256"])
            data = payload if isinstance(payload, dict) else json.loads(payload)
            if data.get("exp", 0) < now():
                raise ValueError("bind token expired")
            return data
            
        except Exception as e:
            log.warning(f"Binding token verification failed: {e}")
            raise ValueError("bind token invalid - please refresh session")
    
    @staticmethod
    def _validate_dpop_header(dpop_header: str, http_method: str, http_uri: str, expected_device_id: str) -> dict:
        """
        Validate a DPoP header for ongoing requests
        
        Args:
            dpop_header: The DPoP proof from the DPoP header
            http_method: The HTTP method of the request
            http_uri: The HTTP URI of the request
            expected_device_id: The expected device ID
            
        Returns:
            dict: The validated DPoP payload
            
        Raises:
            ValueError: If validation fails
        """
        try:
            # Validate the DPoP proof using the generic JWS validator
            dpop_data = validate_jws_token(dpop_header, "dpop+jwt", ["htm", "htu", "iat", "jti", "nonce", "device_id"])
            dpop_payload = dpop_data["payload"]
            dpop_header_data = dpop_data["header"]
            
            # Validate HTTP method
            if dpop_payload.get("htm") != http_method.upper():
                raise ValueError(f"HTTP method mismatch: expected {http_method.upper()}, got {dpop_payload.get('htm')}")
            
            # Validate HTTP URI (remove query parameters for comparison)
            expected_uri = http_uri.split("?")[0]
            if dpop_payload.get("htu") != expected_uri:
                raise ValueError(f"HTTP URI mismatch: expected {expected_uri}, got {dpop_payload.get('htu')}")
            
            # Validate device ID
            if dpop_payload.get("device_id") != expected_device_id:
                raise ValueError(f"Device ID mismatch: expected {expected_device_id}, got {dpop_payload.get('device_id')}")
            
            # Validate issued at time (should not be too old)
            iat = dpop_payload.get("iat")
            if iat and (now() - iat) > 300:  # 5 minutes max age
                raise ValueError(f"DPoP proof too old: {now() - iat} seconds")
            
            # Validate JTI (should be unique per request)
            jti = dpop_payload.get("jti")
            if not jti:
                raise ValueError("Missing JTI in DPoP proof")
            
            log.info("DPoP header validation successful for device: %s, method: %s, uri: %s", 
                    expected_device_id, http_method, expected_uri)
            
            return dpop_payload
            
        except Exception as e:
            log.warning("DPoP header validation failed: %s", e)
            raise ValueError(f"DPoP header validation failed: {e}")
    
    
    
    @staticmethod
    async def _get_session_history(authenticated_username: str) -> list[dict]:
        """Get session history for an authenticated user"""
        created_at = int(time.time()) - (7 * 24 * 60 * 60) #  7 days ago
        return await SessionDB.get_session_history(authenticated_username, created_at)
    
    @staticmethod
    async def validate_dpop_for_request(req: Request, session_id: str) -> dict:
        """
        Validate DPoP header for a protected request
        
        Args:
            req: The FastAPI request object
            session_id: The session ID
            
        Returns:
            dict: The validated DPoP payload
            
        Raises:
            HTTPException: If validation fails
        """
        # Get DPoP header
        dpop_header = req.headers.get("dpop")
        if not dpop_header:
            raise HTTPException(status_code=401, detail="Missing DPoP header")
            
            # Get session data
        session_db = await SessionDB.get_session(session_id)
        if not session_db:
                raise HTTPException(status_code=401, detail="Session not found")
            
        device_id = session_db.get("device_id")
        if not device_id:
            raise HTTPException(status_code=401, detail="Device ID not found in session")
        
        # Validate DPoP header
        try:
            dpop_payload = SessionService._validate_dpop_header(
                dpop_header, 
                req.method, 
                str(req.url), 
                device_id
            )
            
            # Validate nonce if present
            nonce = dpop_payload.get("nonce")
            if nonce:
                nonce_valid, _ = await SessionService._do_nonce_sense(session_id, nonce)
                if not nonce_valid:
                    raise HTTPException(status_code=401, detail="Invalid nonce")
            
            return dpop_payload
            
        except ValueError as e:
            raise HTTPException(status_code=401, detail=str(e))
        except Exception as e:
            log.error("Unexpected error during DPoP validation: %s", e)
            raise HTTPException(status_code=500, detail="DPoP validation error")
    
    @staticmethod
    async def require_dpop_proof(req: Request) -> dict:
        """
        Middleware function to require DPoP proof for protected endpoints
        
        Args:
            req: The FastAPI request object
            
        Returns:
            dict: The validated DPoP payload and session data
            
        Raises:
            HTTPException: If validation fails
        """
        # Get session ID from session cookie
        session_id = req.session.get("session_id")
        if not session_id:
            raise HTTPException(status_code=401, detail="No session found")
        
        # Validate DPoP header
        dpop_payload = await SessionService.validate_dpop_for_request(req, session_id)
        
        # Get session data
        session_db = await SessionDB.get_session(session_id)
        if not session_db:
            raise HTTPException(status_code=401, detail="Session not found")
            
            return {
            "dpop_payload": dpop_payload,
            "session_data": session_db,
            "session_id": session_id
        }
        

