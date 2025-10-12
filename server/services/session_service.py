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
BIND_TTL = 2 * 60  # 2 minutes
NONCE_TTL = 10 * 60  # 10 minutes
SESSION_TTL = 30 * 60  # 30 minutes

SETTINGS = load_settings()
logging.basicConfig(level=SETTINGS.log_level, format="%(asctime)s %(levelname)s [%(name)s.%(funcName)s (%(lineno)d)] %(message)s")
log = logging.getLogger(__name__)



#naming convention: _x_<name> is for headrs, x_<name> is internal, anything else is for client use

#enum for session states
SessionState = Enum("SessionState", ["PENDING_BIND", "BOUND_DPOP", "AUTHENTICATED", "USER_TERMINATED", "SYSTEM_TERMINATED", "EXPIRED"])
SessionStatus = Enum("SessionStatus", ["NEW", "ACTIVE", "EXPIRED", "TERMINATED"])
NonceStatus = Enum("NonceStatus", ["PENDING", "REDEEMED", "EXPIRED"])
SessionFlag = Enum("SessionFlag", ["RED", "AMBER", "GREEN"])


class SessionService:
    """Service class for handling session-related operations"""
    
    @staticmethod
    def _get_default_session_object() -> dict:
    
        SESSION = {
            "_x_x-csrf-token": None,
            "_x_dpop-nonce": None,
            "_x_dpop-bind": None,
            "dpop_bind_expires_at": None,
            "_session_id": None,
            "session_status": SessionStatus.ACTIVE.name,
            "_access_token": None,
            "_refresh_token": None,
            "_id_token": None,
            "signal_data": None,
            "signal_hash": None,
            "bik_jkt": None,
            "dpop_jkt": None,
            "session_flag": None,
            "session_flag_comment": None,
            "device_id": None,
            "bik_jwk": None,
            "dpop_jwk": None,
            "auth_method": None,
            "auth_status": None,
            "auth_username": None,
            "device_type": None,
            "client_ip": None,
            "state": SessionState.PENDING_BIND.name,
            "created_at": None,
            "updated_at": None,
            "expires_at": None,
            "geolocation": None,
            "active_user_sessions": 0
        }
        return SESSION
    
    @staticmethod
    async def session_init(req: Request, response: Response = None) -> dict:
        """
        Unified session initialization orchestrator that coordinates the 4 parts:
        1. Session creation/restoration
        2. BIK registration (if needed)
        3. DPoP binding (if needed) 
        4. Signal data registration (if needed)
        """
        body = await req.json()
        # Create fresh SESSION object for this request

        SESSION = SessionService._get_default_session_object()

        #check origin details from the https request against allow list
        log.info("Session initialization - Origin: %s", req.headers.get("origin"))
        if not req.headers.get("origin") in SETTINGS.allowed_origins:
            log.error("Session initialization - Origin not allowed: %s", req.headers.get("origin"), SETTINGS.allowed_origins)
            raise HTTPException(status_code=400, detail="Origin not allowed")
                
        payload = body.get("payload")
        
        headers = req.headers
        #make sure we have a uuid, bik, and signal data
        # dpop_jws is now optional since we can extract DPoP key from DPoP header
        if not payload.get("device_id") or not headers.get("BIK") or not payload.get("signal_data"):
            raise HTTPException(status_code=400, detail="Missing required fields")
                
        # Validate BIK JWS token (always required)
        try:
            bik_jkt, bik_jwk, bik_payload = validate_key_jws(headers.get("BIK"), "bik-reg+jws", ["device_id"], "BIK")   
        except HTTPException as e:
            raise HTTPException(status_code=400, detail=f"BIK JWS validation failed: {e}")
        
        # Extract DPoP key from either DPoP header (preferred) or dpop_jws in body
        dpop_jkt = None
        dpop_jwk = None
        dpop_payload = None
        
        dpop_header = headers.get("DPoP")
        
        if dpop_header:
            # Prefer DPoP header for key extraction (more secure, includes proper DPoP claims)
            try:
                dpop_payload = SessionService._validate_dpop_header(dpop_header, req.method, str(req.url))
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
                dpop_jkt, dpop_jwk, dpop_payload = validate_key_jws(payload.get("dpop_jws"), "dpop-bind+jws", ["htm", "htu", "iat", "jti", "nonce", "device_id"], "DPoP")
                log.info("Session initialization - DPoP key extracted from dpop_jws in body")
            except HTTPException as e:
                raise HTTPException(status_code=400, detail=f"DPoP JWS validation failed: {e}")
        else:
            raise HTTPException(status_code=400, detail="Either DPoP header or dpop_jws in body is required")
        
        #is there a session and is it valid
        session_id = req.session.get("session_id")
        
        session_db = await SessionDB.get_session(session_id)
        session_status = session_db.get("session_status") if session_db else None
        log.info("Session initialization - Session ID: %s, Session Status: %s", session_id, session_status)
        
        if not session_id or not session_db or session_db.get("session_status") != SessionStatus.ACTIVE.name:
            #create a new session
            log.info("Session initialization - No session found, creating new session")
            session_id = secrets.token_urlsafe(18)
            csrf = secrets.token_urlsafe(18)
            bind_token = SessionService.issue_binding_token(sid=session_id, bik_jkt=bik_jkt, dpop_jkt=dpop_jkt, aud=req.headers.get("origin"), ttl=BIND_TTL)
            nonce_valid, new_nonce = await SessionService._do_nonce_sense(session_id, None)
            log.info("Session initialization - Session ID: %s, CSRF: %s, Bind Token: %s", session_id, csrf, bind_token)
            SESSION["_session_id"] = session_id
            SESSION["session_status"] = SessionStatus.ACTIVE.name
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
            
            # Extract device_type from signal_data for easier access
            if payload.get("signal_data") and payload.get("signal_data").get("deviceType"):
                SESSION["device_type"] = payload.get("signal_data").get("deviceType")
            
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
            log.info("Session initialization - Session ID: %s created, SESSION: %s", session_id, SESSION)
            req.session.update({
                "session_id": session_id,
                "expires_at": now()
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

                log.info("Session initialization - Setting session: %s", SESSION)
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
                
            try:
                await SessionDB.set_session(session_id, SESSION)
            except Exception as e:
                log.error("Session initialization - Error setting session: %s", e)
                await SessionDB.terminate_session(session_id)
                raise HTTPException(status_code=400, detail="Error setting session")
            
        else:
            SESSION = await SessionService.get_session_data(req, response)
                
        #add HTTPS headers
        ret_body = SessionService._sendable_session_data(SESSION)
        headers = SessionService._session_headers(SESSION)
        for header, value in headers.items():
            response.headers[header] = value
            log.info("Session initialization - Setting header: %s: %s", header, value)
            
        return ret_body

    
    @staticmethod
    async def get_session_data(req: Request, response: Response = None) -> dict:
        log.info("Session initialization - FOUND a session of some sort")

        body = await req.json()
        payload = body.get("payload")
        headers = req.headers
        
        log.info("Session initialization - Headers: %s", headers)
        
        session_id = req.session.get("session_id")
        session_db = await SessionDB.get_session(session_id)
        session_status = session_db.get("session_status") if session_db else None
        log.info("Session initialization - Session ID: %s, Session Status: %s, DB DPoP Bind Token: %s", session_id, session_status, session_db.get("_x_dpop_bind"))

        SESSION = SessionService._get_default_session_object()

        try:
            if payload and payload.get("signal_data"):
                signal_data_json = json.dumps(payload.get("signal_data"))
                fingerprint_result = SessionService._generate_browser_fingerprint(signal_data_json)
                SESSION["signal_hash"] = fingerprint_result["hash"]
                
                # Extract device_type from signal_data for existing sessions
                if payload.get("signal_data").get("deviceType"):
                    SESSION["device_type"] = payload.get("signal_data").get("deviceType")
                    log.info("Session initialization - Device type extracted from signal_data: %s", SESSION["device_type"])
                
                # SECURITY: Compare browser fingerprint (Session Hijacking detection)
                stored_signal_hash = session_db.get("signal_hash")
                if stored_signal_hash and stored_signal_hash != fingerprint_result["hash"]:
                    log.warning("SECURITY ALERT - Browser fingerprint mismatch detected")
                    log.warning("Stored hash: %s", stored_signal_hash)
                    log.warning("Current hash: %s", fingerprint_result["hash"])
                    
                    # Only set AMBER flag if not already RED (don't downgrade severity)
                    current_flag = session_db.get("session_flag")
                    if current_flag != SessionFlag.RED.name:
                        flag_comment = "⚠️ Browser characteristics changed mid-session"
                        SESSION["session_flag"] = SessionFlag.AMBER.name
                        SESSION["session_flag_comment"] = flag_comment
                        await SessionDB.update_session_flag(session_id, SessionFlag.AMBER.name, flag_comment)
                        log.warning("Session flagged as AMBER - Potential session hijacking")
            else:
                log.info("Session initialization - No signal_data in payload or payload is None")
                
        except Exception as e:
            log.error("Session initialization - Error comparing browser fingerprint: %s", e)
        
        log.info("Completed browser fingerprint validation for existing session")
        
        # Validate nonce FIRST for existing session so we always have a new nonce to return
        log.info("Session initialization - Validating nonce for existing session, nonce: %s", headers.get("Dpop-Nonce"))
        nonce_valid, new_nonce = await SessionService._do_nonce_sense(session_id, headers.get("Dpop-Nonce"))

        log.info("Session initialization - Nonce valid: %s, New Nonce: %s", nonce_valid, new_nonce)
        
        # Always set the new nonce in response, even if validation fails
        SESSION["_x_dpop_nonce"] = new_nonce
        
        if not nonce_valid:
            await SessionDB.terminate_session(session_id)
            # Include new nonce in error response headers so client can retry
            raise HTTPException(
                status_code=400, 
                detail="Nonce is invalid",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        # Validate CSRF token for existing session
        if headers.get("x-csrf-token") != session_db.get("_x_x_csrf_token"):
            log.info("Session initialization - Session ID: %s, CSRF Token: %s, stored CSRF Token: %s, CSRF Token mismatch", session_id, headers.get("x-csrf-token"), session_db.get("_x_x_csrf_token"))
            await SessionDB.terminate_session(session_id)
            # Include new nonce in error response so client can retry
            raise HTTPException(
                status_code=400, 
                detail="CSRF Token mismatch",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        try:
            client_ip = req.client.host
            log.info("Session initialization - Client IP from request: %s", client_ip)
            geolocation = GeolocationService.get_ip_geolocation(client_ip)
            geolocation_db = session_db.get("geolocation")

            if geolocation:
                geolocation_json = json.dumps(geolocation)
                SESSION["geolocation"] = geolocation_json
                log.info("Session initialization - GeolocationIP City: %s, Country: %s", geolocation.get("city"), geolocation.get("country"))
                
                # Check if geolocation has changed (e.g., VPN change)
                if geolocation_db:
                    geolocation_db_parsed = json.loads(geolocation_db)
                    log.info("Session initialization - GeolocationDB City: %s, Country: %s", geolocation_db_parsed.get("city"), geolocation_db_parsed.get("country"))
                    
                    # SECURITY: Detect mid-session location change (Session Hijacking / ATO indicator)
                    if (geolocation.get("ip") != geolocation_db_parsed.get("ip") or
                        geolocation.get("city") != geolocation_db_parsed.get("city") or
                        geolocation.get("country") != geolocation_db_parsed.get("country")):
                        log.warning("SECURITY ALERT - Geolocation changed mid-session: Old IP=%s, New IP=%s, Old Location=%s, New Location=%s", 
                                geolocation_db_parsed.get("ip"), geolocation.get("ip"),
                                f"{geolocation_db_parsed.get('city')}, {geolocation_db_parsed.get('country')}",
                                f"{geolocation.get('city')}, {geolocation.get('country')}")
                        
                        # Update geolocation in database
                        await SessionDB.update_session_geolocation(session_id, geolocation_json)
                        
                        # Only set AMBER flag if not already RED (don't downgrade severity)
                        current_flag = session_db.get("session_flag")
                        if current_flag != SessionFlag.RED.name:
                            flag_comment = f"⚠️ Suspicious location change: {geolocation_db_parsed.get('city', 'Unknown')}, {geolocation_db_parsed.get('country', 'Unknown')} → {geolocation.get('city', 'Unknown')}, {geolocation.get('country', 'Unknown')}"
                            SESSION["session_flag"] = SessionFlag.AMBER.name
                            SESSION["session_flag_comment"] = flag_comment
                            await SessionDB.update_session_flag(session_id, SessionFlag.AMBER.name, flag_comment)
                            log.warning("Session flagged as AMBER - Potential session hijacking or ATO")
                else:
                    # No geolocation in DB, save it
                    log.info("No geolocation in DB - saving new geolocation")
                    await SessionDB.update_session_geolocation(session_id, geolocation_json)
            else:
                log.warning("Session initialization - No geolocation data returned")
        except Exception as e:
            log.error("Session initialization - Error getting geolocation: %s", e)

        log.info("Completed geolocation validation for existing session")
        
        # For existing sessions, we primarily validate the DPoP header
        # BIK validation is still needed for consistency, but DPoP key comes from header
        try:
            bik_jkt, bik_jwk, bik_payload = validate_key_jws(headers.get("BIK"), "bik-reg+jws", ["device_id"], "BIK")   
            
        except HTTPException as e:
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=400, 
                detail=f"BIK or Bind Token JWS validation failed: {e}",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        log.info("Completed BIK JWS validation for existing session")
        
        # For existing sessions, DPoP key should come from the DPoP header
        dpop_header = headers.get("Dpop")
        if not dpop_header:
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=401, 
                detail="DPoP header required for existing sessions",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        try:
            log.info("Session initialization - Validating DPoP header for existing session: %s %s %s", req.method, str(req.url), dpop_header[:50])
            dpop_payload = SessionService._validate_dpop_header(dpop_header, req.method, str(req.url))
            dpop_data = validate_jws_token(dpop_header, "dpop+jwt", ["htm", "htu", "iat", "jti", "nonce", "device_id"])
            log.info("Session initialization - DPoP header validation successful for existing session: %s", dpop_data)
            dpop_jwk = dpop_data["header"].get("jwk", {})
            dpop_jkt = ec_p256_thumbprint(dpop_jwk)
            log.info("Session initialization - DPoP key extracted from DPoP header for existing session")
        except Exception as e:
            log.warning("Session initialization - DPoP header validation failed for existing session: %s", e)
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=401, 
                detail=f"DPoP header validation failed: {e}",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        log.info("Completed DPoP header validation for existing session")
        
        #check bik and dpop jkt match - only for existing sessions that already have keys
        if session_db and session_db.get("bik_jkt") and session_db.get("bik_jkt") != bik_jkt:
            log.info("Session initialization - Session ID: %s, BIK JKT: %s, BIK JKT mismatch", session_id, bik_jkt)
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=400, 
                detail="BIK JKT mismatch",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        log.info("Completed BIK JKT validation for existing session")
        
        if session_db and session_db.get("dpop_jkt") and session_db.get("dpop_jkt") != dpop_jkt:
            log.info("Session initialization - Session ID: %s, DPoP JKT: %s, DPoP JKT mismatch", session_id, dpop_jkt)
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=400, 
                detail="DPoP JKT mismatch",
                headers={"Dpop-Nonce": new_nonce}
            )
        
        log.info("Completed DPoP JKT validation for existing session")
        
        #check device id matches session and BIK JWS device id and DPoP JWS device id
        if session_db.get("device_id") != bik_payload.get("device_id") or session_db.get("device_id") != dpop_payload.get("device_id"):
            log.info("Session initialization - Session ID: %s, Device ID: %s, Device ID mismatch", session_id, session_db.get("device_id"))
            await SessionDB.terminate_session(session_id)
            raise HTTPException(
                status_code=400, 
                detail="Device ID mismatch",
                headers={"Dpop-Nonce": new_nonce}
            )

        log.info("Completed device ID validation for existing session")

        #get bind token from SESSION
        bind_token = session_db.get("_x_dpop_bind")
        log.info("Got Bind Token: %s", bind_token)
        bind_payload = None
        if bind_token:
            try:
                bind_payload = SessionService.verify_binding_token(bind_token, bik_jkt, dpop_jkt)
            except Exception as e:
                log.warning(f"Bind token validation failed: {e}")

        log.info("Completed bind token validation for existing session")
        #hydrate SESSION with session from db and add headers
        #if key starts with _x_, then replace all _ after position 3 with - // this gets around the db naming constraints
        
        # Save device_type extracted from signal_data before update
        extracted_device_type = SESSION.get("device_type")
        
        SESSION.update(session_db)
        
        # If DB doesn't have device_type but we extracted it from signal_data, use the extracted value
        if not SESSION.get("device_type") and extracted_device_type:
            SESSION["device_type"] = extracted_device_type
            log.info("Session initialization - Using extracted device_type (not in DB): %s", extracted_device_type)
        # Expire old sessions first
        await SessionDB.expire_old_sessions()
        
        #check for other sessions for the authenticated user
        if SESSION.get("auth_username"):
            log.info("Session initialization - Getting active user sessions for username: %s", SESSION.get("auth_username"))
            active_user_sessions = await SessionDB.get_active_user_sessions(SESSION.get("auth_username"))
            log.info("Session initialization - Active user sessions: %s", active_user_sessions)
            SESSION["active_user_sessions"] = len(active_user_sessions)
        else:
            SESSION["active_user_sessions"] = 0
        
        
        
        
        SESSION["_x_dpop_nonce"] = new_nonce
        
        #add HTTPS headers
        ret_body = SessionService._sendable_session_data(SESSION)
        headers = SessionService._session_headers(SESSION)
        for header, value in headers.items():
            response.headers[header] = value
            log.info("Session initialization - Setting header for URL: %s, %s: %s", str(req.url), header, value)
            

        # for header, value in SESSION["headers"].items():
        # log.info("Setting header: %s: %s", header, value)
        # response.headers[header] = value
        return ret_body
            
        
        
        
    @staticmethod
    async def _terminate_session(session_id: str) -> bool:
        """Check if session is active and return True if it is, False if it is not"""
        log.info("Terminating session: %s", session_id)
        return await SessionDB.terminate_session(session_id)

    @staticmethod
    async def logout_session(session_id: str) -> bool:
        """Logout user and set session state to TERMINATED"""
        log.info("Logging out session: %s", session_id)
        
        # Update session auth_status to logged_out and state to TERMINATED
        await SessionDB.logout_session(session_id)
        
        log.info("Session logged out successfully: %s", session_id)
        return True
    
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
        
        log.info("Nonce validation for session: %s, nonce: %s, new nonce: %s", session_id, nonce, new_nonce)

        if not nonce:
            # No nonce provided - this is a first-time request
            log.info("Session initialization - No nonce provided - this is a first-time request")
            await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
            return True, new_nonce
        else:
            # Validate existing nonce
            nonce_record = await SessionDB.get_nonce(session_id, nonce)
            
            if not nonce_record:
                log.warning("Nonce validation failed - nonce not found: %s", nonce)
                await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                return False, new_nonce
            
            # Use match/case for nonce status validation
            match nonce_record.get("nonce_status"):
                case NonceStatus.EXPIRED.name:
                    log.warning("Nonce validation failed - nonce expired: %s", nonce)
                    await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                    return False, new_nonce
                
                case NonceStatus.REDEEMED.name:
                    log.warning("Nonce validation failed - nonce already redeemed: %s", nonce)
                    await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                    return False, new_nonce
                
                case NonceStatus.PENDING.name:
                    # Valid nonce - mark as redeemed and issue new one
                    await SessionDB.set_nonce(session_id, nonce, NonceStatus.REDEEMED.name, NONCE_TTL)
                    await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.PENDING.name, NONCE_TTL)
                    return True, new_nonce
                
                case _:
                    # Unknown status - treat as invalid
                    log.warning("Nonce validation failed - unknown status: %s", nonce_record.get("nonce_status"))
                    await SessionDB.set_nonce(session_id, new_nonce, NonceStatus.REDEEMED.name, NONCE_TTL)
                    return False, new_nonce
    
    
    @staticmethod
    def _session_headers(session_data: dict) -> dict:
        """Return a dictionary of session headers that can be sent to the client.  anything that starts with _x_ and replace_ with -"""
        return {key[3:].replace("_", "-"): value for key, value in session_data.items() if key.startswith("_x_") and value is not None}


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
    def _validate_dpop_header(dpop_header: str, http_method: str, http_uri: str) -> dict:
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
                        
            # Validate issued at time (should not be too old)
            iat = dpop_payload.get("iat")
            if iat and (now() - iat) > 300:  # 5 minutes max age
                raise ValueError(f"DPoP proof too old: {now() - iat} seconds")
            
            # Validate JTI (should be unique per request)
            jti = dpop_payload.get("jti")
            if not jti:
                raise ValueError("Missing JTI in DPoP proof")
                        
            return dpop_payload
            
        except Exception as e:
            log.warning("DPoP header validation failed: %s", e)
            raise ValueError(f"DPoP header validation failed: {e}")
    
    
    
    @staticmethod
    async def get_session_history(authenticated_username: str, days: int = 10) -> list[dict]:
        """Get session history for an authenticated user"""
        created_at = int(time.time()) - (days * 24 * 60 * 60)
        return await SessionDB.get_session_history(authenticated_username, created_at)
    

