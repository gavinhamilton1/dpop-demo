# server/auth_tracking.py
import time
import logging
from server.db import DB

log = logging.getLogger(__name__)

async def mark_user_authenticated(sid: str, username: str, method: str):
    """
    Centralized method to mark a user as authenticated after successful authentication.
    This should be called by all authentication methods (passkey, face, mobile, etc.)
    """
    try:
        # Get session data to find BIK JKT
        session_data = await DB.get_session(sid)
        if not session_data:
            log.warning(f"No session data found for SID {sid}")
            return False
            
        bik_jkt = session_data.get("bik_jkt")
        if not bik_jkt:
            log.warning(f"No BIK JKT found in session data for SID {sid}")
            return False
            
        log.info(f"=== POST-AUTHENTICATION TRACKING ===")
        log.info(f"Session SID: {sid}")
        log.info(f"Username: {username}")
        log.info(f"Authentication method: {method}")
        log.info(f"BIK JKT: {bik_jkt[:8]}")
        
        # Mark BIK as authenticated in signal_data table
        await DB.mark_bik_authenticated(bik_jkt, sid, username, method)
        log.info(f"Successfully marked BIK {bik_jkt[:8]} as authenticated for user {username} via {method}")
        
        # Update session to mark as authenticated
        session_data["authenticated"] = True
        session_data["authentication_method"] = method
        session_data["authentication_timestamp"] = int(time.time())
        await DB.set_session(sid, session_data)
        
        log.info(f"Session updated with authentication status for user {username}")
        return True
        
    except Exception as e:
        log.error(f"Failed to mark user as authenticated: {e}", exc_info=True)
        return False
