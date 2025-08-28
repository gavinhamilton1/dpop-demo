#!/usr/bin/env python3
"""
DPoP Lab Server - Simplified FastAPI implementation
This server provides the backend API endpoints for the DPoP lab.
"""

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import secrets
import json
import base64
import time
from typing import Dict, Any
import os

app = FastAPI(title="DPoP Lab Server", version="1.0.0")

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory storage for lab purposes
sessions = {}
links = {}

# Configuration
BASE_DIR = os.path.dirname(__file__)

def generate_nonce() -> str:
    """Generate a random nonce for DPoP challenges."""
    return base64.urlsafe_b64encode(secrets.token_bytes(18)).decode('utf-8').rstrip('=')

def generate_session_id() -> str:
    """Generate a unique session ID."""
    return secrets.token_urlsafe(18)

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the main lab page."""
    with open(os.path.join(BASE_DIR, "index.html"), "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/utils.js")
async def utils_js():
    """Serve the utils.js file."""
    with open(os.path.join(BASE_DIR, "utils.js"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="application/javascript")

@app.get("/app.js")
async def app_js():
    """Serve the app.js file."""
    with open(os.path.join(BASE_DIR, "app.js"), "r", encoding="utf-8") as f:
        return Response(content=f.read(), media_type="application/javascript")

# ============================================================================
# Session Management Endpoints
# ============================================================================

@app.post("/session/init")
async def session_init(request: Request):
    """
    Initialize a new session.
    Returns CSRF token and registration nonce.
    """
    try:
        body = await request.json()
        browser_uuid = body.get("browser_uuid", "unknown")
        
        # Generate session data
        session_id = generate_session_id()
        csrf_token = secrets.token_urlsafe(18)
        reg_nonce = generate_nonce()
        
        # Store session
        sessions[session_id] = {
            "state": "pending-bind",
            "csrf": csrf_token,
            "reg_nonce": reg_nonce,
            "browser_uuid": browser_uuid,
            "created_at": time.time()
        }
        
        # Set session cookie
        response = JSONResponse({
            "csrf": csrf_token,
            "reg_nonce": reg_nonce,
            "state": "pending-bind"
        })
        response.set_cookie("session_id", session_id, httponly=True, secure=False)
        
        return response
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Session initialization failed: {str(e)}")

@app.get("/session/status")
async def session_status(request: Request):
    """
    Get current session status.
    """
    session_id = request.cookies.get("session_id")
    
    if not session_id or session_id not in sessions:
        return {
            "valid": False,
            "state": None,
            "bik_registered": False,
            "dpop_bound": False
        }
    
    session = sessions[session_id]
    state = session.get("state")
    bik_registered = bool(session.get("bik_jkt"))
    dpop_bound = bool(session.get("dpop_jkt"))
    
    return {
        "valid": True,
        "state": state,
        "bik_registered": bik_registered,
        "dpop_bound": dpop_bound
    }

# ============================================================================
# Browser Identity Key (BIK) Registration
# ============================================================================

@app.post("/browser/register")
async def browser_register(request: Request):
    """
    Register a browser identity key.
    Expects a JWS with the public key and nonce verification.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if csrf_token != session.get("csrf"):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        
        # Get the JWS from request body
        jws_compact = (await request.body()).decode()
        
        # TODO: Implement JWS verification
        # For lab purposes, we'll accept any JWS and extract a mock thumbprint
        
        # Mock implementation - in real implementation, verify the JWS
        bik_jkt = f"bik_{secrets.token_hex(8)}"
        
        # Update session
        session["bik_jkt"] = bik_jkt
        session["state"] = "bound-bik"
        session["reg_nonce"] = None
        
        return {
            "bik_jkt": bik_jkt,
            "state": "bound-bik"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"BIK registration failed: {str(e)}")

# ============================================================================
# DPoP Binding
# ============================================================================

@app.post("/dpop/bind")
async def dpop_bind(request: Request):
    """
    Bind DPoP key to session.
    Expects a DPoP JWS with the public key.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        csrf_token = request.headers.get("X-CSRF-Token")
        
        if csrf_token != session.get("csrf"):
            raise HTTPException(status_code=403, detail="Invalid CSRF token")
        
        if session.get("state") != "bound-bik":
            raise HTTPException(status_code=403, detail="BIK not bound")
        
        # Get the DPoP JWS from request body
        dpop_jws = (await request.body()).decode()
        
        # TODO: Implement DPoP JWS verification
        # For lab purposes, we'll accept any JWS and extract a mock thumbprint
        
        # Mock implementation - in real implementation, verify the DPoP JWS
        dpop_jkt = f"dpop_{secrets.token_hex(8)}"
        
        # Generate binding token (mock)
        bind_token = f"bind_{secrets.token_hex(16)}"
        next_nonce = generate_nonce()
        
        # Update session
        session["dpop_jkt"] = dpop_jkt
        session["state"] = "bound"
        session["bind_token"] = bind_token
        session["current_nonce"] = next_nonce
        
        # Return response with binding token and nonce
        response = JSONResponse({
            "bind": bind_token,
            "cnf": {"dpop_jkt": dpop_jkt},
            "expires_at": int(time.time()) + 3600  # 1 hour
        })
        response.headers["DPoP-Nonce"] = next_nonce
        
        return response
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"DPoP binding failed: {str(e)}")

# ============================================================================
# WebAuthn Passkey Support
# ============================================================================

@app.post("/webauthn/registration/options")
async def webauthn_registration_options(request: Request):
    """
    Get WebAuthn registration options.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate registration options
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        options = {
            "challenge": challenge,
            "rp": {
                "name": "DPoP Lab",
                "id": "localhost"
            },
            "user": {
                "id": base64.urlsafe_b64encode(session_id.encode()).decode('utf-8').rstrip('='),
                "name": f"user_{session_id[:8]}",
                "displayName": f"DPoP Lab User {session_id[:8]}"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7},  # ES256
                {"type": "public-key", "alg": -257}  # RS256
            ],
            "timeout": 60000,
            "attestation": "direct",
            "authenticatorSelection": {
                "authenticatorAttachment": "platform",
                "userVerification": "preferred"
            }
        }
        
        # Store challenge for verification
        session["webauthn_challenge"] = challenge
        
        return options
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate registration options: {str(e)}")

@app.post("/webauthn/registration/verify")
async def webauthn_registration_verify(request: Request):
    """
    Verify WebAuthn registration.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Get attestation from request body
        attestation = await request.json()
        print(f"Received attestation: {attestation}")  # Debug log
        
        # TODO: Implement attestation verification
        # For lab purposes, we'll accept any attestation
        
        # Extract credential ID from the attestation
        # In a real implementation, you would verify the attestation here
        credential_id = attestation.get("id")
        if not credential_id:
            # Fallback to mock ID if not provided
            credential_id = f"cred_{secrets.token_hex(16)}"
        
        # Store credential info
        session["webauthn_credentials"] = session.get("webauthn_credentials", [])
        session["webauthn_credentials"].append({
            "id": credential_id,
            "type": "public-key",
            "transports": ["internal"]
        })
        
        return {"verified": True, "credential_id": credential_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration verification failed: {str(e)}")

@app.post("/webauthn/authentication/options")
async def webauthn_authentication_options(request: Request):
    """
    Get WebAuthn authentication options.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate authentication options
        challenge = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode('utf-8').rstrip('=')
        
        options = {
            "challenge": challenge,
            "rpId": "localhost",
            "timeout": 60000,
            "userVerification": "preferred"
        }
        
        # Add allowed credentials if available
        credentials = session.get("webauthn_credentials", [])
        print(f"Available credentials: {credentials}")  # Debug log
        if credentials:
            options["allowCredentials"] = [
                {
                    "id": cred["id"],  # Keep as base64 string, will be converted to ArrayBuffer by client
                    "type": cred["type"],
                    "transports": cred.get("transports", [])
                }
                for cred in credentials
            ]
        
        # Store challenge for verification
        session["webauthn_challenge"] = challenge
        
        return options
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to generate authentication options: {str(e)}")

@app.post("/webauthn/authentication/verify")
async def webauthn_authentication_verify(request: Request):
    """
    Verify WebAuthn authentication.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Get assertion from request body
        assertion = await request.json()
        
        # TODO: Implement assertion verification
        # For lab purposes, we'll accept any assertion
        
        # Mock implementation - in real implementation, verify the assertion
        return {"verified": True, "user_id": session_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Authentication verification failed: {str(e)}")

# ============================================================================
# Cross-Device Linking
# ============================================================================

@app.post("/link/start")
async def link_start(request: Request):
    """
    Start cross-device linking process.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Generate link ID
        link_id = secrets.token_urlsafe(16)
        
        # Store link information
        links[link_id] = {
            "session_id": session_id,
            "status": "pending",
            "created_at": time.time(),
            "device_info": {}
        }
        
        # Generate linking URL
        base_url = str(request.base_url).rstrip('/')
        link_url = f"{base_url}/link/{link_id}"
        
        return {
            "link_id": link_id,
            "link_url": link_url,
            "status": "pending"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start linking: {str(e)}")

@app.get("/link/{link_id}")
async def link_page(link_id: str):
    """
    Serve the mobile linking page.
    """
    # For lab purposes, return a simple HTML page
    html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>DPoP Lab - Device Linking</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{ font-family: Arial, sans-serif; padding: 20px; text-align: center; }}
            .status {{ margin: 20px; padding: 10px; border-radius: 5px; }}
            .pending {{ background: #fff3cd; color: #856404; }}
            .linked {{ background: #d4edda; color: #155724; }}
            .completing {{ background: #cce5ff; color: #004085; }}
            button {{ 
                background: #007bff; 
                color: white; 
                border: none; 
                padding: 10px 20px; 
                border-radius: 5px; 
                cursor: pointer; 
                margin: 10px;
            }}
            button:hover {{ background: #0056b3; }}
            button:disabled {{ background: #6c757d; cursor: not-allowed; }}
        </style>
    </head>
    <body>
        <h1>🔗 DPoP Lab - Device Linking</h1>
        <p>Link ID: <code>{link_id}</code></p>
        <div id="status" class="status pending">
            <p>Connecting to desktop device...</p>
            <p>Click the button below to complete the link:</p>
            <button id="completeBtn" onclick="completeLink()">Complete Link</button>
        </div>
        <script>
            async function completeLink() {{
                const statusDiv = document.getElementById('status');
                const completeBtn = document.getElementById('completeBtn');
                
                try {{
                    statusDiv.className = 'status completing';
                    statusDiv.innerHTML = '<p>Completing link...</p>';
                    completeBtn.disabled = true;
                    
                    // Send device info to complete the link
                    const response = await fetch('/link/complete/{link_id}', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify({{
                            device_type: 'mobile',
                            user_agent: navigator.userAgent,
                            timestamp: Date.now(),
                            device_info: {{
                                platform: navigator.platform,
                                language: navigator.language,
                                screen_width: screen.width,
                                screen_height: screen.height
                            }}
                        }})
                    }});
                    
                    if (response.ok) {{
                        statusDiv.className = 'status linked';
                        statusDiv.innerHTML = '<p>✅ Successfully linked to desktop device!</p>';
                        completeBtn.style.display = 'none';
                    }} else {{
                        throw new Error('Link completion failed');
                    }}
                }} catch (error) {{
                    console.error('Link completion failed:', error);
                    statusDiv.className = 'status pending';
                    statusDiv.innerHTML = '<p>Link completion failed. Please try again.</p><button id="completeBtn" onclick="completeLink()">Retry</button>';
                }}
            }}
            
            // Auto-complete after 3 seconds for convenience
            setTimeout(() => {{
                const completeBtn = document.getElementById('completeBtn');
                if (completeBtn && !completeBtn.disabled) {{
                    completeBtn.click();
                }}
            }}, 3000);
        </script>
    </body>
    </html>
    """
    return HTMLResponse(html)

@app.get("/link/status/{link_id}")
async def link_status(link_id: str):
    """
    Get linking status.
    """
    if link_id not in links:
        raise HTTPException(status_code=404, detail="Link not found")
    
    link_info = links[link_id]
    return {
        "link_id": link_id,
        "status": link_info["status"],
        "device_info": link_info.get("device_info", {})
    }

@app.post("/link/complete/{link_id}")
async def link_complete(link_id: str, request: Request):
    """
    Complete the linking process.
    """
    try:
        if link_id not in links:
            raise HTTPException(status_code=404, detail="Link not found")
        
        link_info = links[link_id]
        device_info = await request.json()
        
        # Update link status
        link_info["status"] = "linked"
        link_info["device_info"] = device_info
        link_info["linked_at"] = time.time()
        
        return {"status": "linked", "link_id": link_id}
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to complete linking: {str(e)}")

# ============================================================================
# API Testing
# ============================================================================

@app.post("/api/test")
async def api_test(request: Request):
    """
    Test API endpoint that requires DPoP authentication.
    """
    try:
        session_id = request.cookies.get("session_id")
        if not session_id or session_id not in sessions:
            raise HTTPException(status_code=401, detail="No valid session")
        
        session = sessions[session_id]
        
        if session.get("state") != "bound":
            raise HTTPException(status_code=403, detail="DPoP not bound")
        
        # Check for DPoP header
        dpop_header = request.headers.get("DPoP")
        if not dpop_header:
            raise HTTPException(status_code=401, detail="Missing DPoP header")
        
        # Check for DPoP-Bind header
        dpop_bind = request.headers.get("DPoP-Bind")
        if not dpop_bind:
            raise HTTPException(status_code=401, detail="Missing DPoP-Bind header")
        
        # TODO: Implement DPoP verification
        # For lab purposes, we'll accept any DPoP header
        
        # Get request body
        body = await request.json()
        message = body.get("message", "No message provided")
        
        return {
            "success": True,
            "message": f"API test successful! Received: {message}",
            "timestamp": time.time(),
            "session_id": session_id[:8],
            "dpop_verified": True
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"API test failed: {str(e)}")

# ============================================================================
# Admin Endpoints
# ============================================================================

@app.post("/admin/flush")
async def admin_flush():
    """
    Flush all server state (for testing).
    """
    global sessions, links
    sessions.clear()
    links.clear()
    return {"message": "Server state flushed successfully"}

if __name__ == "__main__":
    import uvicorn
    print("🚀 Starting DPoP Lab Server...")
    print("📖 Open http://localhost:8000 to access the lab")
    print("🔧 API documentation: http://localhost:8000/docs")
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
