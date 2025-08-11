from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, Any
from datetime import datetime
import uvicorn

app = FastAPI(title="Device Registration Demo", description="A simple API for registering devices with public keys")

# Mount static files directory
app.mount("/static", StaticFiles(directory="."), name="static")

# In-memory storage for device information
devices: Dict[str, Dict[str, Any]] = {}

# Pydantic model for request validation
class DeviceRegistration(BaseModel):
    public_key: str

@app.get("/", response_class=HTMLResponse)
async def index():
    """Serve the index.html page"""
    with open("index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/register-device")
async def register_device(device: DeviceRegistration):
    """Register a device with its public key"""
    try:
        public_key = device.public_key
        
        # Check if this public key is already registered
        for device_id, device_info in devices.items():
            if device_info['public_key'] == public_key:
                raise HTTPException(
                    status_code=409, 
                    detail=f'Device with this public key is already registered as {device_id}'
                )
        
        # Generate a simple device ID (in a real app, you might use UUID)
        device_id = f"device_{len(devices) + 1}"
        
        # Store device information in memory
        devices[device_id] = {
            'public_key': public_key,
            'registered_at': str(datetime.now())
        }
        
        return {
            'success': True,
            'message': 'Device successfully registered',
            'device_id': device_id
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Registration failed: {str(e)}')

@app.delete("/devices/{device_id}")
async def remove_device(device_id: str):
    """Remove a device by its ID"""
    try:
        if device_id not in devices:
            raise HTTPException(status_code=404, detail=f'Device {device_id} not found')
        
        # Remove the device from memory
        removed_device = devices.pop(device_id)
        
        return {
            'success': True,
            'message': f'Device {device_id} successfully removed',
            'removed_device': removed_device
        }
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'Failed to remove device: {str(e)}')

@app.get("/devices")
async def list_devices():
    """List all registered devices (for debugging/demo purposes)"""
    return {
        'success': True,
        'devices': devices
    }

if __name__ == "__main__":
    uvicorn.run("app:app", host="0.0.0.0", port=8000, reload=True) 