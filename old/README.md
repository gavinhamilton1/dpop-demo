# Device Registration Demo

A simple Python FastAPI backend service for registering devices with public keys.

## Features

- **Index Route (`/`)**: Serves a simple HTML page for device registration
- **Register Device Route (`/register-device`)**: POST endpoint that accepts a JSON payload with a public key
- **List Devices Route (`/devices`)**: GET endpoint to view all registered devices
- **Remove Device Route (`/devices/{device_id}`)**: DELETE endpoint to remove a specific device
- **Duplicate Prevention**: Prevents registration of devices with duplicate public keys
- **In-memory Storage**: All device data is stored in memory (suitable for demos)
- **Automatic API Documentation**: Interactive API docs available at `/docs`
- **Request Validation**: Built-in validation using Pydantic models

## Setup

1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   
   If you encounter build errors (especially on macOS), try:
   ```bash
   pip install -r requirements-simple.txt
   ```

2. Run the FastAPI application:
   ```bash
   python app.py
   ```
   
   Or alternatively:
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000 --reload
   ```

3. Open your browser and navigate to `http://localhost:8000`

## Troubleshooting

### Build Errors (pydantic-core)

If you encounter build errors like "Failed to build wheel for pydantic-core", try these solutions:

1. **Use pre-built wheels** (recommended):
   ```bash
   pip install --only-binary=all fastapi uvicorn
   ```

2. **Update pip and setuptools**:
   ```bash
   pip install --upgrade pip setuptools wheel
   ```

3. **Use conda** (if available):
   ```bash
   conda install fastapi uvicorn -c conda-forge
   ```

4. **Install Xcode Command Line Tools** (macOS):
   ```bash
   xcode-select --install
   ```

5. **Use the simple requirements**:
   ```bash
   pip install -r requirements-simple.txt
   ```

## API Documentation

FastAPI automatically generates interactive API documentation:
- **Swagger UI**: Visit `http://localhost:8000/docs`
- **ReDoc**: Visit `http://localhost:8000/redoc`

## API Endpoints

### POST /register-device
Register a new device with a public key.

**Request Body:**
```json
{
    "public_key": "your-public-key-here"
}
```

**Success Response (200):**
```json
{
    "success": true,
    "message": "Device successfully registered",
    "device_id": "device_1"
}
```

**Conflict Response (409) - Duplicate Public Key:**
```json
{
    "detail": "Device with this public key is already registered as device_1"
}
```

### GET /devices
List all registered devices.

**Response:**
```json
{
    "success": true,
    "devices": {
        "device_1": {
            "public_key": "your-public-key-here",
            "registered_at": "2024-01-01 12:00:00"
        }
    }
}
```

### DELETE /devices/{device_id}
Remove a specific device by its ID.

**Response:**
```json
{
    "success": true,
    "message": "Device device_1 successfully removed",
    "removed_device": {
        "public_key": "your-public-key-here",
        "registered_at": "2024-01-01 12:00:00"
    }
}
```

## Usage

1. Open the web interface at `http://localhost:8000`
2. Enter a public key in the text area
3. Click "Register Device" to register the device
4. If you try to register a duplicate public key, you'll see a warning message
5. Use the "Refresh Devices" button to see all registered devices
6. Click the "Remove" button next to any device to delete it
7. Explore the API documentation at `http://localhost:8000/docs`

## Notes

- This is a demo application with in-memory storage
- Data will be lost when the server restarts
- The service runs on port 8000 by default
- Hot reload is enabled for development purposes
- FastAPI provides automatic request/response validation
- Built-in OpenAPI documentation generation
- Duplicate public keys are prevented with a 409 Conflict response 