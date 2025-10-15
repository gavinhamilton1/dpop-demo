#!/usr/bin/env python3
"""
Main entry point for the DPoP-Fun application
"""

from server.core.app import app

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
