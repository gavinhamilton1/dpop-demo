"""
Test configuration for server-side tests
"""

import pytest
import asyncio
import tempfile
import os
from unittest.mock import patch, MagicMock

# Test database configuration
TEST_DB_PATH = ":memory:"  # Use in-memory database for tests

@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup test environment before each test"""
    # Mock the database to use in-memory SQLite
    with patch('server.db.DATABASE_PATH', TEST_DB_PATH):
        yield

@pytest.fixture
def mock_config():
    """Mock configuration for tests"""
    return {
        "server": {
            "host": "localhost",
            "port": 8000,
            "debug": True
        },
        "security": {
            "session_secret": "test-secret-key",
            "csrf_secret": "test-csrf-key",
            "nonce_window": 300
        },
        "webauthn": {
            "rp_name": "Test App",
            "rp_id": "localhost",
            "origin": "https://localhost:8000"
        }
    }

@pytest.fixture
def mock_session_data():
    """Mock session data for tests"""
    return {
        "session_id": "test-session-123",
        "nonce": "test-nonce-456",
        "created": 1234567890,
        "dpop_bound": False,
        "bik_registered": False,
        "csrf_token": "test-csrf-token"
    }

@pytest.fixture
def mock_device_key():
    """Mock device key for tests"""
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": "test-x-coordinate",
        "y": "test-y-coordinate",
        "kid": "test-key-id-123"
    }

@pytest.fixture
def mock_dpop_token():
    """Mock DPoP token for tests"""
    return {
        "typ": "dpop+jwt",
        "jti": "test-jti-123",
        "htu": "https://localhost:8000/api/echo",
        "htm": "POST",
        "iat": 1234567890,
        "exp": 1234568190
    }

@pytest.fixture
def mock_webauthn_credential():
    """Mock WebAuthn credential for tests"""
    return {
        "id": "test-credential-id",
        "type": "public-key",
        "response": {
            "attestationObject": "test-attestation-object",
            "clientDataJSON": "test-client-data-json"
        }
    }

@pytest.fixture
def mock_webauthn_assertion():
    """Mock WebAuthn assertion for tests"""
    return {
        "id": "test-credential-id",
        "type": "public-key",
        "response": {
            "authenticatorData": "test-authenticator-data",
            "clientDataJSON": "test-client-data-json",
            "signature": "test-signature"
        }
    }
