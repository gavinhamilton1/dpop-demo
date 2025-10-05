"""
Domain Models and Data Structures
"""
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime


@dataclass
class SignalComparison:
    """Result of signal comparison between current and historical data"""
    is_similar: bool
    similarity_score: float
    risk_level: str  # "low", "medium", "high"
    differences: List[str]
    warnings: List[str]


@dataclass
class SessionData:
    """Session data structure"""
    sid: str
    state: str
    csrf: str
    session_nonce: Optional[str] = None
    bik_jkt: Optional[str] = None
    dpop_jkt: Optional[str] = None
    username: Optional[str] = None
    user_authenticated: bool = False
    bik_authenticated: bool = False
    bik_auth_method: Optional[str] = None
    fingerprint: Optional[Dict[str, Any]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


@dataclass
class BrowserData:
    """Browser identification data"""
    device_id: Optional[str] = None
    bik_jkt: Optional[str] = None
    dpop_jkt: Optional[Dict[str, Any]] = None
    fingerprint: Optional[Dict[str, Any]] = None


@dataclass
class FaceEmbedding:
    """Face embedding data"""
    embedding_id: str
    user_id: str
    embedding_data: List[float]
    created_at: datetime
    metadata: Optional[Dict[str, Any]] = None


@dataclass
class AuthenticationResult:
    """Authentication result data"""
    success: bool
    method: str
    user_id: Optional[str] = None
    confidence: Optional[float] = None
    metadata: Optional[Dict[str, Any]] = None
