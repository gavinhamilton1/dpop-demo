# server/signal_service.py
"""
Signal comparison service for cross-session fingerprint analysis
"""
import logging
from typing import Dict, Any, List, Tuple, Optional
from dataclasses import dataclass

log = logging.getLogger("dpop-fun")

@dataclass
class SignalComparison:
    """Result of signal comparison between current and historical data"""
    is_similar: bool
    similarity_score: float
    risk_level: str  # "low", "medium", "high"
    differences: List[str]
    warnings: List[str]

class SignalComparisonService:
    """Service for comparing signal data across sessions"""
    
    def __init__(self):
        # Key signals that must match for session to be allowed
        # These are highly stable, browser-bound characteristics
        self.critical_signals = [
            'platform',
            'hardwareConcurrency', 
            'deviceMemory',
            'webglVendor',
            'webglRenderer',
            'userAgent'  # Browser-bound, shouldn't change for same BIK
        ]
        
        # Signals that are important but not critical
        self.important_signals = [
            'timezone',
            'language',
            'deviceType',
            'colorDepth',      # Can change with display setup
            'screenResolution' # Can change with multi-screen setup
        ]
        
        # Signals that can change (IP, city-level location)
        self.volatile_signals = [
            'ip_address'
        ]
    
    def compare_signals(self, current_fingerprint: Dict[str, Any], 
                       historical_fingerprint: Dict[str, Any]) -> SignalComparison:
        """Compare current fingerprint with historical data"""
        
        differences = []
        warnings = []
        critical_matches = 0
        important_matches = 0
        
        # Check critical signals
        for signal in self.critical_signals:
            current_val = current_fingerprint.get(signal)
            historical_val = historical_fingerprint.get(signal)
            
            if current_val is None or historical_val is None:
                differences.append(f"Missing {signal} data")
                continue
                
            if current_val != historical_val:
                differences.append(f"{signal} changed: {historical_val} -> {current_val}")
            else:
                critical_matches += 1
        
        # Check important signals
        for signal in self.important_signals:
            current_val = current_fingerprint.get(signal)
            historical_val = historical_fingerprint.get(signal)
            
            if current_val is None or historical_val is None:
                continue
                
            if current_val != historical_val:
                warnings.append(f"{signal} changed: {historical_val} -> {current_val}")
            else:
                important_matches += 1
        
        # Check geolocation changes (country = critical, city = important)
        self._check_geolocation_changes(current_fingerprint, historical_fingerprint, differences, warnings)
        
        # Check other volatile signals
        self._check_volatile_signals(current_fingerprint, historical_fingerprint, warnings)
        
        # Calculate similarity score
        total_critical = len(self.critical_signals)
        total_important = len(self.important_signals)
        
        critical_score = critical_matches / total_critical if total_critical > 0 else 1.0
        important_score = important_matches / total_important if total_important > 0 else 1.0
        
        # Weighted similarity score (critical signals are more important)
        similarity_score = (critical_score * 0.7) + (important_score * 0.3)
        
        # Determine if similar enough to allow session
        is_similar = similarity_score >= 0.8  # 80% similarity required
        
        # Determine risk level
        if similarity_score >= 0.9:
            risk_level = "low"
        elif similarity_score >= 0.7:
            risk_level = "medium"
        else:
            risk_level = "high"
        
        # Add risk warnings
        if len(differences) > 2:
            warnings.append("Multiple critical signal changes detected")
        if risk_level == "high":
            warnings.append("High risk: Significant signal changes detected")
        
        return SignalComparison(
            is_similar=is_similar,
            similarity_score=similarity_score,
            risk_level=risk_level,
            differences=differences,
            warnings=warnings
        )
    
    def _check_geolocation_changes(self, current: Dict[str, Any], 
                                  historical: Dict[str, Any], 
                                  differences: List[str], warnings: List[str]):
        """Check geolocation changes - country level is critical, city level is important"""
        
        current_geo = current.get('geolocation', {})
        historical_geo = historical.get('geolocation', {})
        
        if not current_geo or not historical_geo:
            return
        
        # Check country changes (CRITICAL - should block session)
        current_country = current_geo.get('country')
        historical_country = historical_geo.get('country')
        
        if current_country and historical_country and current_country != historical_country:
            differences.append(f"Country changed: {historical_country} -> {current_country}")
        
        # Check city changes (IMPORTANT - should warn but not block)
        current_city = current_geo.get('city')
        historical_city = historical_geo.get('city')
        
        if current_city and historical_city and current_city != historical_city:
            warnings.append(f"City changed: {historical_city} -> {current_city}")
        
        # Check region changes (IMPORTANT)
        current_region = current_geo.get('region')
        historical_region = historical_geo.get('region')
        
        if current_region and historical_region and current_region != historical_region:
            warnings.append(f"Region changed: {historical_region} -> {current_region}")

    def _check_volatile_signals(self, current: Dict[str, Any], 
                              historical: Dict[str, Any], warnings: List[str]):
        """Check volatile signals for significant changes"""
        
        # Check IP address changes
        current_ip = current.get('ip_address')
        historical_ip = historical.get('ip_address')
        
        if current_ip and historical_ip and current_ip != historical_ip:
            warnings.append(f"IP address changed: {historical_ip} -> {current_ip}")
        
        # Check timezone changes
        current_tz = current.get('timezone')
        historical_tz = historical.get('timezone')
        
        if current_tz and historical_tz and current_tz != historical_tz:
            warnings.append(f"Timezone changed: {historical_tz} -> {current_tz}")
    
    def should_allow_session(self, comparison: SignalComparison) -> Tuple[bool, str]:
        """Determine if session should be allowed based on comparison"""
        
        if not comparison.is_similar:
            return False, f"Session blocked: Signal similarity too low ({comparison.similarity_score:.2f})"
        
        if comparison.risk_level == "high":
            return False, f"Session blocked: High risk detected - {', '.join(comparison.differences[:3])}"
        
        if len(comparison.differences) > 3:
            return False, f"Session blocked: Too many critical changes - {', '.join(comparison.differences[:3])}"
        
        # Allow session with warnings
        warning_msg = ""
        if comparison.warnings:
            warning_msg = f" (Warnings: {', '.join(comparison.warnings[:2])})"
        
        return True, f"Session allowed with {comparison.similarity_score:.2f} similarity{warning_msg}"

# Export singleton
signal_service = SignalComparisonService()
