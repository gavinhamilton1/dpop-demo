# server/geolocation.py
import requests
import logging
import time
from typing import Dict, Optional

log = logging.getLogger(__name__)

# Simple in-memory cache for geolocation data
# Format: {ip_address: {'data': geolocation_dict, 'timestamp': unix_timestamp}}
_GEOLOCATION_CACHE = {}
CACHE_TTL = 300  # Cache for 5 minutes (reduced for VPN testing)


class GeolocationService:
    """Service for IP-based geolocation lookup"""
    
    @staticmethod
    def get_ip_geolocation(ip_address: str) -> Optional[Dict[str, str]]:
        """
        Get geolocation data for an IP address using ip-api.com (45 requests/min free)
        Returns None if lookup fails or IP is invalid
        Caches results for 1 hour to reduce API calls
        """
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '::1']:
            log.info("Skipping geolocation for local IP: %s", ip_address)
            # Return mock data for localhost testing
            return {
                'ip': ip_address,
                'city': 'Local Development',
                'region': 'Local Environment',
                'country': 'Development',
                'country_code': 'DEV',
                'postal': '00000',
                'latitude': '0.000000',
                'longitude': '0.000000',
                'timezone': 'UTC',
                'org': 'Local Development Server',
                'asn': 'AS0000'
            }
        
        # Check cache first
        current_time = time.time()
        if ip_address in _GEOLOCATION_CACHE:
            cached_entry = _GEOLOCATION_CACHE[ip_address]
            if current_time - cached_entry['timestamp'] < CACHE_TTL:
                log.info("Using cached geolocation for IP: %s", ip_address)
                return cached_entry['data']
            else:
                # Cache expired, remove it
                del _GEOLOCATION_CACHE[ip_address]
                log.info("Cache expired for IP: %s", ip_address)
            
        try:
            log.info("Looking up geolocation for IP: %s", ip_address)
            
            # Use ip-api.com free service (45 requests/minute, no daily limit)
            response = requests.get(f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    # Extract relevant geolocation data
                    geolocation = {
                        'ip': ip_address,
                        'city': data.get('city', 'Unknown'),
                        'region': data.get('regionName', 'Unknown'),
                        'country': data.get('country', 'Unknown'),
                        'country_code': data.get('countryCode', 'Unknown'),
                        'postal': data.get('zip', 'Unknown'),
                        'latitude': str(data.get('lat', 'Unknown')),
                        'longitude': str(data.get('lon', 'Unknown')),
                        'timezone': data.get('timezone', 'Unknown'),
                        'org': data.get('org', data.get('isp', 'Unknown')),
                        'asn': data.get('as', 'Unknown')
                    }
                    
                    # Cache the result
                    _GEOLOCATION_CACHE[ip_address] = {
                        'data': geolocation,
                        'timestamp': current_time
                    }
                    
                    log.info("Geolocation lookup successful for IP %s: %s, %s, %s", 
                            ip_address, geolocation['city'], geolocation['region'], geolocation['country'])
                    return geolocation
                else:
                    log.warning("Geolocation lookup failed for IP %s: %s", ip_address, data.get('message', 'Unknown error'))
                    return None
                
            else:
                log.warning("Geolocation lookup failed for IP %s: HTTP %s", ip_address, response.status_code)
                return None
                
        except requests.exceptions.Timeout:
            log.warning("Geolocation lookup timeout for IP %s", ip_address)
            return None
        except requests.exceptions.RequestException as e:
            log.warning("Geolocation lookup request failed for IP %s: %s", ip_address, str(e))
            return None
        except Exception as e:
            log.error("Unexpected error in geolocation lookup for IP %s: %s", ip_address, str(e))
            return None
    
    @staticmethod
    def clear_cache():
        """Clear the geolocation cache (useful for testing or if cache gets too large)"""
        global _GEOLOCATION_CACHE
        _GEOLOCATION_CACHE.clear()
        log.info("Geolocation cache cleared")
    
    @staticmethod
    def get_cache_stats():
        """Get cache statistics"""
        current_time = time.time()
        total_entries = len(_GEOLOCATION_CACHE)
        valid_entries = sum(1 for entry in _GEOLOCATION_CACHE.values() 
                           if current_time - entry['timestamp'] < CACHE_TTL)
        return {
            'total_entries': total_entries,
            'valid_entries': valid_entries,
            'expired_entries': total_entries - valid_entries
        }
