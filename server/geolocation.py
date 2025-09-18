# server/geolocation.py
import requests
import logging
from typing import Dict, Optional

log = logging.getLogger("dpop-fun")

class GeolocationService:
    """Service for IP-based geolocation lookup"""
    
    @staticmethod
    def get_ip_geolocation(ip_address: str) -> Optional[Dict[str, str]]:
        """
        Get geolocation data for an IP address using ipapi.co
        Returns None if lookup fails or IP is invalid
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
            
        try:
            log.info("Looking up geolocation for IP: %s", ip_address)
            
            # Use ipapi.co free service (1000 requests/day)
            response = requests.get(f"http://ipapi.co/{ip_address}/json/", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant geolocation data
                geolocation = {
                    'ip': data.get('ip', ip_address),
                    'city': data.get('city', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country_code', 'Unknown'),
                    'postal': data.get('postal', 'Unknown'),
                    'latitude': str(data.get('latitude', 'Unknown')),
                    'longitude': str(data.get('longitude', 'Unknown')),
                    'timezone': data.get('timezone', 'Unknown'),
                    'org': data.get('org', 'Unknown'),
                    'asn': data.get('asn', 'Unknown')
                }
                
                log.info("Geolocation lookup successful for IP %s: %s, %s, %s", 
                        ip_address, geolocation['city'], geolocation['region'], geolocation['country'])
                return geolocation
                
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
    def get_ip_geolocation_fallback(ip_address: str) -> Optional[Dict[str, str]]:
        """
        Fallback geolocation service using ip-api.com
        """
        if not ip_address or ip_address in ['127.0.0.1', 'localhost', '::1']:
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
            
        try:
            log.info("Trying fallback geolocation for IP: %s", ip_address)
            
            # Use ip-api.com free service
            response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
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
                        'org': data.get('org', 'Unknown'),
                        'asn': data.get('as', 'Unknown')
                    }
                    
                    log.info("Fallback geolocation successful for IP %s: %s, %s, %s", 
                            ip_address, geolocation['city'], geolocation['region'], geolocation['country'])
                    return geolocation
                else:
                    log.warning("Fallback geolocation failed for IP %s: %s", ip_address, data.get('message', 'Unknown error'))
                    return None
            else:
                log.warning("Fallback geolocation request failed for IP %s: HTTP %s", ip_address, response.status_code)
                return None
                
        except Exception as e:
            log.error("Fallback geolocation error for IP %s: %s", ip_address, str(e))
            return None
