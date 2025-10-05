"""
URL canonicalization and validation utilities
"""
from typing import List, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit
from fastapi import Request


def _bracket_host(host: str) -> str:
    """Add brackets around IPv6 addresses if needed"""
    if host and ":" in host and not host.startswith("["):
        return f"[{host}]"
    return host


def _is_allowed_origin(url: str, allowed_origins: List[str]) -> bool:
    """Check if a URL origin is in the allowed origins list"""
    try:
        parsed_url = urlsplit(url)
        url_origin = f"{parsed_url.scheme}://{parsed_url.netloc}"
        return url_origin in allowed_origins
    except Exception:
        return False


def _canonicalize_url_for_validation(url: str, allowed_origins: List[str]) -> Optional[str]:
    """Canonicalize a URL for validation against allowed origins"""
    try:
        parsed_url = urlsplit(url)
        scheme = parsed_url.scheme.lower()
        host = parsed_url.hostname.lower() if parsed_url.hostname else ""
        port = parsed_url.port
        if ((scheme == "https" and port == 443) or (scheme == "http" and port == 80)):
            port = None
        netloc = f"{_bracket_host(host)}:{port}" if port else _bracket_host(host)
        canonical = urlunsplit((scheme, netloc, parsed_url.path or "/", parsed_url.query, ""))
        if _is_allowed_origin(canonical, allowed_origins):
            return canonical
        return None
    except Exception:
        return None


def canonicalize_origin_and_url(request: Request, external_origin: Optional[str] = None) -> Tuple[str, str]:
    """Canonicalize origin and URL from a request, handling IPv6 and proxy headers"""
    if external_origin:
        origin = external_origin.rstrip("/")
    else:
        scheme = (request.headers.get("x-forwarded-proto") or request.url.scheme or "").lower()
        host = request.headers.get("x-forwarded-host")
        port = request.headers.get("x-forwarded-port")
        if host:
            if host.startswith("["):
                if "]:" in host:
                    h, p = host.split("]:", 1)
                    host = h.strip("[]"); port = port or p
                else:
                    host = host.strip("[]")
            else:
                if ":" in host and host.count(":") == 1:
                    h, p = host.split(":", 1)
                    host, port = h, (port or p)
        else:
            host = request.url.hostname or ""
            if request.url.port:
                port = str(request.url.port)
        host = host.lower()
        if port and ((scheme == "https" and port == "443") or (scheme == "http" and port == "80")):
            netloc = _bracket_host(host)
        elif port:
            netloc = f"{_bracket_host(host)}:{port}"
        else:
            netloc = _bracket_host(host)
        origin = f"{scheme}://{netloc}"
    
    parts = urlsplit(str(request.url))
    o_parts = urlsplit(origin)
    path = parts.path or "/"
    query = parts.query
    full = urlunsplit((o_parts.scheme, o_parts.netloc, path, query, ""))
    return origin, full
