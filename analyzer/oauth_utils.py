"""
OAuth utility functions
"""
from django.conf import settings


def get_oauth_redirect_uri(request):
    """
    Build OAuth redirect URI - supports both full URIs and path-only with auto-host detection
    
    Examples:
    - OAUTH_REDIRECT_URI="/oauth/callback/" → auto-detects to "https://yourdomain.com/oauth/callback/"
    - OAUTH_REDIRECT_URI="http://localhost:8000/oauth/callback/" → uses as-is
    - OAUTH_REDIRECT_URI="https://myapp.company.com/oauth/callback/" → uses as-is
    """
    redirect_uri = settings.OAUTH_CONFIG.get('REDIRECT_URI', '/oauth/callback/')
    
    # If it's already a full URI (starts with http:// or https://), use as-is
    if redirect_uri.startswith(('http://', 'https://')):
        return redirect_uri
    
    # If it's a path-only, auto-detect host from request
    if request:
        # Determine protocol - check for forwarded headers first (for reverse proxies)
        protocol = 'https' if request.is_secure() else 'http'
        
        # Check for reverse proxy headers
        forwarded_proto = request.META.get('HTTP_X_FORWARDED_PROTO')
        if forwarded_proto:
            protocol = forwarded_proto.lower()
        
        # Get host - prefer X-Forwarded-Host or Host header
        host = (
            request.META.get('HTTP_X_FORWARDED_HOST') or  # Reverse proxy
            request.META.get('HTTP_HOST') or              # Direct access
            request.get_host()                            # Django default
        )
        
        # Normalize host to ensure consistency between requests
        if not host or host in ['', 'None', 'none']:
            host = 'localhost:8000'
            protocol = 'http'
        elif host == 'localhost':
            host = 'localhost:8000'
            protocol = 'http'
        elif host.startswith('127.0.0.1'):
            # Normalize 127.0.0.1 to localhost for consistency
            if ':' in host:
                port = host.split(':')[1]
                host = f'localhost:{port}'
            else:
                host = 'localhost:8000'
            protocol = 'http'
        
        # Ensure path starts with /
        path = redirect_uri if redirect_uri.startswith('/') else f'/{redirect_uri}'
        
        final_uri = f"{protocol}://{host}{path}"
        
        # Debug logging for troubleshooting
        import logging
        logger = logging.getLogger(__name__)
        logger.debug(f"OAuth redirect URI: {final_uri} (host: {host}, protocol: {protocol})")
        
        return final_uri
    
    # Fallback for when no request context is available (e.g., management commands)
    # Use localhost with the path
    path = redirect_uri if redirect_uri.startswith('/') else f'/{redirect_uri}'
    return f"http://localhost:8000{path}"
