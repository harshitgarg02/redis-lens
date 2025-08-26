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
    """
    redirect_uri = settings.OAUTH_CONFIG.get('REDIRECT_URI', '/oauth/callback/')
    
    # If it's already a full URI (starts with http:// or https://), use as-is
    if redirect_uri.startswith(('http://', 'https://')):
        return redirect_uri
    
    # If it's a path-only, auto-detect host from request
    if request:
        # Determine protocol
        protocol = 'https' if request.is_secure() else 'http'
        
        # Get host (includes port if non-standard)
        host = request.get_host()
        
        # Ensure path starts with /
        path = redirect_uri if redirect_uri.startswith('/') else f'/{redirect_uri}'
        
        return f"{protocol}://{host}{path}"
    
    # Fallback for when no request context is available (e.g., management commands)
    # Use localhost with the path
    path = redirect_uri if redirect_uri.startswith('/') else f'/{redirect_uri}'
    return f"http://localhost:8000{path}"
