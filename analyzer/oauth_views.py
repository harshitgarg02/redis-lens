"""
Multiple authentication views for OAuth, LDAP, and generic login
"""
import requests
import secrets
import logging
from urllib.parse import urlencode
from django.shortcuts import redirect, render
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.http import HttpResponseBadRequest
from django.conf import settings
from django.urls import reverse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.views.decorators.cache import never_cache
from .oauth_utils import get_oauth_redirect_uri
from .auth_backends import OAuthBackend, GenericBackend
from .forms import SignupForm

logger = logging.getLogger(__name__)


def oauth_login(request):
    """
    Initiate OAuth login by redirecting to OAuth provider
    """
    try:
        oauth_config = settings.OAUTH_CONFIG
        
        # Validate OAuth configuration (REDIRECT_URI is optional and auto-detected)
        required_config = ['AUTHN_URL', 'CLIENT_ID', 'CLIENT_SECRET']
        missing_config = [key for key in required_config if not oauth_config.get(key)]
        
        if missing_config:
            logger.error(f"OAuth configuration incomplete. Missing: {', '.join(missing_config)}")
            messages.error(request, 
                "OAuth authentication is not properly configured. Please contact your administrator or use local login.")
            return redirect('login_page')
        
        # Generate state parameter for security
        state = secrets.token_urlsafe(32)
        request.session['oauth_state'] = state
        
        # Get redirect URI with auto-host detection
        redirect_uri = get_oauth_redirect_uri(request)
        logger.info(f"Using OAuth redirect URI: {redirect_uri}")
        
        # Build authorization URL
        auth_params = {
            'response_type': 'code',
            'client_id': oauth_config['CLIENT_ID'],
            'redirect_uri': redirect_uri,
            'scope': oauth_config['SCOPE'],
            'state': state,
        }
        
        # Handle different OAuth provider URL formats
        base_url = oauth_config['AUTHN_URL'].rstrip('/')
        if '/authorize' not in base_url:
            if 'google.com' in base_url:
                auth_url = f"{base_url}?{urlencode(auth_params)}"
            elif 'microsoft' in base_url or 'azure' in base_url:
                auth_url = f"{base_url}/authorize?{urlencode(auth_params)}"
            elif 'github.com' in base_url:
                auth_url = f"{base_url}?{urlencode(auth_params)}"
            else:
                # Default assumption: provider expects /oauth/authorize
                auth_url = f"{base_url}/oauth/authorize?{urlencode(auth_params)}"
        else:
            auth_url = f"{base_url}?{urlencode(auth_params)}"
        
        logger.info(f"Redirecting to OAuth provider: {auth_url}")
        return redirect(auth_url)
        
    except Exception as e:
        logger.error(f"OAuth login initiation failed: {str(e)}")
        messages.error(request, "Authentication service is currently unavailable. Please try again later.")
        return redirect('oauth_login_page')


@csrf_exempt
@require_http_methods(["GET"])
def oauth_callback(request):
    """
    Handle OAuth callback from OAuth provider
    """
    try:
        # Get authorization code and state from callback
        auth_code = request.GET.get('code')
        state = request.GET.get('state')
        error = request.GET.get('error')
        
        # Check for errors
        if error:
            logger.error(f"OAuth error: {error}")
            messages.error(request, f"Authentication failed: {error}")
            return redirect('oauth_login_page')
        
        if not auth_code:
            logger.error("No authorization code received")
            messages.error(request, "Authentication failed: No authorization code received")
            return redirect('oauth_login_page')
        
        # Verify state parameter
        session_state = request.session.get('oauth_state')
        if not session_state or session_state != state:
            logger.error("Invalid state parameter")
            messages.error(request, "Authentication failed: Invalid state parameter")
            return redirect('oauth_login_page')
        
        # Exchange authorization code for access token
        access_token = exchange_code_for_token(auth_code, request)
        if not access_token:
            messages.error(request, "Authentication failed: Could not obtain access token")
            return redirect('oauth_login_page')
        
        # Authenticate user using the access token
        auth_backend = OAuthBackend()
        user = auth_backend.authenticate(request, access_token=access_token)
        
        if user:
            # Log in the user
            login(request, user, backend='analyzer.auth_backends.OAuthBackend')
            
            # Clear OAuth state from session
            request.session.pop('oauth_state', None)
            
            logger.info(f"User {user.username} logged in successfully via OAuth")
            messages.success(request, f"Welcome back, {user.first_name or user.username}!")
            
            # Redirect to next URL or dashboard
            next_url = request.session.get('login_redirect_url', settings.LOGIN_REDIRECT_URL)
            request.session.pop('login_redirect_url', None)
            return redirect(next_url)
        else:
            messages.error(request, "Authentication failed: Unable to authenticate user")
            return redirect('oauth_login_page')
            
    except Exception as e:
        logger.error(f"OAuth callback failed: {str(e)}")
        messages.error(request, "Authentication failed: Internal error occurred")
        return redirect('oauth_login_page')


def exchange_code_for_token(auth_code, request=None):
    """
    Exchange authorization code for access token
    """
    try:
        oauth_config = settings.OAUTH_CONFIG
        
        # Validate required configuration (REDIRECT_URI is optional and auto-detected)
        required_config = ['AUTHN_URL', 'CLIENT_ID', 'CLIENT_SECRET']
        missing_config = [key for key in required_config if not oauth_config.get(key)]
        
        if missing_config:
            logger.error(f"OAuth configuration incomplete for token exchange. Missing: {', '.join(missing_config)}")
            return None
        
        # Get redirect URI with auto-host detection
        redirect_uri = get_oauth_redirect_uri(request)
        
        token_data = {
            'client_id': oauth_config['CLIENT_ID'],
            'client_secret': oauth_config['CLIENT_SECRET'],
            'grant_type': 'authorization_code',
            'code': auth_code,
            'redirect_uri': redirect_uri,
        }
        
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Use configurable token URL if provided, otherwise auto-determine
        if oauth_config.get('TOKEN_URL'):
            token_url = oauth_config['TOKEN_URL']
            logger.info(f"Using configured token URL: {token_url}")
        else:
            # Auto-determine token endpoint based on provider
            base_url = oauth_config['AUTHN_URL'].rstrip('/')
            if 'google.com' in base_url:
                token_url = f"{base_url}/token"
            elif 'microsoft' in base_url or 'azure' in base_url:
                token_url = f"{base_url}/token"
            elif 'github.com' in base_url:
                token_url = "https://github.com/login/oauth/access_token"
            else:
                # Default assumption: provider expects /oauth/token
                # For OAuth 2.0 v2.0 endpoints (like Azure), use /token
                if '/v2.0' in base_url:
                    token_url = f"{base_url}/token"
                else:
                    token_url = f"{base_url}/oauth/token"
            logger.info(f"Auto-determined token URL: {token_url}")
        
        logger.info(f"Attempting token exchange with URL: {token_url}")
        
        response = requests.post(
            token_url,
            data=token_data,
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            token_info = response.json()
            access_token = token_info.get('access_token')
            logger.info(f"Token exchange successful, access_token received: {'Yes' if access_token else 'No'}")
            return access_token
        else:
            logger.error(f"Token exchange failed: {response.status_code} - {response.text}")
            logger.error(f"Token URL used: {token_url}")
            logger.error(f"Request data: {token_data}")
            return None
            
    except requests.RequestException as e:
        logger.error(f"Error exchanging code for token: {str(e)}")
        return None


def oauth_logout(request):
    """
    Handle logout and redirect to login page (not OAuth)
    """
    if request.user.is_authenticated:
        username = request.user.username
        logout(request)
        logger.info(f"User {username} logged out")
        messages.info(request, "You have been logged out successfully.")
    
    return redirect('login_page')


def oauth_login_page(request):
    """
    Display OAuth login page with login button
    """
    # If user is already authenticated, redirect to dashboard
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    
    # Check if OAuth is properly configured (REDIRECT_URI is optional and auto-detected)
    oauth_config = settings.OAUTH_CONFIG
    required_config = ['AUTHN_URL', 'CLIENT_ID', 'CLIENT_SECRET']
    missing_config = [key for key in required_config if not oauth_config.get(key)]
    
    if missing_config:
        messages.error(request, 
            "OAuth authentication is not configured. Please use local login or contact your administrator.")
        return redirect('login_page')
    
    # Store the next URL in session if provided
    next_url = request.GET.get('next')
    if next_url:
        request.session['login_redirect_url'] = next_url
    
    from django.shortcuts import render
    return render(request, 'registration/oauth_login.html')


def login_page(request):
    """
    Main login page with multiple authentication options
    """
    # If user is already authenticated, redirect to dashboard
    if request.user.is_authenticated:
        return redirect(settings.LOGIN_REDIRECT_URL)
    
    # Store the next URL in session if provided
    next_url = request.GET.get('next')
    if next_url:
        request.session['login_redirect_url'] = next_url
    
    # Handle form submission
    if request.method == 'POST':
        auth_method = request.POST.get('auth_method')
        
        if auth_method == 'generic':
            username = request.POST.get('username', '').strip()
            password = request.POST.get('password', '').strip()
            return handle_generic_login(request, username, password)
        elif auth_method == 'signup':
            return handle_signup(request)
        else:
            messages.error(request, "Invalid authentication method selected.")
    
    return render(request, 'registration/login.html')


def handle_generic_login(request, username, password):
    """
    Handle generic username/password authentication
    """
    if not username or not password:
        messages.error(request, "Please provide both username and password.")
        return redirect('login_page')
    
    try:
        # Authenticate using generic backend
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            logger.info(f"Generic login successful for user: {username} - Name: '{user.first_name} {user.last_name}'")
            welcome_name = user.first_name if user.first_name else user.username
            messages.success(request, f"Welcome back, {welcome_name}!")
            
            # Redirect to next URL or dashboard
            next_url = request.session.get('login_redirect_url', settings.LOGIN_REDIRECT_URL)
            request.session.pop('login_redirect_url', None)
            return redirect(next_url)
        else:
            messages.error(request, "Invalid username or password.")
            
    except Exception as e:
        logger.error(f"Generic login error for user {username}: {str(e)}")
        messages.error(request, "Authentication failed. Please try again.")
    
    return redirect('login_page')


def handle_signup(request):
    """
    Handle user signup/registration
    """
    form = SignupForm(request.POST)
    
    if form.is_valid():
        try:
            # Create the user
            user = form.save()
            logger.info(f"New user created via signup: {user.username} ({user.email}) - Name: '{user.first_name} {user.last_name}'")
            
            # Log the user in automatically
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            welcome_name = user.first_name if user.first_name else user.username
            messages.success(request, f"Welcome to RedisLens, {welcome_name}! Your account has been created successfully.")
            
            # Redirect to next URL or dashboard
            next_url = request.session.get('login_redirect_url', settings.LOGIN_REDIRECT_URL)
            request.session.pop('login_redirect_url', None)
            return redirect(next_url)
            
        except Exception as e:
            logger.error(f"Signup error for user {form.cleaned_data.get('username', 'unknown')}: {str(e)}")
            messages.error(request, "Account creation failed. Please try again.")
    else:
        # Display form errors
        for field, errors in form.errors.items():
            for error in errors:
                if field == '__all__':
                    messages.error(request, error)
                else:
                    field_name = form.fields[field].label or field.replace('_', ' ').title()
                    messages.error(request, f"{field_name}: {error}")
    
    return redirect('login_page')



