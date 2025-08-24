#!/usr/bin/env python3
"""
Test script for OAuth configuration in development environment
"""
import os
import sys

def check_oauth_config():
    """Check if OAuth is properly configured for development"""
    print("🔍 RedisLens OAuth Development Configuration Check")
    print("=" * 50)
    
    # Check for .env file
    if not os.path.exists('.env'):
        print("❌ No .env file found")
        print("💡 Run ./setup-dev.sh to create one")
        return False
    
    print("✅ .env file found")
    
    # Load environment variables
    with open('.env', 'r') as f:
        env_content = f.read()
    
    # Check OAuth configuration
    oauth_vars = [
        'OAUTH_AUTHN_URL',
        'OAUTH_CLIENT_ID', 
        'OAUTH_CLIENT_SECRET',
        'OAUTH_REDIRECT_URI',
        'OAUTH_SCOPE'
    ]
    
    oauth_configured = False
    oauth_values = {}
    
    for var in oauth_vars:
        # Check if variable exists and is not commented out
        lines = [line for line in env_content.split('\n') 
                if line.startswith(var + '=') and not line.startswith('#')]
        
        if lines:
            oauth_configured = True
            value = lines[0].split('=', 1)[1]
            oauth_values[var] = value
            print(f"✅ {var}={'*' * min(len(value), 10)}...")
        else:
            oauth_values[var] = None
    
    print()
    
    if oauth_configured:
        print("🎉 OAuth Configuration Status: CONFIGURED")
        print()
        print("📋 Configuration Details:")
        
        # Validate redirect URI for development
        redirect_uri = oauth_values.get('OAUTH_REDIRECT_URI', '')
        if 'localhost:8000' in redirect_uri or '127.0.0.1:8000' in redirect_uri:
            print(f"✅ Redirect URI: {redirect_uri} (Development-friendly)")
        else:
            print(f"⚠️  Redirect URI: {redirect_uri} (Should use localhost:8000 for dev)")
        
        # Check scope
        scope = oauth_values.get('OAUTH_SCOPE', '')
        if 'profile' in scope and 'email' in scope:
            print(f"✅ Scope: {scope} (Includes profile and email)")
        else:
            print(f"⚠️  Scope: {scope} (Should include 'profile' and 'email')")
        
        # Provider-specific checks
        auth_url = oauth_values.get('OAUTH_AUTHN_URL', '')
        if 'google.com' in auth_url:
            print("🔍 Provider: Google OAuth (Good for development)")
        elif 'microsoft' in auth_url or 'azure' in auth_url:
            print("🔍 Provider: Azure AD (Enterprise)")
        elif 'github.com' in auth_url:
            print("🔍 Provider: GitHub OAuth")
        else:
            print(f"🔍 Provider: Custom ({auth_url})")
        
        print()
        print("🧪 Testing Instructions:")
        print("1. python manage.py runserver")
        print("2. Open http://localhost:8000/login/")
        print("3. Click 'OAuth Login' tab")
        print("4. Click 'Login with SSO'")
        print("5. Should redirect to your OAuth provider")
        print()
        print("📊 Debugging:")
        print("- Check logs: tail -f logs/redislens.log")
        print("- Look for: 'OAuth user data received'")
        print("- Browser console: F12 Developer Tools")
        
    else:
        print("⏭️  OAuth Configuration Status: NOT CONFIGURED")
        print("RedisLens will use local authentication only (signup/login)")
        print()
        print("🔧 To enable OAuth:")
        print("1. Run ./setup-dev.sh and choose 'y' for OAuth")
        print("2. Or manually edit .env file with OAuth settings")
        print("3. See DEV_OAUTH_SETUP.md for detailed instructions")
    
    print()
    print("🔐 Authentication Methods Available:")
    
    if oauth_configured:
        print("✅ OAuth/SSO Login (configured)")
    else:
        print("⏸️  OAuth/SSO Login (not configured)")
    
    print("✅ Local Login (always available)")
    print("✅ Sign Up (always available)")
    
    print()
    print("=" * 50)
    
    return oauth_configured

def check_django_settings():
    """Check if Django can load OAuth settings"""
    try:
        # Set Django settings module
        os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'redislens.settings')
        
        # Try to import Django and load settings
        import django
        from django.conf import settings
        django.setup()
        
        print("🔧 Django Settings Check:")
        
        # Check if OAuth config is loaded
        oauth_config = getattr(settings, 'OAUTH_CONFIG', None)
        if oauth_config:
            print("✅ OAuth config loaded in Django settings")
            
            # Check authentication backends
            backends = settings.AUTHENTICATION_BACKENDS
            oauth_backend = 'analyzer.auth_backends.OAuthBackend'
            
            if oauth_backend in backends:
                print("✅ OAuth authentication backend enabled")
            else:
                print("⚠️  OAuth authentication backend not enabled")
                
        else:
            print("ℹ️  OAuth config not loaded (using local authentication only)")
        
        print()
        
    except ImportError:
        print("⚠️  Django not available (install with: pip install -r requirements.txt)")
    except Exception as e:
        print(f"❌ Django settings error: {e}")

if __name__ == '__main__':
    print()
    oauth_configured = check_oauth_config()
    print()
    
    if '--django' in sys.argv or oauth_configured:
        check_django_settings()
    
    print("💡 Need help? Check DEV_OAUTH_SETUP.md or run ./setup-dev.sh")
