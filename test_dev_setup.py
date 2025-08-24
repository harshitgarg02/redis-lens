#!/usr/bin/env python3
"""
Test script for development setup validation
"""
import os

def check_dev_setup():
    """Check development setup configuration"""
    print("🔍 RedisLens Development Setup Validation")
    print("=" * 50)
    
    # Check for .env file
    if not os.path.exists('.env'):
        print("❌ No .env file found")
        print("💡 Run ./setup-dev.sh to create development configuration")
        return False
    
    print("✅ .env file found")
    
    # Load environment variables
    with open('.env', 'r') as f:
        env_content = f.read()
    
    print()
    print("📋 Configuration Analysis:")
    
    # Check database configuration
    if 'DATABASE_ENGINE=sqlite' in env_content:
        print("✅ Database: SQLite (development default)")
        print("📁 Database file: db.sqlite3")
    elif 'DATABASE_ENGINE=postgresql' in env_content:
        print("✅ Database: PostgreSQL (production-like)")
        
        # Extract PostgreSQL settings
        db_settings = {}
        for line in env_content.split('\n'):
            if line.startswith('DB_'):
                key, value = line.split('=', 1)
                db_settings[key] = value
        
        if db_settings:
            print(f"🐘 PostgreSQL Configuration:")
            for key, value in db_settings.items():
                if 'PASSWORD' in key:
                    print(f"   {key}: {'*' * len(value)}")
                else:
                    print(f"   {key}: {value}")
    else:
        print("⚠️  Database: Unknown configuration")
    
    # Check OAuth configuration
    oauth_configured = any([
        'OAUTH_AUTHN_URL=' in line and not line.startswith('#') 
        for line in env_content.split('\n')
    ])
    
    if oauth_configured:
        print("✅ OAuth: Configured for SSO testing")
    else:
        print("⏸️  OAuth: Not configured (local authentication only)")
    
    # Check debug mode
    if 'DJANGO_DEBUG=True' in env_content:
        print("✅ Debug Mode: Enabled (development)")
    else:
        print("⚠️  Debug Mode: Disabled (production-like)")
    
    print()
    print("🧪 Development Features Available:")
    print("✅ Local Login (username/password)")
    print("✅ Sign Up (new user registration)")
    
    if oauth_configured:
        print("✅ OAuth/SSO Login (configured)")
    else:
        print("⏸️  OAuth/SSO Login (not configured)")
    
    print()
    print("🚀 Quick Start Commands:")
    print("python3 manage.py runserver  # Start development server")
    print("python3 manage.py check_users  # Check user database")
    print("python3 test_oauth_dev.py  # Test OAuth configuration")
    print("python3 debug_auth.py  # Authentication troubleshooting")
    
    print()
    print("🌐 Access your application at: http://localhost:8000")
    
    return True

def check_requirements():
    """Check if required packages are installed"""
    print()
    print("📦 Requirements Check:")
    
    try:
        import django
        print(f"✅ Django {django.get_version()}")
    except ImportError:
        print("❌ Django not installed: pip install -r requirements.txt")
        return False
    
    try:
        import psycopg2
        print("✅ PostgreSQL adapter (psycopg2) available")
    except ImportError:
        print("⚠️  PostgreSQL adapter not available (only needed for PostgreSQL)")
    
    return True

if __name__ == '__main__':
    print()
    setup_ok = check_dev_setup()
    
    if setup_ok:
        requirements_ok = check_requirements()
        
        print()
        print("=" * 50)
        if setup_ok and requirements_ok:
            print("🎉 Development setup looks good!")
            print("💡 Run 'python3 manage.py runserver' to start")
        else:
            print("⚠️  Some issues found - check above messages")
    
    print()
