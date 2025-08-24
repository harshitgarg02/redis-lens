#!/usr/bin/env python3
"""
Debug script for authentication issues
This script helps diagnose first/last name issues with authentication
"""

def print_debug_guide():
    print("🔍 RedisLens Authentication Debug Guide")
    print("=" * 50)
    print()
    
    print("📋 ISSUE: First and Last Names Not Saving")
    print("-" * 40)
    print("This can happen with both OAuth and local signup authentication.")
    print()
    
    print("🔧 DEBUGGING STEPS:")
    print()
    
    print("1️⃣  Check Current Users:")
    print("   python manage.py check_users")
    print("   This shows all users and their name field status")
    print()
    
    print("2️⃣  Fix Existing Users (Optional):")
    print("   python manage.py check_users --fix-names")
    print("   Attempts to extract names from email/username")
    print()
    
    print("3️⃣  Enable Debug Logging:")
    print("   Add to your .env file:")
    print("   DJANGO_DEBUG=True")
    print("   DJANGO_LOG_LEVEL=INFO")
    print()
    
    print("4️⃣  Test New Signup:")
    print("   - Go to http://localhost:8000/login/")
    print("   - Click 'Sign Up' tab")
    print("   - Fill in ALL fields including first/last name")
    print("   - Check logs for: 'SignupForm saving user'")
    print()
    
    print("5️⃣  For OAuth Issues:")
    print("   - Check logs for: 'OAuth user data received'")
    print("   - Verify your OAuth provider returns name fields")
    print("   - Common field names: first_name, given_name, firstName")
    print()
    
    print("🔍 COMMON CAUSES:")
    print()
    print("▶️  OAuth Issues:")
    print("   - OAuth provider doesn't return name fields")
    print("   - Field names don't match (given_name vs first_name)")
    print("   - OAuth scope doesn't include profile information")
    print("   - User data is empty or malformed")
    print()
    
    print("▶️  Signup Form Issues:")  
    print("   - JavaScript validation blocking form submission")
    print("   - Form fields not properly bound to model")
    print("   - CSRF token issues")
    print("   - Database constraints or migrations")
    print()
    
    print("▶️  Browser Issues:")
    print("   - Form not submitting properly")
    print("   - Browser autocomplete interfering")
    print("   - JavaScript errors preventing submission")
    print()
    
    print("🛠️  SOLUTIONS:")
    print()
    
    print("✅ For OAuth:")
    print("   1. Check OAUTH_SCOPE includes 'profile' or 'openid profile'")
    print("   2. Verify OAuth provider configuration")
    print("   3. Check auth_backends.py field mapping")
    print("   4. Test with different OAuth providers")
    print()
    
    print("✅ For Local Signup:")
    print("   1. Ensure all form fields are required")
    print("   2. Check browser developer tools for errors")
    print("   3. Verify forms.py save() method")
    print("   4. Test signup form in Django admin")
    print()
    
    print("✅ General Fixes:")
    print("   1. Run migrations: python manage.py migrate")
    print("   2. Check database schema for first_name/last_name columns")
    print("   3. Clear browser cache and cookies")
    print("   4. Test with different browsers")
    print()
    
    print("📊 LOG FILES TO CHECK:")
    print("   - logs/redislens.log (application logs)")
    print("   - Django console output (if DEBUG=True)")
    print("   - Browser developer console (F12)")
    print()
    
    print("🆘 EMERGENCY USER CREATION:")
    print("   python manage.py create_admin")
    print("   Then manually set first_name/last_name in Django admin")
    print()
    
    print("=" * 50)
    print("💡 TIP: Enable logging and test both OAuth and signup")
    print("   to see exactly what data is being received/saved.")


if __name__ == '__main__':
    print_debug_guide()
