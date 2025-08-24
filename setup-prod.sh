#!/bin/bash
# RedisLens Production Setup Script

echo "🚀 Setting up RedisLens for production..."
echo ""

# Ask for Python path
echo "🐍 Python Configuration"
echo "Please specify the Python executable path to use."
echo "Examples: python3, /usr/bin/python3, /opt/homebrew/bin/python3, python"
echo ""
read -p "Python path (default: python3): " PYTHON_PATH
PYTHON_PATH=${PYTHON_PATH:-python3}
echo ""
echo "✅ Using Python: $PYTHON_PATH"
echo ""

# Check if .env exists
if [ -f ".env" ]; then
    echo "⚠️  .env file already exists. Please review and update it manually."
    echo "📋 Required production settings:"
    echo "   - DJANGO_SECRET_KEY (generate a new one!)"
    echo "   - DJANGO_DEBUG=False"
    echo "   - DJANGO_ALLOWED_HOSTS (your domain)"
    echo "   - DATABASE_ENGINE=postgresql (recommended)"
    echo "   - Database credentials (DB_NAME, DB_USER, DB_PASSWORD, etc.)"
    echo "   - OAuth settings (if using SSO)"
else
    echo "📝 Creating production .env template..."
    cat > .env << EOF
# Production Configuration
DJANGO_SECRET_KEY=$($PYTHON_PATH -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())" 2>/dev/null || openssl rand -base64 32)
DJANGO_DEBUG=False
DJANGO_ALLOWED_HOSTS=*

# PostgreSQL for production (recommended)
DATABASE_ENGINE=postgresql
DB_NAME=redislens
DB_USER=redislens_user
DB_PASSWORD=CHANGE-THIS-TO-SECURE-PASSWORD
DB_HOST=localhost
DB_PORT=5432

# OAuth Configuration (Optional)
# OAUTH_AUTHN_URL=https://your-sso-provider.com/oauth/authorize
# OAUTH_TOKEN_URL=https://your-sso-provider.com/oauth/token
# OAUTH_CLIENT_ID=redislens
# OAUTH_CLIENT_SECRET=your-oauth-secret
# OAUTH_REDIRECT_URI=https://yourdomain.com/oauth/callback/
# OAUTH_SCOPE=openid profile email
EOF
    echo "✅ Created .env template for production"
    echo "⚠️  Please edit .env and update all values for your environment!"
fi

echo ""
echo "🔧 Next steps for production deployment:"
echo "1. Edit .env with your actual values"
echo "2. Set up your database (PostgreSQL recommended)"
echo "3. Run: $PYTHON_PATH manage.py migrate"
echo "4. Run: $PYTHON_PATH manage.py import_anomaly_rules"
echo "5. Run: $PYTHON_PATH manage.py collectstatic"
echo "6. Create admin user: $PYTHON_PATH manage.py create_admin"
echo "7. Configure your web server (nginx + gunicorn)"
echo ""
echo "🐳 Or use Docker:"
echo "   docker build -t redislens ."
echo "   docker run -p 8000:8000 --env-file .env redislens"
echo ""
echo "📖 Documentation:"
echo "🔧 OAuth setup: OAUTH_SETUP.md"
echo "👥 Check users: $PYTHON_PATH manage.py check_users"
