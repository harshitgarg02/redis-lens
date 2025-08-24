#!/bin/bash
# RedisLens Development Setup Script

echo "🚀 Setting up RedisLens for development..."
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

# Ask about database configuration
echo "🗄️ Database Configuration"
echo "Choose your development database:"
echo "1. SQLite (simple, no setup required)"
echo "2. PostgreSQL (production-like, requires local PostgreSQL)"
echo ""
read -p "Choose database (1 for SQLite, 2 for PostgreSQL): " -n 1 -r DB_CHOICE
echo ""

# Initialize variables
DB_ENGINE="sqlite"
DB_CONFIG=""

if [[ $DB_CHOICE == "2" ]]; then
    echo ""
    echo "🐘 Setting up PostgreSQL for development..."
    echo "Make sure PostgreSQL is installed and running on your system."
    echo ""
    
    # Get PostgreSQL configuration
    read -p "Database name (default: redislens_dev): " DB_NAME
    read -p "Database user (default: postgres): " DB_USER
    read -s -p "Database password: " DB_PASSWORD
    echo ""
    read -p "Database host (default: localhost): " DB_HOST
    read -p "Database port (default: 5432): " DB_PORT
    
    # Set defaults
    DB_NAME=${DB_NAME:-redislens_dev}
    DB_USER=${DB_USER:-postgres}
    DB_HOST=${DB_HOST:-localhost}
    DB_PORT=${DB_PORT:-5432}
    
    DB_ENGINE="postgresql"
    DB_CONFIG="
# PostgreSQL Configuration (Development)
DB_NAME=$DB_NAME
DB_USER=$DB_USER
DB_PASSWORD=$DB_PASSWORD
DB_HOST=$DB_HOST
DB_PORT=$DB_PORT"

    echo ""
    echo "📝 PostgreSQL configuration will be added to .env"
    echo "⚠️  Make sure PostgreSQL is running and the database '$DB_NAME' exists"
    echo ""
else
    echo ""
    echo "📝 Using SQLite for development (stored in db.sqlite3)"
fi

# Create base .env file
cat > .env << EOF
# Development Configuration
DJANGO_SECRET_KEY=$($PYTHON_PATH -c "from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())" 2>/dev/null || openssl rand -base64 32)
DJANGO_DEBUG=True
DJANGO_ALLOWED_HOSTS=localhost,127.0.0.1

# Database Configuration
DATABASE_ENGINE=$DB_ENGINE$DB_CONFIG
EOF

echo "✅ Created .env file for development"

# Ask if user wants to configure OAuth
echo ""
echo "🔐 OAuth Configuration (Optional)"
echo "RedisLens supports OAuth/SSO authentication alongside local accounts."
echo "You can set this up now or skip and use local authentication only."
echo ""
read -p "Configure OAuth for development? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    echo ""
    echo "🔧 Setting up OAuth for development..."
    echo "Please provide your OAuth provider details:"
    echo ""
    
    read -p "OAuth Provider URL (e.g., https://accounts.google.com/o/oauth2/v2/auth): " OAUTH_URL
    read -p "Client ID: " CLIENT_ID  
    read -p "Client Secret: " CLIENT_SECRET
    read -p "Token URL (optional - leave blank for auto-detection): " TOKEN_URL
    read -p "Scopes (default: openid profile email): " SCOPES
    
    # Set default scope if empty
    if [ -z "$SCOPES" ]; then
        SCOPES="openid profile email"
    fi
    
    # Update .env file with OAuth settings
    cat >> .env << EOF

# OAuth Configuration (Development)
OAUTH_AUTHN_URL=$OAUTH_URL
OAUTH_CLIENT_ID=$CLIENT_ID
OAUTH_CLIENT_SECRET=$CLIENT_SECRET
OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback/
OAUTH_SCOPE=$SCOPES
EOF
    
    # Add token URL if provided
    if [ -n "$TOKEN_URL" ]; then
        echo "OAUTH_TOKEN_URL=$TOKEN_URL" >> .env
    fi
    
    echo "✅ OAuth configuration added to .env"
    echo ""
    echo "📋 Important OAuth Setup Notes:"
    echo "1. Make sure your OAuth provider is configured with redirect URI: http://localhost:8000/oauth/callback/"
    echo "2. Your OAuth app should allow localhost redirects for development"
    echo "3. Ensure the scopes include profile information for name fields"
    echo ""
else
    echo "⏭️  Skipping OAuth setup - you can configure it later by editing .env"
fi

# Setup database
echo ""
echo "🗄️ Setting up database..."

if [[ $DB_CHOICE == "2" ]]; then
    echo "🐘 PostgreSQL database setup..."
    echo "1. Make sure PostgreSQL is running"
    echo "2. Creating database if it doesn't exist..."
    
    # Try to create database (ignore error if exists)
    PGPASSWORD="$DB_PASSWORD" createdb -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" "$DB_NAME" 2>/dev/null || echo "   Database '$DB_NAME' already exists or couldn't be created"
    
    echo "3. Creating and running Django migrations..."
    $PYTHON_PATH manage.py makemigrations
    $PYTHON_PATH manage.py migrate
    
    if [ $? -eq 0 ]; then
        echo "✅ PostgreSQL database setup complete"
    else
        echo "❌ Database migration failed. Please check:"
        echo "   - PostgreSQL is running: brew services start postgresql (macOS) or sudo systemctl start postgresql (Linux)"
        echo "   - Database credentials are correct"
        echo "   - User '$DB_USER' has permission to create databases"
        echo "   - You can manually create the database: createdb -U $DB_USER $DB_NAME"
        echo ""
        echo "After fixing, run: $PYTHON_PATH manage.py makemigrations && $PYTHON_PATH manage.py migrate"
    fi
else
    echo "📁 SQLite database setup..."
    $PYTHON_PATH manage.py makemigrations
    $PYTHON_PATH manage.py migrate
    echo "✅ SQLite database created at db.sqlite3"
fi

# Import anomaly rules
echo "📋 Importing anomaly detection rules..."
$PYTHON_PATH manage.py import_anomaly_rules

# Create admin user (optional)
echo "👤 Creating admin user (optional)..."
echo "You can skip this step and create users through the web interface"
read -p "Create admin user now? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    $PYTHON_PATH manage.py create_admin
fi

echo ""
echo "🎉 RedisLens development setup complete!"
echo ""
echo "🚀 Next Steps:"
echo "🌐 Run '$PYTHON_PATH manage.py runserver' to start the application"
echo "🔗 Access at: http://localhost:8000"
echo ""

if [[ $DB_CHOICE == "2" ]]; then
    echo "🐘 PostgreSQL Development Notes:"
    echo "📋 Database: $DB_NAME on $DB_HOST:$DB_PORT"
    echo "👤 User: $DB_USER"
    echo "🔧 Connection: Make sure PostgreSQL service is running"
    echo "📊 Admin: Use pgAdmin or psql to manage your database"
    echo ""
fi

echo "🔐 Authentication Methods Available:"
if [[ $REPLY =~ ^[Yy]$ ]] 2>/dev/null; then
    echo "✅ OAuth/SSO Login (configured)"
else
    echo "⚪ OAuth/SSO Login (not configured - edit .env to add)"
fi
echo "✅ Local Login (username/password)"  
echo "✅ Sign Up (new user registration)"
echo ""
echo "📖 Documentation:"
echo "🔧 OAuth setup: DEV_OAUTH_SETUP.md"
echo "🐛 Troubleshooting: $PYTHON_PATH debug_auth.py"
echo "👥 Check users: $PYTHON_PATH manage.py check_users"
