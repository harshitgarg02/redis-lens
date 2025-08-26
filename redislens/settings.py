"""
Django settings for RedisLens project.

For more information on this file, see
https://docs.djangoproject.com/en/4.2/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/4.2/ref/settings/
"""

from pathlib import Path
import os
import environ
from django.core.management.utils import get_random_secret_key

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent

# Initialize django-environ to load .env file
env = environ.Env()
environ.Env.read_env(BASE_DIR / '.env')

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = os.getenv('DJANGO_SECRET_KEY', get_random_secret_key())

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = os.getenv('DJANGO_DEBUG', 'False').lower() == 'true'

ALLOWED_HOSTS = os.getenv('DJANGO_ALLOWED_HOSTS', 'localhost,127.0.0.1').split(',')

# Application definition
INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'analyzer',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]

ROOT_URLCONF = 'redislens.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',
            ],
        },
    },
]

WSGI_APPLICATION = 'redislens.wsgi.application'

# Database
# https://docs.djangoproject.com/en/4.2/ref/settings/#databases

# Default to SQLite for development, PostgreSQL for production
DATABASE_ENGINE = os.getenv('DATABASE_ENGINE', 'sqlite')

if DATABASE_ENGINE == 'postgresql':
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': os.getenv('DB_NAME', 'redislens'),
            'USER': os.getenv('DB_USER', 'postgres'),
            'PASSWORD': os.getenv('DB_PASSWORD'),
            'HOST': os.getenv('DB_HOST', 'localhost'),
            'PORT': os.getenv('DB_PORT', '5432'),
        }
    }
else:
    # SQLite configuration for development
    DATABASES = {
        'default': {
            'ENGINE': 'django.db.backends.sqlite3',
            'NAME': BASE_DIR / 'db.sqlite3',
        }
    }

# Password validation
# https://docs.djangoproject.com/en/4.2/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]

# Internationalization
# https://docs.djangoproject.com/en/4.2/topics/i18n/

LANGUAGE_CODE = 'en-us'
TIME_ZONE = 'UTC'
USE_I18N = True
USE_TZ = True

# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/4.2/howto/static-files/

STATIC_URL = 'static/'
STATICFILES_DIRS = [
    BASE_DIR / "static",
]
STATIC_ROOT = BASE_DIR / "staticfiles"

# Default primary key field type
# https://docs.djangoproject.com/en/4.2/ref/settings/#default-auto-field

DEFAULT_AUTO_FIELD = 'django.db.models.BigAutoField'

# Authentication settings
LOGIN_URL = '/login/'
LOGIN_REDIRECT_URL = '/'
LOGOUT_REDIRECT_URL = '/login/'

# OAuth Configuration (Optional - for enterprise integration)
# Set these environment variables if you want to use OAuth authentication
OAUTH_CONFIG = {
    'AUTHN_URL': os.getenv('OAUTH_AUTHN_URL'),
    'TOKEN_URL': os.getenv('OAUTH_TOKEN_URL'),  # Optional - if not set, will be auto-determined
    'CLIENT_ID': os.getenv('OAUTH_CLIENT_ID'),
    'CLIENT_SECRET': os.getenv('OAUTH_CLIENT_SECRET'),
    'REDIRECT_URI': os.getenv('OAUTH_REDIRECT_URI'),
    'SCOPE': os.getenv('OAUTH_SCOPE', 'openid profile email'),
}

def get_oauth_redirect_uri(request):
    """
    Build OAuth redirect URI - supports both full URIs and path-only with auto-host detection
    
    Examples:
    - OAUTH_REDIRECT_URI="/oauth/callback/" → auto-detects to "https://yourdomain.com/oauth/callback/"
    - OAUTH_REDIRECT_URI="http://localhost:8000/oauth/callback/" → uses as-is
    """
    redirect_uri = OAUTH_CONFIG.get('REDIRECT_URI', '/oauth/callback/')
    
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

# Authentication backends
# OAuth is optional - if not configured, falls back to local authentication
AUTHENTICATION_BACKENDS = [
    'django.contrib.auth.backends.ModelBackend',  # Local authentication (always enabled)
]

# Only enable OAuth backend if minimum configuration is provided
# REDIRECT_URI is optional and defaults to '/oauth/callback/' with auto-host detection
required_oauth_keys = ['AUTHN_URL', 'CLIENT_ID', 'CLIENT_SECRET']
if all(OAUTH_CONFIG[key] for key in required_oauth_keys):
    AUTHENTICATION_BACKENDS.insert(0, 'analyzer.auth_backends.OAuthBackend')
    AUTHENTICATION_BACKENDS.insert(1, 'analyzer.auth_backends.GenericBackend')

# Security settings for production
if not DEBUG:
    # Security middleware
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = 'DENY'
    SECURE_HSTS_SECONDS = 86400
    SECURE_HSTS_INCLUDE_SUBDOMAINS = True
    SECURE_HSTS_PRELOAD = True
    
    # HTTPS settings (uncomment if using HTTPS)
    # SECURE_SSL_REDIRECT = True
    # SESSION_COOKIE_SECURE = True
    # CSRF_COOKIE_SECURE = True

# Logging configuration with environment-based log level control
# DJANGO_LOG_LEVEL environment variable controls logging verbosity
# Valid levels: DEBUG, INFO, WARNING, ERROR, CRITICAL
LOG_LEVEL = os.getenv('DJANGO_LOG_LEVEL', 'INFO').upper()

# Validate log level
VALID_LOG_LEVELS = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
if LOG_LEVEL not in VALID_LOG_LEVELS:
    print(f"Warning: Invalid DJANGO_LOG_LEVEL '{LOG_LEVEL}'. Using 'INFO' instead.")
    LOG_LEVEL = 'INFO'

# In DEBUG mode, default to DEBUG logging unless explicitly set
if DEBUG and os.getenv('DJANGO_LOG_LEVEL') is None:
    LOG_LEVEL = 'DEBUG'

LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'formatters': {
        'verbose': {
            'format': '{levelname} {asctime} {module} {process:d} {thread:d} {message}',
            'style': '{',
        },
        'simple': {
            'format': '{levelname} {message}',
            'style': '{',
        },
        'debug': {
            'format': '{levelname} {asctime} {module} {lineno:d} {message}',
            'style': '{',
        },
    },
    'handlers': {
        'file': {
            'level': LOG_LEVEL,
            'class': 'logging.FileHandler',
            'filename': BASE_DIR / 'logs' / 'redislens.log',
            'formatter': 'verbose' if LOG_LEVEL == 'DEBUG' else 'verbose',
        },
        'console': {
            'level': LOG_LEVEL,
            'class': 'logging.StreamHandler',
            'formatter': 'debug' if LOG_LEVEL == 'DEBUG' else 'simple',
        },
    },
    'root': {
        'handlers': ['console', 'file'],
        'level': LOG_LEVEL,
    },
    'loggers': {
        'django': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'analyzer': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        # Redis and Sentinel analysis logging
        'analyzer.redis_service': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'analyzer.sentinel_service': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'analyzer.anomaly_detector': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        # Authentication debugging
        'analyzer.oauth_views': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'analyzer.auth_backends': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
        'analyzer.forms': {
            'handlers': ['console', 'file'], 
            'level': LOG_LEVEL,
            'propagate': False,
        },
        # Views and URL routing
        'analyzer.views': {
            'handlers': ['console', 'file'],
            'level': LOG_LEVEL,
            'propagate': False,
        },
    },
}

# Log the current log level for reference
print(f"RedisLens logging level set to: {LOG_LEVEL}")

# Ensure logs directory exists
LOG_DIR = BASE_DIR / 'logs'
LOG_DIR.mkdir(exist_ok=True)