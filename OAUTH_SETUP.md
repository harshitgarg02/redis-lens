# OAuth Integration Setup Guide

This document explains how to configure OAuth 2.0 authentication for RedisLens with your organization's identity provider.

## Overview

RedisLens supports optional OAuth 2.0 authentication integration. By default, the application uses local user accounts, but you can configure it to work with your organization's SSO provider (Azure AD, Google Workspace, Okta, etc.).

## Environment Variables

You need to set the following environment variables for OAuth to work:

```bash
# Required OAuth Configuration
export OAUTH_AUTHN_URL="https://your-sso-provider.com"
export OAUTH_CLIENT_ID="redislens"
export OAUTH_CLIENT_SECRET="your-client-secret-here"
export OAUTH_REDIRECT_URI="http://your-domain.com/oauth/callback/"
export OAUTH_SCOPE="openid profile email"

# Optional - Database settings (if different from defaults)
export DB_NAME="redislens"
export DB_USER="postgres"
export DB_PASSWORD="your-db-password"
export DB_HOST="localhost"
export DB_PORT="5432"
```

## OAuth Provider Registration

Before using OAuth, you need to register your application with your OAuth provider:

### Generic OAuth 2.0 Provider

1. **Register your application**:

   - Application name: `RedisLens`
   - Client ID: `redislens` (or your preferred client ID)
   - Redirect URI: `http://your-domain.com/oauth/callback/`
   - Grant types: `authorization_code`
   - Scopes: `openid profile email`

2. **Get your client credentials**:
   - Client ID (use in `OAUTH_CLIENT_ID`)
   - Client secret (use in `OAUTH_CLIENT_SECRET`)
   - Authorization URL (use in `OAUTH_AUTHN_URL`)

### Popular Providers

#### Azure AD

- Authorization URL: `https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0`
- Scopes: `openid profile email`

#### Google Workspace

- Authorization URL: `https://accounts.google.com/o/oauth2/v2/auth`
- Scopes: `openid profile email`

#### Okta

- Authorization URL: `https://{your-domain}.okta.com/oauth2/default`
- Scopes: `openid profile email`

## Installation and Setup

1. **Install dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

2. **Set environment variables** (create a `.env` file or export them):

   ```bash
   # Copy the environment variables from above
   ```

3. **Run database migrations**:

   ```bash
   python manage.py migrate
   ```

4. **Create a superuser** (for admin access, optional):

   ```bash
   python manage.py createsuperuser
   ```

5. **Start the development server**:
   ```bash
   python manage.py runserver
   ```

## OAuth Flow

1. **User visits login page** (`/login/`)
2. **Clicks "OAuth Login" tab** and then "Login with SSO"
3. **Redirected to OAuth provider** for authentication
4. **User authenticates** with their organization credentials
5. **OAuth provider redirects back** with authorization code
6. **Application exchanges code for access token**
7. **Application fetches user details** and creates/updates user account
8. **User is logged in** and redirected to dashboard

## URL Endpoints

- `/login/` - Main login page with multiple authentication options
- `/oauth/login/` - Initiates OAuth flow (redirects to OAuth provider)
- `/oauth/callback/` - OAuth callback endpoint (receives authorization code)
- `/logout/` - Logout and redirect to login page
- `/admin/` - Django admin (uses fallback authentication)

## Security Features

- **State parameter validation** prevents CSRF attacks
- **Access token verification** with OAuth provider
- **Automatic user provisioning** from organization identity
- **Session management** with Django's built-in security
- **Secure token handling** with proper expiration and refresh

## User Management

- **New users** are automatically created when they first login via OAuth
- **User information** is updated from OAuth provider on each login
- **No local passwords** - all authentication handled by OAuth provider
- **Mixed authentication** - OAuth users + local accounts supported
- **Admin users** can still use Django admin with local authentication

## Troubleshooting

### Common Issues

1. **"Authentication service is currently unavailable"**

   - Check `OAUTH_AUTHN_URL` environment variable
   - Verify network connectivity to OAuth provider
   - Check OAuth provider service status
   - Confirm OAuth provider endpoints are accessible

2. **"Authentication failed: Invalid state parameter"**

   - This indicates a potential CSRF attack or session issue
   - Clear browser cookies and try again
   - Check if multiple browser tabs are interfering
   - Verify session storage is working properly

3. **"Could not obtain access token"**

   - Verify `OAUTH_CLIENT_ID` and `OAUTH_CLIENT_SECRET` are correct
   - Check that redirect URI matches OAuth provider registration exactly
   - Verify authorization code is valid and not expired
   - Ensure OAuth provider allows your redirect URI

4. **"Unable to authenticate user"**
   - Check OAuth provider's user info endpoint configuration
   - Verify user has required permissions/scopes
   - Check application logs for detailed error messages
   - Confirm user exists in OAuth provider's directory

### Logs

Enable DEBUG logging in Django settings to see detailed OAuth flow:

```python
LOGGING = {
    'version': 1,
    'disable_existing_loggers': False,
    'handlers': {
        'console': {
            'class': 'logging.StreamHandler',
        },
    },
    'loggers': {
        'analyzer.oauth_views': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
        'analyzer.auth_backends': {
            'handlers': ['console'],
            'level': 'DEBUG',
        },
    },
}
```

## Production Deployment

For production deployment:

1. Set `DEBUG = False` in settings
2. Use HTTPS for all URLs
3. Set proper `ALLOWED_HOSTS`
4. Use environment variables for all secrets
5. Consider using a proper secret management system
6. Set up proper logging and monitoring

## Support

For OAuth-related issues:

1. **Check this documentation first** - Most common issues are covered above
2. **Review application logs** - Enable debug logging to see detailed OAuth flow
3. **Contact your OAuth provider administrator** - For provider-specific configuration issues
4. **Check provider documentation** - Each OAuth provider has specific setup requirements:
   - [Azure AD OAuth Documentation](https://docs.microsoft.com/en-us/azure/active-directory/develop/)
   - [Google OAuth Documentation](https://developers.google.com/identity/protocols/oauth2)
   - [Okta OAuth Documentation](https://developer.okta.com/docs/guides/)
5. **RedisLens Community** - Check GitHub issues for similar problems

## Alternative Authentication

If OAuth setup is complex for your environment, RedisLens also supports:

- **Local User Accounts** - Built-in username/password authentication
- **User Self-Registration** - Sign-up functionality for new users
- **Mixed Authentication** - OAuth for enterprise users + local accounts for developers/contractors

Simply omit the OAuth environment variables to use local authentication only.
