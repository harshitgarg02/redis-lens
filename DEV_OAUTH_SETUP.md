# OAuth Setup for Development Environment

Quick guide to set up OAuth authentication for **local development** with RedisLens.

## Quick Setup

### Automated Setup (Recommended)

```bash
./setup-dev.sh
# Choose OAuth configuration when prompted
```

### Manual Setup

```bash
cp env.example .env
# Edit .env file with OAuth settings below
```

## Popular OAuth Providers for Development

### Google OAuth (Easiest)

1. **Go to [Google Cloud Console](https://console.cloud.google.com/)**
2. **Create OAuth credentials:**

   - Application type: "Web application"
   - Authorized redirect URIs: `http://localhost:8000/oauth/callback/`

3. **Add to .env:**
   ```bash
   OAUTH_AUTHN_URL=https://accounts.google.com/o/oauth2/v2/auth
   OAUTH_TOKEN_URL=https://oauth2.googleapis.com/token
   OAUTH_CLIENT_ID=your-google-client-id
   OAUTH_CLIENT_SECRET=your-google-client-secret
   OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback/
   OAUTH_SCOPE=openid profile email
   ```

### Azure AD

1. **Azure Portal > App registrations > New registration**
2. **Redirect URI:** `http://localhost:8000/oauth/callback/`
3. **Add to .env:**
   ```bash
   OAUTH_AUTHN_URL=https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/authorize
   OAUTH_TOKEN_URL=https://login.microsoftonline.com/{tenant-id}/oauth2/v2.0/token
   OAUTH_CLIENT_ID=your-application-id
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback/
   OAUTH_SCOPE=openid profile email
   ```

### GitHub OAuth

1. **GitHub Settings > Developer settings > OAuth Apps**
2. **Authorization callback URL:** `http://localhost:8000/oauth/callback/`
3. **Add to .env:**
   ```bash
   OAUTH_AUTHN_URL=https://github.com/login/oauth/authorize
   OAUTH_TOKEN_URL=https://github.com/login/oauth/access_token
   OAUTH_CLIENT_ID=your-github-client-id
   OAUTH_CLIENT_SECRET=your-github-client-secret
   OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback/
   OAUTH_SCOPE=user:email
   ```

### Generic OAuth 2.0 Provider

1. **Register your application** with your OAuth provider
2. **Get OAuth endpoints** from your provider's documentation
3. **Add to .env:**
   ```bash
   OAUTH_AUTHN_URL=https://your-oauth-provider.com/oauth/authorize
   OAUTH_TOKEN_URL=https://your-oauth-provider.com/oauth/token
   OAUTH_CLIENT_ID=your-client-id
   OAUTH_CLIENT_SECRET=your-client-secret
   OAUTH_REDIRECT_URI=http://localhost:8000/oauth/callback/
   OAUTH_SCOPE=openid profile email
   ```

## Configuration Options

### Required Settings

- `OAUTH_AUTHN_URL`: Authorization endpoint of your OAuth provider
- `OAUTH_CLIENT_ID`: Client ID from your OAuth provider
- `OAUTH_CLIENT_SECRET`: Client secret from your OAuth provider
- `OAUTH_REDIRECT_URI`: Must match your provider's configuration

### Optional Settings

- `OAUTH_TOKEN_URL`: Token endpoint (if not provided, will be auto-detected)
- `OAUTH_SCOPE`: OAuth scopes (default: "openid profile email")

## Testing OAuth

1. **Start server:** `python3 manage.py runserver`
2. **Visit:** `http://localhost:8000/login/`
3. **Click:** "OAuth Login" tab → "Login with SSO"
4. **Check logs:** `tail -f logs/redislens.log`

## Troubleshooting

```bash
# Test OAuth configuration
python3 test_oauth_dev.py

# Check authentication
python3 debug_auth.py

# Check users created via OAuth
python3 manage.py check_users
```

## Common Issues

- **Redirect URI mismatch:** Make sure OAuth provider has exactly `http://localhost:8000/oauth/callback/`
- **Missing user data:** Ensure scope includes `profile` or `openid profile email`
- **HTTPS required:** Some providers need `DJANGO_DEBUG=True` for localhost HTTP

## Development vs Production

| Setting      | Development                             | Production                               |
| ------------ | --------------------------------------- | ---------------------------------------- |
| Redirect URI | `http://localhost:8000/oauth/callback/` | `https://yourdomain.com/oauth/callback/` |
| Debug Mode   | `True`                                  | `False`                                  |
| HTTPS        | Not required                            | Required                                 |

---

✅ **Result:** OAuth login working alongside local accounts at `http://localhost:8000/login/`
