# Single Sign-On (SSO) Setup Guide

## Overview
The NEXUS supports Microsoft Azure AD Single Sign-On (SSO) for authentication. This allows users to log in using their Microsoft/Office 365 credentials.

## Current Status
SSO functionality is **partially implemented** and requires Azure AD configuration to work fully.

## Requirements for SSO

### 1. Azure AD App Registration
You need to register an application in Azure AD:

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** → **App registrations**
3. Click **New registration**
4. Fill in the details:
   - **Name**: NEXUS
   - **Supported account types**: Accounts in this organizational directory only
   - **Redirect URI**: `http://your-vm-ip:5000/auth/callback` (or your domain)

### 2. Environment Variables
Set these environment variables on your VM:

```bash
# Azure AD Configuration
export AZURE_CLIENT_ID="your-azure-app-client-id"
export AZURE_CLIENT_SECRET="your-azure-app-client-secret"
export AZURE_TENANT_ID="your-tenant-id"  # or "common" for multi-tenant
```

### 3. API Permissions
In Azure AD App Registration, configure API permissions:
- **Microsoft Graph** → **User.Read** (Delegated)
- **OpenID permissions** (automatically included)

### 4. Domain Validation (Optional)
If you want to restrict access to specific domains (e.g., only @team.nxlink.com emails):
- Configure this in the OAuth callback handler in `api_server.py`

## Current Implementation

The SSO flow is implemented but requires:
1. ✅ Frontend: Login page with SSO button (`login.html`)
2. ✅ Backend: `/api/auth/microsoft` endpoint to generate OAuth URL
3. ⚠️ **Missing**: OAuth callback handler (`/auth/callback`)
4. ⚠️ **Missing**: Token exchange and user session creation

## Next Steps to Enable SSO

1. **Complete OAuth Callback Handler** in `api_server.py`:
   - Handle the authorization code from Microsoft
   - Exchange code for access token
   - Get user information from Microsoft Graph
   - Create/update user in local database
   - Generate JWT token for session

2. **Test SSO Flow**:
   - Click "Sign in with Microsoft" on login page
   - Should redirect to Microsoft login
   - After authentication, redirect back to app
   - User should be logged in automatically

## Alternative: Email/Password Login

Currently, the system works with email/password authentication:
- Users can register with email/password
- Login works via `/api/auth/login`
- JWT tokens are used for session management

## Notes

- SSO will work once Azure AD is configured and callback handler is implemented
- Email/password authentication continues to work regardless of SSO status
- Admin access is determined by email address (set via `ADMIN_EMAILS` env var)

