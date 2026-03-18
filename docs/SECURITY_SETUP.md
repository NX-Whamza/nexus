# Security Configuration Guide

## Proprietary Information Protection

This document outlines security measures to protect NextLink proprietary information.

## Required Environment Variables

### RADIUS Secret Configuration

**IMPORTANT**: The RADIUS secret is no longer hardcoded. It should be set as an environment variable for production use.

**Note**: If the environment variable is not set, the system will use a placeholder (`CHANGE_ME_RADIUS_SECRET`) and display a warning. This allows the system to function, but you must replace the placeholder with the actual secret before deploying configurations.

#### Windows (PowerShell)
```powershell
$env:NEXTLINK_RADIUS_SECRET="your_radius_secret_here"
```

#### Windows (Command Prompt)
```cmd
set NEXTLINK_RADIUS_SECRET=your_radius_secret_here
```

#### Linux/macOS
```bash
export NEXTLINK_RADIUS_SECRET="your_radius_secret_here"
```

#### Permanent Setup (Windows)
1. Open System Properties -> Environment Variables
2. Add new User/System variable:
   - Name: `NEXTLINK_RADIUS_SECRET`
   - Value: `your_radius_secret_here`

#### Permanent Setup (Linux/macOS)
Add to `~/.bashrc` or `~/.zshrc`:
```bash
export NEXTLINK_RADIUS_SECRET="your_radius_secret_here"
```

## Database Security

- **Database Location**: All databases are stored in `secure_data/` directory
- **Access Control**: Databases are not accessible via HTTP
- **File Permissions**: Secure directory has restricted permissions (700 on Unix)
- **Backup**: Ensure `secure_data/` is backed up securely

## HTTP Server Security

`serve_html.py` is obsolete and should not be used for current deployment guidance.

Current frontend options:
- Packaged/EXE runtime: `vm_deployment/launcher.py`
- Local development only: `python -m http.server 8000 --directory vm_deployment`

Security note:
- `vm_deployment/launcher.py` uses a restricted handler instead of a raw directory listing server
- `python -m http.server` is not a hardened frontend server and should not be exposed to untrusted networks

## What's Protected

1. **RADIUS Secret**: Moved to environment variable
2. **Database Files**: Moved to `secure_data/` directory
3. **Source Code**: Not accessible via HTTP
4. **Configuration Files**: Blocked from HTTP access
5. **Proprietary IPs**: Still in code (infrastructure IPs - acceptable)

## Migration Instructions

If you have existing database files in the root directory:

1. **Stop the server** if running
2. **Create secure directory**:
   ```bash
   mkdir secure_data
   ```
3. **Move databases**:
   ```bash
   move chat_history.db secure_data\
   move completed_configs.db secure_data\
   ```
4. **Set environment variable** (see above)
5. **Restart server**

## Verification

After setup, verify:
- Environment variable is set: `echo $NEXTLINK_RADIUS_SECRET` (Linux) or `echo %NEXTLINK_RADIUS_SECRET%` (Windows)
- Database files are in `secure_data/` directory
- Accessing `http://your-ip:8000/` redirects to UI (no directory listing)
- Accessing `http://your-ip:8000/secure_data/` returns 404
- Accessing `http://your-ip:8000/api_server.py` returns 404

## Important Notes

- **NEVER** commit the `.env` file or `secure_data/` directory to Git
- **NEVER** hardcode secrets in source code
- **NEVER** expose database files via HTTP
- Always use environment variables for sensitive configuration

---

## Single Sign-On (SSO) Setup

### Overview
The NOC Config Maker supports Microsoft Azure AD Single Sign-On (SSO) for authentication. This allows users to log in using their Microsoft/Office 365 credentials.

### Current Status
SSO functionality is partially implemented and requires Azure AD configuration to work fully.

### Requirements for SSO

#### 1. Azure AD App Registration
You need to register an application in Azure AD:

1. Go to [Azure Portal](https://portal.azure.com)
2. Navigate to **Azure Active Directory** -> **App registrations**
3. Click **New registration**
4. Fill in the details:
   - **Name**: NOC Config Maker
   - **Supported account types**: Accounts in this organizational directory only
   - **Redirect URI**: `http://your-vm-ip:5000/auth/callback` (or your domain)

#### 2. Environment Variables
Set these environment variables on your VM:

```bash
# Azure AD Configuration
export AZURE_CLIENT_ID="your-azure-app-client-id"
export AZURE_CLIENT_SECRET="your-azure-app-client-secret"
export AZURE_TENANT_ID="your-tenant-id"  # or "common" for multi-tenant
```

#### 3. API Permissions
In Azure AD App Registration, configure API permissions:
- **Microsoft Graph** -> **User.Read** (Delegated)
- **OpenID permissions** (automatically included)

#### 4. Domain Validation (Optional)
If you want to restrict access to specific domains (for example, only `@team.nxlink.com` emails):
- Configure this in the OAuth callback handler in `api_server.py`

### Current Implementation

The SSO flow is implemented but requires:
1. Frontend: Login page with SSO button (`login.html`)
2. Backend: `/api/auth/microsoft` endpoint to generate OAuth URL
3. **Missing**: OAuth callback handler (`/auth/callback`)
4. **Missing**: Token exchange and user session creation

### Next Steps to Enable SSO

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

### Alternative: Email/Password Login

Currently, the system works with email/password authentication:
- Users can register with email/password
- Login works via `/api/auth/login`
- JWT tokens are used for session management

### Notes

- SSO will work once Azure AD is configured and callback handler is implemented
- Email/password authentication continues to work regardless of SSO status
- Admin access is determined by email address (set via `ADMIN_EMAILS` env var)
