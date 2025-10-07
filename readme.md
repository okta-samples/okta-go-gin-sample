# Okta Golang Gin & Okta-Hosted Login Page Example

This example shows you how to use the [OIDC-certified zitadel/oidc library][zitadel oidc library] to login an Okta user to a Golang Gin application. The login is achieved through the [Authorization Code Flow][authorization code flow] with PKCE (Proof Key for Code Exchange) where the user is redirected to the Okta-Hosted login page. After the user authenticates, they are redirected back to the application and a local cookie session is created.

This application uses Okta's **Org Authorization Server** for authentication, providing a standards-compliant OIDC implementation with automatic PKCE support.

## Prerequisites

Before running this sample, you will need the following:

- [Go 1.24 +](https://go.dev/dl/)
- An Okta Integrator account (free). To get one, sign up for an [Okta Integrator account](https://developer.okta.com/signup).

## Setup Instructions

### 1. Create an Okta Application

Once you have an account, sign in to your Okta Integrator account and in the Admin Console:

1. Go to **Applications > Applications**
2. Click **Create App Integration**
3. Select **OIDC - OpenID Connect** as the sign-in method
4. Select **Web Application** as the application type, then click **Next**
5. Enter an app integration name, e.g. `okta-go-gin-sample`
6. Accept the default redirect URIs:
   - **Sign-in redirect URIs:** `http://localhost:8080/authorization-code/callback`
   - **Sign-out redirect URIs:** `http://localhost:8080`
7. In the **Assignments** section, select the appropriate access level for your needs
8. Click **Save**

After saving, note down the **Client ID** and **Client Secret** from the application's **General** tab - you'll need these in the next step.

### 2. Configure Grant Types

On your application's **General** tab:

1. Scroll to **General Settings** and click **Edit**
2. In the **Grant type** section, ensure these are checked:
   - ✅ **Authorization Code**
   - ✅ **Refresh Token** (recommended to avoid third-party cookie issues)
3. Click **Save**

### 3. Configure Trusted Origins

For local development, configure trusted origins:

1. Go to **Security > API > Trusted Origins**
2. Click **Add Origin**
3. Configure the origin:
   - **Name:** `Local Development`
   - **Origin URL:** `http://localhost:8080`
   - **Type:** Check both **CORS** and **Redirect**
4. Click **Save**

## Configure the Application

### 1. Clone the Repository

```bash
git clone https://github.com/okta-samples/okta-go-gin-sample.git
cd okta-go-gin-sample
```

### 2. Create Configuration File

Copy the example configuration file and update it with your values:

```bash
cp .okta.env.example .okta.env
```

Edit `.okta.env` with your application's configuration:

```bash
OKTA_OAUTH2_ISSUER="https://dev-133337.okta.com"
OKTA_OAUTH2_CLIENT_ID="0oab8eb55Kb9jdMIr5d6"
OKTA_OAUTH2_CLIENT_SECRET="your_client_secret_here"
OKTA_OAUTH2_REDIRECT_URL="http://localhost:8080/authorization-code/callback"
SESSION_SECRET="generate_with_openssl_rand_hex_32"
```

**Important Configuration Notes:**

- **OKTA_OAUTH2_ISSUER:** This is your Okta domain **without** `/oauth2/default` (we use the Org Authorization Server)
  - ✅ Correct: `https://dev-133337.okta.com`
  - ❌ Incorrect: `https://dev-133337.okta.com/oauth2/default`
- **SESSION_SECRET:** Generate a secure random key:
  ```bash
  openssl rand -hex 32
  ```

> **Security Warning**: Never commit `.okta.env` to source control! It's already in `.gitignore`.

### Where to Find Your Application Credentials

After creating the app, find these values in the Okta Admin Console:

- **Client ID:** On the application's **General** tab, in the **Client Credentials** section
- **Client Secret:** Click **Show** in the **Client Credentials** section to reveal
- **Issuer (Org Authorization Server):** Your Okta domain URL (e.g., `https://dev-133337.okta.com`)

## Run the Application

### Install Dependencies

```bash
go mod download
```

### Run the Server

```bash
go run main.go
```

The application will start on http://localhost:8080

### Test the Application

1. Navigate to http://localhost:8080 in your browser
2. You should see a home page with a **Log in** button
3. Click **Log in** - you'll be redirected to the Okta-hosted login page
4. Sign in with your Okta credentials
5. After successful authentication, you'll be redirected back to the application
6. Click **Profile** to view your user information from Okta
7. Click **Logout** to end your session

> **Note**: If you're already signed into the Okta Admin Console, you may have an active SSO session. To test the full login flow, use an incognito/private browser window.

## Build for Production

To create a production build:

```bash
go build -o okta-app
./okta-app
```

## Architecture & Security Features

This application demonstrates several security best practices:

- **OIDC-Certified Library**: Uses [zitadel/oidc v3][zitadel oidc library], certified by the OpenID Foundation
- **PKCE Support**: Automatic Proof Key for Code Exchange implementation for enhanced security
- **Org Authorization Server**: Uses Okta's org-level authorization server for standard OIDC flows
- **Secure Sessions**: HTTP-only, secure cookies with SameSite protection
- **Token Revocation**: Proper token cleanup on logout

## Troubleshooting

### "invalid_grant" Error

If you see `oauth2: "invalid_grant" "The authorization code is invalid or has expired"`:

- Verify your `OKTA_OAUTH2_ISSUER` does NOT include `/oauth2/default`
- Ensure the redirect URI matches exactly: `http://localhost:8080/authorization-code/callback`
- Check that **Authorization Code** grant type is enabled in your Okta app
- Verify Trusted Origins are configured correctly

### Session Secret Error

If you see `securecookie: error - caused by: crypto/aes: invalid key size`:

- Make sure `SESSION_SECRET` is exactly 64 characters (32 bytes in hex)
- Generate a new one with: `openssl rand -hex 32`

### Port Already in Use

If port 8080 is already in use, kill old running instances of this app, or use a different port:

```bash
PORT=3000 go run main.go
```

Update your redirect URIs in Okta to match the new port.

## Additional Resources

- [Okta Go Samples Repository](https://github.com/okta/samples-golang)
- [Okta Developer Documentation](https://developer.okta.com/)
- [ZITADEL OIDC Library Documentation](https://pkg.go.dev/github.com/zitadel/oidc/v3)
- [Authorization Code Flow Guide](https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/)

[zitadel oidc library]: https://github.com/zitadel/oidc
[authorization code flow]: https://developer.okta.com/docs/guides/implement-grant-type/authcode/main/
