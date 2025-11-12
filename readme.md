# Okta Golang Gin & Okta-Hosted Login Page Example

This example shows you how to use the [Okta JWT verifier library][] to login a user to a Golang Gin application. The login is achieved through the [Authorization Code Flow][] where the user is redirected to the Okta-Hosted login page. After the user authenticates, they are redirected back to the application and a local cookie session is created.

## Prerequisites

Before running this sample, you will need the following:

- [Go 1.23 +](https://go.dev/dl/)
* An Okta Integrator Free Plan account. To get one, sign up for an [Integrator account](https://developer.okta.com/login). Once you have an account, sign in to your [Integrator account](https://developer.okta.com/login). Next, in the Admin Console:

1. Go to **Applications > Applications**
2. Click **Create App Integration**
3. Select **OIDC - OpenID Connect** as the sign-in method
4. Select **Web Application** as the application type, then click **Next**
5. Enter an app integration name, e.g. `My Golang Gin App`
6. Configure the redirect URIs:
- Accept the default redirect URI values:
- **Sign-in redirect URIs:** `http://localhost:8080/authorization-code/callback`
- **Sign-out redirect URIs:** `http://localhost:8080`
7. In the **Controlled access** section, select the appropriate access level
8. Click **Save**

Creating an OIDC Web App manually in the Admin Console configures your Okta Org with the application settings. You may also need to configure trusted origins for `http://localhost:8080` in **Security > API > Trusted Origins**.

## Get the Code

```bash
git clone https://github.com/okta-samples/okta-go-gin-sample.git
cd okta-go-gin-sample
```

Update your config file at `.okta.env` with the values from your application's configuration:

```text
OKTA_OAUTH2_ISSUER="https://dev-133337.okta.com/oauth2/default"
OKTA_OAUTH2_CLIENT_ID="0oab8eb55Kb9jdMIr5d6"
OKTA_OAUTH2_CLIENT_SECRET="myClientSecret"
```

> **Note**: Don't EVER commit `.okta.env` into source control. Add it to the `.gitignore` file.

### Where are my new app's credentials?

After creating the app, you can find the configuration details on the app’s **General** tab:
- **Client ID:** Found in the **Client Credentials** section
- **Client Secret:** Click **Show** in the **Client Credentials** section to reveal
- **Issuer:** Found in the **Issuer URI** field for the authorization server that appears by selecting **Security > API** from the navigation pane.

## Enable Refresh Token

Manually enable Refresh Token on your Okta application to avoid third-party cookies. Sign in to your Okta Developer Edition account. Press the **Admin Console** button to navigate to the Okta Admin Console. In the sidenav, navigate to **Applications** > **Applications** and find the Okta application for this project named `okta-go-api-sample`. Edit the application's **General Setting** to enable the **Refresh Token** checkbox. **Save** your changes.

## Run the Example

```bash
go run main.go
```

Now, navigate to http://localhost:8080 in your browser.

If you see a home page that prompts you to login, then things are working! Clicking the Log in button will redirect you to the Okta hosted sign-in page.

You can sign in with the same account that you created when signing up for your Developer Org, or you can use a known username and password from your Okta Directory.

> **Note**: If you are currently using the Okta Admin Console, you already have a Single Sign-On (SSO) session for your Org. You will be automatically logged into your application as the same user that is using the Developer Console. You may want to use an incognito tab to test the flow from a blank slate.

You can find more Golang sample in [this repository](https://github.com/okta/samples-golang)

[okta jwt verifier library]: github.com/okta/okta-jwt-verifier-golang
[oidc web application setup instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
[authorization code flow]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code
