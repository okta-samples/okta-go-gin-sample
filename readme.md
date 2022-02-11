# Okta Golang Gin & Okta-Hosted Login Page Example

This example shows you how to use the [Okta JWT verifier library][] to login a user to a Golang Gin application. The login is achieved through the [Authorization Code Flow][] where the user is redirected to the Okta-Hosted login page. After the user authenticates, they are redirected back to the application and a local cookie session is created.

## Prerequisites

Before running this sample, you will need the following:

- [Go 1.13 +](https://go.dev/dl/)
- [The Okta CLI Tool](https://github.com/okta/okta-cli/#installation)
- An Okta Developer Account, create one using `okta register`, or configure an existing one with `okta login`

## Get the Code

Grab and configure this project using `okta start go-gin`

You can also clone this project from GitHub and run `okta start` in it.

```bash
git clone https://github.com/okta-samples/okta-go-gin-sample.git
cd okta-go-gin-sample
okta start
```

Follow the instructions printed to the console.

> **Note**: Don't EVER commit `.okta.env` into source control. Add it to the `.gitignore` file.

## Run the Example

```bash
go run main.go
```

Now, navigate to http://localhost:4200 in your browser.

If you see a home page that prompts you to login, then things are working! Clicking the Log in button will redirect you to the Okta hosted sign-in page.

You can sign in with the same account that you created when signing up for your Developer Org, or you can use a known username and password from your Okta Directory.

> **Note**: If you are currently using the Okta Admin Console, you already have a Single Sign-On (SSO) session for your Org. You will be automatically logged into your application as the same user that is using the Developer Console. You may want to use an incognito tab to test the flow from a blank slate.

You can find more Golang sample in [this repository](https://github.com/okta/samples-golang)

[okta jwt verifier library]: github.com/okta/okta-jwt-verifier-golang
[oidc web application setup instructions]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code#1-setting-up-your-application
[authorization code flow]: https://developer.okta.com/authentication-guide/implementing-authentication/auth-code
