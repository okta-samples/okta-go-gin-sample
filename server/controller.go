package server

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	"github.com/thanhpk/randstr"
	"golang.org/x/oauth2"
)

var sessionStore = sessions.NewCookieStore([]byte("okta-hosted-login-session-store"))

// IndexHandler serves the index.html page
func IndexHandler(c *gin.Context) {
	log.Println("Loading main page")

	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}

	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.gohtml template
		"index.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func LoginHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	// Generate a random state parameter for CSRF security
	oauthState := randstr.Hex(16)

	// Create the PKCE code verifier and code challenge
	oauthCodeVerifier := randstr.Hex(50)
	// create sha256 hash of the code verifier
	oauthCodeChallenge := generateOauthCodeChallenge(oauthCodeVerifier)

	session.Values["oauth_state"] = oauthState
	session.Values["oauth_code_verifier"] = oauthCodeVerifier

	session.Save(c.Request, c.Writer)

	redirectURI := oktaOauthConfig.AuthCodeURL(
		oauthState,
		oauth2.SetAuthURLParam("code_challenge", oauthCodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	c.Redirect(http.StatusFound, redirectURI)
}

func LogoutHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("The state was not as expected"))
		return
	}

	delete(session.Values, "access_token")

	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")
}

func ProfileHandler(c *gin.Context) {
	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the profile.gohtml template
		"profile.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func getProfileData(r *http.Request) (map[string]string, error) {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m, nil
	}

	reqUrl := os.Getenv("OKTA_OAUTH2_ISSUER") + "/v1/userinfo"

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return m, err
	}

	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}

	json.Unmarshal(body, &m)

	return m, nil
}

func AuthCodeCallbackHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
		return
	}

	// Check the state that was returned in the query string is the same as the above state
	if c.Query("state") == "" || c.Query("state") != session.Values["oauth_state"] {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("The state was not as expected"))
		return
	}

	// Make sure the code was provided
	if c.Query("error") != "" {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("Authorization server returned an error: %s", c.Query("error")))
		return
	}

	// Make sure the code was provided
	if c.Query("code") == "" {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("The code was not returned or is not accessible"))
		return
	}

	token, err := oktaOauthConfig.Exchange(
		context.Background(),
		c.Query("code"),
		oauth2.SetAuthURLParam("code_verifier", session.Values["oauth_code_verifier"].(string)),
	)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("Id token missing from OAuth2 token"))
		return
	}
	_, err = verifyToken(rawIDToken)

	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
		return
	} else {
		session.Values["access_token"] = token.AccessToken

		session.Save(c.Request, c.Writer)
	}

	c.Redirect(http.StatusFound, "/")
}

func generateOauthCodeChallenge(oauthCodeVerifier string) string {
	h := sha256.New()
	h.Write([]byte(oauthCodeVerifier))
	return base64.RawURLEncoding.EncodeToString(h.Sum(nil))
}

func verifyToken(t string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["aud"] = os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("OKTA_OAUTH2_ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified")
}
