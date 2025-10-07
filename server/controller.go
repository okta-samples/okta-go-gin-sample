package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/thanhpk/randstr"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var sessionStore *sessions.CookieStore

func initSessionStore() {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET environment variable is required")
	}
	sessionStore = sessions.NewCookieStore([]byte(secret))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

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

	// Use zitadel's AuthURLHandler with custom state generator
	stateFunc := func() string {
		return randstr.Hex(16)
	}

	// Create the auth URL handler and execute it
	handler := rp.AuthURLHandler(stateFunc, relyingParty)
	handler(c.Writer, c.Request)
}

func LogoutHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("failed to get session"))
		return
	}

	// Revoke the access token using zitadel's RevokeToken
	if accessToken, ok := session.Values["access_token"].(string); ok && accessToken != "" {
		err := rp.RevokeToken(context.Background(), relyingParty, accessToken, "access_token")
		if err != nil {
			log.Printf("Failed to revoke token: %v", err)
			// Continue with logout even if revocation fails
		}
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

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}

	err = json.Unmarshal(body, &m)
	if err != nil {
		return m, err
	}

	return m, nil
}

func AuthCodeCallbackHandler(c *gin.Context) {
	// Use zitadel's built-in callback handler which properly handles PKCE cookies
	marshalToken := func(w http.ResponseWriter, r *http.Request, tokens *oidc.Tokens[*oidc.IDTokenClaims], state string, rp rp.RelyingParty) {
		// Store access token in session
		session, err := sessionStore.Get(r, "okta-hosted-login-session-store")
		if err != nil {
			http.Error(w, "Failed to get session", http.StatusInternalServerError)
			return
		}

		session.Values["access_token"] = tokens.AccessToken
		if err := session.Save(r, w); err != nil {
			http.Error(w, "Failed to save session", http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusFound)
	}

	// Use the library's CodeExchangeHandler which handles PKCE automatically
	handler := rp.CodeExchangeHandler(marshalToken, relyingParty)
	handler(c.Writer, c.Request)
}
