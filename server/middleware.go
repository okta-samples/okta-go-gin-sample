package server

import (
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
)

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		log.Printf("Access token not found")
		return false
	}

	bearerToken := session.Values["access_token"].(string)
	toValidate := map[string]string{}
	toValidate["aud"] = "api://default"
	toValidate["cid"] = os.Getenv("OKTA_OAUTH2_CLIENT_ID")

	verifier := jwtverifier.JwtVerifier{
		Issuer:           os.Getenv("OKTA_OAUTH2_ISSUER"),
		ClaimsToValidate: toValidate,
	}
	_, err = verifier.New().VerifyAccessToken(bearerToken)

	if err != nil {
		log.Printf("Validation failed: %s", err.Error())
		return false
	}
	return true
}

func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !isAuthenticated(c.Request) {
			log.Printf("Unauthorized route: %s", c.Request.URL.Path)
			c.Redirect(http.StatusFound, "/login")
			return
		}

		c.Next()
	}
}
