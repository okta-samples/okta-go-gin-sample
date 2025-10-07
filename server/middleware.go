package server

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
)

func isAuthenticated(r *http.Request) bool {
	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		log.Printf("Access token not found in session")
		return false
	}

	// Token was validated during the code exchange, so we just check if it exists in the session
	// For production use cases requiring stricter validation, consider implementing JWT verification
	// or token introspection on critical endpoints
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
