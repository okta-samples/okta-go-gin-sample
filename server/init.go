package server

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"github.com/zitadel/oidc/v3/pkg/client/rp"
	httphelper "github.com/zitadel/oidc/v3/pkg/http"
	"github.com/zitadel/oidc/v3/pkg/oidc"
)

var relyingParty rp.RelyingParty

func Init() {

	godotenv.Load("./.okta.env")

	initSessionStore()

	issuer := os.Getenv("OKTA_OAUTH2_ISSUER")
	clientID := os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")

	if issuer == "" {
		log.Fatal("OKTA_OAUTH2_ISSUER environment variable is required")
	}
	if clientID == "" {
		log.Fatal("OKTA_OAUTH2_CLIENT_ID environment variable is required")
	}
	if clientSecret == "" {
		log.Fatal("OKTA_OAUTH2_CLIENT_SECRET environment variable is required")
	}

	redirectURL := os.Getenv("OKTA_OAUTH2_REDIRECT_URL")
	if redirectURL == "" {
		redirectURL = "http://localhost:8080/authorization-code/callback"
	}

	// Initialize OIDC RelyingParty with PKCE support
	sessionSecret := []byte(os.Getenv("SESSION_SECRET"))
	// Cookie handler needs 32-byte keys for encryption
	// Use first 32 bytes for hash key and last 32 bytes for encryption key
	hashKey := sessionSecret[:32]
	encryptKey := sessionSecret[:32] // In production, use different keys

	cookieHandler := httphelper.NewCookieHandler(
		hashKey,
		encryptKey,
		httphelper.WithSameSite(http.SameSiteLaxMode),
		httphelper.WithMaxAge(3600),
	)

	var err error
	relyingParty, err = rp.NewRelyingPartyOIDC(
		context.Background(),
		issuer,
		clientID,
		clientSecret,
		redirectURL,
		[]string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeOfflineAccess},
		rp.WithPKCE(cookieHandler),
	)
	if err != nil {
		log.Fatalf("Failed to create OIDC relying party: %v", err)
	}

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080" // default when missing
	}

	// Set the router as the default one shipped with Gin
	router := gin.Default()

	// Serve HTML templates
	router.LoadHTMLGlob("./templates/*")
	// Serve frontend static files
	router.Use(static.Serve("/static", static.LocalFile("./static", true)))

	// setup public routes
	router.GET("/", IndexHandler)
	router.GET("/login", LoginHandler)
	router.GET("/authorization-code/callback", AuthCodeCallbackHandler)

	// setup private routes
	authorized := router.Group("/", AuthMiddleware())

	authorized.POST("/logout", LogoutHandler)
	authorized.GET("/profile", ProfileHandler)

	// Start and run the server
	log.Printf("Running on http://localhost:" + port)
	router.Run(":" + port)
}
