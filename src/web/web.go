package web

import (
	"log"
	"os"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func Init() {

	godotenv.Load("./.okta.env")

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

	// setup client side routes
	router.GET("/", IndexHandler)
	router.GET("/profile", ProfileHandler)

	// setup API routes
	router.GET("/login", LoginHandler)
	router.GET("/authorization-code/callback", AuthCodeCallbackHandler)
	router.POST("/logout", LogoutHandler)

	// Start and run the server
	log.Printf("Running on http://localhost:" + port)
	router.Run(":" + port)
}
