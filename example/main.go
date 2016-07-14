package main

import _ "github.com/KristinaEtc/slflog"

import (
	auth "github.com/KristinaEtc/auth"
	//"github.com/gin-gonic/contrib/sessions"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	//"net/http"
	"github.com/gin-gonic/contrib/sessions"
)

var log slf.StructuredLogger

func main() {

	log = slf.WithContext("auth-main.go")
	log.Info("test")

	auth.ConfigureFromFile("./webauthExample.json")

	r := gin.Default()
	r.Use(gin.Logger())

	//r.NoRoute(redirect)

	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "static")

	monitoring := r.Group("/")

	store := sessions.NewCookieStore([]byte("authStore"))
	monitoring.Use(sessions.Sessions("Authorization", store))
	r.Use(sessions.Sessions("Authorization", store))

	monitoring.Use(auth.MultiAuthMiddleware(),
		auth.TrustMiddleware(),
		auth.BasicAuthMiddleware(),
		auth.DigestAuthMiddleware(),
		auth.MiddlewareSecond(),
		auth.CookieMiddleware(),
	)
	{
		monitoring.POST("/monitoring", func(c *gin.Context) {
			c.HTML(200, "monitoring.html", nil)
		})
		monitoring.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "/",
			})
		})
		monitoring.GET("/status", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "status",
			})
		})
		monitoring.GET("/monitoring", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "monitoring",
			})
		})
	}

	r.POST("/login", auth.LoginHandler)

	r.Run(":8080")
}
