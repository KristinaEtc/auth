package main

import _ "github.com/KristinaEtc/slflog"

import (
	auth "github.com/KristinaEtc/auth/auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
)

func main() {

	log := slf.WithContext("stomp-client.go")
	log.Info("test")

	auth.ConfigureFromFile("./webauth.json")
	r := gin.New()

	r.Use(auth.MultiAuthMiddleware(),
		auth.BasicAuthMiddleware(),
		auth.DigestAuthMiddleware(),
		auth.MiddlewareSecond(),
	)

	r.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "status",
		})
	})

	r.GET("/monitoring", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "monitoring",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
