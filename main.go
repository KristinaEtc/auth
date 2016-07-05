package main

import _ "github.com/KristinaEtc/slflog"

import (
	auth "github.com/KristinaEtc/auth/auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	webauth "tekinsoft/web"
)

func main() {

	log := slf.WithContext("main.go")
	log.Info("test")

	webauth.ConfigureFromFile("./webauth.json")
	r := gin.New()

	r.Use(auth.MultiAuthMiddleware(),
		auth.BasicMiddleware(),
		auth.DigestMiddleware(),
		auth.MiddlewareSecond(),
	)

	r.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "test",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
