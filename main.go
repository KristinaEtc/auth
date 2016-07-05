package main

import _ "github.com/KristinaEtc/slflog"

import (
	//"fmt"
	auth "github.com/KristinaEtc/auth/auth"
	authD "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	webauth "tekinsoft/web"
)

func Secret(user, realm string) string {
	if user == "john" {
		return "b98e16cbc3d01734b264adba7baa3bf9"
	}
	return ""
}

func main() {

	log := slf.WithContext("stomp-client.go")
	log.Info("test")

	authenticator := authD.NewDigestAuthenticator("Authorization", Secret)
	webauth.ConfigureFromFile("./webauth.json")
	r := gin.New()

	r.Use(auth.MultiAuthMiddleware(),
		auth.BasicMiddleware(),
		auth.DigestAuth(authenticator),
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
