package main

import _ "github.com/KristinaEtc/slflog"

import (
	//"fmt"
	auth "github.com/KristinaEtc/auth/auth"
	//dAuth "github.com/abbot/go-http-auth"
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

	log := slf.WithContext("main.go")
	log.Info("test")

	webauth.ConfigureFromFile("./webauth.json")
	r := gin.New()

	r.Use(auth.MultiAuthMiddleware())
	r.Use(auth.BasicMiddleware())
	r.Use(auth.DigestMiddleware())
	r.Use(auth.MiddleSecond())

	r.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
