package main

import _ "github.com/KristinaEtc/slflog"

import (
	auth "github.com/KristinaEtc/auth"
	//
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	//"net/http"
	//"github.com/gin-gonic/contrib/sessions"
)

var log slf.StructuredLogger

func main() {

	log = slf.WithContext("auth-main.go")

	// for readable logs
	log.Error("-------------------------------------------------")

	auth.ConfigureFromFile("./webauthExample.json")

	r := gin.Default()
	r.Use(gin.Logger())
	(*r).LoadHTMLGlob("templates/*.html")

	//r.NoRoute(redirect)

	monitoring := r.Group("/")
	auth.InitAuthMiddlewares(&r, //global ini (for cookies and templates)
		&monitoring,       // group, which will be configured with middlewares
		"monitoring.html", // page, that will be loaded after login page
	)

	monitoring.POST("/monitoring", func(c *gin.Context) {
		c.HTML(200, "monitoring.html", nil)
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

	/*	r.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "/",
			})
		})
	message*/
	//r.POST("/login", auth.LoginHandler)

	r.Run(":8080")
}
