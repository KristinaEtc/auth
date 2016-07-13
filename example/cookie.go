package main

import _ "github.com/KristinaEtc/slflog"

import (
	auth "github.com/KristinaEtc/auth"
	"github.com/gin-gonic/contrib/sessions"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	"net/http"
)

var log slf.StructuredLogger

func loginHandler(c *gin.Context) {

	name := c.Request.FormValue("name")
	pass := c.Request.FormValue("password")

	if name != "" && pass != "" {
		log.Debugf("name=%s, pass=%s\n", name, pass)
		session := sessions.Default(c)
		session.Set("name", name)
		session.Set("password", pass)
		session.Save()
		//c.HTML(200, "index.html", nil)
	} else {
		//should never happend: was checked by html
		log.WithFields(slf.Fields{"name=": name,
			"password=": pass,
		}).Warnf("User authorization with emply field")
	}
}

func indexPageHandler(c *gin.Context) {
	c.HTML(200, "index.html", nil)
}

func main() {

	log = slf.WithContext("auth-main.go")
	log.Info("test")

	auth.ConfigureFromFile("./webauthExample.json")

	r := gin.Default()
	r.Use(gin.Logger())

	store := sessions.NewCookieStore([]byte("authStore"))
	r.Use(sessions.Sessions("Authorization", store))

	r.LoadHTMLGlob("templates/*.html")
	r.Static("/static", "static")

	r.GET("/", indexPageHandler)

	r.POST("/monitoring", func(c *gin.Context) {
		defer log.WithFields(slf.Fields{"func": "/monitoring handler"})
		session := sessions.Default(c)
		userName := session.Get("name")

		if userName != "" {
			//fmt.Fprintf(response, internalPage, userName)
			log.Debug(userName.(string))
			c.HTML(http.StatusOK, "monitoring.html", nil)
		} else {
			log.WithFields(slf.Fields{"endpoint=": "/monitoring"}).Debug("wrong username")
			//http.Redirect(response, request, "/", 302)
		}

	})

	r.POST("/login", loginHandler)
	//	r.POST("/logout", logoutHandler)

	r.Run(":8000")
}
