package auth

import (
	//dAuth "github.com/abbot/go-http-auth"
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"

	//"net"
	//	"strings"
)

// A middleware that implement digest authorization
func CookieMiddleware() (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{"func": "CookieMiddleware"})

	return func(c *gin.Context) {
		//	r := c.Request
		//	w := c.Writer

		//get request parametrs
		reqAuthParams := c.MustGet("a").(*authParams)
		if reqAuthParams.authType == "cookie" {
			log.Debug("here-cookie")
			session := sessions.Default(c)
			username := session.Get("username")
			password := session.Get("password")

			if username == nil && password == nil {
				c.HTML(200, "login.html", nil)
				log.Warn("An attempt to enter without cookies")
				c.Abort()
				return
			} else {
				if username == "" && password == "" {
					log.Debug("username == \" \" && password == \" \"")
					c.Abort()
					return
				}
			}
		}
	}
}

func loginRoute(redirectPage string) (result gin.HandlerFunc) {

	return func(c *gin.Context) {

		defer log.WithFields(slf.Fields{"func": "LoginHandler"})

		name := c.Request.FormValue("username")
		pass := c.Request.FormValue("password")

		if name != "" && pass != "" {
			if checkPwdCorrect(name, pass) == true {
				log.Debugf("name=%s, pass=%s\n", name, pass)
				session := sessions.Default(c)
				session.Set("name", name)
				session.Set("password", pass)
				session.Save()
				c.HTML(200, redirectPage, nil)
			} else {
				//should never happend: was checked by html
				log.WithFields(slf.Fields{"name=": name,
					"password=": pass,
				}).Warnf("Cookie: wrong password")
			}
		}
	}
}
