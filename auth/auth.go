package auth

import (
	auth "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	"sync"
)

const pwdCurr string = "github.com/KristinaEtc/auth"

var log slf.StructuredLogger
var once sync.Once

func initLogger() {
	once.Do(func() {
		log = slf.WithContext(pwdCurr)
	})
	return
}

func DigestAuth(a *auth.DigestAuth) (result gin.HandlerFunc) {
	initLogger()
	defer log.WithFields(slf.Fields{
		"func": "DigestAuth",
	}).Info("working middleware")

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		if username, authinfo := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
			log.Debug("sended")

		} else {
			ar := &auth.AuthenticatedRequest{Request: *r, Username: username}
			if authinfo != nil {
				log.Debug("check")
				w.Header().Set("Authentication-Info", *authinfo)
				//c.Next()
			}
			c.Request = &ar.Request
			return
		}
	}
}
