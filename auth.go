package auth

import (
	auth "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
)

const pwdCurr string = "/home/k/work/go/src/github.com/KristinaEtc/auth"

var log slf.StructuredLogger

func initLogger() {
	log = slf.WithContext(pwdCurr)
}

func DigestAuth(a *auth.DigestAuth) (result gin.HandlerFunc) {
	initLogger()
	defer log.WithFields(slf.Fields{
		"func": "DigestAuth",
	}).Info("New user wants to connect")

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
