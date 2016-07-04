package auth

import (
	auth "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	//"net/http"
	//"strings"
	"sync"
	//webauth "tekinsoft/web"

	//"encoding/base64"
	//"fmt"
)

const pwdCurr string = "github.com/KristinaEtc/auth"

var log slf.StructuredLogger
var once sync.Once

func init() {
	log = slf.WithContext(pwdCurr)
}

func DigestAuth(a *auth.DigestAuth) (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{
		"func": "DigestAuth",
	}).Info("working middleware")

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		if username, authinfo := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
			c.Abort()
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

/*func MultiAuthMiddleware() {

	hdrAuthorization := c.Request.Header.Get("Authorization")
	uri := c.Request.URL.Path
	verb := c.Request.Method
	addr := strings.Split(c.ClientIP(), ":")[0]
	ip := net.ParseIP(addr)
	if ip == nil {
		log.Warnf("Error IP conversion from %s", c.ClientIP())
	}
	log.Warnf("2TTTTTTTTTTTTTTTTTTTTT\n")

	//decode if basic auth
	basic_decoded := ""
	var i int = 1
	//if strings.HasPrefix(hdrAuthorization, "Basic ") {
	if i == 1 {
		return webauth.BasicAuthTest(c)
		buf, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(hdrAuthorization, "Basic "))
		basic_decoded = string(buf)
	} else {
		return DigestAuth(c)
	}
}*/
