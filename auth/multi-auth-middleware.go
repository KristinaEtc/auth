package auth

import (
	"github.com/gin-gonic/gin"
	"net"
	"strings"
)

type authParams struct {
	uri              string
	verb             string
	addr             string
	ip               net.IP
	basic_decoded    string
	uri_lst          string
	user             string
	hdrAuthorization string
}

func MultiAuthMiddleware() func(*gin.Context) gin.HandlerFunc {
	return func(c *gin.Context) gin.HandlerFunc {
		a := &authParams{hdrAuthorization: c.Request.Header.Get("Authorization"),
			uri:  c.Request.URL.Path,
			verb: c.Request.Method,
			addr: strings.Split(c.ClientIP(), ":")[0],
		}
		a.ip = net.ParseIP(a.addr)

		var one int = 1
		var f gin.HandlerFunc
		log.Debug("//Test Multi Auth Middleware///")
		switch one {
		case 1:
			f = TestBasicA(a)
		case 2:
			f = TestDigestN(a)
		default:
			f = TestTrust(a)
		}
		return f
	}
}

// used c.Next()
func TestDigestN(a *authParams) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("///Test DigestN///")
		//log.Println(myStruct.Test)
		c.Next()
	}
}

// used c.Abort()
func TestBasicA(a *authParams) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("///Test BasicA///")
		//log.Println(myStruct.Test)
		c.Abort()
	}
}

func TestTrust(a *authParams) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("///Test Trust///")
		//log.Println(myStruct.Test)
	}
}

func MiddleSecond() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("///Test Middle Second///")
	}
}
