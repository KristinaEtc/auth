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

func MultiAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		a := &authParams{hdrAuthorization: c.Request.Header.Get("Authorization"),
			uri:  c.Request.URL.Path,
			verb: c.Request.Method,
			addr: strings.Split(c.ClientIP(), ":")[0],
		}
		a.ip = net.ParseIP(a.addr)

		var one int = 1
		log.Debug("//Test Multi Auth Middleware///")
		switch one {
		case 1:
			return TestBasicA(a)
		case 2:
			return TestDigestN(a)
		default:
			return TestTrust(a)
		}
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

func TestMiddleSecond() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("///Test Middle Second///")
	}
}

/*func main() {
	r := gin.New()
	//r.Use()

	r.Use(TestMiddle())
	r.Use(TestMiddleSecond())

	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}*/
