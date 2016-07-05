package auth

import (
	dAuth "github.com/abbot/go-http-auth"
	webauth "tekinsoft/web"

	"github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	"net"
	"strings"
)

type authParams struct {
	uri              string
	verb             string
	addr             string
	ip               net.IP
	basic_decoded    string
	uri_lst          []*webauth.AuthOptionItem
	user             string
	hdrAuthorization string
	queryTitle       string
	authType         string
}

func MultiAuthMiddleware() gin.HandlerFunc {

	log.Debug("MultiAuthMiddleware")

	return func(c *gin.Context) {

		// request information struct for all middlewares
		a := &authParams{hdrAuthorization: c.Request.Header.Get("Authorization"),
			uri:  c.Request.URL.Path,
			verb: c.Request.Method,
			addr: strings.Split(c.ClientIP(), ":")[0],
		}
		a.ip = net.ParseIP(a.addr)
		if a.ip == nil {
			log.Warnf("Error IP conversion from %s", c.ClientIP())
		}
		c.Set("a", a)
		log.Debugf("MultiAuthMiddleware: %v\n", a)

		// check if client has access for such uri (in configuration repository: file, DB, map of struct, etc...)
		a.uri_lst = webauth.GetUriPatterns(webauth.Configuration.AuthOptions, a.uri, a.verb)
		if len(a.uri_lst) == 0 {
			log.Warnf("URI pattern not found [%s]", a.queryTitle)
			//c.String(403, "No route")
			c.JSON(403, gin.H{
				"message": "No route",
			})
			c.Abort()
			return
		}

		//check if clients network is enabled in found patterns
		a.uri_lst = webauth.GetNetworkIsEnabled(a.uri_lst, a.ip)
		if len(a.uri_lst) == 0 {
			log.Warnf("Forbidden network %s", a.queryTitle)
			c.JSON(403, gin.H{
				"message": "Forbidden network",
			})
			c.Abort()
			return
		}

		// check authentication for a client
		a.authType = webauth.GetAuthType(webauth.Configuration.AuthOptions, a.uri, a.verb)
		c.Next()
	}
}

func CheckDigestHash(user, realm string) string {
	for userInfo, _ := range webauth.Configuration.UserAccounts {
		if userInfo.User == user {
			return userInfo.DigestHash
		}
	}
	return ""
}

// A middleware that implement digest authorization
func DigestAuth(a *dAuth.DigestAuth) (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{"func": "DigestAuth"})

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		//get request parametrs
		reqAuthParams := c.MustGet("a").(*authParams)
		if reqAuthParams.authType == "digest" {

			//check if user was registered
			if username, authinfo := a.CheckAuth(r); username == "" {
				a.RequireAuth(w, r)
				c.Abort()
				log.Debug("sended")
			} else {
				// if he didn't - setting a header with digest request
				ar := &dAuth.AuthenticatedRequest{Request: *r, Username: username}
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
}

// A middleware that implement basic authorization
func BasicMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("BasicMiddleware")

		a := c.MustGet("a").(*authParams)

		if a.authType == "basic" {
			// basic auth
		} else {
			c.Next()
			return
		}
		//c.Abort()
	}
}

/*func TrustMiddleware(a *authParams) gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("Trust Middleware")
	}
}*/

func MiddlewareSecond() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("Test Middleware Second")
	}
}
