package auth

import (
	dAuth "github.com/abbot/go-http-auth"
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
	uri_lst          []*AuthOptionItem
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

		log.Debug(a.uri)
		log.Debug(a.verb)

		// check if client has access for such uri (in configuration repository: file, DB, map of struct, etc...)
		a.uri_lst = GetUriPatterns(Configuration.AuthOptions, a.uri, a.verb)
		if len(a.uri_lst) == 0 {
			log.Warnf("URI pattern not found [%s]", a.queryTitle)
			//c.String(403, "No route")
			c.JSON(403, gin.H{
				"message": "No route",
			})
			c.Abort()
			return
		}

		//TODO: add ipv6  support! (in chrome natively)
		//check if clients network is enabled in found patterns
		a.uri_lst = GetNetworkIsEnabled(a.uri_lst, a.ip)
		if len(a.uri_lst) == 0 {
			log.Warnf("Forbidden network %s", a.queryTitle)
			c.JSON(403, gin.H{
				"message": "Forbidden network",
			})
			c.Abort()
			return
		}

		// check authentication for a client
		a.authType = GetAuthType(Configuration.AuthOptions, a.uri, a.verb)
		c.Next()
	}
}

// A middleware that implement digest authorization
func DigestAuthMiddleware() (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{"func": "DigestAuth"})

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		//get request parametrs
		reqAuthParams := c.MustGet("a").(*authParams)
		if reqAuthParams.authType == "digest" {

			//check if user was registered
			if username, authinfo := dAuthenticator.CheckAuth(r); username == "" {
				dAuthenticator.RequireAuth(w, r)
				c.Abort()
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

func BasicAuthMiddleware() (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{"func": "Basic Auth"})

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer
		reqAuthParams := c.MustGet("a").(*authParams)

		if reqAuthParams.authType == "basic" {

			if username := bAuthenticator.CheckAuth(r); username == "" {
				bAuthenticator.RequireAuth(w, r)
				c.Abort()
			} else {
				ar := &dAuth.AuthenticatedRequest{Request: *r, Username: username}
				c.Request = &ar.Request
				return
			}
		}
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
