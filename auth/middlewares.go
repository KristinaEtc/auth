package auth

import (
	dAuth "github.com/abbot/go-http-auth"
	webauth "tekinsoft/web"

	//"encoding/base64"
	//	"fmt"
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

		log.Debug(a.uri)
		log.Debug(a.verb)

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

		//TODO: add ipv6  support! (in chorme natively)
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

/*// A middleware that implement basic authorization
func BasicMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("BasicMiddleware")

		reqAuthParams := c.MustGet("a").(*authParams)

		if reqAuthParams.authType == "basic" {
			// basic auth
			log.Debugf("reqAuthParams.authType: %s", reqAuthParams.authType)
			reqAuthParams.basic_decoded = ""
			if strings.HasPrefix(reqAuthParams.hdrAuthorization, "Basic ") {
				buf, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(reqAuthParams.hdrAuthorization, "Basic "))
				reqAuthParams.basic_decoded = string(buf)
			}
			queryTitle := fmt.Sprintf("Auth:[%s][%s] URI:[%s] Addr:[%s] ClntIP:[%s] Verb:[%s]",
				reqAuthParams.hdrAuthorization,
				reqAuthParams.basic_decoded,
				reqAuthParams.uri,
				reqAuthParams.addr,
				c.ClientIP(),
				reqAuthParams.verb,
			)

			user := webauth.CheckUserBasicPassw(reqAuthParams.uri_lst, reqAuthParams.hdrAuthorization)
			log.Debugf("user %s", user)
			if user == "" && reqAuthParams.hdrAuthorization == "" {
				log.Debugf("Authorization Required %s", queryTitle)
				c.Header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
				c.String(401, "Authorization Required\r\n")
				c.Abort()
				return
			}
			if user == "" && reqAuthParams.hdrAuthorization != "" {
				log.Debugf("Authorization Required %s", queryTitle)
				c.Header("WWW-Authenticate", "Basic realm=\"Authorization Required\"")
				c.String(403, "Forbidden")
				c.Abort()
				return
			}
			log.Debugf("Authoruzed as user [%s] %s", user, queryTitle)
		} else {

			c.Next()
			return
		}
		//c.Abort()
	}
}*/

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
