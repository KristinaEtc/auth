package auth

import (
	"github.com/gin-gonic/gin"
	"net"
	"strings"
	webauth "tekinsoft/web"
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
	for _, item := range webauth.Configuration.AuthOptions {
		log.Debugf("%v+++\n", item.Ipnets)
	}
	return func(c *gin.Context) {
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
		log.Debugf("---------------ip: %s, /uri_list:  %v", a.ip.String(), a.uri_lst)
		if len(a.uri_lst) == 0 {
			log.Warnf("Forbidden network %s", a.queryTitle)
			c.JSON(403, gin.H{
				"message": "Forbidden network",
			})
			c.Abort()
			return
		}

		a.authType = webauth.GetAuthType(webauth.Configuration.AuthOptions, a.uri, a.verb)
		c.Next()
	}
}

func DigestMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("DigestMiddleware")
		a := c.MustGet("a").(*authParams)

		if a.authType == "digest" {
			log.Debug("got it! digest")
		} else {
			c.Next()
			return
		}
	}
}

func BasicMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("BasicMiddleware")

		a := c.MustGet("a").(*authParams)
		log.Debugf("a: %v\n", a)

		if a.authType == "basic" {
			log.Debug("got it! basic")
		} else {
			c.Next()
			return
		}

		//c.Abort()
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
