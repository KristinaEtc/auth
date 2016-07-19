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
			log.WithFields(slf.Fields{
				"func": "MultiAuthMiddleware()",
			}).Warnf("Error IP conversion from %s", c.ClientIP())
		}
		c.Set("a", a)
		log.Debugf("MultiAuthMiddleware: %v\n", a)

		// check if client has access for such uri (in configuration repository: file, DB, map of struct, etc...)
		a.uri_lst = getUriPatterns(Configuration.AuthOptions, a.uri, a.verb)
		if len(a.uri_lst) == 0 {
			log.WithFields(slf.Fields{
				"func": "MultiAuthMiddleware()",
			}).Warnf("URI pattern not found [%s]", a.queryTitle)

			//c.String(403, "No route")
			c.JSON(403, gin.H{
				"message": "No route",
			})
			c.Abort()
			return
		}

		//TODO: add ipv6 support! (in Chrome natively)
		//check if client's network is enabled in founded patterns
		a.uri_lst = getNetworkIsEnabled(a.uri_lst, a.ip)
		if len(a.uri_lst) == 0 {
			log.WithFields(slf.Fields{"func": "MultiAuthMiddleware()"}).Warnf("Forbidden network %s", a.queryTitle)
			c.JSON(403, gin.H{
				"message": "Forbidden network",
			})
			c.Abort()
			return
		}

		// check authentication for a client
		a.authType = getAuthType(Configuration.AuthOptions, a.uri, a.verb)
		c.Next()
	}
}

// A middleware that implement digest authorization
func DigestAuthMiddleware() (result gin.HandlerFunc) {

	defer log.WithFields(slf.Fields{"func": "DigestAuthMiddleware"})

	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		//get request parametrs
		reqAuthParams := c.MustGet("a").(*authParams)
		if reqAuthParams.authType == "digest" {

			//check if user was registered
			if username, authinfo := dAuthenticator.CheckAuth(r); username == "" {
				dAuthenticator.RequireAuth(w, r)
				log.WithFields(slf.Fields{"func": "DigestAuthMiddleware()"}).Debug("Authorization required")
				c.Abort()
				return
			} else {
				// if he didn't - setting a header with digest request
				ar := &dAuth.AuthenticatedRequest{Request: *r, Username: username}
				if authinfo != nil {
					w.Header().Set("Authentication-Info", *authinfo)
					//c.Next()
				}
				log.WithFields(slf.Fields{
					"func": "DigestAuthMiddleware()",
				}).Debugf("User %s has been logged", username)
				c.Request = &ar.Request
				return
			}
		} else {
			return
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
			log.Debug("ee")

			if username := bAuthenticator.CheckAuth(r); username == "" {
				bAuthenticator.RequireAuth(w, r)
				log.WithFields(slf.Fields{"func": "BasicAuthMiddleware()"}).Debug("Authorization required")
				c.Abort()
			} else {
				log.WithFields(slf.Fields{
					"func": "BasicAuthMiddleware()",
				}).Debugf("Authorization Required %s", reqAuthParams.queryTitle)

				ar := &dAuth.AuthenticatedRequest{Request: *r, Username: username}
				c.Request = &ar.Request
				log.WithFields(slf.Fields{
					"func": "BasicAuthMiddleware()",
				}).Debugf("User %s has been logged", username)
				return
			}

		} else {
			return
		}
	}
}

func TrustMiddleware() gin.HandlerFunc {

	defer log.WithFields(slf.Fields{"func": "Trust Auth"})

	return func(c *gin.Context) {
		reqAuthParams := c.MustGet("a").(*authParams)
		if reqAuthParams.authType == "trust" {
			c.Next()
		} else {
			return
		}
	}
}

func MiddlewareSecond() gin.HandlerFunc {
	return func(c *gin.Context) {
		log.Debug("Test Middleware Second")
	}
}

//Parse IP addr in CIDR format (addr/bits)
func splitNetAddrV4(addr string) (ipnet *net.IPNet, err error) {
	if addr == "*" || addr == "" {
		addr = "0.0.0.0/32"
	}
	if !strings.Contains(addr, "/") {
		addr += "/32"
	}
	_, ipnet, err = net.ParseCIDR(addr)
	return
}

//Convert string network list to list in IPnet format
func parseNetworkList(acllist string) ([]net.IPNet, error) {
	var ipnets []net.IPNet
	acllist = strings.Replace(acllist, ",", " ", -1)
	acllist = strings.Replace(acllist, ";", " ", -1)
	acl_fields := strings.Fields(acllist)
	for _, field := range acl_fields {
		ipnet, err := splitNetAddrV4(field)
		if err != nil {
			return nil, err
		}
		ipnets = append(ipnets, *ipnet)
	}
	for _, value := range ipnets {
		log.Debugf("\n%s", value.String())
	}
	return ipnets, nil
}

//Check if IP addr in string in network range
/*func IsNetworkContainsAddr4(ip_s string, ipnet *IPNet) bool {
	ip := ParseIP(ip_s)
	return ipnet.Contains(ip)
}*/
