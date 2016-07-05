package main

import _ "github.com/KristinaEtc/slflog"

import (
	//"fmt"
	auth "github.com/KristinaEtc/auth/auth"
	authD "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
	webauth "tekinsoft/web"
)

func Secret(user, realm string) string {
	if user == "john" {
		return "b98e16cbc3d01734b264adba7baa3bf9"
	}
	return ""
}

/*func DigestAuth(a *auth.DigestAuth) (result gin.HandlerFunc) {
	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		if username, authinfo := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
			fmt.Println("sended")

		} else {
			//fmt.Fprintln(c.Writer, "helloooo")
			ar := &auth.AuthenticatedRequest{Request: *r, Username: username}
			if authinfo != nil {
				fmt.Println("check")
				w.Header().Set("Authentication-Info", *authinfo)
				//c.Next()
			}
			c.Request = &ar.Request
			return
		}
	}
}*/

func main() {

	log := slf.WithContext("stomp-client.go")
	log.Info("test")

	authenticator := authD.NewDigestAuthenticator("example.com", Secret)
	webauth.ConfigureFromFile("./webauth.json")
	r := gin.New()

	r.Use(auth.MultiAuthMiddleware(),
		auth.BasicMiddleware(),
		auth.DigestAuth(authenticator),
		auth.MiddlewareSecond(),
	)

	r.GET("/status", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
