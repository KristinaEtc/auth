package main

import (
	"fmt"
	auth "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
)

func Secret(user, realm string) string {
	if user == "john" {
		return "b98e16cbc3d01734b264adba7baa3bf9"
	}
	return ""
}

func DigestAuth(a *auth.DigestAuth) (result gin.HandlerFunc) {
	return func(c *gin.Context) {
		r := c.Request
		w := c.Writer

		if username, authinfo := a.CheckAuth(r); username == "" {
			a.RequireAuth(w, r)
			fmt.Println("sended")

		} else {
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
}

func main() {

	authenticator := auth.NewDigestAuthenticator("example.com", Secret)

	r := gin.New()

	r.Use(DigestAuth(authenticator))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
