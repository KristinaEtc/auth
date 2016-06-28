package main

import (
	"flag"
	mAuth "github.com/KristinaEtc/auth/auth"
	"github.com/KristinaEtc/slflog"
	auth "github.com/abbot/go-http-auth"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
)

/*func Secret(user, realm string) string {
	if userData, userExists := mAuth.FindUser(user); userExists {
		return userData.DigestHash
	}
}*/

var (
	helpFlag       = flag.Bool("help", false, "Show this help text")
	configAuthFile = flag.String("userpwd", "webauth.json", "configfile with logins and passwords")
	logPath        = flag.String("logpath", "/home/k/work/go/src/github.com/KristinaEtc/auth/logs", "path to logfiles")
	logLevel       = flag.String("loglevel", "DEBUG", "INFO, DEBUG, ERROR, WARN, PANIC, FATAL - loglevel for stderr")
)

func main() {

	flag.Parse()

	slflog.InitLoggers(*logPath, *logLevel)
	// TODO: add Close method!!
	log := slf.WithContext("main.go")

	uData := mAuth.InitCustomUserData(*configAuthFile)

	authenticator := auth.NewDigestAuthenticator("Authentication", func(user, realm string) string {
		if userData, userExists := uData.FindUser(user); userExists {
			return userData.DigestHash
		}
		return ""
	})
	log.Debug("starting working")

	r := gin.New()

	r.Use(mAuth.DigestAuth(authenticator))
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{
			"message": "pong",
		})
	})

	// Listen and server on 0.0.0.0:8080
	r.Run(":8080")
}
