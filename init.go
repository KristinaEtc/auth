package auth

import (
	"github.com/gin-gonic/contrib/sessions"
	gin "github.com/gin-gonic/gin"
	"github.com/ventu-io/slf"
)

const pwdCurr string = "github.com/KristinaEtc/auth"

var log slf.StructuredLogger

func init() {
	log = slf.WithContext(pwdCurr)
}

// InitAuthMiddlewares is a function for init middlewares
func InitAuthMiddlewares(r **gin.Engine, g **gin.RouterGroup, pageAfterLogin string) {

	//(*r).LoadHTMLGlob("templates/*.html")
	(*r).Static("/static", "static")

	store := sessions.NewCookieStore([]byte("authStore"))
	(*r).Use(sessions.Sessions("Authorization", store))
	(*g).Use(sessions.Sessions("Authorization", store))

	(*g).Use(MultiAuthMiddleware(),
		TrustMiddleware(),
		BasicAuthMiddleware(),
		DigestAuthMiddleware(),
		CookieMiddleware(),
	)

	//	(*r).GET("/", loginRoute(pageAfterLogin))
	(*r).POST("/login", loginRoute(pageAfterLogin))
}
