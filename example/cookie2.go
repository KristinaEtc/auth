/*package main

import (
	"github.com/gin-gonic/contrib/sessions"
	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()
	store := sessions.NewCookieStore([]byte("secret"))
	r.Use(sessions.Sessions("mysession", store))

	r.GET("/incr", func(c *gin.Context) {
		session := sessions.Default(c)
		var count int
		v := session.Get("count")
		if v == nil {
			count = 0
		} else {
			count = v.(int)
			count += 1
		}
		session.Set("count", count)
		session.Save()
		c.JSON(200, gin.H{"count": count})
	})
	r.Run(":8000")
}
*/

package main

import (
	"fmt"
	"github.com/gin-gonic/contrib/sessions"
	gin "github.com/gin-gonic/gin"
)

func loginHandler(c *gin.Context) {
	request := c.Request
	name := request.FormValue("name")
	pass := request.FormValue("password")

	if name != "" && pass != "" {
		fmt.Println(name, pass)
		session := sessions.Default(c)
		session.Set("name", name)
		session.Save()
		c.JSON(200, gin.H{"name": name})

	}
}

func indexPageHandler(c *gin.Context) {

	c.HTML(200, "index3.html", nil)

}

//func internalPageHandler(response http.ResponseWriter, request *http.Request) {
func internalPageHandler(c *gin.Context) {

	session := sessions.Default(c)
	userName := session.Get("name")

	if userName != "" {
		//fmt.Fprintf(response, internalPage, userName)
		fmt.Println(userName)
	} else {
		fmt.Println("FUCK")
		//http.Redirect(response, request, "/", 302)
	}
}

func main() {

	store := sessions.NewCookieStore([]byte("authStore"))

	router := gin.Default()
	router.Use(gin.Logger())
	router.LoadHTMLGlob("templates/*.html")
	router.Use(sessions.Sessions("Authorization", store))

	router.GET("/", indexPageHandler)
	router.GET("/internal", internalPageHandler)

	router.POST("/login", loginHandler)
	//	router.POST("/logout", logoutHandler)

	router.Run(":8000")
}
