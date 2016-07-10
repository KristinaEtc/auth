# auth
Authentication module for [gin-gonic](https://github.com/gin-gonic) web framework<br/ >

Testing on: Ubuntu 14.04.4 LTS<br/ >
Programming language: Golang: go1.5.2 linux/amd64<br/ >

* Authorization depends on url-prefix, client address and request header, as specified in webconfig file<br/ >
* Authentications: http basic, http digest, windows NTLM, trust, forms/cookie<br/ >
* Uses a list of users from different repositories (configfile/DB), configured in main.go. For example:
```golang
webauth.ConfigureFromFile("./webauth.json")
```

### run a program
```
go build main.go 
./main
```
Warning: the [log library](https://github.com/KristinaEtc/slflog) used in this module creates logs in the directory from where executable is run ; it is not recommended to use `go run` therefore.


