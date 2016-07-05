# auth
Authentication module<br/ >

Testing on: Ubuntu 14.04.4 LTS<br/ >
Programming language: Golang: go1.5.2 linux/amd64<br/ >
Web-framework: [gin-gonic] (https://github.com/gin-gonic)<br/ >
 
* Using authorization depends on url-prefix, client address and request header, that indicated in webconfig file<br/ >
* Authentications: http basic, http digest, windows NTLM, trust, forms/cookie<br/ >
* Implemented the ability to pass a list of users from different repositories (configfile/DB): it setting in main.go. For example:
```golang
webauth.ConfigureFromFile("./webauth.json")
```

### run a program
```
go build main.go 
./main
```
Warning: in this module [log library](https://github.com/KristinaEtc/slflog) creates a log directory where exec file is situated; it is not recommended to use `go run`.


