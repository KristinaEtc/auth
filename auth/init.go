package auth

import (
	"github.com/ventu-io/slf"
)

const pwdCurr string = "github.com/KristinaEtc/auth"

var log slf.StructuredLogger

func init() {
	log = slf.WithContext(pwdCurr)
}
