package auth

import (
	"crypto/md5"
	"encoding/hex"
	dAuth "github.com/abbot/go-http-auth"
	"net"
)

// A function that search digest user information
// and send it to digest auth middleware
func getDigestHash(user, realm string) string {
	for _, userInfo := range Configuration.UserAccounts {
		if userInfo.User == user {
			return getMd5(user + ":" + realm + ":" + userInfo.Pass)
		}
	}
	return ""
}

func getMd5(s string) string {
	h := md5.New()
	h.Write([]byte(s))
	return hex.EncodeToString(h.Sum(nil))
}

// MD5Hash for password with basic authorization
func getCrypt(password string) string {
	md5 := string(dAuth.MD5Crypt([]byte(password), []byte(""), []byte("$$")))
	return md5
}

// A function that search basic user information
// and send it to basic auth middleware
func getBasicHash(user, realm string) string {
	for _, userInfo := range Configuration.UserAccounts {
		if userInfo.User == user {
			// Now configfile stored pure password;
			// it's easier to testing a program
			return getCrypt(userInfo.Pass)
		}
	}
	return ""
}

func checkPwdCorrect(user, pwd string) bool {
	for _, userInfo := range Configuration.UserAccounts {
		if userInfo.User == user {
			if userInfo.Pass == pwd {
				return true
			}
			// Now configfile stored pure password;
			// it's easier to testing a program
		}
	}
	return false
}

//find in auth options list by pattern URI and VERB
func getUriPatterns(lst []*AuthOptionItem, uri string, verb string) (res []*AuthOptionItem) {

	for _, item := range lst {
		//log.Debugf("getUriPatterns/item.URI=%s/item.Verb=%s", item.URI, item.Verb)
		if (item.URI == uri || item.URI == "*") && (item.Verb == verb || item.Verb == "*") {
			//log.Debugf("getUriPatterns/got it/item.URI=%s/item.Verb=%s", item.URI, item.Verb)
			res = append(res, item)
		}
	}
	return
}

func getAuthType(lst []*AuthOptionItem, uri string, verb string) (res string) {
	for _, item := range lst {
		//log.Debugf("getAuthType/item.URI=%s/item.Verb=%s", item.URI, item.Verb)
		if (item.URI == uri || item.URI == "*") && (item.Verb == verb || item.Verb == "*") {
			//log.Debugf("getAuthType/got it/item.URI=%s/item.Verb=%s", item.URI, item.Verb)
			return item.Auth
		}
	}
	// default - basic
	return "basic"
}

//compare clients addr and internal ACL list. Return true in one of networks contains IP
func getNetworkIsEnabled(lst []*AuthOptionItem, ip net.IP) (res []*AuthOptionItem) {
	//log.Debugf("getNetworkIsEnabled:ip.String()=%s", ip.String())
	for _, item := range lst {
		for _, ipnet := range item.Ipnets {
			//log.Debugf("ipnet.String()=%s", ipnet.String())
			if ipnet.Contains(ip) {

				res = append(res, item)
			}
		}
	}
	return
}

//return true it one of item in list configured with "trust" params
func checkTrust(lst []*AuthOptionItem) bool {
	for _, item := range lst {
		if item.Auth == "trust" {
			return true
		}
	}
	return false
}

//check if this user joined to any Auth options from list by groups
func checkAuthOptionsListContainsUser(lst []*AuthOptionItem, user *UserAccountItem) bool {
	for _, item := range lst {
		for _, uitem := range item.users {
			if uitem == user {
				return true
			}
		}
	}
	return false
}
