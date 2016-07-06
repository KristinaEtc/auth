package auth

import "net"

// A function that search digest user information
// and send it to digest auth middleware
func GetDigestHash(user, realm string) string {
	for _, userInfo := range Configuration.UserAccounts {
		if userInfo.User == user {
			return userInfo.DigestHash
		}
	}
	return ""
}

// A function that search basic user information
// and send it to basic auth middleware
func GetBasicHash(user, realm string) string {
	for _, userInfo := range Configuration.UserAccounts {
		if userInfo.User == user {
			return userInfo.Pass
		}
	}
	return ""
}

//find in auth options list by pattern URI and VERB
func GetUriPatterns(lst []*AuthOptionItem, uri string, verb string) (res []*AuthOptionItem) {

	for _, item := range lst {
		log.Debugf("%s/%s/\n", item.URI, item.Verb)
		if (item.URI == uri || item.URI == "*") && (item.Verb == verb || item.Verb == "*") {
			log.Debugf("yes/%s/%s/\n", item.URI, item.Verb)
			res = append(res, item)
		}
	}
	return
}

func GetAuthType(lst []*AuthOptionItem, uri string, verb string) (res string) {
	for _, item := range lst {
		log.Debugf("%s/%s/\n", item.URI, item.Verb)
		if (item.URI == uri || item.URI == "*") && (item.Verb == verb || item.Verb == "*") {
			log.Debugf("gg/%s/%s/\n", item.URI, item.Verb)
			return item.Auth
		}
	}
	// default - basic
	return "basic"
}

//compare clients addr and internal ACL list. Return true in one of networks contains IP
func GetNetworkIsEnabled(lst []*AuthOptionItem, ip net.IP) (res []*AuthOptionItem) {
	log.Debugf("\n---%s\n", ip.String())
	for _, item := range lst {
		for _, ipnet := range item.Ipnets {

			log.Debugf("\n777%s\n", ipnet.String())
			if ipnet.Contains(ip) {

				res = append(res, item)
			}
		}
	}
	return
}

//return true it one of item in list configured with "trust" params
func CheckTrust(lst []*AuthOptionItem) bool {
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
