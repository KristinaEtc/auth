package auth

import (
	authD "github.com/abbot/go-http-auth"
	. "github.com/ahmetalpbalkan/go-linq"
	"github.com/ventu-io/slf"

	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"strings"
)

var Configuration WebAuthConfig = WebAuthConfig{}

var (
	dAuthenticator *authD.DigestAuth
	bAuthenticator *authD.BasicAuth
)

//AuthOption, one item configuration (json)
type AuthOptionItem struct {
	Verb     string //GET, POST... *
	URI      string //path /,*,...
	Auth     string //basic, trust
	Groups   string //user groups valid for access
	Networks string //ACL networks in CIDR format or *
	//internal field for interpreted data
	Ipnets []net.IPNet        // ACL networks CIDR, interpreted
	users  []*UserAccountItem //users,  joined by groups
}

//user-password-group structures (json)
type UserAccountItem struct {
	User       string //login
	Pass       string //password
	Groups     string //groups (joined with AuthOption
	DigestHash string
	//internal fields
	base64value string //base64 interpreted login and passord, for basic auth
}

//Common config structure (json-based and automatic interpreted)
type WebAuthConfig struct {
	UserAccounts []*UserAccountItem
	AuthOptions  []*AuthOptionItem
	BindingAddr  string //format IP:PORT
}

//Load appropriate json configuration into Config structure. Parse and prepare some fields
func ConfigureFromFile(configFile string) WebAuthConfig {
	log = slf.WithContext(pwdCurr)

	log.Debugf("Configure with config file %s", configFile)

	dAuthenticator = authD.NewDigestAuthenticator("Authorization", getDigestHash)
	bAuthenticator = authD.NewBasicAuthenticator("Authorization", getBasicHash)

	if _, err := os.Stat(configFile); os.IsNotExist(err) {
		log.Error("WebAuth config file not exists - use default")
		return Configuration
	}
	//Open config file
	file, err := os.Open(configFile)
	if err != nil {
		log.Panicf("Error load WebAuth config file: [%s]  %s", configFile, err)
	}
	//JSON parse
	decoder := json.NewDecoder(file)
	if err = decoder.Decode(&Configuration); err != nil {
		log.Panicf("Unable interpret config file: %s", err.Error())
	}
	//Interpret network lists
	for idx, item := range Configuration.AuthOptions {
		item.Ipnets, err = parseNetworkList(item.Networks)
		if err != nil {
			log.Panicf("Unable interpret networks line %d  %s  %s", idx, item.Networks, err.Error())
		}
	}

	/*for _, item := range Configuration.AuthOptions {
		log.Debugf("Configuration.AuthOption: Ipnets-%v-", item.Ipnets)
	}*/

	//Interpret user accounts, build base64 of account:passw pairs for basic auth
	for _, v := range Configuration.UserAccounts {
		base := v.User + ":" + v.Pass
		v.base64value = "Basic " + base64.StdEncoding.EncodeToString([]byte(base))
	}
	//Interpret access list and join users by group parameter
	for idx, authItem := range Configuration.AuthOptions {
		log.Debugf("Pass Auth item %d [%s %s]", idx, authItem.URI, authItem.Groups)
		authItem.Groups = strings.Replace(authItem.Groups, ",", " ", -1)
		authItem.Groups = strings.Replace(authItem.Groups, ";", " ", -1)
		aGroups := strings.Fields(authItem.Groups)
		for _, user := range Configuration.UserAccounts {
			if authItem.Groups == "*" {
				authItem.users = append(authItem.users, user)
				log.Debugf("ADD USER [%s] to [%d] by group *", user.User, idx)
				continue
			}
			user.Groups = strings.Replace(user.Groups, ",", " ", -1)
			user.Groups = strings.Replace(user.Groups, ";", " ", -1)
			uGroups := strings.Fields(user.Groups)
			for _, ugrp := range uGroups {
				if sliceContains(aGroups, ugrp) && !sliceContains(authItem.users, user) {
					authItem.users = append(authItem.users, user)
					log.Debugf("ADD USER [%s] to [%d] by group [%s]", user.User, idx, ugrp)
				}
			}
		}
	}
	//output info
	log.Infof("Binding addr %s", Configuration.BindingAddr)
	log.Debugf("%d BasicAccounts items: %v", len(Configuration.UserAccounts), Configuration.UserAccounts)
	log.Debugf("%d AuthOptions items: %v", len(Configuration.AuthOptions), Configuration.AuthOptions)
	return Configuration
}

//check if item in slice. Based on linq
func sliceContains(lst T, item T) bool {
	res, _ := From(lst).Where(func(a T) (bool, error) {
		return item == a, nil
	}).Any()
	return res
}
