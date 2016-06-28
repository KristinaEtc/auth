package auth

import (
	//"buf"
	"bytes"
	//"bufio"
	"encoding/json"
	"github.com/ventu-io/slf"
	"io"
	"os"
	"sync"
)

var log slf.StructuredLogger
var once sync.Once

func initLogger() {
	once.Do(func() {
		//GetStorage
		log = slf.WithContext(pwdCurr)
	})
	return
}

//--------------------------------
//  Factory for user/pwd storage
//--------------------------------
type UserRepository interface {
	FindUser(string) (*UserData, bool)
}

type UserData struct {
	Login      string `json:Login`
	Passcode   string `json:Passcode`
	DigestHash string `json:DigestHash`
}

//--------------------------------
// Confing File Storage
//--------------------------------

type FileRepository struct {
	userData map[string]UserData
}

func InitCustomUserData(configFile string) UserRepository {
	initLogger()

	fRep := &FileRepository{}
	fRep.initFileRepository(configFile)
	return fRep
}

func (f *FileRepository) initFileRepository(configFile string) UserRepository {

	log.Debugf("initFileRepository %s", configFile)

	buf := bytes.NewBuffer(nil)

	fp, err := os.Open(configFile)
	if err != nil {
		log.Errorf("Could not read data from configureAuthFile: %s ", err.Error())
	}
	defer fp.Close()

	_, err = io.Copy(buf, fp)
	if err != nil {
		log.Errorf("Could not process data from configureAuthFile: %s ", err.Error())
	}

	authDataJSON := buf.Bytes()
	authData := make([]UserData, 0)

	err = json.Unmarshal(authDataJSON, &authData)
	if err != nil {
		log.Errorf("Couldn't get auth params from configureAuthFile: %s", err.Error())
	}

	dataMap := make(map[string]UserData)
	for _, userAuth := range authData {
		if len(dataMap) != 0 {
			if _, userExist := dataMap[userAuth.Login]; userExist {
				log.Warn("User already exists in database; ignored")
				continue
			}
		}
		dataMap[userAuth.Login] = userAuth
	}
	f.userData = dataMap
	log.Debugf("%v", f.userData)

	return f
}

func (f *FileRepository) FindUser(login string) (*UserData, bool) {
	if login == "" {
		log.Warn("Empty user login")
		return nil, false
	}
	if pwd, ok := f.userData[login]; ok {
		return &pwd, true
	}
	log.WithFields(slf.Fields{"login": "DigestAuth"}).Warn("User with login not found")
	return nil, false
}
