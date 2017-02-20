package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/elgs/gostrgen"
	couch "github.com/fjl/go-couchdb"
	"github.com/juju/errors"
)

type magicTracker struct {
	LoginKey string
	Return   chan bool
}

var magicLogins = make(chan string)
var magicTrackerChan = make(chan magicTracker)

const magicTimeLimit = 5 * time.Minute

// keep track of new 2fa attempts and deal with link clicks
func trackMagic() {
	magicChannels := make(map[string]chan bool)
	for {
		select {
		case loginKey := <-magicLogins:
			// link has been clicked with a valid token
			loginChannel, ok := magicChannels[loginKey]
			if ok {
				loginChannel <- true
				close(loginChannel)
				delete(magicChannels, loginKey) // stop listening
			}
		case tracker := <-magicTrackerChan:
			// start listening for magic clicks for this loginKey
			oldChannel, ok := magicChannels[tracker.LoginKey]
			if ok {
				close(oldChannel)
			}
			magicChannels[tracker.LoginKey] = tracker.Return
		}
	}
}

func login2FA(loginKey, email, secretHash string, response http.ResponseWriter) {
	response.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	loginKeyBytes, err := hex.DecodeString(loginKey)
	if err != nil {
		log.Error(errors.Trace(err), loginKey)
		http.Error(response, "Problem decoding hex of loginKey", 401)
		return
	}
	secretHashBytes, err := hex.DecodeString(secretHash)
	if err != nil {
		log.Error(errors.Trace(err), secretHash)
		http.Error(response, "Problem decoding hex of secretHash", 401)
		return
	}
	secretDoubleHash := sha256.Sum256(secretHashBytes)
	emailHash := sha256.Sum256([]byte(email))
	checkLoginKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		checkLoginKey[i] = emailHash[i] ^ secretDoubleHash[i]
	}
	if !bytes.Equal(checkLoginKey, loginKeyBytes) {
		http.Error(response, "Problem verifying that email with that secretHash and the loginKey", 401)
		return
	}
	token, err := gostrgen.RandGen(10, gostrgen.LowerUpperDigit, "", "")
	if err != nil {
		log.Error(errors.Trace(err))
		http.Error(response, "Problem producing token", 401)
		return
	}
	updateFAToken(loginKey, token, response)
	clickSignal := make(chan bool, 1)
	magicTrackerChan <- magicTracker{loginKey, clickSignal} // listen for magic link clicks
	// build and send magic link
	link := loginAPIHost + factorEndpoint + "?&loginKey=" + loginKey + "&token=" + token
	log.Info(link)
	// uncomment to send emails with Amazon SES
	// body := fmt.Sprintf(factorEmailBody, link)
	// _, err = emailConfig.SendEmail(fromEmail, email, factorEmailSubject, body)
	// if err != nil {
	// 	log.Error(errors.Trace(err))
	// 	http.Error(response, "Problem sending email", 401)
	// 	return
	// }
	select {
	case _, ok := <-clickSignal:
		if !ok {
			// closed, ie another login attempt replaced us
			http.Error(response, "A login request was attempted elsewhere before magic link was clicked", 401)
			return
		}
		returnMnemonic(loginKey, response)
		return
	case <-time.After(magicTimeLimit):
		http.Error(response, "Did not click magic link in time window", 401)
		return
	}
}

func updateFAToken(loginKey, token string, response http.ResponseWriter) {
	var user loginData
	err := usersDB.Get(loginKey, &user, nil)
	if err != nil {
		if couch.NotFound(err) {
			http.Error(response, "Could not find user", 401)
			return
		}
		log.Error(errors.Trace(err), loginKey)
		http.Error(response, "Unknown error getting user", 401)
		return
	}
	user.LastToken = token
	_, err = usersDB.Put(loginKey, user, user.Rev)
	if err != nil {
		if couch.Conflict(err) {
			updateFAToken(loginKey, token, response)
			return
		}
		log.Error(errors.Trace(err), loginKey)
		http.Error(response, "Unknown error adding to users database", 401)
		return
	}

}

// does the user have 2FA enabled
func is2FA(user loginData) (bool, error) {
	signedBytes, err := hex.DecodeString(user.SignedTwoFA)
	if err != nil {
		log.Error(errors.Trace(err), user.ID)
		return false, errors.New("Problem decoding hex of SignedTwoFA")
	}
	// first 64 bytes are signature, 64 is 0 or 1
	if signedBytes[64] == byte(1) {
		return true, nil
	} else if signedBytes[64] == byte(0) {
		return false, nil
	}
	return false, errors.New("Unexpected byte in 2FA signature")
}

func twoFALink(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	request.ParseForm()
	loginKey := request.Form.Get("loginKey")
	token := request.Form.Get("token")
	if loginKey == "" || token == "" {
		http.Error(response, "You must pass (in formdata) a loginKey, token", 403)
		return
	}
	if !validateToken(loginKey, token) {
		http.Error(response, "That token and loginKey did not validate", 403)
		return
	}
	magicLogins <- loginKey
	return
}

func validateToken(loginKey, token string) bool {
	var user loginData
	err := usersDB.Get(loginKey, &user, nil)
	if err != nil {
		if couch.NotFound(err) {
			return false
		}
		log.Error(errors.Trace(err), loginKey)
		return false
	}
	if fa, _ := is2FA(user); !fa {
		return false
	}
	if user.LastToken == "" {
		return false
	}
	return token == user.LastToken
}
