package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/agl/ed25519"
	couch "github.com/fjl/go-couchdb"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/juju/errors"
	mh "github.com/multiformats/go-multihash"
	"github.com/op/go-logging"
	ses "github.com/sourcegraph/go-ses"
)

var router = mux.NewRouter()

var log = logging.MustGetLogger("outbox")

var couchClient *couch.Client
var usersDB *couch.DB

const factorEmailSubject = "2FA Login Request"
const factorEmailBody = `Someone has requested a 2FA Login with your account.
To log in, click the following link:
%s`
const loginAPIHost = "http://yourhostname.com"
const factorEndpoint = "/factor"
const fromEmail = "noreply@yourhostname.com"

var emailConfig ses.Config

// stored in users db to handle login challenges
type loginData struct {
	ID                string `json:"_id"`
	Rev               string `json:"_rev,omitempty"`
	SignedTwoFA       string `json:"signedTwoFA"`
	LastChallenge     int64  `json:"lastChallenge"`
	PublicSKey        string `json:"publicKey"`
	EncryptedMnemonic string `json:"encryptedMnemonic"`
	MNonce            string `json:"mNonce"`
	LastToken         string `json:"lastToken,omitempty"`
}

type mnemonicReturn struct {
	EncryptedMnemonic string `json:"encryptedMnemonic"`
	MNonce            string `json:"mnemonicNonce"`
}

// all of these values are file paths
type config struct {
	Cert               string
	Key                string
	CouchURL           string
	SESEndpoint        string
	SESAccessKeyID     string
	SESSecretAccessKey string
}

func main() {
	var err error
	configFile := flag.String("c", "config.toml", "Path to the config toml file")
	flag.Parse()
	var conf config
	if _, err = toml.DecodeFile(*configFile, &conf); err != nil {
		log.Error(err)
		os.Exit(1)
	}

	emailConfig = ses.Config{
		Endpoint:        conf.SESEndpoint,
		AccessKeyID:     conf.SESAccessKeyID,
		SecretAccessKey: conf.SESSecretAccessKey,
	}
	couchClient, err = couch.NewClient(conf.CouchURL, nil)
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	usersDB, err = couchClient.EnsureDB("users")
	if err != nil {
		log.Error(err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go deleteLastChallenges(ctx) // remove users last used challenges
	go trackMagic()              // handles 2FA magic links

	router.HandleFunc(factorEndpoint, twoFALink).Methods("GET")
	router.HandleFunc("/login", login).Methods("POST")
	router.HandleFunc("/register", register).Methods("POST")
	cors := handlers.CORS(
		handlers.AllowedOrigins([]string{"*"}),
		handlers.AllowedHeaders([]string{
			"content-type", "origin", "referer",
		}))(router)
	srv := &http.Server{
		Addr:    ":4000",
		Handler: cors,
		// prevent very slow connection attacks
		ReadTimeout: 5 * time.Second,
		// do not set a writetimeout as 2FA logins can take minutes
	}
	err = srv.ListenAndServe()
	// replace with below to use HTTPS
	// err = srv.ListenAndServeTLS(conf.Cert, conf.Key)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

var errUserNotFound = errors.New("That user isn't present in our database")
var errChallengeSig = errors.New("Challenge signature could not be verified")
var errChallengeUsed = errors.New("You have already used a challenge more recent than that")
var errTimeWindow error

func validateHashes(hashes ...string) error {
	// hashes are all 32 bytes
	var badHashes []string
	for _, hash := range hashes {
		if len(hash) != 64 {
			badHashes = append(badHashes, hash)
		}
	}
	if len(badHashes) > 0 {
		return fmt.Errorf("Hashes are of wrong length: %s", strings.Join(badHashes, ", "))
	}
	return nil
}

func login(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	var r map[string]string
	if request.Body == nil {
		http.Error(response, "Please send a request body", 400)
		return
	}
	err := json.NewDecoder(request.Body).Decode(&r)
	if err != nil {
		http.Error(response, "Request body could not be decoded into valid json with string keys and values", 403)
		return
	}

	loginKey, ok0 := r["loginKey"]
	signedChallenge, ok1 := r["signedChallenge"]
	if !(ok0 && ok1) {
		http.Error(response, "You must pass (in JSON) a loginKey, signedChallenge", 403)
		return
	}
	if err = validateHashes(loginKey); err != nil {
		http.Error(response, err.Error(), 401)
		return
	}
	signedChallengeBytes, err := hex.DecodeString(signedChallenge)
	if err != nil {
		http.Error(response, fmt.Sprintf("Malformed challenge signature; not hex: %s", signedChallenge), 401)
		return
	}
	if err = validateChallenge(signedChallengeBytes); err != nil {
		if err == errTimeWindow {
			ret := map[string]string{
				"error":      "Challenge outside of server time range",
				"serverTime": strconv.FormatInt(time.Now().UnixNano(), 10),
			}
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("X-Content-Type-Options", "nosniff")
			response.WriteHeader(401) // error 401
			err = json.NewEncoder(response).Encode(ret)
			if err != nil {
				log.Error(errors.Trace(err), loginKey)
			}
			return
		}
		http.Error(response, err.Error(), 401)
		return
	}

	verified, err := verifyChallenge(loginKey, signedChallengeBytes)
	if err != nil {
		http.Error(response, err.Error(), 401)
		return
	}
	if !verified {
		http.Error(response, "Unknown auth error", 401)
		return
	}
	var user loginData
	err = usersDB.Get(loginKey, &user, nil)
	if err != nil {
		if couch.NotFound(err) {
			http.Error(response, errUserNotFound.Error(), 401)
			return
		}
		log.Error(errors.Trace(err), loginKey)
		http.Error(response, "Unknown error getting user", 401)
		return
	}
	fa, err := is2FA(user)
	if err != nil {
		http.Error(response, err.Error(), 401)
		return
	}
	if fa {
		email, ok0 := r["email"]
		secretHash, ok1 := r["secretHash"]
		if !(ok0 && ok1) {
			response.WriteHeader(http.StatusUnauthorized)
			ret := map[string]string{
				"error":       "You must provide an email and secretHash in JSON, as 2FA is enabled",
				"signedTwoFA": user.SignedTwoFA,
			}
			response.Header().Set("Content-Type", "application/json")
			response.Header().Set("X-Content-Type-Options", "nosniff")
			err = json.NewEncoder(response).Encode(ret)
			if err != nil {
				log.Error(errors.Trace(err), loginKey)
			}
			return
		}
		login2FA(loginKey, email, secretHash, response)
		return
	}
	returnMnemonic(loginKey, response)
	return
}

func returnMnemonic(loginKey string, response http.ResponseWriter) {
	encryptedMnemonic, mNonce, err := getUserMnemonic(loginKey)
	if err != nil {
		http.Error(response, err.Error(), 401)
		return
	}

	ret := mnemonicReturn{}
	ret.EncryptedMnemonic = encryptedMnemonic
	ret.MNonce = mNonce
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	err = json.NewEncoder(response).Encode(ret)
	if err != nil {
		log.Error(errors.Trace(err), loginKey)
		return
	}
}

func getUserMnemonic(loginKey string) (string, string, error) {
	var user loginData
	err := usersDB.Get(loginKey, &user, nil)
	if err != nil {
		if couch.NotFound(err) {
			return "", "", errUserNotFound
		}
		log.Error(errors.Trace(err), loginKey)
		return "", "", errors.New("Unknown error getting user mnemonic")
	}
	return user.EncryptedMnemonic, user.MNonce, nil
}

// Produce a deterministic revision number from the plaintext, 1-2^16, and a hash
// After compaction, the number of revisions for a doc is now masked on the server
// Input should be the document
func randomRev(doc interface{}) string {
	encoded, err := json.Marshal(doc)
	if err != nil {
		log.Error(errors.Trace(err))
		return ""
	}
	multihash, err := mh.Sum(append([]byte("revsalt"), encoded...), mh.SHA1, 16)
	if err != nil {
		log.Error(errors.Trace(err))
		return ""
	}
	revNum := binary.BigEndian.Uint16(multihash[15:17]) // two bytes ie 0-2^16
	return strconv.Itoa(int(revNum)) + "-" + multihash.HexString()[4:]
}

func validateTwoFA(signedTwoFA, publicSKey string) error {
	twoFABytes, err := hex.DecodeString(signedTwoFA)
	if err != nil {
		log.Error(errors.Trace(err), signedTwoFA)
		return errors.New("Problem decoding hex of signedTwoFA")
	}
	if len(twoFABytes) != 65 {
		return errors.New("signedTwoFA is of wrong length")
	}
	pubBytes, err := hex.DecodeString(publicSKey)
	if err != nil {
		log.Error(errors.Trace(err), publicSKey)
		return errors.New("Problem decoding hex of PublicSKey")
	}

	var pubByteArray [32]byte
	var sigByteArray [64]byte
	copy(pubByteArray[:], pubBytes[:])
	copy(sigByteArray[:], twoFABytes[:])
	if !ed25519.Verify(&pubByteArray, twoFABytes[64:], &sigByteArray) {
		return errors.New("TwoFA signature is invalid")
	}
	if !(twoFABytes[64] == byte(1) || twoFABytes[64] == byte(0)) {
		return errors.New("TwoFA signed byte is neither 1 nor 0")
	}
	return nil
}

func register(response http.ResponseWriter, request *http.Request) {
	response.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	var r map[string]string
	if request.Body == nil {
		http.Error(response, "Please send a request body", 400)
		return
	}
	err := json.NewDecoder(request.Body).Decode(&r)
	if err != nil {
		http.Error(response, "Request body could not be decoded into valid json with string keys and values", 403)
		return
	}
	loginKey, ok0 := r["loginKey"]
	mnemonicHash, ok1 := r["mnemonicHash"]
	publicSKey, ok2 := r["secretPublicSigningKey"]
	encryptedMnemonic, ok3 := r["encryptedMnemonic"]
	mNonce, ok4 := r["mNonce"]
	signedTwoFA, ok5 := r["signedTwoFA"]
	if !(ok0 && ok1 && ok2 && ok3 && ok4 && ok5) {
		http.Error(response, "You must pass (in JSON) a loginKey, mnemonicHash, secretPublicSigningKey, encryptedMnemonic, mNonce, signedTwoFA variable", 403)
		return
	}
	if err = validateHashes(loginKey, mnemonicHash, publicSKey); err != nil {
		http.Error(response, err.Error(), 401)
		return
	}
	if err = validateTwoFA(signedTwoFA, publicSKey); err != nil {
		http.Error(response, err.Error(), 401)
		return
	}
	// encrypted mnemonic is always 32 bytes
	if len(encryptedMnemonic) != 64 {
		http.Error(response, "Encrypted mnemonic is not the valid size", 403)
		return
	}
	_, _, err = getUserMnemonic(loginKey)
	if err == nil {
		http.Error(response, "User already exists in users database", 409)
		return
	}
	user := loginData{}
	user.ID = loginKey
	user.SignedTwoFA = signedTwoFA
	user.LastChallenge = 0
	user.PublicSKey = publicSKey
	user.EncryptedMnemonic = encryptedMnemonic
	user.MNonce = mNonce
	userRev := randomRev(user)
	user.Rev = userRev
	_, err = usersDB.Put(user.ID, user, userRev)
	if err != nil {
		if couch.Conflict(err) {
			http.Error(response, "Error putting document - already exists in users database", 409)
			return
		}
		log.Error(errors.Trace(err), loginKey)
		http.Error(response, "Unknown error adding to users database", 401)
		return
	}

	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	ret := map[string]bool{"Success": true}
	err = json.NewEncoder(response).Encode(ret)
	if err != nil {
		log.Error(errors.Trace(err), loginKey)
		return
	}
}
