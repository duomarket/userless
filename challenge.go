package main

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/agl/ed25519"
	couch "github.com/fjl/go-couchdb"
	"github.com/juju/errors"
	"golang.org/x/time/rate"
)

type alldocsResult struct {
	Rows []map[string]interface{}
}

// attempt to loop through users and delete last challenges
// no error handling here as it is not mission critical
// conflicts etc are fine, just move on to the next user
func deleteLastChallenges(ctx context.Context) {
	limit := rate.NewLimiter(rate.Every(time.Second), 2)
	var result alldocsResult
	for limit.Wait(ctx) == nil { // ends on context close
		usersDB.AllDocs(&result, couch.Options{"include_docs": true})
		for _, row := range result.Rows {
			docInterface, ok := row["doc"]
			if !ok {
				continue
			}
			doc, ok := docInterface.(map[string]interface{})
			if !ok {
				continue
			}
			lastChallenge, ok := doc["lastChallenge"]
			if !ok {
				continue
			}
			// Go only lets us cast this to a float64, even though it was originally an int64
			lastChallengeFloat64, ok := lastChallenge.(float64)
			if !ok {
				continue
			}
			if lastChallengeFloat64 == 0 {
				continue
			}
			// check if it was more than 6 mins ago
			if time.Unix(0, int64(lastChallengeFloat64)).Before(time.Now().Add(time.Minute * -6)) {
				idInterface, ok := row["id"]
				if !ok {
					continue
				}
				id, ok := idInterface.(string)
				if !ok {
					continue
				}
				revInterface, ok := doc["_rev"]
				if !ok {
					continue
				}
				rev, ok := revInterface.(string)
				if !ok {
					continue
				}
				doc["lastChallenge"] = int64(0)
				_, _ = usersDB.Put(id, doc, rev)
				continue
			}
		}
	}
}

// keep this in parity with the identical function in proxy
func validateChallenge(signedChallenge []byte) error {
	// 64 byte signature, 8 byte challenge
	if len(signedChallenge) != 72 {
		return fmt.Errorf("Signed challenge is of wrong length: %v", len(signedChallenge))
	}

	challenge := signedChallenge[64:] // first 64 bytes are sig
	challengeInt := binary.BigEndian.Uint32(challenge)
	challengeInt64 := int64(challengeInt)
	if challengeInt64 == 0 { // zero doesn't play nice with the time package
		return errTimeWindow
	}
	if time.Unix(0, challengeInt64).After(time.Now().Add(time.Minute * 3)) {
		return errTimeWindow
	}
	if time.Unix(0, challengeInt64).Before(time.Now().Add(time.Minute * -3)) {
		return errTimeWindow
	}

	return nil
}

// pass in the loginKey
// keep this in parity with the identical function in proxy
func verifyChallenge(identifier string, signedChallenge []byte) (bool, error) {
	var challengeData map[string]interface{}
	err := usersDB.Get(identifier, &challengeData, nil)
	if err != nil {
		if couch.NotFound(err) {
			return false, errUserNotFound
		}
		return false, err
	}
	pubKey, ok1 := challengeData["publicKey"]
	pubKeyString, ok2 := pubKey.(string)
	if !(ok1 && ok2) {
		err = errors.New("Problem reading PublicKey from database")
		log.Error(errors.Trace(err), challengeData)
		return false, err
	}

	pubBytes, err := hex.DecodeString(pubKeyString)
	if err != nil {
		log.Error(errors.Trace(err), pubKeyString)
		return false, errors.New("Problem decoding hex of PublicKey")
	}

	var pubByteArray [32]byte
	var sigByteArray [64]byte
	copy(pubByteArray[:], pubBytes[:])
	copy(sigByteArray[:], signedChallenge[:])
	if !ed25519.Verify(&pubByteArray, signedChallenge[64:], &sigByteArray) {
		return false, errChallengeSig
	}

	lastChallenge, ok1 := challengeData["lastChallenge"]
	// Go only lets us cast this to a float64, even though it was originally an int64
	lastChallengeFloat64, ok2 := lastChallenge.(float64)
	if !(ok1 && ok2) {
		err = errors.New("Problem reading lastChallenge from database")
		log.Error(errors.Trace(err), challengeData)
		return false, err
	}
	challenge := signedChallenge[64:] // first 64 bytes are sig
	challengeUInt := binary.BigEndian.Uint64(challenge)
	challengeInt64 := int64(challengeUInt)

	if challengeInt64 <= int64(lastChallengeFloat64) {
		return false, errChallengeUsed
	}
	challengeData["lastChallenge"] = challengeInt64

	rev, ok1 := challengeData["_rev"]
	revString, ok2 := rev.(string)
	if !(ok1 && ok2) {
		err = errors.New("Problem reading rev from database")
		log.Error(errors.Trace(err), challengeData)
		return false, err
	}

	_, err = usersDB.Put(identifier, challengeData, revString)
	if err != nil {
		if couch.Conflict(err) {
			return verifyChallenge(identifier, signedChallenge) // try again
		}
		log.Error(errors.Trace(err), challengeData)
		return false, errors.New("Problem updating last challenge")
	}
	return true, nil
}
