package net

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/ugorji/go/codec"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/utils"
	"strconv"
)

func serveIndex(w http.ResponseWriter, r *http.Request) {
	fmt.Println("host -> " + r.Host)
	pubKeyCred := base.NewPubKeyCred(r.Host)
	tmpl.Execute(w, pubKeyCred)
}

func register(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	a, err := strconv.Atoi(r.Form.Get("a"))
	if err != nil {
		fmt.Println("invalid attestation data length")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	c, err := strconv.Atoi(r.Form.Get("c"))
	if err != nil {
		fmt.Println("invalid client data length")
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println(a, "  ", c)
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	fmt.Println(len(data))
	fmt.Println(string(data[a:]))

	var clientData base.CollectedClientData
	json.Unmarshal(data[a:], &clientData)
	clientData.RawBytes = data[a:]
	fmt.Println(clientData)

	ch := new(codec.CborHandle)
	dec := codec.NewDecoderBytes(data[:a], ch)
	var m map[string]interface{}
	dec.Decode(&m)
	fmt.Println(m)

	err = validateRegistrationData(clientData, m, r)
	if err != nil {
		fmt.Println(err)
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	authReq := base.NewPubKeyAuthReq(curCredId)
	authReqData, _ :=json.Marshal(authReq)
	w.Write(authReqData)
}

func validateRegistrationData(clientData base.CollectedClientData, attData map[string]interface{}, r *http.Request) error {
	if clientData.Type != "webauthn.create" {
		return fmt.Errorf("invalid type value")
	}

	// FIXME change the challenge to a stateless value
	// https://crypto.stackexchange.com/questions/2226/what-challenge-should-i-use-in-a-challenge-response-proof-of-work
	if clientData.Challenge == "" {
		return fmt.Errorf("invalid challenge value")
	}

	scheme := "http://";
	if r.TLS != nil {
		scheme = "https://"
	}

	origin := (scheme + r.Host)
	if clientData.Origin != origin {
		return fmt.Errorf("invalid origin")
	}

	// TODO support token binding
	//if clientData.TokenBinding.Status

	cdataHash := sha256.Sum256(clientData.RawBytes)
	fmt.Printf("client data hash %x\n", cdataHash)

	// FXIME this should be fetched from challenge data or some other place, calculating here is a security risk
	calculatedRpIdHash := sha256.Sum256([]byte(r.Host))
	//if attData["rpIdHash"] != challenge.rpIdHash

	authData := attData["authData"].([]byte)

	rpIdHash := authData[:32]
	if bytes.Compare(calculatedRpIdHash[:], rpIdHash) != 0 {
		fmt.Printf("calculated RP ID hash: %x \nrpIdHash: %x\n", calculatedRpIdHash[:], rpIdHash)
		//return fmt.Errorf("invalid RP ID hash %x", rpIdHash)
	}

	flags := authData[32]

	// user present
	if (flags & 1) != 1 {
		return fmt.Errorf("user is not present")
	}

	// will depend on authenticator's capabilities
	//if (flags & (1 << 2) ) != 1 {
	//	return fmt.Errorf("user is not verified")
	//}

	var signCount uint32
	signCount = utils.DecodeUint32(authData[33:37])
	fmt.Printf("signature count %d\n", signCount)
	if len(authData) > 37 {
		attestedCredData := authData[37:]
		aaguid := attestedCredData[:16]
		fmt.Printf("AAUGUID %s\n", utils.B64Encode(aaguid))
		var credentialIdLength uint16

		credentialIdLength = credentialIdLength <<8 | uint16(attestedCredData[16])
		credentialIdLength = credentialIdLength <<8 | uint16(attestedCredData[17])
		credIdLenEndPos := 18 + int(credentialIdLength)
		credentialId := attestedCredData[18: credIdLenEndPos]
		credIdStr := utils.B64Encode(credentialId)
		fmt.Printf("CredentialId %s\n", credIdStr)
		if len(attestedCredData) > credIdLenEndPos {
			ch := new(codec.CborHandle)
			pubKeyData := attestedCredData[credIdLenEndPos:]
			fmt.Printf("pubkey %x\n", pubKeyData)
			fmt.Println(pubKeyData)
			dec := codec.NewDecoderBytes(pubKeyData, ch)
			m := make(map[int]interface{})
			err := dec.Decode(&m)
			if err != nil {
				fmt.Printf("error while decoding the credentialPublicKey %#v", err)
				return err
			}
			fmt.Printf("credentialPublicKey %#v",m)
			users[credIdStr] = m
			curCredId = credIdStr
		}
	}

	return nil
}