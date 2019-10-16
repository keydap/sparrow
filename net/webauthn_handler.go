package net

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ugorji/go/codec"
	"io/ioutil"
	"net/http"
	"sparrow/base"
	"sparrow/utils"
	"strconv"
	"strings"
)

func (sp *Sparrow) deletePubKey(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)

	path := strings.TrimRight(r.RequestURI, "/")
	pos := strings.LastIndex(path, "/")
	if pos < 0 || (pos+1 >= len(path)) {
		msg := "invalid request, no credential ID found in the path"
		log.Debugf(msg)
		writeError(w, base.NewNotFoundError(msg))
		return
	}
	err = pr.DeleteSecurityKey(opCtx.Session.Sub, path[pos+1:])
	if err != nil {
		log.Debugf("%#v", err)
		writeError(w, err)
		return
	}
}

func (sp *Sparrow) registerPubKey(w http.ResponseWriter, r *http.Request) {
	_, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

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
	fmt.Printf("%s", utils.B64Encode(data))

	var clientData base.CollectedClientData
	json.Unmarshal(data[a:], &clientData)
	clientData.RawBytes = data[a:]
	fmt.Println(clientData)

	ch := new(codec.CborHandle)
	dec := codec.NewDecoderBytes(data[:a], ch)
	var attData map[string]interface{}
	dec.Decode(&attData)
	fmt.Println(attData)

	challengeBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		err = base.NewBadRequestError("invalid challenge value")
		writeError(w, err)
		return
	}

	challengeBytes, err = sp.ckc.DecryptBytes(challengeBytes)
	if err != nil {
		err = base.NewBadRequestError("corrupted challenge value")
		writeError(w, err)
		return
	}

	// TODO check the timeout against the configured timeout
	//cTime := utils.Btoi(challengeBytes[:8])

	skey, err := validateRegistrationData(clientData, attData, r, sp)
	if err != nil {
		log.Debugf("%#v", err)
		err = base.NewBadRequestError(err.Error())
		writeError(w, err)
		return
	}

	prId := string(challengeBytes[8:16])
	resId := utils.FormatUUID(challengeBytes[16:32])
	// the nonce is discarded which is at 40-44

	pr := sp.dcPrvMap[prId]
	if pr == nil {
		log.Debugf("unknown provider")
		err = base.NewBadRequestError("unknown provider")
		writeError(w, err)
		return
	}

	err = pr.StoreSecurityKey(resId, skey)
	if err != nil {
		writeError(w, err)
	}

	data, _ = json.Marshal(skey)
	w.Header().Add("Content-Type", JSON_TYPE)
	w.Write(data)

	//authReq := base.NewPubKeyAuthReq(curCredId)
	//authReqData, _ :=json.Marshal(authReq)
	//w.Write(authReqData)
}

func validateRegistrationData(clientData base.CollectedClientData, attData map[string]interface{}, r *http.Request, sp *Sparrow) (*base.SecurityKey, error) {
	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid type value")
	}

	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}

	origin := (scheme + r.Host)
	if clientData.Origin != origin {
		return nil, fmt.Errorf("invalid origin")
	}

	// TODO support token binding
	//if clientData.TokenBinding.Status

	cdataHash := sha256.Sum256(clientData.RawBytes)
	fmt.Printf("client data hash %x\n", cdataHash)

	rpId := getRpId(r.Host)
	// FXIME this should be fetched from challenge data or some other place, calculating here is a security risk
	calculatedRpIdHash := sha256.Sum256([]byte(rpId))
	if attData["rpIdHash"] != calculatedRpIdHash {
		log.Debugf("invalid RP ID hash")
		//return nil, fmt.Errorf("invalid RP ID hash")
	}

	authData := attData["authData"].([]byte)

	rpIdHash := authData[:32]
	if bytes.Compare(calculatedRpIdHash[:], rpIdHash) != 0 {
		log.Debugf("calculated RP ID hash: %x rpIdHash: %x", calculatedRpIdHash[:], rpIdHash)
		return nil, fmt.Errorf("invalid RP ID hash %x", rpIdHash)
	}

	flags := authData[32]

	// user present
	if (flags & 1) != 1 {
		return nil, fmt.Errorf("user is not present")
	}

	// will depend on authenticator's capabilities
	//if (flags & (1 << 2) ) != 1 {
	//	return fmt.Errorf("user is not verified")
	//}

	var skey *base.SecurityKey
	var signCount uint32
	var err error
	signCount = utils.DecodeUint32(authData[33:37])

	if (flags & (1 << 6)) != 0 { // attested credential data
		skey = &base.SecurityKey{}
		skey.SignCount = signCount
		log.Debugf("signature count %d", signCount)
		attestedCredData := authData[37:]
		aaguid := base64.RawURLEncoding.EncodeToString(attestedCredData[:16])
		skey.DeviceId = aaguid
		log.Debugf("AAUGUID %s", aaguid)
		var credIdLength uint16

		credIdLength = credIdLength<<8 | uint16(attestedCredData[16])
		credIdLength = credIdLength<<8 | uint16(attestedCredData[17])
		credIdLenEndPos := 18 + int(credIdLength)
		credentialId := attestedCredData[18:credIdLenEndPos]
		credIdStr := base64.RawURLEncoding.EncodeToString(credentialId)
		skey.CredentialId = credIdStr
		log.Debugf("CredentialId %s", credIdStr)
		if len(attestedCredData) > credIdLenEndPos {
			ch := new(codec.CborHandle)
			ch.SkipUnexpectedTags = true

			pubKeyData := attestedCredData[credIdLenEndPos:]
			log.Debugf("pubkey data in hex form: %x", pubKeyData)
			dec := codec.NewDecoderBytes(pubKeyData, ch)
			m := make(map[int]interface{})
			err := dec.Decode(&m)
			if err != nil {
				log.Warningf("error while decoding the credentialPublicKey %#v", err)
			}
			log.Debugf("credentialPublicKey %#v", m)
			skey.PubKeyCOSE = m
			skey.RegisteredDate = utils.DateTimeMillis()
		}
	} else {
		err = fmt.Errorf("no credential data found")
	}

	return skey, err
}

func (sp *Sparrow) pubKeyOptions(w http.ResponseWriter, r *http.Request) {
	opCtx, err := createOpCtx(r, sp)
	if err != nil {
		writeError(w, err)
		return
	}

	pr := sp.providers[opCtx.Session.Domain]
	log.Debugf("handling %s request on %s for the domain %s", r.Method, r.RequestURI, pr.Name)
	user, err := pr.GetUserById(opCtx.Session.Sub)
	if err != nil {
		writeError(w, err)
		return
	}

	username := user.GetAttr("username").GetSimpleAt().GetStringVal()
	displayName := username
	displayNameAt := user.GetAttr("displayName")
	if displayNameAt != nil {
		displayName = displayNameAt.GetSimpleAt().GetStringVal()
	}

	webauthnId := user.AuthData.WebauthnId
	if webauthnId == "" {
		webauthnId, err = pr.GenWebauthnIdFor(opCtx.Session.Sub)
	}

	challenge := make([]byte, 0)
	challenge = append(challenge, utils.Itob(utils.DateTimeMillis())...)
	challenge = append(challenge, []byte(pr.DomainCode())...)
	userId := opCtx.Session.Sub
	userId = strings.Replace(userId, "-", "", -1)
	data, _ := hex.DecodeString(userId)
	challenge = append(challenge, data...)
	// random nonce
	challenge = append(challenge, utils.RandBytes(4)...)

	challenge = sp.ckc.Encrypt(challenge)
	log.Debugf("length of the webauthn register credential challenge %d", len(challenge))

	pkco := base.PublicKeyCredentialCreationOptions{}
	pkco.Challenge = base64.RawURLEncoding.EncodeToString(challenge) // without padding cause the response strips padding
	log.Debugf("challenge: %s", pkco.Challenge)
	pkco.RpName = "Sparrow Identity Server"
	pkco.RpId = getRpId(r.Host)

	pkco.UserName = username
	pkco.UserDisplayName = displayName
	pkco.Attestation = "none"
	pkco.Timeout = 90000
	pkco.UserId = webauthnId
	if user.AuthData.Skeys != nil {
		pkco.ExcludeCredentials = make([]base.PublicKeyCredentialDescriptor, len(user.AuthData.Skeys))
		i := 0
		for _, v := range user.AuthData.Skeys {
			pkco.ExcludeCredentials[i] = base.PublicKeyCredentialDescriptor{Type: "public-key", Id: v.CredentialId}
		}
	} else {
		pkco.ExcludeCredentials = make([]base.PublicKeyCredentialDescriptor, 0)
	}

	data, err = json.Marshal(pkco)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Add("Content-Type", JSON_TYPE)
	w.Write(data)
}

func getRpId(host string) string {
	// if it is on localhost:xx then return just localhost to avoid `DOMException: "The operation is insecure."`
	pos := strings.Index(host, ":")
	if pos > 0 {
		host = host[:pos]
	}
	return host
}
