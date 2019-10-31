package net

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ugorji/go/codec"
	"hash"
	"io/ioutil"
	"math/big"
	"net/http"
	"sparrow/base"
	"sparrow/provider"
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

	webauthnResp, err := sp.parseWebauthnResp(r)
	if err != nil {
		writeError(w, err)
		return
	}

	skey, err := validateRegistrationData(webauthnResp, r, sp)
	if err != nil {
		log.Debugf("%#v", err)
		err = base.NewBadRequestError(err.Error())
		writeError(w, err)
		return
	}

	pr := sp.dcPrvMap[webauthnResp.PrId]
	if pr == nil {
		log.Debugf("unknown provider")
		err = base.NewBadRequestError("unknown provider")
		writeError(w, err)
		return
	}

	err = pr.StoreSecurityKey(webauthnResp.ResId, skey)
	if err != nil {
		writeError(w, err)
	}

	data, _ := json.Marshal(skey)
	w.Header().Add("Content-Type", JSON_TYPE)
	w.Write(data)
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

	pkco := base.PublicKeyCredentialCreationOptions{}
	pkco.Challenge = sp.createWebauthnChallenge(opCtx.Session.Sub, pr)
	log.Debugf("challenge: %s", pkco.Challenge)
	pkco.RpName = "Sparrow Identity Server"
	pkco.RpId = stripPortNumber(r.Host)
	pkco.PubKeyCredParams = base.DEFAULT_PUB_KEY_CRED_PARAMS

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
			i++
		}
	} else {
		pkco.ExcludeCredentials = make([]base.PublicKeyCredentialDescriptor, 0)
	}

	data, err := json.Marshal(pkco)
	if err != nil {
		writeError(w, err)
		return
	}

	w.Header().Add("Content-Type", JSON_TYPE)
	w.Write(data)
}

func (sp *Sparrow) sendWebauthnAuthReq(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := strings.TrimSpace(r.Form.Get("username"))
	if username == "" {
		redirectToLogin(w, r)
		return
	}

	username, domain := sp.splitUsernameAndDomain(username)

	pr := sp.providers[domain]
	if pr == nil {
		redirectToLogin(w, r)
		return
	}

	user := pr.GetUserByName(username)
	if user == nil {
		redirectToLogin(w, r)
		return
	}

	// if no webauthn ID then return to login page
	if len(user.AuthData.Skeys) == 0 {
		redirectToLogin(w, r)
		return
	}

	authReq := base.PublicKeyCredentialRequestOptions{}
	authReq.Challenge = sp.createWebauthnChallenge(user.GetId(), pr)
	authReq.CredIds = make([]string, len(user.AuthData.Skeys))
	i := 0
	for _, v := range user.AuthData.Skeys {
		authReq.CredIds[i] = v.CredentialId
		i++
	}
	authReq.RpId = stripPortNumber(r.Host)
	authReq.Timeout = 90000
	authReq.UserVerification = "discouraged" // TODO should be fetched from RP specific policy

	tmpl := sp.templates["webauthn.html"]
	tmpl.Execute(w, authReq)
}

func (sp *Sparrow) webauthnVerifyCred(w http.ResponseWriter, r *http.Request) {
	webauthnResp, err := sp.parseWebauthnResp(r)
	if err != nil {
		redirectToLogin(w, r)
		return
	}

	user, err := validateCredLoginData(webauthnResp, r, sp)
	if err != nil {
		redirectToLogin(w, r)
		return
	}

	pr := sp.dcPrvMap[webauthnResp.PrId]

	af := getAuthFlow(r, sp)
	if af == nil {
		af = &authFlow{}
	}
	af.SetPasswordVerified(true)
	af.SetTfaVerified(true)
	af.SetTfaRequired(false)
	//setSessionCookie(sp, user, af, pr, w, r, params)
	session := pr.GenSessionForUser(user)
	pr.StoreSsoSession(session)
	setSsoCookie(pr, session, w)
	w.Write([]byte("/redirect"))
}

func stripPortNumber(host string) string {
	// if it is on localhost:xx then return just localhost to avoid `DOMException: "The operation is insecure."`
	pos := strings.Index(host, ":")
	if pos > 0 {
		host = host[:pos]
	}
	return host
}

func (sp *Sparrow) createWebauthnChallenge(userId string, pr *provider.Provider) string {
	challenge := make([]byte, 0)
	challenge = append(challenge, utils.Itob(utils.DateTimeMillis())...)
	challenge = append(challenge, []byte(pr.DomainCode())...)
	userId = strings.Replace(userId, "-", "", -1)
	data, _ := hex.DecodeString(userId)
	challenge = append(challenge, data...)
	// random nonce
	challenge = append(challenge, utils.RandBytes(4)...)

	challenge = sp.ckc.Encrypt(challenge)
	log.Debugf("length of the webauthn register credential challenge %d", len(challenge))
	return base64.RawURLEncoding.EncodeToString(challenge) // without padding cause the response strips padding
}

func parseAuthenticatorData(data []byte) (base.AuthenticatorData, error) {
	authData := base.AuthenticatorData{}
	authData.RpIdHash = data[:32]
	authData.Flags = data[32]

	authData.SignCount = utils.DecodeUint32(data[33:37])
	log.Debugf("signature count %d", authData.SignCount)

	var err error
	if (authData.Flags & (1 << 6)) != 0 { // attested credential data
		attestedCredData := data[37:]
		authData.AAGUID = base64.RawURLEncoding.EncodeToString(attestedCredData[:16])
		log.Debugf("AAUGUID %s", authData.AAGUID)
		var credIdLength uint16

		credIdLength = credIdLength<<8 | uint16(attestedCredData[16])
		credIdLength = credIdLength<<8 | uint16(attestedCredData[17])
		credIdLenEndPos := 18 + int(credIdLength)
		credentialId := attestedCredData[18:credIdLenEndPos]
		authData.CredentialId = base64.RawURLEncoding.EncodeToString(credentialId)
		log.Debugf("CredentialId %s", authData.CredentialId)
		if len(attestedCredData) > credIdLenEndPos {
			ch := new(codec.CborHandle)
			ch.SkipUnexpectedTags = true

			pubKeyData := attestedCredData[credIdLenEndPos:]
			log.Debugf("pubkey data in hex form: %x", pubKeyData)
			dec := codec.NewDecoderBytes(pubKeyData, ch)
			m := make(map[int]interface{})
			err = dec.Decode(&m)
			if err != nil {
				msg := fmt.Sprintf("error while decoding the credentialPublicKey %#v", err)
				log.Warningf(msg)
				err = fmt.Errorf(msg)
			} else {
				log.Debugf("credentialPublicKey %#v", m)
				authData.PubKeyCOSE = m
			}
		}
	}

	return authData, err
}

func (sp *Sparrow) parseWebauthnResp(r *http.Request) (base.WebauthnResponse, error) {
	r.ParseForm()
	webauthnResp := base.WebauthnResponse{}
	a, err := strconv.Atoi(r.Form.Get("a"))
	if err != nil {
		return webauthnResp, base.NewBadRequestError("invalid attestation data length")
	}

	c, err := strconv.Atoi(r.Form.Get("c"))
	if err != nil {
		return webauthnResp, base.NewBadRequestError("invalid client data length")
	}

	s := -1 // length of signature array
	sField := r.Form.Get("s")
	if sField != "" {
		s, err = strconv.Atoi(sField)
		if err != nil {
			return webauthnResp, base.NewBadRequestError("invalid signature data length")
		}
	}

	fmt.Println(a, "  ", c, " ", s)
	data, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return webauthnResp, base.NewBadRequestError(err.Error())
	}

	log.Debugf("%d", len(data))
	log.Debugf("%s", utils.B64Encode(data))

	var attStmt map[string]interface{}
	var rawAuthData []byte
	if s > 0 {
		rawAuthData = data[:a]
	} else {
		ch := new(codec.CborHandle)
		dec := codec.NewDecoderBytes(data[:a], ch)
		dec.Decode(&attStmt)
		webauthnResp.AttStmt = attStmt
		rawAuthData = attStmt["authData"].([]byte)
	}

	authData, err := parseAuthenticatorData(rawAuthData)
	if err != nil {
		return webauthnResp, err
	}
	if s > 0 {
		authData.CredentialId = r.Form.Get("id") // this is the case only during authentication, during registration this SHOULD not be done
	}
	authData.RawData = rawAuthData
	webauthnResp.AuthData = authData

	var clientData base.CollectedClientData
	clientData.RawBytes = data[a : a+c]
	err = json.Unmarshal(clientData.RawBytes, &clientData)
	if err != nil {
		log.Warningf("failed to parse the clientDataJSON %#v", err)
	}
	webauthnResp.ClientData = clientData
	log.Debugf("client data: %s", utils.B64Encode(clientData.RawBytes))

	log.Debugf("received challenge: %s", clientData.Challenge)

	challengeBytes, err := base64.RawURLEncoding.DecodeString(clientData.Challenge)
	if err != nil {
		return webauthnResp, base.NewBadRequestError("invalid challenge value")
	}

	log.Debugf("decrypting the challenge: %s", clientData.Challenge)
	challengeBytes, err = sp.ckc.DecryptBytes(challengeBytes)
	if err != nil {
		return webauthnResp, base.NewBadRequestError("corrupted challenge value")
	}

	// TODO check the timeout against the configured timeout
	webauthnResp.CTime = utils.Btoi(challengeBytes[:8])
	log.Debugf("%d", webauthnResp.CTime)

	webauthnResp.PrId = string(challengeBytes[8:16])
	webauthnResp.ResId = utils.FormatUUID(challengeBytes[16:32])
	// the nonce is discarded which is at 32-36

	if s > 0 {
		webauthnResp.Signature = data[a+c : a+c+s]
	}

	return webauthnResp, nil
}

func validateRegistrationData(webauthnResp base.WebauthnResponse, r *http.Request, sp *Sparrow) (*base.SecurityKey, error) {
	clientData := webauthnResp.ClientData
	authData := webauthnResp.AuthData

	if clientData.Type != "webauthn.create" {
		return nil, fmt.Errorf("invalid type value")
	}

	scheme := "http://"
	if r.TLS != nil {
		scheme = "https://"
	}

	origin := (scheme + r.Host)
	if clientData.Origin != origin {
		return nil, fmt.Errorf("invalid origin %s", origin)
	}

	// TODO support token binding
	//if clientData.TokenBinding.Status

	cdataHash := sha256.Sum256(clientData.RawBytes)
	fmt.Printf("client data hash %x\n", cdataHash)

	rpId := stripPortNumber(r.Host)
	calculatedRpIdHash := sha256.Sum256([]byte(rpId))

	if bytes.Compare(calculatedRpIdHash[:], authData.RpIdHash) != 0 {
		log.Debugf("calculated RP ID hash: %x rpIdHash: %x", calculatedRpIdHash[:], authData.RpIdHash)
		return nil, fmt.Errorf("invalid RP ID hash %x", authData.RpIdHash)
	}

	// user present
	if (authData.Flags & 1) != 1 {
		msg := "user is not present"
		log.Debugf(msg)
		return nil, fmt.Errorf(msg)
	}

	// will depend on authenticator's capabilities
	//if (flags & (1 << 2) ) != 1 {
	//	return fmt.Errorf("user is not verified")
	//}

	if authData.PubKeyCOSE == nil {
		msg := "no publickey credential data found"
		log.Debugf(msg)
		return nil, fmt.Errorf(msg)
	}

	skey := &base.SecurityKey{}
	skey.PubKeyCOSE = authData.PubKeyCOSE
	skey.CredentialId = authData.CredentialId
	skey.DeviceId = authData.AAGUID
	skey.RegisteredDate = utils.DateTimeMillis()
	skey.SignCount = authData.SignCount

	return skey, nil
}

func validateCredLoginData(webauthnResp base.WebauthnResponse, r *http.Request, sp *Sparrow) (*base.Resource, error) {
	clientData := webauthnResp.ClientData
	authData := webauthnResp.AuthData

	if clientData.Type != "webauthn.get" {
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

	rpId := stripPortNumber(r.Host)
	calculatedRpIdHash := sha256.Sum256([]byte(rpId))

	if bytes.Compare(calculatedRpIdHash[:], authData.RpIdHash) != 0 {
		log.Debugf("calculated RP ID hash: %x rpIdHash: %x", calculatedRpIdHash[:], authData.RpIdHash)
		return nil, fmt.Errorf("invalid RP ID hash %x", authData.RpIdHash)
	}

	// user present
	if (authData.Flags & 1) != 1 {
		msg := "user is not present"
		log.Debugf(msg)
		return nil, fmt.Errorf(msg)
	}

	// will depend on authenticator's capabilities
	//if (flags & (1 << 2) ) != 1 {
	//	return fmt.Errorf("user is not verified")
	//}

	pr := sp.dcPrvMap[webauthnResp.PrId]
	if pr == nil {
		log.Debugf("unknown provider")
		err := fmt.Errorf("unknown provider")
		return nil, err
	}

	user, err := pr.GetUserById(webauthnResp.ResId)
	if err != nil {
		return nil, err
	}

	skey := user.AuthData.Skeys[authData.CredentialId]
	if skey == nil {
		msg := "unknown credential"
		log.Debugf(msg)
		err := fmt.Errorf(msg)
		return nil, err
	}

	valid := validateSignature(skey, webauthnResp, cdataHash[:])
	if !valid {
		return nil, fmt.Errorf("signature verification failed")
	}

	return user, nil
}

func validateSignature(skey *base.SecurityKey, webauthnResp base.WebauthnResponse, cdataHash []byte) bool {
	coseKey := skey.PubKeyCOSE
	kty := coseKey[1].(uint64) // key type

	log.Debugf("signature urlb64: %s", base64.RawURLEncoding.EncodeToString(webauthnResp.Signature))
	sigValid := false
	switch kty {
	case 2: // EC2
		type ecdsaParts struct {
			R *big.Int
			S *big.Int
		}
		key, h, err := parseEC2Key(coseKey)
		parts := ecdsaParts{}
		rest, err := asn1.Unmarshal(webauthnResp.Signature, &parts)
		fmt.Println(rest, err)
		if err == nil {
			h.Write(webauthnResp.AuthData.RawData)
			h.Write(cdataHash)
			digest := h.Sum(nil)
			sigValid = ecdsa.Verify(key, digest, parts.R, parts.S)
		}
	case 3: // RSA
		alg := coseKey[3] // algorithm
		// "PS256"
		if alg == -37 {
			nBytes, _ := hex.DecodeString(coseKey[-1].(string))
			n := new(big.Int).SetBytes(nBytes)
			eBytes, _ := hex.DecodeString(coseKey[-2].(string))
			e := 0
			e = e | int(eBytes[0])
			e = e<<8 | int(eBytes[1])
			e = e<<8 | int(eBytes[2])

			h := crypto.SHA256.New()
			h.Write(webauthnResp.AuthData.RawData)
			h.Write(cdataHash)
			key := &rsa.PublicKey{N: n, E: e}
			err := rsa.VerifyPSS(key, crypto.SHA256, h.Sum(nil), webauthnResp.Signature, nil)
			if err == nil {
				sigValid = true
			} else {
				log.Debugf("%#v", err)
			}
		} else {
			log.Warningf("unsupported RSA algorithm identifier %d", alg)
		}
	}

	return sigValid
}

func parseEC2Key(coseKey map[int]interface{}) (*ecdsa.PublicKey, hash.Hash, error) {
	alg := coseKey[3].(int64) // algorithm
	x := coseKey[-2].([]uint8)
	xInt := new(big.Int).SetBytes(x)
	y := coseKey[-3].([]uint8)
	yInt := new(big.Int).SetBytes(y)

	var curve elliptic.Curve
	var h hash.Hash
	switch alg {
	case -7: // "ES256"
		curve = elliptic.P256()
		h = sha256.New()
	case -35: // "ES384"
		curve = elliptic.P384()
		h = crypto.SHA384.New()
	case -36: // "ES512"
		curve = elliptic.P521()
		h = crypto.SHA512.New()
	default:
		msg := fmt.Sprintf("unsupported EC2 algorithm identifier %d", alg)
		log.Warningf(msg)
		return nil, nil, fmt.Errorf(msg)
	}

	return &ecdsa.PublicKey{X: xInt, Y: yInt, Curve: curve}, h, nil
}
