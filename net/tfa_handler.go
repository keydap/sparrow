// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"bytes"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"image/png"
	"net/http"
	"sparrow/provider"
	"sparrow/utils"
)

const OTP_LEN = 6

func showTotpRegistration(username string, prv *provider.Provider, af *authFlow, w http.ResponseWriter, paramMap map[string]string, sp *Sparrow) {
	// only SHA1 seems to be supported by google's authenticator app
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      prv.Name,
		AccountName: username,
		Digits:      6,
		Algorithm:   otp.AlgorithmSHA1,
		SecretSize:  16})

	// should not happen
	if err != nil {
		log.Criticalf("Failed to generate TOTP secret key for user %s [%#v]", username, err)
		panic(err)
	}

	af.TotpSecret = key.Secret()
	setAuthFlow(sp, af, w)

	var buf bytes.Buffer
	img, _ := key.Image(250, 250)
	png.Encode(&buf, img)
	qrcode := utils.B64Encode(buf.Bytes())
	// add image metadata to let HTML browser render the image
	qrcode = "data:image/png;base64," + qrcode

	tmplMap := make(map[string]interface{})
	tmplMap["paramMap"] = paramMap
	tmplMap["qrcode"] = qrcode

	tmpl := sp.templates["totp-register.html"]
	tmpl.Execute(w, tmplMap)
}

func (sp *Sparrow) registerTotp(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r, sp)

	if af == nil || !af.VerifiedPassword() {
		sp.showLogin(w, r)
		return
	}

	pr := sp.dcPrvMap[af.DomainCode]
	err := pr.StoreTotpSecret(af.UserId, af.TotpSecret, utils.GetRemoteAddr(r))
	if err != nil {
		log.Warningf("Failed to store totp secret %s", err)
	}

	af.TotpSecret = ""
	af.SetTfaRegister(false)
	af.SetTfaRequired(true)
	setAuthFlow(sp, af, w)

	tmpl := sp.templates["totp-send.html"]
	tmpl.Execute(w, copyParams(r))
}
