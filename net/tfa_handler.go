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

func showTotpRegistration(username string, prv *provider.Provider, af *authFlow, w http.ResponseWriter, paramMap map[string]string) {
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
	setAuthFlow(af, w)

	var buf bytes.Buffer
	img, _ := key.Image(250, 250)
	png.Encode(&buf, img)
	qrcode := utils.B64Encode(buf.Bytes())
	// add image metadata to let HTML browser render the image
	qrcode = "data:image/png;base64," + qrcode

	tmplMap := make(map[string]interface{})
	tmplMap["paramMap"] = paramMap
	tmplMap["qrcode"] = qrcode

	tmpl := templates["totp-register.html"]
	tmpl.Execute(w, tmplMap)
}

func registerTotp(w http.ResponseWriter, r *http.Request) {
	af := getAuthFlow(r)

	if af == nil || !af.VerifiedPassword() {
		showLogin(w, r)
		return
	}

	pr := dcPrvMap[af.DomainCode]
	err := pr.StoreTotpSecret(af.UserId, af.TotpSecret)
	if err != nil {
		log.Warningf("Failed to store totp secret %s", err)
	}

	af.TotpSecret = ""
	af.SetTfaRegister(false)
	af.SetTfaRequired(true)
	setAuthFlow(af, w)

	tmpl := templates["totp-send.html"]
	tmpl.Execute(w, copyParams(r))
}