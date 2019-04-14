// Copyright 2018 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

package net

import (
	"bytes"
	"net/http"
	"sparrow/utils"
	"strings"
	"time"
)

const idpMetadataXml = `<?xml version="1.0" encoding="UTF-8"?>
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="{{.CacheDuration}}" entityID="{{.EntityID}}" validUntil="{{.ValidUntil}}">
    <md:IDPSSODescriptor WantAuthnRequestsSigned="{{.WantAuthnRequestsSigned}}" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
        <md:KeyDescriptor use="signing">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{{.X509Certificate}}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:KeyDescriptor use="encryption">
            <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                <ds:X509Data>
                    <ds:X509Certificate>{{.X509Certificate}}</ds:X509Certificate>
                </ds:X509Data>
            </ds:KeyInfo>
        </md:KeyDescriptor>
        <md:SingleLogoutService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{{.SLOLocation}}" ResponseLocation="{{.SLORespLocation}}" />
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat>
        <md:NameIDFormat>urn:oasis:names:tc:SAML:2.0:nameid-format:persistent</md:NameIDFormat>
        <md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="{{.SSOLocation}}" />
    </md:IDPSSODescriptor>
</md:EntityDescriptor>`

type idpMetadata struct {
	CacheDuration           string
	EntityID                string // equivalent to IdpIssuer in samlResponse
	ValidUntil              string
	WantAuthnRequestsSigned bool
	X509Certificate         string
	SLOLocation             string
	SLORespLocation         string
	SSOLocation             string
}

func (sp *Sparrow) serveIdpMetadata(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimSpace(r.URL.Path)
	plen := len(path) - 1
	if path[plen] == '/' {
		path = path[:plen]
	}

	pos := strings.LastIndex(path, "/")
	domain := path[pos+1:]
	domain = strings.ToLower(domain)
	pr := sp.providers[domain]
	if pr == nil {
		// send error
		w.WriteHeader(http.StatusNotFound)
		return
	}

	// send domain metadata

	meta := idpMetadata{}
	meta.CacheDuration = "P0Y0M30DT0H0M0.000S"
	meta.EntityID = pr.Name
	validity := time.Now().AddDate(2, 0, 0).UTC()
	RFC3339Millis := "2006-01-02T15:04:05.999Z07:00"
	meta.ValidUntil = validity.Format(RFC3339Millis)
	meta.WantAuthnRequestsSigned = false // for now
	meta.X509Certificate = utils.B64Encode(pr.Cert.Raw)

	meta.SLOLocation = sp.homeUrl + SAML_BASE + "/idp/logout"
	meta.SLORespLocation = meta.SLOLocation
	meta.SSOLocation = sp.homeUrl + SAML_BASE + "/idp"

	var buf bytes.Buffer
	metaTemplate.Execute(&buf, meta)
	w.Header().Add("Content-Type", "application/xml")
	w.Write(buf.Bytes())
}
