package provider

import (
	"fmt"
	"net/url"
	"sparrow/base"
	"sparrow/utils"
	"strings"
)

type ApplicationInterceptor struct {
}

func (ai *ApplicationInterceptor) PreCreate(crCtx *base.CreateContext) error {
	if crCtx.InRes.GetType().Name != "Application" {
		return nil
	}

	//	err := crCtx.InRes.CheckMissingRequiredAts()
	//	if err != nil {
	//		return err
	//	}

	err := validateClient(crCtx.InRes, crCtx.OpContext)
	if err != nil {
		return err
	}

	return nil
}

func (ai *ApplicationInterceptor) PostCreate(crCtx *base.CreateContext) {
	// do nothing
}

func (ai *ApplicationInterceptor) PrePatch(patchCtx *base.PatchContext) error {
	return nil
}

func (ai *ApplicationInterceptor) PostPatch(patchedRs *base.Resource, patchCtx *base.PatchContext) {
}

func validateClient(rs *base.Resource, opCtx *base.OpContext) error {
	redUriAtName := "redirecturi"
	spIssuerName := "spissuer"
	idpIssuerName := "idpissuer"
	consentRequired := "consentrequired"

	at := rs.GetAttr(redUriAtName)

	// the redirectUri and issuer attributes are required but can be set to arbitrary
	// values if not provided for the convenience of admin users
	randStr := utils.NewRandShaStr()[:11]
	if at == nil {
		// add a default value
		rs.AddSA(redUriAtName, "https://"+opCtx.Session.Domain+"/redirect")
	}

	at = rs.GetAttr(spIssuerName)
	if at == nil {
		// add a default value
		rs.AddSA(spIssuerName, randStr)
	}

	at = rs.GetAttr(idpIssuerName)
	if at == nil {
		// add a default value
		rs.AddSA(idpIssuerName, "https://"+opCtx.Session.Domain+"/saml/idp")
	}

	at = rs.GetAttr(consentRequired)
	if at == nil {
		// add a default value
		rs.AddSA(consentRequired, false)
	}

	redirectUriAt := rs.GetAttr("redirecturi").GetSimpleAt()
	redUrlStr := redirectUriAt.GetStringVal()
	redUrl, err := url.Parse(strings.ToLower(redUrlStr))

	if err != nil {
		msg := fmt.Sprintf("Invalid redirect URI %s", redUrlStr)
		log.Debugf(msg)
		return base.NewBadRequestError(msg)
	}

	if redUrl.Scheme != "http" && redUrl.Scheme != "https" {
		msg := fmt.Sprintf("Unknown protocol in the redirect URI %s", redUrlStr)
		log.Debugf(msg)
		return base.NewBadRequestError(msg)
	}

	rs.AddSA("secret", utils.NewRandShaStr())
	rs.AddSA("serversecret", utils.NewRandShaStr())
	hasQuery := (len(redUrl.RawQuery) != 0)
	rs.AddSA("hasqueryinuri", hasQuery)

	return nil
}
