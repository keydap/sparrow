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

func (ai *ApplicationInterceptor) PostPatch(patchCtx *base.PatchContext) {
}

func validateClient(rs *base.Resource, opCtx *base.OpContext) error {
	redUriAtName := "redirecturi"
	spIssuerName := "spissuer"
	idpIssuerName := "idpissuer"
	consentRequired := "consentrequired"
	icon := "icon"

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
		rs.AddSA(idpIssuerName, opCtx.Session.Domain)
	} else {
		at.GetSimpleAt().Values[0] = opCtx.Session.Domain // overwrite the value
	}

	at = rs.GetAttr(consentRequired)
	if at == nil {
		// add a default value
		rs.AddSA(consentRequired, false)
	}

	at = rs.GetAttr(icon)
	if at != nil {
		val := at.GetSimpleAt().GetStringVal()
		if !strings.HasPrefix(val, "data:image/") {
			// send error
			return base.NewBadRequestError("invalid image data given for icon attribute")
		}
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

func (ai *ApplicationInterceptor) PreDelete(delCtx *base.DeleteContext) error {
	return nil
}

func (ai *ApplicationInterceptor) PostDelete(delCtx *base.DeleteContext) {
}
