package net

import (
	"bytes"
	"compress/flate"
	"encoding/xml"
	"fmt"
	"github.com/beevik/etree"
	saml "github.com/russellhaering/gosaml2"
	"github.com/russellhaering/gosaml2/types"
	"github.com/russellhaering/goxmldsig"
	"io/ioutil"
	"net/http"
	"net/url"
	"sparrow/base"
	"sparrow/oauth"
	"sparrow/provider"
	"sparrow/utils"
	"strings"
	"text/template"
	"time"
)

const respXml = `<samlp:Response Destination="{{.DestinationUrl}}" ID="{{.RespId}}" InResponseTo="{{.ReqId}}" IssueInstant="{{.CurTime}}" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">
	<saml:Issuer>{{.IdpIssuer}}</saml:Issuer>
	<samlp:Status>
		<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
	</samlp:Status>
	<saml:Assertion ID="{{.AssertionId}}" IssueInstant="{{.CurTime}}" Version="2.0" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
		<saml:Issuer>{{.IdpIssuer}}</saml:Issuer>
		<saml:Subject>
			<saml:NameID SPNameQualifier="{{.SpIssuer}}" Format="{{.NameIdFormat}}">{{.NameId}}</saml:NameID>
			<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">
				<saml:SubjectConfirmationData InResponseTo="{{.ReqId}}" NotOnOrAfter="{{.NotOnOrAfter}}" Recipient="{{.DestinationUrl}}"/>
			</saml:SubjectConfirmation>
		</saml:Subject>
		<saml:Conditions NotBefore="{{.CurTime}}" NotOnOrAfter="{{.NotOnOrAfter}}">
		  <saml:AudienceRestriction>
			<saml:Audience>{{.SpIssuer}}</saml:Audience>
		  </saml:AudienceRestriction>
		</saml:Conditions>
		<saml:AuthnStatement AuthnInstant="{{.CurTime}}" SessionIndex="{{.SessionIndexId}}" SessionNotOnOrAfter="{{.SessionNotOnOrAfter}}">
			<saml:AuthnContext>
				<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>
			</saml:AuthnContext>
		</saml:AuthnStatement>
		{{if .Attributes}}
		<saml:AttributeStatement>
		{{range $_, $v := .Attributes}}
			{{$v}}
		{{end}}
		</saml:AttributeStatement>
		{{end}}
	</saml:Assertion>
</samlp:Response>`

const attributeXml = `<saml:Attribute Name="{{.Name}}" NameFormat="{{.Format}}">
  <saml:AttributeValue>{{.Value}}</saml:AttributeValue>
 </saml:Attribute>`

const logoutReqXml = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion" ID="{{.ReqId}}" IssueInstant="{{.IssueInstant}}" Version="2.0">
    <Issuer>{{.Issuer}}</Issuer>
    <NameID Format="{{.NameIDFormat}}">{{.NameId}}</NameID>
    <samlp:SessionIndex>{{.SessionIndex}}</samlp:SessionIndex>
</samlp:LogoutRequest>`

type samlResponse struct {
	DestinationUrl      string
	RespId              string
	ReqId               string
	IdpIssuer           string
	SpIssuer            string
	CurTime             string
	AssertionId         string
	NameId              string // only persistent format is supported
	NotOnOrAfter        string
	SessionIndexId      string
	SessionNotOnOrAfter string
	Attributes          map[string]string
	ResponseText        string
	RelayStateVal       string
	NameIdFormat        string
}

// this struct is used for sending out logout requests
type logoutReqTmplData struct {
	ID           string
	IssueInstant string
	Issuer       string
	NameID       string
	NameIDFormat string
	SessionIndex string
}

// this struct is used for parsing recieved logout requests
type LogoutRequest struct {
	ID           string    `xml:",attr"`
	Version      string    `xml:",attr"`
	IssueInstant time.Time `xml:",attr"`
	Issuer       string
	NameID       LogoutNameID
	SessionIndex string
}

type LogoutNameID struct {
	XMLName xml.Name `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	Format  string   `xml:",attr"`
	Value   string   `xml:",chardata"`
}

var respTemplate *template.Template
var attributeTemplate *template.Template
var metaTemplate *template.Template
var logoutReqTemplate *template.Template

const saml_received_via = "saml_received_via"

func init() {
	respTemplate = &template.Template{}
	attributeTemplate = &template.Template{}
	template.Must(respTemplate.Parse(respXml))
	template.Must(attributeTemplate.Parse(attributeXml))
	logoutReqTemplate = &template.Template{}
	template.Must(logoutReqTemplate.Parse(logoutReqXml))
	// for some unknown reason if the metaTemplate is parsed in an init()
	// inside idp_metadata_handler.go then it is failing with a nil pointer error
	metaTemplate = &template.Template{}
	template.Must(metaTemplate.Parse(idpMetadataXml))
}

func handleSamlLogout(w http.ResponseWriter, r *http.Request) {
	log.Debugf("handling SAML logout")

	err := r.ParseForm()
	if err != nil {
		err = fmt.Errorf("Failed to parse the request form %s", err.Error())
		log.Debugf("%s", err.Error())
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	relayState := strings.TrimSpace(r.Form.Get("RelayState"))
	if relayState == "" {
		relayState = "/ui"
	}

	samlReq := r.Form.Get("SAMLRequest")
	var logoutReq *LogoutRequest
	if samlReq != "" {
		data, err := readSamlReq(r)
		if err == nil {
			err = xml.Unmarshal(data, &logoutReq)
			if err != nil {
				log.Debugf("failed to parse logout request %v", err)
			}
		}
	}

	session := getSession(r)
	if session == nil && (&logoutReq == nil) { // both session and logout requests are nil
		log.Debugf("no session exists, redirecting to the relaystate %s", relayState)
		http.Redirect(w, r, relayState, http.StatusFound)
		return
	} else if logoutReq != nil { //
		_handleSamlBackChannelLogoutReq(r, w, logoutReq)
		return
	}

	pr := providers[session.Domain]

	if pr == nil {
		log.Debugf("invalid session, no provider found for %s", session.Domain)
		return
	}

	opCtx := &base.OpContext{}
	opCtx.Session = session
	opCtx.Sso = true
	opCtx.ClientIP = utils.GetRemoteAddr(r)
	opCtx.Endpoint = getEndpoint(r)
	pr.DeleteSsoSession(opCtx)

	_logoutSessionApps(pr, opCtx)
	http.Redirect(w, r, relayState, http.StatusFound)
}

// STEP 1 - check the presence of session otherwise redirect to login
func handleSamlReq(w http.ResponseWriter, r *http.Request) {
	log.Debugf("handling saml request")
	session := getSession(r)
	if session != nil {
		// valid session exists serve the SAMLResponse
		log.Debugf("Valid session exists, sending the final response")
		sendSamlResponse(w, r, session, nil)
		return
	}

	err := r.ParseForm()
	if err != nil {
		err = fmt.Errorf("Failed to parse the request form %s", err.Error())
		log.Debugf("%s", err.Error())
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	af := &authFlow{}
	af.SetFromSaml(true)

	setAuthFlow(af, w)

	paramMap, err := parseParamMap(r)
	if err != nil {
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	if r.Method == http.MethodGet {
		paramMap[saml_received_via] = http.MethodGet
	}

	log.Debugf("no valid session exists, redirecting to login")
	// do a redirect to /login with all the parameters
	redirect("/login", w, r, paramMap)
}

func parseParamMap(r *http.Request) (paramMap map[string]string, err error) {
	paramMap = make(map[string]string)

	for k, v := range r.Form {
		if len(v) > 1 {
			err = fmt.Errorf("Invalid request the parameter %s is included more than once", k)
			return nil, err
		}

		paramMap[k] = v[0]
	}

	return paramMap, nil
}

func sendSamlResponse(w http.ResponseWriter, r *http.Request, session *base.RbacSession, af *authFlow) {
	err := r.ParseForm()
	if err != nil {
		log.Debugf("Failed to parse the form, sending error to the user agent")
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	var samlAuthnReq saml.AuthNRequest
	data, err := readSamlReq(r)
	if err != nil {
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	log.Debugf("Received SAMLRequest: %s", string(data))
	err = xml.Unmarshal(data, &samlAuthnReq)
	if err != nil {
		err = fmt.Errorf("Failed to parse the SAML authentication request %s", err.Error())
		log.Debugf("%s", err.Error())
		sendSamlError(w, err, http.StatusBadRequest)
		return
	}

	//TODO verify signature of received SAML request

	log.Debugf("Received SAMLRequest is valid, searching for client")

	pr, _ := getPrFromParam(r)
	var cl *oauth.Client
	if pr != nil {
		cl = pr.GetClientByIssuer(samlAuthnReq.Issuer)
	}

	if cl == nil {
		err = fmt.Errorf("Application with issuer ID %s not found", samlAuthnReq.Issuer)
		log.Warningf("%s", err.Error())
		sendSamlError(w, err, http.StatusNotFound)
		return
	}

	allowed := false
	// if there are no groups then grant access to any user
	if len(cl.GroupIds) == 0 {
		allowed = true
	} else {
		for role, _ := range cl.GroupIds {
			if _, ok := session.Roles[role]; ok {
				allowed = true
				break
			}
		}
	}

	if !allowed {
		err = fmt.Errorf("User %s does not have privileges to access application with issuer ID %s", session.Sub, samlAuthnReq.Issuer)
		log.Warningf("%s", err.Error())
		sendSamlError(w, err, http.StatusForbidden)
		return
	}

	genSamlResponse(w, r, pr, session, cl, samlAuthnReq)
}

func genSamlResponse(w http.ResponseWriter, r *http.Request, pr *provider.Provider, session *base.RbacSession, cl *oauth.Client, authnReq saml.AuthNRequest) {
	user, err := pr.GetUserById(session.Sub)
	if err != nil {
		err = fmt.Errorf("Error while generating SAML response for the request ID %s", authnReq.ID)
		log.Warningf("%s", err.Error())
		sendSamlError(w, err, http.StatusInternalServerError)
		return
	}

	sp := samlResponse{}
	sp.AssertionId = "_" + utils.GenUUID()

	curTime := time.Now().UTC()

	sp.CurTime = curTime.Format(time.RFC3339)
	sp.NotOnOrAfter = curTime.Add(time.Duration(cl.Saml.AssertionValidity) * time.Second).Format(time.RFC3339)
	sp.DestinationUrl = authnReq.AssertionConsumerServiceURL
	log.Debugf("destination url %s", sp.DestinationUrl)
	sp.IdpIssuer = cl.Saml.IdpIssuer
	sp.SpIssuer = cl.Saml.SpIssuer
	sp.NameId = session.Sub
	sp.NameIdFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" // the default
	sp.ReqId = authnReq.ID
	sp.RespId = "_" + utils.GenUUID()
	sp.SessionIndexId = "_" + pr.DomainCode() + session.Jti + "." + utils.GenUUID() // prefix the session ID so that session data can be retrieved in backchannel logout
	sp.SessionNotOnOrAfter = curTime.Add(time.Duration(10) * time.Hour).Format(time.RFC3339)

	sp.Attributes = make(map[string]string)
	var buf bytes.Buffer
	for k, v := range cl.Saml.Attributes {
		if len(v.StaticVal) > 0 {
			if len(v.StaticMultiValDelim) == 0 {
				v.Value = v.StaticMultiValDelim
				attributeTemplate.Execute(&buf, v)
				sp.Attributes[k] = buf.String()
				buf.Reset()
			} else {
				splitValues := strings.Split(v.StaticVal, v.StaticMultiValDelim)
				for i, s := range splitValues {
					v.Value = s
					attributeTemplate.Execute(&buf, v)
					sp.Attributes[k+string(i)] = buf.String()
					buf.Reset()
				}
			}
		} else {
			val := v.GetValueFrom(user)
			if val != nil {
				if v.NormName == "nameid" {
					// special handling for NameId
					// this won't be added to the attribute statement
					sp.NameId = fmt.Sprint(val)
					if v.Format != "" {
						sp.NameIdFormat = v.Format
					}
				} else {
					v.Value = val
					attributeTemplate.Execute(&buf, v)
					sp.Attributes[k] = buf.String()
					buf.Reset()
				}
			}
		}
	}

	sas := base.SamlAppSession{NameID: sp.NameId, NameIDFormat: sp.NameIdFormat, SessionIndex: sp.SessionIndexId}
	go pr.AddAppToSsoSession(session.Jti, cl.Saml.SpIssuer, sas)

	respTemplate.Execute(&buf, sp)
	doc := etree.NewDocument()
	doc.ReadFromBytes(buf.Bytes())

	ctx := dsig.NewDefaultSigningContext(pr)
	ctx.SetSignatureMethod(dsig.RSASHA1SignatureMethod)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("ds")

	asrtn := doc.FindElement("//saml:Assertion")
	asrtnDoc := etree.NewDocument()
	asrtnDoc.SetRoot(asrtn)
	signedAsrtn, _ := signEnveloped(ctx, asrtnDoc.Root())
	asrtnDoc.SetRoot(signedAsrtn)

	root := doc.Root()
	root.RemoveChild(asrtn)
	root.AddChild(asrtnDoc.Root())

	//	c, _ := asrtnDoc.WriteToBytes()
	//	serAsrtn := utils.B64Encode(c)

	//root, _ := ctx.SignEnveloped(doc.Root())
	//doc.SetRoot(root)
	signedContent, _ := doc.WriteToBytes()
	sp.RelayStateVal = r.Form.Get("RelayState")
	sp.ResponseText = utils.B64Encode(signedContent)
	log.Debugf("SAML response: %s", sp.ResponseText)
	log.Debugf("RelayState: %s", sp.RelayStateVal)
	//log.Debugf("assertion: %s", serAsrtn)
	templates["saml_response.html"].Execute(w, sp)
}

func sendSamlError(w http.ResponseWriter, err error, status int) {
	http.Error(w, err.Error(), status)
}

func signEnveloped(ctx *dsig.SigningContext, el *etree.Element) (*etree.Element, error) {
	sig, err := ctx.ConstructSignature(el, true)
	if err != nil {
		return nil, err
	}

	ret := el.Copy()
	// place the signature exactly under <saml:Issuer> without which
	// gsuite fails to parse the response
	issuer := ret.FindElement("//saml:Issuer")
	if issuer != nil {
		pos := 1
		tmp := make([]etree.Token, 0)
		for i, c := range ret.Child {
			tmp = append(tmp, c)
			if c == issuer {
				pos = i
				break
			}
		}

		tmp = append(tmp, sig)
		ret.Child = append(tmp, ret.Child[pos+1:]...)
	} else {
		ret.Child = append(ret.Child, sig)
	}

	return ret, nil
}

func readSamlReq(r *http.Request) (data []byte, err error) {
	samlReq := r.Form.Get("SAMLRequest")
	receivedVia := r.Form.Get(saml_received_via)
	log.Debugf("http method %s", r.Method)

	if r.Method == http.MethodGet || receivedVia == http.MethodGet {
		log.Debugf("Received SAMLRequest (raw): %s", samlReq)
		if strings.Contains(samlReq, "%") {
			log.Debugf("URL decoding the received SAMLRequest")
			samlReq, _ = url.QueryUnescape(samlReq)
		}
		data, err = utils.B64Decode(samlReq)
		if err != nil {
			err = fmt.Errorf("Failed to base64 decode the SAML authentication request %s", err.Error())
			log.Debugf("%s", err.Error())
			return nil, err
		}

		if len(data) == 0 {
			err = fmt.Errorf("No SAML request is present")
			log.Debugf("%s", err.Error())
			return nil, err
		}

		// remove the GLIB header if present
		if data[0] == 0x78 && data[1] == 0x9C {
			data = data[2:]
		}
		r := flate.NewReader(bytes.NewReader(data))
		data, err = ioutil.ReadAll(r)
		r.Close()
		if err != nil {
			err = fmt.Errorf("Failed to inflate the SAML authentication request %s", err.Error())
			log.Debugf("%s", err.Error())
			return nil, err
		}
	} else {
		data, err = utils.B64Decode(samlReq)
		if err != nil {
			err = fmt.Errorf("Failed to base64 decode the SAML authentication request %s", err.Error())
			log.Debugf("%s", err.Error())
			return nil, err
		}
	}

	return data, nil
}

func _handleSamlBackChannelLogoutReq(r *http.Request, w http.ResponseWriter, logoutReq *LogoutRequest) {
	samlSessId := logoutReq.SessionIndex
	// extract SSO session ID
	pos := strings.Index(samlSessId, ".")
	ssoId := samlSessId[1:pos]
	domainCode := ssoId[:8]
	ssoId = ssoId[8:]

	pr := dcPrvMap[domainCode]
	if pr == nil {
		log.Debugf("invalid session index %s", samlSessId)
		return
	}

	session := pr.GetSsoSession(ssoId)
	opCtx := &base.OpContext{}
	opCtx.Session = session
	opCtx.Sso = true
	opCtx.ClientIP = utils.GetRemoteAddr(r)
	opCtx.Endpoint = getEndpoint(r)
	pr.DeleteSsoSession(opCtx)

	_logoutSessionApps(pr, opCtx)
}

func _logoutSessionApps(pr *provider.Provider, opCtx *base.OpContext) {
	lrtd := logoutReqTmplData{}
	lrtd.ID = "_" + utils.GenUUID()
	lrtd.IssueInstant = time.Now().UTC().Format(time.RFC3339)

	for iss, sas := range opCtx.Session.Apps {
		md := pr.SamlMdCache[iss]
		if md != nil {
			sloServices := md.SingleLogoutServices
			if len(sloServices) > 0 {
				log.Debugf("sending logout request to %s", iss)
				fmt.Println(sas)
				sendLogoutReq(sloServices[0], lrtd, sas)
			}
		} else {
			log.Debugf("there is no metadata for the issuer %s", iss)
		}
	}
}

func sendLogoutReq(endpoint types.Endpoint, lrtd logoutReqTmplData, sas base.SamlAppSession) {
	lrtd.SessionIndex = sas.SessionIndex
	lrtd.NameIDFormat = sas.NameIDFormat
	lrtd.NameID = sas.NameID

	var buf bytes.Buffer
	logoutReqTemplate.Execute(&buf, lrtd)
	if endpoint.Binding == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" {
		form := url.Values{}
		encodedSamlData := utils.B64Encode(buf.Bytes())
		form.Add("SAMLRequest", encodedSamlData)
		resp, err := http.PostForm(endpoint.Location, form)
		if err != nil {
			log.Debugf("failed to send the logout request to %s [%v]", endpoint.Location, err)
		} else {
			log.Debugf("received status %s", resp.Status)
			resp.Body.Close()
		}
	} else {
		log.Debugf("only HTTP-POST binding is supported by SingleLogout service, cannot send logout request to %s", endpoint.Location)
	}
}
