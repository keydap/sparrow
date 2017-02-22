package net

import (
	"crypto/tls"
	"errors"
	"fmt"
	"github.com/go-ldap/ldap"
	ber "gopkg.in/asn1-ber.v1"
	"io"
	"net"
	"runtime/debug"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/schema"
	"strconv"
	"strings"
)

type LdapSession struct {
	Id    string
	con   net.Conn
	token *base.RbacSession
}

var ldapSessions = make(map[string]*LdapSession)

var tlsConf *tls.Config

func startLdap() error {
	hostAddr := srvConf.Ipaddress + ":" + strconv.Itoa(srvConf.LdapPort)

	log.Infof("Starting ldap server %s", hostAddr)
	laddr, err := net.ResolveTCPAddr("tcp", hostAddr)
	if err != nil {
		log.Warningf("Failed to resolve the local address, %s", err)
		return err
	}

	listener, err := net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Warningf("Failed to listen at the local address %s, %s", hostAddr, err)
		return err
	}

	tlsConf = &tls.Config{}
	tlsCert, _ := tls.LoadX509KeyPair(srvConf.CertFile, srvConf.PrivKeyFile)
	tlsConf.Certificates = []tls.Certificate{tlsCert}

	go acceptConns(listener)

	return nil
}

func acceptConns(listener *net.TCPListener) {
	for {
		con, err := listener.AcceptTCP()
		if err != nil {
			log.Warningf("Failed to accept connection %s", err)
			continue
		}

		remoteAddr := con.RemoteAddr().String()
		log.Debugf("Serving new connection from %s", remoteAddr)
		ls := &LdapSession{}
		ls.Id = remoteAddr
		ls.con = con
		ldapSessions[remoteAddr] = ls
		go serveClient(ls)
	}
}

func serveClient(ls *LdapSession) {
	defer func() {
		e := recover()
		if e != nil {
			log.Criticalf("recovered from panic while serving LDAP client %v", e)
			debug.PrintStack()
		}

		log.Debugf("closing connection %s", ls.Id)
		ls.con.Close()
		delete(ldapSessions, ls.Id)
	}()

	for {
		packet, err := ber.ReadPacket(ls.con)
		if err != nil {
			if err == io.ErrUnexpectedEOF || err == io.EOF {
				break
			}

			log.Warningf("error while reading packet %s", err)
			//le := ldap.NewError(ldap.LDAPResultOther, err)
			//ber.Encode(ber.ClassApplication, TagType, Tag, Value, "Insufficient packet bytes")
			continue
		}

		if log.IsDebugEnabled() {
			log.Debugf("read packet with children %d", len(packet.Children))
			ber.PrintPacket(packet)
		}

		messageId := int(packet.Children[0].Value.(int64))
		appMessage := packet.Children[1]

		switch appMessage.Tag {
		case ldap.ApplicationBindRequest:
			secure := isSecure(messageId, ldap.ApplicationBindResponse, ls)
			if !secure {
				continue
			}

			bindReq := &ldap.SimpleBindRequest{}
			bindReq.Username = string(appMessage.Children[1].ByteValue)
			bindReq.Password = string(appMessage.Children[2].Data.Bytes())

			handleSimpleBind(bindReq, ls, messageId)

		case ldap.ApplicationSearchRequest:
			secure := isSecure(messageId, ldap.ApplicationSearchResultDone, ls)
			if !secure {
				continue
			}

			if ls.token == nil {
				// throw unauthorized error
				errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights, "insufficientAccessRights")
				ls.con.Write(errResp.Bytes())
				continue
			}

			handleSearch(messageId, packet, ls)

		case ldap.ApplicationExtendedRequest:
			oid := string(appMessage.Children[0].Data.Bytes())
			if oid == "1.3.6.1.4.1.1466.20037" { // startTLS
				resp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess, "")
				ls.con.Write(resp.Bytes())
				startTls(messageId, ls)
			} else {
				errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultOther, "Unsupported extended operation "+oid)
				ls.con.Write(errResp.Bytes())
			}

		default:
			log.Warningf("Unsupported operation")
			//errResp := generateResultCode(messageId, ?, ldap.LDAPResultOther, "Unsupported operation")
			//ls.con.Write(errResp.Bytes())
		}
	}
}

func isSecure(messageId int, appRespTag ber.Tag, ls *LdapSession) bool {
	_, isTlsCon := ls.con.(*tls.Conn)
	if srvConf.LdapOverTlsOnly && !isTlsCon {
		errResp := generateResultCode(messageId, appRespTag, ldap.LDAPResultConfidentialityRequired, "operations are allowed only on connections secured using TLS")
		ls.con.Write(errResp.Bytes())
		return false
	}

	return true
}

func startTls(messageId int, ls *LdapSession) {
	log.Debugf("securing the connection %s using startTLS", ls.Id)
	ls.con = tls.Server(ls.con, tlsConf)
}

func handleSimpleBind(bindReq *ldap.SimpleBindRequest, ls *LdapSession, messageId int) {
	log.Debugf("handling bind request from %s", ls.Id)
	log.Debugf("username = %s , password %s", bindReq.Username, bindReq.Password)

	domain, _ := getDomainAndEndpoint(bindReq.Username)

	pr := providers[domain]

	if pr == nil {
		errResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "Invalid username or password")
		ls.con.Write(errResp.Bytes())
		return
	}

	bindReq.Username = getUsernameFromDn(bindReq.Username)
	user := pr.Authenticate(bindReq.Username, bindReq.Password)
	if user == nil {
		errResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "Invalid username or password")
		ls.con.Write(errResp.Bytes())
		return
	}

	ls.token = pr.GenSessionForUser(user)
	successResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "")
	ls.con.Write(successResp.Bytes())
}

func getUsernameFromDn(baseDn string) string {
	rdns := strings.Split(baseDn, ",")

	pos := strings.IndexRune(rdns[0], '=')

	return rdns[0][pos+1:]
}

func generateResultCode(messageId int, appRespTag ber.Tag, resultCode int, errMsg string) *ber.Packet {
	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, appRespTag, nil, "Response")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, resultCode, "Result code"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, errMsg, "Error message"))
	response.AppendChild(result)

	return response
}

func toSearchContext(req ldap.SearchRequest, ls *LdapSession) (searchCtx *base.SearchContext, pr *provider.Provider, err error) {
	opCtx := &base.OpContext{}
	opCtx.ClientIP = ls.Id

	searchCtx = &base.SearchContext{}
	searchCtx.OpContext = opCtx

	// detect ResourceTypes from baseDN
	domain, endPoint := getDomainAndEndpoint(req.BaseDN)
	searchCtx.Endpoint = endPoint

	pr = providers[domain]

	if pr == nil {
		return nil, nil, fmt.Errorf("Invalid base DN '%s'", domain)
	}

	searchCtx.ResTypes = make([]*schema.ResourceType, 0)

	rt := pr.RtPathMap[searchCtx.Endpoint]
	if rt != nil {
		searchCtx.ResTypes = append(searchCtx.ResTypes, rt)
	} else {
		for _, v := range pr.RsTypes {
			searchCtx.ResTypes = append(searchCtx.ResTypes, v)
		}
	}

	searchCtx.MaxResults = req.SizeLimit
	searchCtx.Session = ls.token

	return searchCtx, pr, nil
}

func toLdapSearchRequest(packet *ber.Packet) ldap.SearchRequest {
	req := ldap.SearchRequest{}
	req.BaseDN = strings.TrimSpace(packet.Children[0].Value.(string))
	req.Scope = int(packet.Children[1].Value.(int64))
	// derefAliases := int(packet.Children[2].Value.(int64))
	req.SizeLimit = int(packet.Children[3].Value.(int64))
	req.TimeLimit = int(packet.Children[4].Value.(int64))
	req.TypesOnly = packet.Children[5].Value.(bool)
	// ldapFilter, err := ldap.DecompileFilter(packet.Children[6])

	return req
}

func handleSearch(messageId int, packet *ber.Packet, ls *LdapSession) {
	log.Debugf("handling search request from %s", ls.Id)
	child := packet.Children[1]

	ldapReq := toLdapSearchRequest(child)

	// RootDSE search
	if len(ldapReq.BaseDN) == 0 {
		sendRootDSE(messageId, ls)
		return
	}

	sc, pr, err := toSearchContext(ldapReq, ls)

	if err != nil {
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	attrLst, err := parseFilter(child, ldapReq, sc, pr)
	if err != nil {
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultOther, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	outPipe := make(chan *base.Resource, 0)

	// search starts a go routine and returns nil error immediately
	// or returns an error before starting the go routine
	err = pr.Search(sc, outPipe)
	if err != nil {
		close(outPipe)
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultOther, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	for rs := range outPipe {
		sendSearchResultEntry(rs, attrLst, pr, messageId, ls)
	}

	entryEnvelope := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
	ls.con.Write(entryEnvelope.Bytes())
}

func sendRootDSE(messageId int, ls *LdapSession) {
	rootDseEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	rootDseEnvelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	se := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "RootDSE")
	se.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "RootDSE DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "RootDSE Attributes")

	ocLdapAt := &schema.LdapAttribute{LdapAttrName: "objectClass"}
	addAttributeStringsPacket(ocLdapAt, attributes, "top", "extensibleObject")

	vendorLdapAt := &schema.LdapAttribute{LdapAttrName: "vendorName"}
	addAttributeStringsPacket(vendorLdapAt, attributes, "Keydap Software")

	versionLdapAt := &schema.LdapAttribute{LdapAttrName: "vendorVersion"}
	addAttributeStringsPacket(versionLdapAt, attributes, "1.0") //TODO fix the hardcoded version

	se.AppendChild(attributes)
	rootDseEnvelope.AppendChild(se)
	ls.con.Write(rootDseEnvelope.Bytes())

	result := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
	ls.con.Write(result.Bytes())
}

func sendSearchResultEntry(rs *base.Resource, attrLst []*base.AttributeParam, pr *provider.Provider, messageId int, ls *LdapSession) {
	typeName := rs.GetType().Name
	tmpl := pr.LdapTemplates[typeName]
	if tmpl == nil {
		return
	}

	dnAtVal := "at-not-found"
	dnAt := rs.GetAttr(tmpl.DnAtName)
	if dnAt != nil {
		dnAtVal = fmt.Sprintf("%s", dnAt.GetSimpleAt().Values[0])
	}

	dn := fmt.Sprintf(tmpl.DnPrefix, dnAtVal, pr.Name)

	entryEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	entryEnvelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	se := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SerchResultEntry")
	se.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Entry Attributes")

	ocLdapAt := &schema.LdapAttribute{LdapAttrName: "objectClass"}
	addAttributeStringsPacket(ocLdapAt, attributes, tmpl.ObjectClasses...)

	for _, ap := range attrLst {
		at := rs.GetAttr(ap.Name)
		if at == nil {
			continue
		}

		atType := at.GetType()

		if atType.IsSimple() {
			ldapAt := tmpl.AttrMap[ap.Name]
			if ldapAt != nil {
				sa := at.GetSimpleAt()
				// the varargs is necessary otherwise caller will treat the entire array as one interface value
				addAttributePacket(ldapAt, attributes, sa.Values...)
			}
		} else {
			ca := at.GetComplexAt()
			ldapAt := tmpl.AttrMap[ap.Name]
			if ldapAt != nil {
				// fill in the format
				values := make([]string, 0)
				for _, mapOfSa := range ca.SubAts {
					formattedVal := ""
					valPresent := false
					for _, sn := range ldapAt.SubAtNames {
						sa, ok := mapOfSa[sn]
						if ok {
							formattedVal += fmt.Sprintf("%s", sa.Values[0])
							valPresent = true
						}

						formattedVal += ldapAt.FormatDelim
					}

					if valPresent {
						fvl := len(formattedVal) - 1
						values = append(values, formattedVal[:fvl])
					}
				}

				if len(values) > 0 {
					addAttributeStringsPacket(ldapAt, attributes, values...)
				}
			}
			// FIXME schema URI prefixed attributes won't work in the below scheme
			// check if any attribute starts with ca.name + "."
			for _, subAt := range atType.SubAttributes {
				ldapAt := tmpl.AttrMap[ap.Name+"."+subAt.NormName]
				if ldapAt != nil {
					subAtVal := ca.GetValue(subAt.NormName)
					if subAtVal != nil {
						addAttributePacket(ldapAt, attributes, subAtVal)
					}
				}
			}
		}
	}

	se.AppendChild(attributes)
	entryEnvelope.AppendChild(se)
	ls.con.Write(entryEnvelope.Bytes())
}

func addAttributePacket(ldapAt *schema.LdapAttribute, attributes *ber.Packet, scimValues ...interface{}) {
	atPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, ldapAt.LdapAttrName+" Attribute")
	atPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ldapAt.LdapAttrName, ldapAt.LdapAttrName))
	atValuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, ldapAt.LdapAttrName+" Attribute Values")
	for _, v := range scimValues {
		strVal := fmt.Sprintf("%s", v)
		atValuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, strVal, strVal))
	}
	atPacket.AppendChild(atValuesPacket)
	attributes.AppendChild(atPacket)
}

func addAttributeStringsPacket(ldapAt *schema.LdapAttribute, attributes *ber.Packet, strValues ...string) {
	atPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, ldapAt.LdapAttrName+" Attribute")
	atPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, ldapAt.LdapAttrName, ldapAt.LdapAttrName))
	atValuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, ldapAt.LdapAttrName+" Attribute Values")
	for _, v := range strValues {
		atValuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, v, v))
	}
	atPacket.AppendChild(atValuesPacket)
	attributes.AppendChild(atPacket)
}

// converts a packet representation of a LDAP filter into a string representation of SCIM filter
// taken from go-ldap
func ldapToScimFilter(packet *ber.Packet, sc *base.SearchContext, pr *provider.Provider) (ret string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = ldap.NewError(ldap.ErrorFilterDecompile, errors.New("ldap: error decompiling filter"))
		}
	}()
	ret = "("
	err = nil
	childStr := ""

	switch packet.Tag {
	case ldap.FilterAnd:
		nc := len(packet.Children) - 1
		for i, child := range packet.Children {
			childStr, err = ldapToScimFilter(child, sc, pr)
			if err != nil {
				return
			}
			ret += childStr
			if i < nc {
				ret += " AND "
			}
		}
	case ldap.FilterOr:
		nc := len(packet.Children) - 1
		for i, child := range packet.Children {
			childStr, err = ldapToScimFilter(child, sc, pr)
			if err != nil {
				return
			}
			ret += childStr
			if i < nc {
				ret += " OR "
			}
		}
	case ldap.FilterNot:
		ret += "NOT "
		childStr, err = ldapToScimFilter(packet.Children[0], sc, pr)
		if err != nil {
			return
		}
		ret += childStr

	case ldap.FilterSubstrings:
		atName := ber.DecodeString(packet.Children[0].Data.Bytes())
		atName, atType := findScimName(atName, sc, pr)
		ret += atName
		ret += " co "
		for i, child := range packet.Children[1].Children {
			if i == 0 && child.Tag != ldap.FilterSubstringsInitial {
				//ret += "*"
			}
			val := ber.DecodeString(child.Data.Bytes())
			if atType != nil {
				if atType.IsStringType() {
					val = `"` + val + `"`
				}
			}

			ret += val
			if child.Tag != ldap.FilterSubstringsFinal {
				//ret += "*"
			}
		}
	case ldap.FilterEqualityMatch, ldap.FilterApproxMatch:
		atName := ber.DecodeString(packet.Children[0].Data.Bytes())
		atName, atType := findScimName(atName, sc, pr)
		ret += atName
		ret += " eq "

		val := ber.DecodeString(packet.Children[1].Data.Bytes())
		if atType != nil {
			if atType.IsStringType() {
				val = `"` + val + `"`
			}
		}

		ret += val
	case ldap.FilterGreaterOrEqual:
		atName := ber.DecodeString(packet.Children[0].Data.Bytes())
		atName, atType := findScimName(atName, sc, pr)
		ret += atName
		ret += " ge "

		val := ber.DecodeString(packet.Children[1].Data.Bytes())
		if atType != nil {
			if atType.IsStringType() {
				val = `"` + val + `"`
			}
		}

		ret += val
	case ldap.FilterLessOrEqual:
		atName := ber.DecodeString(packet.Children[0].Data.Bytes())
		atName, atType := findScimName(atName, sc, pr)
		ret += atName
		ret += " le "

		val := ber.DecodeString(packet.Children[1].Data.Bytes())
		if atType != nil {
			if atType.IsStringType() {
				val = `"` + val + `"`
			}
		}

		ret += val
	case ldap.FilterPresent:
		atName := ber.DecodeString(packet.Data.Bytes())
		atName, _ = findScimName(atName, sc, pr)
		ret += atName
		ret += " pr "
	case ldap.FilterExtensibleMatch:
		// unsupported
	}

	ret += ")"
	return
}

func findScimName(ldapAtName string, sc *base.SearchContext, pr *provider.Provider) (scimAtName string, atType *schema.AttrType) {
	log.Debugf("Finding mapped SCIM name for ldap attribute %s", ldapAtName)
	ldapAtName = strings.ToLower(ldapAtName)
	for _, rt := range sc.ResTypes {
		tmpl := pr.LdapTemplates[rt.Name]
		if tmpl != nil {
			scimName, ok := tmpl.LdapToScimAtMap[ldapAtName]
			if ok {
				log.Debugf("Found SCIM name %s for ldap attribute %s", scimName, ldapAtName)
				return scimName, tmpl.AttrMap[scimName].AtType
			}
		}
	}

	return ldapAtName, nil
}

func getDomainAndEndpoint(baseDN string) (domain string, endPoint string) {
	rdns := strings.Split(baseDN, ",")

	rdnLen := len(rdns)
	if rdnLen < 2 {
		return domain, endPoint
	}

	for i, v := range rdns {
		v = strings.ToLower(v)
		pos := strings.Index(v, "dc=")
		if pos == 0 {
			if domain == "" {
				domain += v[3:]
			} else {
				domain += ("." + v[3:])
			}
		}
		pos = strings.Index(v, "ou=")
		if pos == 0 {
			endPoint = "/" + rdns[i][3:]
		}
	}

	return strings.ToLower(domain), endPoint
}

func parseFilter(packet *ber.Packet, ldapReq ldap.SearchRequest, searchCtx *base.SearchContext, pr *provider.Provider) (attrParam []*base.AttributeParam, err error) {
	scimFilter, err := ldapToScimFilter(packet.Children[6], searchCtx, pr)
	if err != nil {
		return nil, err
	}

	log.Debugf("SCIM filter %s", scimFilter)

	// handle OBJECT scope
	if ldapReq.Scope == 0 {
		if len(searchCtx.Endpoint) == 0 {
			return nil, errors.New("Invalid base DN for searching at object scope")
		}

		tmpl := pr.LdapTemplates[searchCtx.Endpoint]
		if tmpl == nil {
			return nil, fmt.Errorf("No ldap template configured for resource '%s'", searchCtx.Endpoint)
		}

		rdnVal := getUsernameFromDn(ldapReq.BaseDN)

		// FIXME not checking the DN attribute's type, just using string
		scimFilter = tmpl.DnAtName + " eq \"" + rdnVal + "\" AND " + scimFilter
	}

	searchCtx.Filter, err = base.ParseFilter(scimFilter)
	if err != nil {
		return nil, err
	}

	reqAttrs := ""
	hasStar := false
	hasPlus := false

	attrChildren := packet.Children[7].Children
	for _, c := range attrChildren {
		name := strings.TrimSpace(c.Value.(string))
		name = strings.ToLower(name)
		if name == "*" {
			hasStar = true
			continue
		}

		if name == "+" {
			hasPlus = true
			continue
		}

		foundScimAt := false
		for _, rt := range searchCtx.ResTypes {
			tmpl := pr.LdapTemplates[rt.Name]
			if tmpl != nil {
				scimName, ok := tmpl.LdapToScimAtMap[name]
				if ok {
					name = scimName
					foundScimAt = true
					break
				}
			}
		}
		if !foundScimAt {
			log.Debugf("No equivalent SCIM attribute found for the requested LDAP attribute %s", name)
			continue
		}

		reqAttrs += (name + ",")
	}

	searchCtx.ParamAttrs = reqAttrs

	attrSet, subAtPresent := base.SplitAttrCsv(reqAttrs, searchCtx.ResTypes)

	if attrSet == nil {
		attrSet = make(map[string]int)
	}

	// the mandatory attributes that will always be returned
	for _, rt := range searchCtx.ResTypes {
		for k, _ := range rt.AtsAlwaysRtn {
			attrSet[k] = 1
		}

		if hasPlus || hasStar {
			for k, _ := range rt.AtsRequestRtn {
				attrSet[k] = 1
			}

			for k, _ := range rt.AtsDefaultRtn {
				attrSet[k] = 1
			}
		}

		for k, _ := range rt.AtsNeverRtn {
			if _, ok := attrSet[k]; ok {
				delete(attrSet, k)
			}
		}
	}

	// sort the names and eliminate redundant values, for example "name, name.familyName" will be reduced to name
	attrParam = base.ConvertToParamAttributes(attrSet, subAtPresent)

	return attrParam, nil
}
