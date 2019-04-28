// Copyright 2017 Keydap. All rights reserved.
// Licensed under the Apache License, Version 2.0, see LICENSE.

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
	"sparrow/utils"
	"strconv"
	"strings"
)

type LdapSession struct {
	Id       string
	con      net.Conn
	username string
	*base.OpContext
}

func (sp *Sparrow) startLdap() error {
	hostAddr := sp.srvConf.IpAddress + ":" + strconv.Itoa(sp.srvConf.LdapPort)

	log.Infof("Starting ldap server...")
	laddr, err := net.ResolveTCPAddr("tcp", hostAddr)
	if err != nil {
		log.Warningf("Failed to resolve the local address, %s", err)
		return err
	}

	sp.listener, err = net.ListenTCP("tcp", laddr)
	if err != nil {
		log.Warningf("Failed to listen at the local address %s, %s", hostAddr, err)
		return err
	}

	tlsConf := &tls.Config{}
	tlsCert, _ := tls.LoadX509KeyPair(sp.srvConf.CertFile, sp.srvConf.PrivKeyFile)
	tlsConf.Certificates = []tls.Certificate{tlsCert}

	go acceptConns(sp, tlsConf)

	log.Infof("LDAP server is accessible at ldap://%s", hostAddr)
	return nil
}

func (sp *Sparrow) stopLdap() {
	sp.listener.Close()
	log.Debugf("Stopped LDAP server")
}

func acceptConns(sp *Sparrow, tlsConf *tls.Config) {
	for {
		con, err := sp.listener.AcceptTCP()
		if err != nil {
			if oe, ok := err.(*net.OpError); ok {
				// Source will be null if the listener was closed
				if oe.Source == nil {
					break
				}
			}

			log.Warningf("Failed to accept connection %#v", err)
			continue
		}

		remoteAddr := con.RemoteAddr().String()
		log.Debugf("Serving new connection from %s", remoteAddr)
		ls := &LdapSession{}
		ls.OpContext = &base.OpContext{}
		ls.ClientIP = remoteAddr
		ls.con = con
		go serveClient(ls, sp, tlsConf)
	}
}

func serveClient(ls *LdapSession, sp *Sparrow, tlsConf *tls.Config) {
	defer func() {
		e := recover()
		if e != nil {
			log.Criticalf("recovered from panic while serving LDAP client %v", e)
			debug.PrintStack()
		}

		log.Debugf("closing connection %s", ls.ClientIP)
		ls.con.Close()
		if ls.Session != nil {
			pr := sp.providers[ls.Session.Domain]
			if pr != nil {
				pr.Al.LogDelSession(ls.OpContext, true)
			}
		}
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
			break
		}

		messageId := int(packet.Children[0].Value.(int64))
		appMessage := packet.Children[1]

		if log.IsDebugEnabled() {
			log.Debugf("received LDAP request with tag %d", appMessage.Tag)
			log.Debugf("read packet with children %d", len(packet.Children))
			ber.PrintPacket(packet)
		}

		switch appMessage.Tag {
		case ldap.ApplicationBindRequest:
			secure := isSecure(sp, messageId, ldap.ApplicationBindResponse, ls)
			if !secure {
				continue
			}

			bindReq := &ldap.SimpleBindRequest{}
			bindReq.Username = string(appMessage.Children[1].ByteValue)
			// password is sometimes coming as wrong or empty
			bindReq.Password = string(appMessage.Children[2].Data.Bytes())

			handleSimpleBind(sp, bindReq, ls, messageId)

		case ldap.ApplicationUnbindRequest:
			return // defer() will close the connection

		case ldap.ApplicationSearchRequest:
			secure := isSecure(sp, messageId, ldap.ApplicationSearchResultDone, ls)
			if !secure {
				continue
			}

			if ls.Session == nil {
				// throw unauthorized error
				errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultInsufficientAccessRights, "insufficientAccessRights")
				ls.con.Write(errResp.Bytes())
				continue
			}

			handleSearch(sp, messageId, packet, ls)

		case ldap.ApplicationExtendedRequest:
			oid := string(appMessage.Children[0].Data.Bytes())
			if oid == "1.3.6.1.4.1.1466.20037" { // startTLS
				resp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess, "")
				ls.con.Write(resp.Bytes())
				startTls(messageId, ls, tlsConf)
			} else if oid == "1.3.6.1.4.1.4203.1.11.1" { // PasswordModify
				secure := isSecure(sp, messageId, ldap.ApplicationExtendedResponse, ls)
				if !secure {
					continue
				}

				modifyPassword(sp, messageId, appMessage.Children[1], ls)
			} else {
				errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultOther, "Unsupported extended operation "+oid)
				ls.con.Write(errResp.Bytes())
			}

		case ldap.ApplicationAbandonRequest:
			log.Debugf("abandon request with id %d", messageId)

		default:
			log.Warningf("Unsupported operation application request tag %d", appMessage.Tag)
			//errResp := generateResultCode(messageId, ?, ldap.LDAPResultOther, "Unsupported operation")
			//ls.con.Write(errResp.Bytes())
		}
	}
}

func isSecure(sp *Sparrow, messageId int, appRespTag ber.Tag, ls *LdapSession) bool {
	_, isTlsCon := ls.con.(*tls.Conn)
	if sp.srvConf.LdapOverTlsOnly && !isTlsCon {
		errResp := generateResultCode(messageId, appRespTag, ldap.LDAPResultConfidentialityRequired, "operation is allowed only on connections secured using TLS")
		ls.con.Write(errResp.Bytes())
		return false
	}

	return true
}

func startTls(messageId int, ls *LdapSession, tlsConf *tls.Config) {
	log.Debugf("securing the connection %s using startTLS", ls.ClientIP)
	ls.con = tls.Server(ls.con, tlsConf)
}

func handleSimpleBind(sp *Sparrow, bindReq *ldap.SimpleBindRequest, ls *LdapSession, messageId int) {
	log.Debugf("handling bind request from %s", ls.ClientIP)
	log.Debugf("bind dn = %s", bindReq.Username)

	domain, _ := getDomainAndEndpoint(bindReq.Username)

	pr := sp.providers[domain]

	if pr == nil {
		errResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "Invalid username or password")
		ls.con.Write(errResp.Bytes())
		return
	}

	bindReq.Username = getUsernameFromDn(bindReq.Username)
	ar := base.AuthRequest{Username: bindReq.Username, Password: bindReq.Password, ClientIP: ls.ClientIP}

	user := ldap_authenticate(ar, pr)
	if user == nil {
		errResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultInvalidCredentials, "Invalid username or password")
		ls.con.Write(errResp.Bytes())
		return
	}

	ls.Session = pr.GenSessionForUser(user)
	ls.username = user.GetAttr("username").GetSimpleAt().GetStringVal()
	ls.username = strings.ToLower(ls.username)
	successResp := generateResultCode(messageId, ldap.ApplicationBindResponse, ldap.LDAPResultSuccess, "")
	ls.con.Write(successResp.Bytes())
}

func getUsernameFromDn(baseDn string) string {
	rdns := strings.Split(baseDn, ",")
	if len(rdns) == 0 {
		log.Debugf("Empty DN given")
		return ""
	}

	pos := strings.IndexRune(rdns[0], '=')

	if pos <= 0 {
		log.Debugf("Invalid DN given %s", baseDn)
		return ""
	}
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

func toSearchContext(req ldap.SearchRequest, ls *LdapSession, sp *Sparrow) (searchCtx *base.SearchContext, pr *provider.Provider, err error) {
	sr := &base.SearchRequest{Schemas: []string{"urn:ietf:params:scim:api:messages:2.0:SearchRequest"}}
	sr.Count = req.SizeLimit
	searchCtx = &base.SearchContext{}
	searchCtx.RawReq = sr
	searchCtx.OpContext = ls.OpContext

	// detect ResourceTypes from baseDN
	domain, endPoint := getDomainAndEndpoint(req.BaseDN)
	searchCtx.Endpoint = endPoint

	pr = sp.providers[domain]

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

func handleSearch(sp *Sparrow, messageId int, packet *ber.Packet, ls *LdapSession) {
	log.Debugf("handling search request from %s", ls.username)
	child := packet.Children[1]

	ldapReq := toLdapSearchRequest(child)

	// RootDSE search
	if len(ldapReq.BaseDN) == 0 {
		sendRootDSE(sp, messageId, ls)
		return
	}

	sc, pr, err := toSearchContext(ldapReq, ls, sp)

	if pr != nil {
		defer pr.Al.Log(sc, nil, err)
	}

	if err != nil {
		log.Warningf("%s", err)
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultNoSuchObject, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	objectScope := (ldapReq.Scope == 0)
	isVirtual := false
	isDc := strings.HasPrefix(ldapReq.BaseDN, "dc=")
	isOu := strings.HasPrefix(ldapReq.BaseDN, "ou=")
	if ((ldapReq.Scope < 2) && isDc) || (objectScope && isOu) {
		isVirtual = true
	}

	// handle OBJECT scope of namingContext
	if isVirtual {
		sendVirtualBase(ldapReq, pr, messageId, ls)
		return
	}

	// for ONE level searches under a resource entry return nothing
	if ldapReq.Scope == 1 && !isDc && !isOu {
		resp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
		ls.con.Write(resp.Bytes())
		return
	}

	attrLst, err := parseFilter(child, ldapReq, sc, pr)
	if err != nil {
		log.Warningf("%s", err)
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultOther, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	attrByRtName := make(map[string]map[string]*base.AttributeParam)
	domainBaseDn := domainNameToDn(pr.Name)

	// special handling for reading selfentry
	if objectScope && isSelfServe(ls, ldapReq) {
		attrByRtName["User"] = attrLst
		rs, _ := pr.GetUserById(ls.Session.Sub)
		sendSearchResultEntry(rs, pr, messageId, ls, domainBaseDn, attrByRtName)

		entryEnvelope := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
		ls.con.Write(entryEnvelope.Bytes())

		return
	}

	// more generic searching
	for _, rt := range sc.ResTypes {
		rp := ls.OpContext.Session.EffPerms[rt.Name]
		if rp == nil {
			continue
		}

		if !rp.ReadPerm.AllowAll {
			tmp := make(map[string]*base.AttributeParam)
			for k, v := range attrLst {
				tmp[k] = v
			}
			filterAllowedAttrs(rp.ReadPerm.AllowAttrs, tmp)
			attrByRtName[rt.Name] = tmp
		} else {
			attrByRtName[rt.Name] = attrLst
		}
	}

	outPipe := make(chan *base.Resource, 0)

	// search starts a go routine and returns nil error immediately
	// or returns an error before starting the go routine
	err = pr.Search(sc, outPipe)
	if err != nil {
		log.Debugf("failed to search %s", err)
		close(outPipe)
		errResp := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultOther, err.Error())
		ls.con.Write(errResp.Bytes())
		return
	}

	for rs := range outPipe {
		//log.Debugf("sending ldap entry %s", rs)
		sendSearchResultEntry(rs, pr, messageId, ls, domainBaseDn, attrByRtName)
	}

	entryEnvelope := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
	ls.con.Write(entryEnvelope.Bytes())
}

func sendRootDSE(sp *Sparrow, messageId int, ls *LdapSession) {
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
	addAttributeStringsPacket(versionLdapAt, attributes, SparrowVersion)

	namingContextsAt := &schema.LdapAttribute{LdapAttrName: "namingContexts"}
	for k, _ := range sp.providers {
		dn := domainNameToDn(k)
		addAttributeStringsPacket(namingContextsAt, attributes, dn)
	}

	supportedExtAt := &schema.LdapAttribute{LdapAttrName: "supportedExtension"}
	addAttributeStringsPacket(supportedExtAt, attributes, "1.3.6.1.4.1.1466.20037")
	addAttributeStringsPacket(supportedExtAt, attributes, "1.3.6.1.4.1.4203.1.11.1")

	uuidAt := &schema.LdapAttribute{LdapAttrName: "entryUUID"}
	addAttributeStringsPacket(uuidAt, attributes, utils.GenUUID())

	ldapVersionAt := &schema.LdapAttribute{LdapAttrName: "supportedLDAPVersion"}
	addAttributeStringsPacket(ldapVersionAt, attributes, "3")

	se.AppendChild(attributes)
	rootDseEnvelope.AppendChild(se)
	ls.con.Write(rootDseEnvelope.Bytes())

	result := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
	ls.con.Write(result.Bytes())
}

func sendSearchResultEntry(rs *base.Resource, pr *provider.Provider, messageId int, ls *LdapSession, domainBaseDn string, attrByRtName map[string]map[string]*base.AttributeParam) {
	typeName := rs.GetType().Name
	tmpl := pr.LdapTemplates[typeName]
	if tmpl == nil {
		return
	}

	attrLst := attrByRtName[typeName]
	// no read permission for this ResourceType
	if attrLst == nil {
		return
	}

	dnAtVal := "at-not-found"
	dnAt := rs.GetAttr(tmpl.DnAtName)
	if dnAt != nil {
		dnAtVal = fmt.Sprintf("%s", dnAt.GetSimpleAt().Values[0])
	}

	isGroup := false
	if typeName == "Group" {
		isGroup = true
	}

	dn := fmt.Sprintf(tmpl.DnPrefix, dnAtVal, domainBaseDn)
	log.Debugf("dn>>>>>>>> %s", dn)

	entryEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	entryEnvelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	se := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SerchResultEntry")
	se.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Entry Attributes")

	ocLdapAt := &schema.LdapAttribute{LdapAttrName: "objectClass"}
	addAttributeStringsPacket(ocLdapAt, attributes, tmpl.ObjectClasses...)

	for _, ap := range attrLst {
		//log.Debugf(">>>>>>>>.. %s", ap.Name)
		//		switch ap.Name {
		//		case "uidnumber":
		//			val := strToInt(rs.GetId())
		//			log.Debugf("calculated uidNumber %d for %s", val, dn)
		//			uidNumber := &schema.LdapAttribute{LdapAttrName: "uidNumber"}
		//			addAttributePacket(uidNumber, attributes, val)
		//		case "gidnumber":
		//			val := strToInt(rs.GetId())
		//			log.Debugf("calculated gidNumber %d for %s", val, dn)
		//			gidNumber := &schema.LdapAttribute{LdapAttrName: "gidNumber"}
		//			addAttributePacket(gidNumber, attributes, val)
		//		}

		at := rs.GetAttr(ap.Name)
		if at == nil {
			continue
		}

		fetchUser := false
		if ap.Name == "members" && isGroup {
			fetchUser = true
		}

		atType := at.GetType()
		if strings.Contains(ap.Name, "uidnumber") {
			fmt.Println("")
		}

		ldapAt := tmpl.AttrMap[ap.Name]
		// if null check if removing schema URN results in a match
		// LDAP templates are made easier by not requiring to prefix
		// schema URN for extended attributes
		if ldapAt == nil {
			cpos := strings.LastIndex(ap.Name, ":")
			if cpos > 0 && cpos < (len(ap.Name)-2) {
				ap.Name = ap.Name[cpos+1:]
				ldapAt = tmpl.AttrMap[ap.Name]
			}
		}

		if atType.IsSimple() {
			if ldapAt != nil {
				sa := at.GetSimpleAt()
				// the varargs is necessary otherwise caller will treat the entire array as one interface value
				addAttributePacket(ldapAt, attributes, sa.Values...)
			}
		} else {
			ca := at.GetComplexAt()
			if ldapAt != nil {
				// fill in the format
				allValues := make([]string, 0)
				for _, mapOfSa := range ca.SubAts {
					subAtValues := make([]interface{}, len(ldapAt.SubAtNames))
					valPresent := false
					for i, sn := range ldapAt.SubAtNames {
						if sn == "dn" { // special meta attribute place holder
							subAtValues[i] = domainBaseDn
							valPresent = true
						} else {
							sa, ok := mapOfSa[sn]
							if ok {
								// if Group's memebers attribute to be formatted with "value" sub-attribute
								// then fetch the User associated with the "value" and fill in the userName value
								if fetchUser && sn == "value" {
									user, _ := pr.GetUserById(sa.Values[0].(string))
									if user != nil {
										subAtValues[i] = user.GetAttr("username").GetSimpleAt().GetStringVal()
									} else {
										subAtValues[i] = ""
									}
								} else {
									subAtValues[i] = sa.Values[0]
								}
								valPresent = true
							} else {
								subAtValues[i] = ""
							}
						}
					}

					if valPresent {
						formattedVal := fmt.Sprintf(ldapAt.Format, subAtValues...)
						allValues = append(allValues, formattedVal)
					}
				}

				if len(allValues) > 0 {
					addAttributeStringsPacket(ldapAt, attributes, allValues...)
				}
			}
			// check if any attribute starts with ca.name + "."
			for _, subAt := range atType.SubAttributes {
				ldapAt = tmpl.AttrMap[ap.Name+"."+subAt.NormName]
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
		switch v.(type) {
		//case int, uint, int8, uint8, int16, uint16, int64, uint64, int32, uint32 :
		//log.Debugf("%T %#v", t, v)
		//atValuesPacket.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, v, ""))
		default:
			strVal := fmt.Sprintf("%v", v)
			atValuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, strVal, strVal))
		}
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
				if atName == "schemas" {
					val = mapObjectClassToSchema(val, sc, pr)
				} else {
					val = `"` + val + `"`
				}
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
				if atName == "schemas" {
					val = mapObjectClassToSchema(val, sc, pr)
				} else {
					val = `"` + val + `"`
				}
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
				if atName == "schemas" {
					val = mapObjectClassToSchema(val, sc, pr)
				} else {
					val = `"` + val + `"`
				}
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

	if ldapAtName == "objectclass" {
		scimAtName := "schemas"
		schemasAt := sc.ResTypes[0].GetAtType(scimAtName)

		return scimAtName, schemasAt
	}

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

func parseFilter(packet *ber.Packet, ldapReq ldap.SearchRequest, searchCtx *base.SearchContext, pr *provider.Provider) (attrParam map[string]*base.AttributeParam, err error) {
	scimFilter, err := ldapToScimFilter(packet.Children[6], searchCtx, pr)
	searchCtx.RawReq.Filter = scimFilter
	if err != nil {
		return nil, err
	}

	log.Debugf("SCIM filter %s", scimFilter)

	// handle OBJECT scope
	if ldapReq.Scope == 0 {
		if searchCtx.Endpoint == "" {
			return nil, errors.New(fmt.Sprintf("Invalid base DN %s for searching at object scope", ldapReq.BaseDN))
		}

		var tmpl *schema.LdapEntryTemplate

		for _, v := range pr.LdapTemplates {
			if v.Endpoint == searchCtx.Endpoint {
				tmpl = v
				break
			}
		}

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
			if name == "dn" {
				log.Debugf("including uid instead of dn so that dn gets sent")
				name = "uid"
			} else {
				continue
			}
		}

		reqAttrs += (name + ",")
	}

	searchCtx.RawReq.Attributes = reqAttrs

	attrSet, subAtPresent := base.SplitAttrCsv(reqAttrs, searchCtx.ResTypes...)

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

func modifyPassword(sp *Sparrow, messageId int, extReqValPacket *ber.Packet, ls *LdapSession) {
	var userIdentity, oldPasswd, newPasswd string
	var hasUserId, hasOldPasswd, hasNewPasswd bool

	reqPacket := ber.DecodePacket(extReqValPacket.Data.Bytes())

	for i, child := range reqPacket.Children {
		if i == 0 {
			userIdentity = strings.TrimSpace(string(child.Data.Bytes()))
			if len(userIdentity) != 0 {
				hasUserId = true
			}
		}

		if i == 1 {
			oldPasswd = string(child.Data.Bytes())
			hasOldPasswd = true
		}

		if i == 2 {
			newPasswd = string(child.Data.Bytes())
			hasNewPasswd = true
		}
	}

	// no userID and not an authenticated connection
	if !hasUserId && ls.Session == nil {
		// throw unauthorized error
		errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInsufficientAccessRights, "insufficientAccessRights")
		ls.con.Write(errResp.Bytes())
		return
	}

	if !hasNewPasswd {
		// throw invalidcredentials
		errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInvalidCredentials, "New password is required")
		ls.con.Write(errResp.Bytes())
		return
	}

	var user *base.Resource
	var effSession *base.RbacSession
	var pr *provider.Provider
	var oldPasswdCompared bool

	// if the userId is nil then take the user of the current session
	if !hasUserId {
		getCtx := &base.GetContext{}
		getCtx.OpContext = ls.OpContext
		getCtx.Rid = ls.Session.Sub
		pr = sp.providers[ls.Session.Domain]
		var err error
		user, err = pr.GetResource(getCtx)
		if err != nil {
			errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultNoSuchObject, "user doesn't exist")
			ls.con.Write(errResp.Bytes())
			return
		}

		effSession = ls.Session
	} else {
		getCtx := &base.GetContext{}
		getCtx.OpContext = ls.OpContext

		var normDomain string
		getCtx.Username, normDomain = getUserNameAndDomainFromPasswdReq(userIdentity)

		if ls.Session == nil {
			if getCtx.Username == "" {
				// throw invalidcredentials
				errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInvalidCredentials, "Invalid user identity")
				ls.con.Write(errResp.Bytes())
				return
			}

			pr = sp.providers[normDomain]
		} else {
			pr = sp.providers[ls.Session.Domain]
			effSession = ls.Session
		}

		if pr == nil {
			// throw invalidcredentials
			errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInvalidCredentials, "Invalid domain")
			ls.con.Write(errResp.Bytes())
			return
		}

		if effSession == nil {
			ar := base.AuthRequest{Username: getCtx.Username, Password: oldPasswd, ClientIP: ls.ClientIP}
			user = ldap_authenticate(ar, pr)
			if user == nil {
				errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultNoSuchObject, "user doesn't exist")
				ls.con.Write(errResp.Bytes())
				return
			}
			effSession = pr.GenSessionForUser(user)
			oldPasswdCompared = true
		} else {
			getCtx.OpContext = ls.OpContext

			user = pr.GetUserByName(getCtx.Username)
			if user == nil {
				errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultNoSuchObject, "user doesn't exist")
				ls.con.Write(errResp.Bytes())
				return
			}
		}
	}

	// only allow an administrator to change someone else's password
	if hasUserId && (effSession.Sub != user.GetId()) {
		if !canChangePassword(effSession, user) {
			// throw unauthorized error
			errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInsufficientAccessRights, "insufficientAccessRights")
			ls.con.Write(errResp.Bytes())
			return
		}
	}

	pwdAt := user.GetAttr("password")
	if (pwdAt != nil) && !hasOldPasswd {
		// throw invalidcredentials
		errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInvalidCredentials, "Old password is required")
		ls.con.Write(errResp.Bytes())
		return
	}

	if pwdAt != nil && !oldPasswdCompared {
		existingPasswdHash := pwdAt.GetSimpleAt().Values[0].(string)
		matched := utils.ComparePassword(oldPasswd, existingPasswdHash)
		if !matched {
			// throw invalidcredentials
			errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultInvalidCredentials, "Old password is incorrect")
			ls.con.Write(errResp.Bytes())
			return
		}
	}

	patchCtx := &base.PatchContext{}
	patchCtx.OpContext = ls.OpContext
	patchCtx.Rid = user.GetId()
	patchCtx.Session = effSession
	patchCtx.Rt = pr.RsTypes["User"]

	replace := &base.PatchOp{}
	replace.Index = 1
	replace.Op = "replace"
	replace.Path = "password"
	replace.ParsedPath, _ = base.ParsePath(replace.Path, patchCtx.Rt)
	replace.Value = newPasswd

	patchReq := base.NewPatchReq()
	patchReq.IfMatch = user.GetVersion()
	patchReq.Operations = append(patchReq.Operations, replace)
	patchCtx.Pr = patchReq
	err := pr.Patch(patchCtx)
	if err != nil {
		// throw other error
		log.Debugf("Failed to update the password %s", err)
		errResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultOther, "Failed to update password")
		ls.con.Write(errResp.Bytes())
		return
	}

	successResp := generateResultCode(messageId, ldap.ApplicationExtendedResponse, ldap.LDAPResultSuccess, "password updated")
	ls.con.Write(successResp.Bytes())
}

func getUserNameAndDomainFromPasswdReq(userIdentity string) (uid string, domain string) {
	pos := strings.LastIndex(userIdentity, "@")
	if pos > 0 {
		return userIdentity[:pos], strings.ToLower(userIdentity[pos+1:])
	}

	// if not parse the DN
	domain, _ = getDomainAndEndpoint(userIdentity)
	uid = getUsernameFromDn(userIdentity)
	if uid == "" {
		uid = userIdentity
	}
	return uid, strings.ToLower(domain)
}

func sendVirtualEntry(dn string, objectClass string, rdns map[string][]string, pr *provider.Provider, messageId int, ls *LdapSession) {
	entryEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	entryEnvelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	se := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultEntry, nil, "SerchResultEntry")
	se.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, dn, "DN"))
	attributes := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Entry Attributes")

	ocLdapAt := &schema.LdapAttribute{LdapAttrName: "objectClass"}
	addAttributeStringsPacket(ocLdapAt, attributes, "top", objectClass)

	for k, v := range rdns {
		rdnAt := &schema.LdapAttribute{LdapAttrName: k}
		addAttributeStringsPacket(rdnAt, attributes, v...)
	}

	uuidAt := &schema.LdapAttribute{LdapAttrName: "entryUUID"}
	addAttributeStringsPacket(uuidAt, attributes, utils.GenUUID())

	se.AppendChild(attributes)
	entryEnvelope.AppendChild(se)
	ls.con.Write(entryEnvelope.Bytes())
}

func sendVirtualBase(req ldap.SearchRequest, pr *provider.Provider, messageId int, ls *LdapSession) {
	isDc := strings.HasPrefix(req.BaseDN, "dc=")
	isOu := strings.HasPrefix(req.BaseDN, "ou=")

	if isDc {
		if req.Scope == 0 { // OBJECT
			rdns := make(map[string][]string)
			rdns["dc"] = strings.Split(req.BaseDN, ".")
			sendVirtualEntry(req.BaseDN, "domain", rdns, pr, messageId, ls)
		} else {
			for _, v := range pr.RsTypes {
				rdns := make(map[string][]string)
				dn := req.BaseDN
				ou := v.Endpoint[1:]
				dn = "ou=" + ou + "," + dn
				rdns["ou"] = []string{ou}
				sendVirtualEntry(dn, "organizationalUnit", rdns, pr, messageId, ls)
			}
		}
	}
	if isOu { // OBJECT ONLY
		rdns := make(map[string][]string)
		_, ouEndpoint := getDomainAndEndpoint(req.BaseDN)
		rdns["ou"] = []string{ouEndpoint[1:]} // leave the prefixed /
		sendVirtualEntry(req.BaseDN, "organizationalUnit", rdns, pr, messageId, ls)
	}

	result := generateResultCode(messageId, ldap.ApplicationSearchResultDone, ldap.LDAPResultSuccess, "")
	ls.con.Write(result.Bytes())
}

func domainNameToDn(domainName string) string {
	rdns := strings.Split(domainName, ".")
	dn := ""
	prefix := "dc="
	commaPrefix := "," + prefix
	for i, s := range rdns {
		if i > 0 {
			dn += commaPrefix + s
		} else {
			dn += prefix + s
		}
	}

	return dn
}

func mapObjectClassToSchema(objectClassName string, sc *base.SearchContext, pr *provider.Provider) string {
	for _, rt := range sc.ResTypes {
		tmpl := pr.LdapTemplates[rt.Name]
		if tmpl != nil {
			for _, v := range tmpl.ObjectClasses {
				if strings.EqualFold(objectClassName, v) {
					return `"` + rt.Schema + `"`
				}
			}
		}
	}

	// if not found just return the given objectClassName
	return `"` + objectClassName + `"`
}

func canChangePassword(effSession *base.RbacSession, user *base.Resource) bool {
	rp := effSession.EffPerms[user.GetType().Name]
	if rp == nil {
		return false
	}

	if rp.WritePerm.OnAnyResource && rp.WritePerm.AllowAll {
		return true
	}

	_, hasPassword := rp.WritePerm.AllowAttrs["password"]
	if !hasPassword {
		return false
	}

	return rp.WritePerm.EvalFilter(user)
}

func ldap_authenticate(ar base.AuthRequest, pr *provider.Provider) (user *base.Resource) {
	user = pr.GetUserByName(ar.Username)
	if user == nil {
		pr.Al.LogAuth("", ar.Username, ar.ClientIP, base.LOGIN_USER_NOT_FOUND)
		return nil
	}

	tfaEnabled := user.IsTfaEnabled()
	totpCode := ""
	// in case of LDAP, if TFA is enabled for a user then it is assumed that
	// user already performed the necessary setup to obtain OTPs
	if tfaEnabled {
		plen := len(ar.Password)
		// OTP code contains 6 digits
		if plen <= OTP_LEN {
			pr.Al.LogAuth("", ar.Username, ar.ClientIP, base.LOGIN_FAILED)
			return nil
		}

		plen = plen - OTP_LEN
		totpCode = ar.Password[plen:]
		ar.Password = ar.Password[:plen]
	}

	log.Debugf("<<<<< username %s password %s", ar.Username, ar.Password)
	lr := pr.Authenticate(ar)
	pr.Al.LogAuth(lr.Id, ar.Username, ar.ClientIP, lr.Status)

	if lr.Status == base.LOGIN_TFA_REQUIRED {
		lr = pr.VerifyOtp(lr.Id, totpCode, ar.ClientIP)
		pr.Al.LogOtp(lr.Id, ar.ClientIP, lr.User, lr.Status)
	}

	if lr.Status == base.LOGIN_SUCCESS {
		return lr.User
	}

	return nil
}

func strToInt(id string) uint32 {
	var number uint32
	for _, r := range id {
		number += uint32(r)
	}
	return number
}

func isSelfServe(ls *LdapSession, ldapReq ldap.SearchRequest) bool {
	dn := strings.ToLower(ldapReq.BaseDN)
	return strings.HasPrefix(dn, "uid="+ls.username+",ou=users,")
}
