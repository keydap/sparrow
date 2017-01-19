package net

import (
	"errors"
	"fmt"
	"github.com/go-ldap/ldap"
	ber "gopkg.in/asn1-ber.v1"
	"io"
	"net"
	"sparrow/base"
	"sparrow/provider"
	"sparrow/schema"
	"strings"
)

type LdapSession struct {
	con   *net.TCPConn
	token *base.RbacSession
}

var ldapSessions = make(map[string]*LdapSession)

func StartLdap(hostAddr string) error {
	//hostAddr := srvConf.Ipaddress + ":" + strconv.Itoa(srvConf.LdapPort)

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

	acceptConns(listener)

	return nil
}

func acceptConns(listener *net.TCPListener) {
	for {
		con, err := listener.AcceptTCP()
		if err != nil {
			log.Warningf("Failed to accept connection %s", err)
			continue
		}

		log.Debugf("Serving new connection from %s", con.RemoteAddr())
		go serveClient(con)
	}
}

func serveClient(con *net.TCPConn) {

	remoteAddr := con.RemoteAddr().String()

	defer func() {
		log.Debugf("closing connection %s", remoteAddr)
		con.Close()
		delete(ldapSessions, remoteAddr)
	}()

	ls := &LdapSession{}
	ls.con = con
	ldapSessions[remoteAddr] = ls

	for {
		packet, err := ber.ReadPacket(con)
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

		switch packet.Children[1].Tag {
		case ldap.ApplicationBindRequest:
			child := packet.Children[1]
			bindReq := &ldap.SimpleBindRequest{}
			bindReq.Username = string(child.Children[1].ByteValue)
			bindReq.Password = string(child.Children[2].Data.Bytes())
			messageId := int(packet.Children[0].Value.(int64))

			handleSimpleBind(bindReq, ls, messageId)

		case ldap.ApplicationSearchRequest:
			//			if ls.token == nil {
			//				// throw unauthorized error
			//			}
			handleSearch(packet, ls)

		}
	}
}

func handleSimpleBind(bindReq *ldap.SimpleBindRequest, ls *LdapSession, messageId int) {
	log.Debugf("handling bind request from %s", ls.con.RemoteAddr())
	log.Debugf("username = %s , password %s", bindReq.Username, bindReq.Password)

	response := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	response.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	result := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationBindResponse, nil, "Bind response")
	result.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Result code"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	result.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Error message"))
	response.AppendChild(result)

	ls.con.Write(response.Bytes())
}

func toSearchContext(packet *ber.Packet, ls *LdapSession) (searchCtx *base.SearchContext, pr *provider.Provider, attrParam []*base.AttributeParam) {
	opCtx := &base.OpContext{}
	opCtx.ClientIP = ls.con.RemoteAddr().Network()

	searchCtx = &base.SearchContext{}
	searchCtx.OpContext = opCtx

	baseDN := packet.Children[0].Value.(string)
	//scope := int(packet.Children[1].Value.(int64))

	// detect ResourceTypes from baseDN
	rdns := strings.Split(baseDN, ",")

	rdnLen := len(rdns)
	if rdnLen < 2 {
		// throw error
	}

	domain := ""

	for _, v := range rdns {
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
			searchCtx.Endpoint = "User" //v[3:]
		}
	}

	pr = providers[domain]

	if pr == nil {
		// throw error
	}

	searchCtx.ResTypes = make([]*schema.ResourceType, 0)

	rt := pr.RsTypes[searchCtx.Endpoint]
	if rt != nil {
		searchCtx.ResTypes = append(searchCtx.ResTypes, rt)
	} else {
		for _, v := range pr.RsTypes {
			searchCtx.ResTypes = append(searchCtx.ResTypes, v)
		}
	}

	// derefAliases := int(packet.Children[2].Value.(int64))
	searchCtx.MaxResults = int(packet.Children[3].Value.(int64))
	// timeLimit := int(packet.Children[4].Value.(int64))
	// typesOnly := packet.Children[5].Value.(bool)
	// ldapFilter, err := ldap.DecompileFilter(packet.Children[6])

	scimFilter, _ := ldapToScimFilter(packet.Children[6], searchCtx, pr)
	// TODO handle OBJECT scope
	// if scope == 0
	log.Debugf("SCIM filter %s", scimFilter)

	var err error
	searchCtx.Filter, err = base.ParseFilter(scimFilter)
	if err != nil {
		//throw error
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

	return searchCtx, pr, attrParam
}

func handleSearch(packet *ber.Packet, ls *LdapSession) {
	log.Debugf("handling search request from %s", ls.con.RemoteAddr())
	messageId := int(packet.Children[0].Value.(int64))
	child := packet.Children[1]
	sc, pr, attrLst := toSearchContext(child, ls)
	//	log.Debugf("%#v", searchReq)

	outPipe := make(chan *base.Resource, 0)

	// search starts a go routine and returns nil error immediately
	// or returns an error before starting the go routine
	err := pr.Search(sc, outPipe)
	if err != nil {
		close(outPipe)
		//writeError(err)
		return
	}

	count := 0
	for rs := range outPipe {
		typeName := rs.GetType().Name
		tmpl := pr.LdapTemplates[typeName]
		if tmpl == nil {
			continue
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

		ocAtPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "ObjectClass Attribute")
		ocAtPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "objectClass", "objectClass"))
		ocAtValuesPacket := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSet, nil, "ObjectClass Attribute Values")

		for _, oc := range tmpl.ObjectClasses {
			ocAtValuesPacket.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, oc, oc))
		}
		ocAtPacket.AppendChild(ocAtValuesPacket)
		attributes.AppendChild(ocAtPacket)

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
					addAttributePacket(ldapAt, attributes, sa.Values)
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
						addAttributePacket(ldapAt, attributes, values)
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

			//attributes.AppendChild(child)
		}
		count++

		se.AppendChild(attributes)
		entryEnvelope.AppendChild(se)
		ls.con.Write(entryEnvelope.Bytes())
	}

	entryEnvelope := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "Message Envelope")
	entryEnvelope.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, messageId, "Message ID"))

	sd := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationSearchResultDone, nil, "SerchResultDone")
	sd.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagEnumerated, 0, "Result code"))
	sd.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Matched DN"))
	sd.AppendChild(ber.NewString(ber.ClassUniversal, ber.TypePrimitive, ber.TagOctetString, "", "Error message"))
	entryEnvelope.AppendChild(sd)
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
