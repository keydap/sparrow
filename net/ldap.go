package net

import (
	"errors"
	"github.com/go-ldap/ldap"
	ber "gopkg.in/asn1-ber.v1"
	"io"
	"net"
	"sparrow/base"
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
			child := packet.Children[1]
			searchReq := &ldap.SearchRequest{}
			searchReq.BaseDN = child.Children[0].Value.(string)
			searchReq.Scope = int(child.Children[1].Value.(int64))
			searchReq.DerefAliases = int(child.Children[2].Value.(int64))
			searchReq.SizeLimit = int(child.Children[3].Value.(int64))
			searchReq.TimeLimit = int(child.Children[4].Value.(int64))
			searchReq.TypesOnly = child.Children[5].Value.(bool)
			searchReq.Filter, err = ldap.DecompileFilter(child.Children[6])

			if err != nil {
				// reject request
			}

			scimFilter, _ := ldapToScimFilter(child.Children[6])
			log.Debugf("SCIM filter %s", scimFilter)

			attr := make([]string, 0)

			attrChildren := child.Children[7].Children
			for _, c := range attrChildren {
				attr = append(attr, c.Value.(string))
			}

			searchReq.Attributes = attr

			handleSearch(searchReq, ls)

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

func handleSearch(searchReq *ldap.SearchRequest, ls *LdapSession) {
	log.Debugf("handling search request from %s", ls.con.RemoteAddr())
	log.Debugf("%#v", searchReq)
}

// converts a packet representation of a LDAP filter into a string representation of SCIM filter
// taken from go-ldap
func ldapToScimFilter(packet *ber.Packet) (ret string, err error) {
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
			childStr, err = ldapToScimFilter(child)
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
			childStr, err = ldapToScimFilter(child)
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
		childStr, err = ldapToScimFilter(packet.Children[0])
		if err != nil {
			return
		}
		ret += childStr

	case ldap.FilterSubstrings:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += " co "
		for i, child := range packet.Children[1].Children {
			if i == 0 && child.Tag != ldap.FilterSubstringsInitial {
				//ret += "*"
			}
			ret += ldap.EscapeFilter(ber.DecodeString(child.Data.Bytes()))
			if child.Tag != ldap.FilterSubstringsFinal {
				//ret += "*"
			}
		}
	case ldap.FilterEqualityMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += " eq "
		ret += ldap.EscapeFilter(ber.DecodeString(packet.Children[1].Data.Bytes()))
	case ldap.FilterGreaterOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += " ge "
		ret += ldap.EscapeFilter(ber.DecodeString(packet.Children[1].Data.Bytes()))
	case ldap.FilterLessOrEqual:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += " le "
		ret += ldap.EscapeFilter(ber.DecodeString(packet.Children[1].Data.Bytes()))
	case ldap.FilterPresent:
		ret += ber.DecodeString(packet.Data.Bytes())
		ret += " pr "
	case ldap.FilterApproxMatch:
		ret += ber.DecodeString(packet.Children[0].Data.Bytes())
		ret += "~="
		ret += ldap.EscapeFilter(ber.DecodeString(packet.Children[1].Data.Bytes()))
	case ldap.FilterExtensibleMatch:
		attr := ""
		dnAttributes := false
		matchingRule := ""
		value := ""

		for _, child := range packet.Children {
			switch child.Tag {
			case ldap.MatchingRuleAssertionMatchingRule:
				matchingRule = ber.DecodeString(child.Data.Bytes())
			case ldap.MatchingRuleAssertionType:
				attr = ber.DecodeString(child.Data.Bytes())
			case ldap.MatchingRuleAssertionMatchValue:
				value = ber.DecodeString(child.Data.Bytes())
			case ldap.MatchingRuleAssertionDNAttributes:
				dnAttributes = child.Value.(bool)
			}
		}

		if len(attr) > 0 {
			ret += attr
		}
		if dnAttributes {
			ret += ":dn"
		}
		if len(matchingRule) > 0 {
			ret += ":"
			ret += matchingRule
		}
		ret += ":="
		ret += ldap.EscapeFilter(value)
	}

	ret += ")"
	return
}
