package net

import (
	"github.com/go-ldap/ldap"
	ber "gopkg.in/asn1-ber.v1"
	"net"
	"sparrow/base"
	//	"strconv"
	"io"
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
			bindReq := packet.Children[1]
			handleSimpleBind(bindReq, ls)

		case ldap.ApplicationSearchRequest:
			//			if ls.token == nil {
			//				// throw unauthorized error
			//			}
			searchReq := packet.Children[1]
			handleSearch(searchReq, ls)

		}
	}
}

func handleSimpleBind(bindReq *ber.Packet, ls *LdapSession) {
	username := string(bindReq.Children[1].ByteValue)
	password := string(bindReq.Children[2].Data.Bytes())

	log.Debugf("username = %s , password %s", username, password)

}

func handleSearch(searchReq *ber.Packet, ls *LdapSession) {

}
