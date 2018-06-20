#!/usr/bin/env bash
echo 'getting packages'

# boltdb has been replaced with coreos/bbolt
# go get github.com/boltdb/bolt
go get github.com/coreos/bbolt
# logging package
go get github.com/juju/loggo
# http routing package
go get github.com/gorilla/mux
#fernet token (we don't need this cause JWT is there)
#go get github.com/fernet/fernet-go
#JWT
go get github.com/dgrijalva/jwt-go

go get github.com/go-ldap/ldap

go get github.com/gorilla/securecookie

go get github.com/gorilla/sessions

go get github.com/russellhaering/gosaml2

go get github.com/pquerna/otp