#!/usr/bin/env bash
echo 'getting packages'

# boltdb
go get github.com/boltdb/bolt
# logging package
go get github.com/juju/loggo
# http routing package
go get github.com/gorilla/mux
#fernet token (we don't need this cause JWT is there)
#go get github.com/fernet/fernet-go
#JWT
go get github.com/dgrijalva/jwt-go
