#!/bin/bash
# builds x64 binaries for Linux, OS X and Windows operating systems

DIST_DIR="dist"

copyVersionFile() {
    cp resources/version.txt net/version.go
}


buildLinux() {
    env GOOS=linux GOARCH=386 go build -v -o $DIST_DIR/sparrow-linux32
    env GOOS=linux GOARCH=amd64 go build -v -o $DIST_DIR/sparrow-linux64 
}

buildOsX() {
    env GOOS=darwin GOARCH=amd64 go build -v -o $DIST_DIR/sparrow-darwin64
}

buildWindows() {
    env GOOS=windows GOARCH=386 go build -v -o $DIST_DIR/sparrow-win32
    env GOOS=windows GOARCH=amd64 go build -v -o $DIST_DIR/sparrow-win64
}

buildLinux
buildOsX
buildWindows