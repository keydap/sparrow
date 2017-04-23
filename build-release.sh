#!/bin/bash
# builds x64 binaries for Linux, OS X and Windows operating systems

copyVersionFile() {
    cp resources/version.txt net/version.go
}

genVersionInfo() {

}

buildLinux() {
    #env GOOS=linux GOARCH=arm go build -v github.com/path/to/your/app
}