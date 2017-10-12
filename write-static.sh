#!/bin/bash
# a shell script to write all the static text data content in .go files

writeConst() {
   printf "const $1=\`" >> $3
   cat $2 >> $3
   printf "\`\n\n" >> $3
}

writeHtml() {
  targetFile="net/static_html.go"
  printf "package net\n\n" > $targetFile
  writeConst "login_html" "templates/login.html" $targetFile
  writeConst "consent_html" "templates/consent.html" $targetFile
}

writeSchemas() {
  targetFile="net/static_schemas.go"
  printf "package net\n\n" > $targetFile
  writeConst "device_schema" "resources/schemas/device.json" $targetFile
  writeConst "enterprise_user_schema" "resources/schemas/enterprise-user.json" $targetFile
  writeConst "group_schema" "resources/schemas/group.json" $targetFile
  writeConst "user_schema" "resources/schemas/user.json" $targetFile  
  writeConst "posix_user_schema" "resources/schemas/posix-user.json" $targetFile  
  writeConst "posix_group_schema" "resources/schemas/posix-group.json" $targetFile  
}

writeResourceTypes() {
  targetFile="net/static_resourcetypes.go"
  printf "package net\n\n" > $targetFile
  writeConst "device_type" "resources/types/device.json" $targetFile
  writeConst "group_type" "resources/types/group.json" $targetFile
  writeConst "user_type" "resources/types/user.json" $targetFile
}

copyVersionFile() {
    cp resources/version.txt net/version.go
}

copyVersionFile() {
    cp resources/version.txt net/version.go
}

printf "Writing HTML templates\n"
writeHtml

printf "Writing schemas\n"
writeSchemas

printf "Writing resourcetype\n"
writeResourceTypes

printf "Copying version file\n"
copyVersionFile
printf "Copying version file\n"
copyVersionFile